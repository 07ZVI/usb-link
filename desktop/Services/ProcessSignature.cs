using System.Diagnostics;
using System.Formats.Asn1;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using Microsoft.Win32.SafeHandles;

namespace Suhang.Desktop;

// Two persistent, disposable child processes isolate potentially slow Windows
// trust providers. Only this private pipe receives their JSON; backend IPC is untouched.
internal sealed class ProcessSignatureWorker : IDisposable
{
    Process? child;
    internal async Task<ProcessTrust> CheckAsync(string path, string identity, CancellationToken cancellation) {
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellation);
        timeout.CancelAfter(TimeSpan.FromSeconds(8));
        try {
            if (child == null || child.HasExited) {
                Dispose();
                var executable = Environment.ProcessPath ?? throw new IOException("Missing executable");
                var start = new ProcessStartInfo(executable) {
                    UseShellExecute = false, CreateNoWindow = true, WindowStyle = ProcessWindowStyle.Hidden,
                    RedirectStandardInput = true, RedirectStandardOutput = true, RedirectStandardError = true,
                    StandardInputEncoding = new UTF8Encoding(false), StandardOutputEncoding = Encoding.UTF8,
                    StandardErrorEncoding = Encoding.UTF8
                };
                if (System.IO.Path.GetFileNameWithoutExtension(executable).Equals("dotnet", StringComparison.OrdinalIgnoreCase))
                    start.ArgumentList.Add(Assembly.GetEntryAssembly()!.Location);
                start.ArgumentList.Add("--process-signature-worker");
                child = Process.Start(start) ?? throw new IOException("Worker did not start");
                child.ErrorDataReceived += (_, _) => { }; child.BeginErrorReadLine();
            }
            await child.StandardInput.WriteLineAsync(JsonSerializer.Serialize(new SignatureRequest(path, identity)).AsMemory(), timeout.Token);
            await child.StandardInput.FlushAsync(timeout.Token);
            var result = await ReadLineAsync(child.StandardOutput, 16384, timeout.Token);
            return JsonSerializer.Deserialize<ProcessTrust>(result) ?? new("unverified", "簽章驗證結果無法讀取。");
        } catch (OperationCanceledException) {
            Dispose(); return new("unverified", "簽章驗證逾時或已取消，請重新驗證。");
        } catch {
            Dispose(); return new("unverified", "簽章驗證元件未完成，請重新驗證。");
        }
    }

    // Bounded line reader, including malformed child output and worker input.
    internal static async Task<string> ReadLineAsync(StreamReader reader, int limit, CancellationToken token) {
        var result = new StringBuilder(); var character = new char[1];
        while (await reader.ReadAsync(character.AsMemory(), token) != 0) {
            if (character[0] == '\n') return result.ToString().TrimEnd('\r');
            if (result.Length >= limit) throw new InvalidDataException("Worker line too large");
            result.Append(character[0]);
        }
        if (result.Length > 0) return result.ToString();
        throw new EndOfStreamException();
    }

    internal static int Run() {
        Console.InputEncoding = Encoding.UTF8; Console.OutputEncoding = new UTF8Encoding(false);
        using var input = new StreamReader(Console.OpenStandardInput(), Encoding.UTF8);
        while (true) {
            string line;
            try { line = ReadLineAsync(input, 16384, CancellationToken.None).GetAwaiter().GetResult(); }
            catch (EndOfStreamException) { return 0; }
            catch { return 1; }
            ProcessTrust result;
            try {
                var request = JsonSerializer.Deserialize<SignatureRequest>(line);
                result = request == null ? new("unverified", "程式身分不完整。") : NativeProcessSignature.Inspect(request.Path, request.Identity);
            } catch { result = new("unverified", "驗證時無法讀取程式檔案。"); }
            Console.WriteLine(JsonSerializer.Serialize(result)); 
        }
    }
    public void Dispose() {
        if (child == null) return;
        try { if (!child.HasExited) child.Kill(entireProcessTree: true); } catch { }
        child.Dispose(); child = null;
    }
    sealed record SignatureRequest(string Path, string Identity);
}

// Independent implementation against Microsoft's documented APIs. Reference:
// System Informer phlib/verify.c (catalog fallback, WinVerifyTrust and cached trust).
// The checked subject is the executable on disk, not arbitrary in-memory code.
internal static class NativeProcessSignature
{
    const uint NoSignature = 0x800B0100;
    internal const uint TrustFlags = 0x1000 | 0x80; // CACHE_ONLY_URL_RETRIEVAL | CHECK_CHAIN_EXCLUDE_ROOT
    static readonly Guid VerifyAction = new("00AAC56B-CD44-11D0-8CC2-00C04FC295EE");
    static readonly Guid CatalogSubsystem = new("F750E6C3-38EE-11D1-85E5-00C04FC295EE");

    internal static string? LocalDriveRoot(string path) {
        var local=path.StartsWith(@"\\?\",StringComparison.Ordinal)?path[4..]:path;
        return local.Length>=3 && char.IsAsciiLetter(local[0]) && local[1]==':' && local[2]=='\\' ? local[..3] : null;
    }
    internal static bool IsLocalPath(string path) {
        var root=LocalDriveRoot(path); if(root==null)return false;
        if(!OperatingSystem.IsWindows())return true;
        return GetDriveType(root) is 2 or 3 or 5 or 6;
    }
    [DllImport("kernel32.dll",EntryPoint="GetDriveTypeW",CharSet=CharSet.Unicode),DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    static extern uint GetDriveType(string root);

    internal static ProcessTrust Inspect(string path, string expectedIdentity) {
        if (!OperatingSystem.IsWindows()) return new("unverified", "需由 Windows 驗證。");
        if (!IsLocalPath(path) || expectedIdentity.Length == 0)
            return new("unverified", "需為本機程式檔案，遠端路徑不自動驗證。");
        using var file = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read);
        if (ProcessInventory.FileIdentity(file, path) != expectedIdentity) return new("unverified", "程式檔案已變更，等待重新整理後驗證。");
        if (file.Length > 1L << 30) return new("unverified", "程式檔案超過 1 GB，未自動驗證。");
        var hash = Convert.ToHexString(SHA256.HashData(file)); file.Position = 0;
        using var info = new NativeValue<FileInfo>(new() { Size = (uint)Marshal.SizeOf<FileInfo>(), Path = path, File = file.SafeFileHandle.DangerousGetHandle() });
        var result = Verify(info.Pointer, 1, "內嵌簽章");
        if (result.Status != "valid") {
            foreach (var algorithm in new[] { "SHA256", "SHA1" }) {
                var catalog = VerifyCatalog(file, path, algorithm);
                if (catalog?.Status == "valid") { result = catalog; break; }
                if (catalog != null && (result.Code == $"0x{NoSignature:X8}" || catalog.Priority < result.Priority)) result = catalog;
            }
        }
        bool? protectedFile = null;
        string company = "", originalName = "";
        try { protectedFile = SfcIsFileProtected(IntPtr.Zero,path); } catch { }
        try { var version = FileVersionInfo.GetVersionInfo(path); company = ProcessInventory.Clean(new string((version.CompanyName ?? "").Take(512).ToArray())); originalName = ProcessInventory.Clean(new string((version.OriginalFilename ?? "").Take(512).ToArray())); } catch { }
        if (ProcessInventory.FileIdentity(file, path) != expectedIdentity) return new("unverified", "驗證期間檔案已變更。");
        return result with { Hash = hash, CheckedAt = DateTimeOffset.UtcNow.ToString("O"), WindowsProtected=protectedFile, ClaimedCompany=company, ClaimedOriginalName=originalName };
    }

    [DllImport("sfc.dll",CharSet=CharSet.Unicode),DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    [return:MarshalAs(UnmanagedType.Bool)] static extern bool SfcIsFileProtected(IntPtr reserved,string path);

    static ProcessTrust? VerifyCatalog(FileStream file, string path, string algorithm) {
        var subsystem = CatalogSubsystem;
        if (!CryptCATAdminAcquireContext2(out var admin, ref subsystem, algorithm, IntPtr.Zero, 0))
            return new("unverified", "Windows 系統目錄簽章資料庫無法讀取。");
        IntPtr current = IntPtr.Zero;
        try {
            uint size = 0; file.Position = 0;
            if (!CryptCATAdminCalcHashFromFileHandle2(admin, file.SafeFileHandle, ref size, null, 0) || size is 0 or > 128)
                return new("unverified", "目錄簽章雜湊無法計算。");
            var hash = new byte[size]; file.Position = 0;
            if (!CryptCATAdminCalcHashFromFileHandle2(admin, file.SafeFileHandle, ref size, hash, 0))
                return new("unverified", "目錄簽章雜湊無法計算。");
            ProcessTrust? result = null;
            for (var i = 0; i < 64; i++) {
                // The native enumerator consumes the previous context. Release
                // the current context explicitly only when stopping early.
                current = CryptCATAdminEnumCatalogFromHash(admin, hash, size, 0, ref current);
                if (current == IntPtr.Zero) {
                    var error = Marshal.GetLastPInvokeError();
                    return error is 0 or 1168 or 259 ? result : new("unverified", "系統目錄簽章查詢失敗，無法確認。", Code: $"Win32 {error}");
                }
                var catalog = new CatalogInfo { Size = (uint)Marshal.SizeOf<CatalogInfo>(), Path = "" };
                if (!CryptCATCatalogInfoFromContext(current, ref catalog, 0)) {
                    result ??= new("unverified", "無法讀取目錄簽章路徑。"); continue;
                }
                file.Position = 0;
                using var info = new NativeValue<CatalogTrustInfo>(new() {
                    Size = (uint)Marshal.SizeOf<CatalogTrustInfo>(), Catalog = catalog.Path, MemberTag = Convert.ToHexString(hash),
                    Member = path, File = file.SafeFileHandle.DangerousGetHandle(), Admin = admin
                });
                var candidate = Verify(info.Pointer, 2, "系統目錄簽章（" + algorithm + "）");
                if (candidate.Status == "valid") return candidate;
                if (result == null || candidate.Priority < result.Priority) result = candidate;
            }
            return new("unverified", "系統目錄簽章數量超出驗證範圍。");
        } finally {
            if (current != IntPtr.Zero) CryptCATAdminReleaseCatalogContext(admin, current, 0);
            CryptCATAdminReleaseContext(admin, 0);
        }
    }

    static ProcessTrust Verify(IntPtr subject, uint choice, string source) {
        if (choice != 1) return VerifyOne(subject, choice, source, IntPtr.Zero);
        using var settings = new NativeValue<SignatureSettings>(new() { Size = (uint)Marshal.SizeOf<SignatureSettings>(), Flags = 2 });
        var result = VerifyOne(subject, choice, source, settings.Pointer);
        if (result.Status == "valid") return result;
        var count = Marshal.PtrToStructure<SignatureSettings>(settings.Pointer).SecondaryCount;
        // Dual-signed executables can have an obsolete primary signer and a
        // valid secondary signer. Verify each bounded candidate independently.
        for (uint i = 1; i <= Math.Min(count, 16); i++) {
            using var next = new NativeValue<SignatureSettings>(new() { Size = (uint)Marshal.SizeOf<SignatureSettings>(), Flags = 1, Index = i });
            var candidate = VerifyOne(subject, choice, source + "（簽章 " + (i + 1) + "）", next.Pointer);
            if (candidate.Status == "valid") return candidate;
            if (candidate.Priority < result.Priority) result = candidate;
        }
        return count > 16 ? new("unverified", "程式簽章數量超出自動驗證範圍。") : result;
    }

    static ProcessTrust VerifyOne(IntPtr subject, uint choice, string source, IntPtr settings) {
        var action = VerifyAction;
        var data = new TrustData {
            Size = (uint)Marshal.SizeOf<TrustData>(), UiChoice = 2, Revocation = 1, Choice = choice,
            Subject = subject, StateAction = 1, Flags = TrustFlags, SignatureSettings = settings
        };
        try {
            var code = unchecked((uint)WinVerifyTrust(new IntPtr(-1), ref action, ref data));
            var result = ProcessTrust.FromCode(code) with { Source = source };
            var provider = WTHelperProvDataFromStateData(data.State);
            if (provider == IntPtr.Zero) return result;
            var pointer = WTHelperGetProvSignerFromChain(provider, 0, false, 0);
            if (pointer == IntPtr.Zero) return result;
            var signer = Marshal.PtrToStructure<ProviderSigner>(pointer);
            if (signer.CertificateCount == 0 || signer.Certificates == IntPtr.Zero) return result;
            var cert = Marshal.PtrToStructure<ProviderCertificate>(signer.Certificates);
            if (cert.Certificate == IntPtr.Zero) return result;
            var context = Marshal.PtrToStructure<CertificateContext>(cert.Certificate);
            if (context.Size is 0 or > 1048576 || context.Encoded == IntPtr.Zero) return result;
            var bytes = new byte[context.Size]; Marshal.Copy(context.Encoded, bytes, 0, bytes.Length);
            using var certificate = X509CertificateLoader.LoadCertificate(bytes);
            return result with {
                VerifiedMicrosoft = result.Status == "valid" && IsMicrosoftOrganization(certificate.SubjectName),
                Publisher = ProcessInventory.Clean(certificate.GetNameInfo(X509NameType.SimpleName, false)),
                Subject = ProcessInventory.Clean(certificate.Subject), Issuer = ProcessInventory.Clean(certificate.Issuer),
                Thumbprint = certificate.Thumbprint, NotBefore = certificate.NotBefore.ToUniversalTime().ToString("O"),
                NotAfter = certificate.NotAfter.ToUniversalTime().ToString("O"), Timestamped = signer.CounterSigners > 0
            };
        } finally {
            data.StateAction = 2; WinVerifyTrust(new IntPtr(-1), ref action, ref data);
        }
    }

    // Read the actual organization RDN; a display name or text embedded in CN
    // must not be mistaken for Microsoft's certificate organization.
    internal static bool IsMicrosoftOrganization(X500DistinguishedName name) {
        try {
            var reader=new AsnReader(name.RawData,AsnEncodingRules.DER).ReadSequence();
            var organizations=new List<string>();
            while(reader.HasData) {
                var set=reader.ReadSetOf();
                while(set.HasData) {
                    var attribute=set.ReadSequence();var oid=attribute.ReadObjectIdentifier();
                    if(oid=="2.5.4.10")organizations.Add(attribute.ReadCharacterString((UniversalTagNumber)attribute.PeekTag().TagValue));
                }
            }
            return organizations.Count==1&&organizations[0].Equals("Microsoft Corporation",StringComparison.OrdinalIgnoreCase);
        } catch { return false; }
    }

    sealed class NativeValue<T> : IDisposable where T : struct {
        internal IntPtr Pointer { get; } = Marshal.AllocHGlobal(Marshal.SizeOf<T>());
        internal NativeValue(T value) => Marshal.StructureToPtr(value, Pointer, false);
        public void Dispose() { Marshal.DestroyStructure<T>(Pointer); Marshal.FreeHGlobal(Pointer); }
    }
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)] struct FileInfo {
        internal uint Size; [MarshalAs(UnmanagedType.LPWStr)] internal string Path;
        internal IntPtr File, KnownSubject;
    }
    [StructLayout(LayoutKind.Sequential)] internal struct TrustData {
        internal uint Size; internal IntPtr Policy, Sip;
        internal uint UiChoice, Revocation, Choice; internal IntPtr Subject;
        internal uint StateAction; internal IntPtr State, Url;
        internal uint Flags, UiContext; internal IntPtr SignatureSettings;
    }
    [StructLayout(LayoutKind.Sequential)] struct SignatureSettings {
        internal uint Size, Index, Flags, SecondaryCount, VerifiedIndex;
        internal IntPtr Policy;
    }
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)] struct CatalogTrustInfo {
        internal uint Size, Version;
        [MarshalAs(UnmanagedType.LPWStr)] internal string Catalog;
        [MarshalAs(UnmanagedType.LPWStr)] internal string MemberTag;
        [MarshalAs(UnmanagedType.LPWStr)] internal string Member;
        internal IntPtr File, Hash; internal uint HashSize; internal IntPtr Context, Admin;
    }
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)] struct CatalogInfo {
        internal uint Size; [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 260)] internal string Path;
    }
    [StructLayout(LayoutKind.Sequential)] struct ProviderSigner {
        internal uint Size, TimeLow, TimeHigh, CertificateCount; internal IntPtr Certificates;
        internal uint Type; internal IntPtr Signer; internal uint Error, CounterSigners; internal IntPtr Counters, Chain;
    }
    [StructLayout(LayoutKind.Sequential)] struct ProviderCertificate { internal uint Size; internal IntPtr Certificate; }
    [StructLayout(LayoutKind.Sequential)] struct CertificateContext { internal uint Encoding; internal IntPtr Encoded; internal uint Size; }

    [DllImport("wintrust.dll", ExactSpelling = true), DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    static extern int WinVerifyTrust(IntPtr window, ref Guid action, ref TrustData data);
    [DllImport("wintrust.dll", ExactSpelling = true), DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    static extern IntPtr WTHelperProvDataFromStateData(IntPtr state);
    [DllImport("wintrust.dll", ExactSpelling = true), DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    static extern IntPtr WTHelperGetProvSignerFromChain(IntPtr provider, uint index, [MarshalAs(UnmanagedType.Bool)] bool counter, uint counterIndex);
    [DllImport("wintrust.dll", CharSet = CharSet.Unicode, ExactSpelling = true, SetLastError = true), DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    [return: MarshalAs(UnmanagedType.Bool)] static extern bool CryptCATAdminAcquireContext2(out IntPtr admin, ref Guid subsystem, string algorithm, IntPtr policy, uint flags);
    [DllImport("wintrust.dll", ExactSpelling = true, SetLastError = true), DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    [return: MarshalAs(UnmanagedType.Bool)] static extern bool CryptCATAdminCalcHashFromFileHandle2(IntPtr admin, SafeFileHandle file, ref uint size, [Out] byte[]? hash, uint flags);
    [DllImport("wintrust.dll", ExactSpelling = true, SetLastError = true), DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    static extern IntPtr CryptCATAdminEnumCatalogFromHash(IntPtr admin, byte[] hash, uint size, uint flags, ref IntPtr previous);
    [DllImport("wintrust.dll", CharSet = CharSet.Unicode, ExactSpelling = true, SetLastError = true), DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    [return: MarshalAs(UnmanagedType.Bool)] static extern bool CryptCATCatalogInfoFromContext(IntPtr catalog, ref CatalogInfo info, uint flags);
    [DllImport("wintrust.dll", ExactSpelling = true), DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    [return: MarshalAs(UnmanagedType.Bool)] static extern bool CryptCATAdminReleaseCatalogContext(IntPtr admin, IntPtr catalog, uint flags);
    [DllImport("wintrust.dll", ExactSpelling = true), DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    [return: MarshalAs(UnmanagedType.Bool)] static extern bool CryptCATAdminReleaseContext(IntPtr admin, uint flags);
}
