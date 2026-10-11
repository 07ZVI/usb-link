using System.Diagnostics;
using System.Globalization;
using System.Runtime.InteropServices;
using System.Threading.Channels;
using Microsoft.Win32.SafeHandles;

namespace Suhang.Desktop;

internal sealed record ProcessTrust(string Status, string Reason = "", string Publisher = "", string Subject = "",
    string Issuer = "", string Thumbprint = "", string NotBefore = "", string NotAfter = "", string Source = "",
    string Hash = "", string Code = "", string CheckedAt = "", bool Timestamped = false)
{
    internal string Label => Status switch {
        "valid" => "簽章有效", "invalid" => "簽章無效", "revoked" => "憑證已撤銷",
        "expired" => "憑證已過期", "untrusted" => "憑證不受信任", "unsigned" => "未簽署",
        "pending" => "等待驗證", _ => "無法確認"
    };
    internal string Tone => Status switch {
        "valid" => "Ok", "invalid" or "revoked" or "expired" or "untrusted" => "Error",
        "unsigned" => "Warn", _ => "Muted"
    };
    internal int Priority => Status switch {
        "invalid" or "revoked" => 0, "expired" or "untrusted" => 1, "unsigned" => 2,
        "unverified" => 3, "pending" => 4, _ => 5
    };
    internal bool Attention => Status is not ("valid" or "pending");
    internal static ProcessTrust FromCode(uint code) => code switch {
        0 => new ProcessTrust("valid", "Windows Authenticode 驗證通過；吊銷檢查僅使用本機快取。"),
        0x800B0100 => new("unsigned", "未找到內嵌或系統目錄簽章；未簽署本身不代表惡意程式。"),
        0x80096010 or 0x80096004 => new("invalid", "檔案內容或簽章與簽署時不符，需注意可能遭到修改。"),
        0x800B010C or 0x80092010 => new("revoked", "Windows 回報簽署憑證已撤銷。"),
        0x800B0101 => new("expired", "Windows 驗證判定憑證時間無效；未取得可接受的時間戳記。"),
        0x800B0109 or 0x800B010A or 0x800B0111 or 0x800B0004 or 0x800B0110 =>
            new("untrusted", "憑證鏈、用途或信任原則未通過 Windows 驗證。"),
        0x80092013 or 0x800B010E or 0x80092012 =>
            new("unverified", "本機快取沒有足夠的憑證吊銷資訊，無法確認。"),
        _ => new("unverified", "Windows 無法完成驗證。")
    } with { Code = $"0x{code:X8}" };
}

internal sealed record RunningProgram(int Pid, long Started, string Name, string Path, string Identity,
    double? Cpu, long? Memory, ProcessTrust Trust)
{
    internal string CpuText => Cpu is double c ? c.ToString("0.0", CultureInfo.InvariantCulture) + "%" : "—";
    internal string MemoryText => Memory is long m ? (m / 1048576d).ToString("N1") + " MB" : "—";
    internal string Risk => Trust.Status switch {
        "invalid" or "revoked" => "可疑 · " + Trust.Reason,
        "expired" or "untrusted" => "需注意 · " + Trust.Reason,
        "unsigned" when ProcessInventory.IsTemporaryPath(Path) => "可疑 · 未簽署且從暫存目錄執行，請核對來源。",
        _ => Trust.Reason
    };
    internal bool Matches(string search) => new[] { Name, Path, Pid.ToString(), Trust.Publisher, Trust.Label, Risk }
        .Any(s => s.Contains(search, StringComparison.OrdinalIgnoreCase));
}

// Read-only, minimum-rights process observation. Never requests debug privileges,
// terminates a process or modifies firewall policy. PID reuse is keyed by creation time.
internal sealed class ProcessInventory : IDisposable
{
    readonly CancellationTokenSource lifetime = new();
    readonly Channel<(string Path, string Identity, int Generation)> queue = Channel.CreateBounded<(string, string, int)>(512);
    readonly Dictionary<string, ProcessTrust> cache = new(StringComparer.OrdinalIgnoreCase);
    readonly HashSet<string> queued = new(StringComparer.OrdinalIgnoreCase);
    readonly Dictionary<(int Pid, long Start), (long Cpu, long Observed)> previous = new();
    readonly object gate = new();
    readonly Task[] workers;
    int generation;

    internal ProcessInventory() => workers = Enumerable.Range(0, 2).Select(_ => Task.Run(VerifyLoop)).ToArray();

    internal static bool IsTemporaryPath(string path) {
        var normalized = path.Replace('/', '\\');
        return normalized.Contains("\\AppData\\Local\\Temp\\", StringComparison.OrdinalIgnoreCase) ||
            normalized.Contains("\\Windows\\Temp\\", StringComparison.OrdinalIgnoreCase);
    }

    internal static double? CpuPercent(long cpu, long oldCpu, long elapsedTicks, int cores) =>
        elapsedTicks <= 0 || cpu < oldCpu || cores < 1 ? null :
        Math.Clamp((cpu - oldCpu) / 10000000d / (elapsedTicks / (double)Stopwatch.Frequency) / cores * 100, 0, 100);

    internal void Reverify() { lock (gate) { generation++; cache.Clear(); queued.Clear(); } }

    internal RunningProgram[] Capture(Action<RunningProgram[]>? initial = null) {
        if (!OperatingSystem.IsWindows()) throw new PlatformNotSupportedException("此功能需在 Windows 執行。");
        var rows = new List<RunningProgram>();
        var seen = new HashSet<(int, long)>();
        var identities = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var process in Process.GetProcesses()) {
            using (process) {
                if (lifetime.IsCancellationRequested) continue;
                var pid = process.Id;
                string name; try { name = process.ProcessName; } catch { name = "PID " + pid; }
                using var handle = OpenProcess(0x1000, false, pid); // PROCESS_QUERY_LIMITED_INFORMATION
                string path = "", identity = "";
                long started = 0; double? cpu = null; long? memory = null;
                var issue = pid is 0 or 4 ? "Windows 核心程序，不適用一般 EXE 簽章驗證。" : "權限不足或程序已結束，無法讀取執行檔。";
                if (!handle.IsInvalid) {
                    var buffer = new char[32768]; uint size = (uint)buffer.Length;
                    if (QueryFullProcessImageName(handle, 0, buffer, ref size)) { path = new string(buffer, 0, (int)size); name = System.IO.Path.GetFileName(path); }
                    var observed = Stopwatch.GetTimestamp();
                    if (GetProcessTimes(handle, out var creation, out _, out var kernel, out var user)) {
                        started = creation; var total = kernel + user; var id = (pid, started); seen.Add(id);
                        if (previous.TryGetValue(id, out var old)) cpu = CpuPercent(total, old.Cpu, observed - old.Observed, Environment.ProcessorCount);
                        previous[id] = (total, observed);
                    }
                    var counters = new MemoryCounters { Size = (uint)Marshal.SizeOf<MemoryCounters>() };
                    if (K32GetProcessMemoryInfo(handle, ref counters, counters.Size)) memory = (long)counters.WorkingSet;
                }
                rows.Add(new(pid, started, Clean(name), path, identity, cpu, memory,
                    new(path.Length > 0 ? "pending" : "unverified", path.Length > 0 ? "正在讀取程式檔案與簽署憑證。" : issue)));
            }
        }
        // Show the process census before any executable file I/O or signature work.
        // Records are immutable; later verification cannot mutate this first view.
        if (!lifetime.IsCancellationRequested) initial?.Invoke(rows.ToArray());
        var fileObservations = new Dictionary<string, (string Identity, string Issue)>(StringComparer.OrdinalIgnoreCase);
        for (var index = 0; index < rows.Count && !lifetime.IsCancellationRequested; index++) {
            var row = rows[index]; var path = row.Path;
            if (path.Length == 0) continue;
            if (!fileObservations.TryGetValue(path, out var observed)) {
                string fileID = "", problem = "";
                if (!NativeProcessSignature.IsLocalPath(path)) problem = "程式位於遠端路徑，不自動讀取或驗證。";
                else {
                    try {
                        using var file = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
                        fileID = FileIdentity(file, path);
                    } catch { problem = "無法讀取程式檔案，可能為受保護程序或檔案已移除。"; }
                }
                observed = (fileID, problem); fileObservations[path] = observed;
            }
            var (identity, issue) = observed;
            ProcessTrust trust = new("unverified", issue);
            if (identity.Length > 0) {
                identities.Add(identity);
                lock (gate) {
                    if (cache.TryGetValue(identity, out var saved) && DateTimeOffset.TryParse(saved.CheckedAt, out var checkedAt) &&
                        DateTimeOffset.UtcNow - checkedAt < TimeSpan.FromSeconds(30)) trust = saved;
                    else {
                        trust = new("pending", "正在背景驗證程式檔案與簽署憑證。" );
                        if (queued.Add(identity) && !queue.Writer.TryWrite((path, identity, generation))) queued.Remove(identity);
                    }
                }
            }
            rows[index] = row with { Identity = identity, Trust = trust };
        }
        foreach (var key in previous.Keys.Where(k => !seen.Contains(k)).ToArray()) previous.Remove(key);
        lock (gate) foreach (var key in cache.Keys.Where(k => !identities.Contains(k)).ToArray()) cache.Remove(key);
        return rows.ToArray();
    }

    async Task VerifyLoop() {
        using var worker = new ProcessSignatureWorker();
        try {
            await foreach (var item in queue.Reader.ReadAllAsync(lifetime.Token)) {
                lock (gate) { if (item.Generation != generation) continue; }
                var trust = await worker.CheckAsync(item.Path, item.Identity, lifetime.Token);
                lock (gate) {
                    if (item.Generation != generation) continue;
                    cache[item.Identity] = trust with { CheckedAt = DateTimeOffset.UtcNow.ToString("O") };
                    queued.Remove(item.Identity);
                }
            }
        } catch (OperationCanceledException) { }
    }

    internal static string Clean(string text) => string.Concat(text.Where(c => !char.IsControl(c) &&
        CharUnicodeInfo.GetUnicodeCategory(c) != UnicodeCategory.Format)).Trim();

    internal static string FileIdentity(FileStream file, string path) {
        if (!GetFileInformationByHandle(file.SafeFileHandle, out var info)) throw new IOException("File identity unavailable");
        return $"{path}|{info.Volume:X8}:{info.IndexHigh:X8}{info.IndexLow:X8}:{info.WriteHigh:X8}{info.WriteLow:X8}:{info.SizeHigh:X8}{info.SizeLow:X8}";
    }

    public void Dispose() {
        lifetime.Cancel(); queue.Writer.TryComplete();
        // Release the CTS after both child workers have killed/disposed their helpers.
        _ = Task.WhenAll(workers).ContinueWith(_ => lifetime.Dispose(), TaskScheduler.Default);
    }

    [StructLayout(LayoutKind.Sequential)] struct MemoryCounters {
        internal uint Size, PageFaults;
        internal nuint PeakWorkingSet, WorkingSet, PeakPaged, Paged, PeakNonpaged, Nonpaged, Pagefile, PeakPagefile;
    }
    [StructLayout(LayoutKind.Sequential)] struct FileInformation {
        internal uint Attributes, CreationLow, CreationHigh, AccessLow, AccessHigh, WriteLow, WriteHigh;
        internal uint Volume, SizeHigh, SizeLow, Links, IndexHigh, IndexLow;
    }
    [DllImport("kernel32.dll", SetLastError = true), DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    static extern SafeProcessHandle OpenProcess(uint access, [MarshalAs(UnmanagedType.Bool)] bool inherit, int pid);
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, EntryPoint = "QueryFullProcessImageNameW", SetLastError = true), DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    [return: MarshalAs(UnmanagedType.Bool)] static extern bool QueryFullProcessImageName(SafeProcessHandle process, uint flags, [Out] char[] path, ref uint length);
    [DllImport("kernel32.dll"), DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    [return: MarshalAs(UnmanagedType.Bool)] static extern bool GetProcessTimes(SafeProcessHandle process, out long creation, out long exit, out long kernel, out long user);
    [DllImport("kernel32.dll"), DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    [return: MarshalAs(UnmanagedType.Bool)] static extern bool K32GetProcessMemoryInfo(SafeProcessHandle process, ref MemoryCounters counters, uint size);
    [DllImport("kernel32.dll", SetLastError = true), DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    [return: MarshalAs(UnmanagedType.Bool)] static extern bool GetFileInformationByHandle(SafeFileHandle file, out FileInformation info);
}
