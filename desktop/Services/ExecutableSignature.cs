using System.Diagnostics;
using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace Suhang.Desktop;

// Display-only trust information. Permission decisions remain bound to the
// backend's SHA256 check; a trusted signature never grants network access.
internal sealed record ExecutableSignature(string Status, string Publisher = "", string Reason = "")
{
    internal string Display => Status switch {
        "valid" => "數位簽章：有效\n已驗證簽署者：" + Publisher,
        "unsigned" => "數位簽章：未簽署",
        "changed" => "警示：程式檔案已變更，與已儲存授權不符；簽章尚未確認",
        "invalid" => "數位簽章：無效（檔案與簽章不符）" + ClaimedPublisher,
        "untrusted" => "數位簽章：不受 Windows 信任" + ClaimedPublisher,
        _ => "數位簽章：無法驗證" + (Reason.Length == 0 ? "" : "（" + Reason + "）")
    };
    internal string Tone => Status switch { "valid" => "Ok", "invalid" or "untrusted" or "changed" => "Error", "unsigned" => "Warn", _ => "Muted" };
    string ClaimedPublisher => Publisher.Length == 0 ? "" : "\n聲稱的簽署者：" + Publisher;

    internal static ExecutableSignature Parse(string json)
    {
        try {
            using var d = JsonDocument.Parse(json);
            var root = d.RootElement;
            var status = root.GetProperty("status").GetString();
            var publisher = root.GetProperty("publisher").GetString() ?? "";
            publisher = string.Concat(publisher.Where(c => !char.IsControl(c) && CharUnicodeInfo.GetUnicodeCategory(c) != UnicodeCategory.Format)).Trim();
            if (publisher.Length > 256) return new("unverified", Reason: "簽署者資料異常");
            return status switch {
                "Valid" when publisher.Length > 0 => new("valid", publisher),
                "NotSigned" => new("unsigned"),
                "HashMismatch" => new("invalid", publisher),
                "NotTrusted" => new("untrusted", publisher),
                _ => new("unverified", Reason: "Windows 未能確認簽章")
            };
        } catch { return new("unverified", Reason: "驗證結果無法讀取"); }
    }

    // Windows checks embedded and catalog signatures. The path is passed as an
    // environment value, never interpolated into PowerShell program text.
    const string Script = "[Console]::OutputEncoding=[System.Text.UTF8Encoding]::new($false); $ErrorActionPreference='Stop'; " +
        "$s=Microsoft.PowerShell.Security\\Get-AuthenticodeSignature -LiteralPath $env:USB_LINK_SIGNATURE_PATH; " +
        "$p=''; if($s.SignerCertificate){$p=$s.SignerCertificate.GetNameInfo([System.Security.Cryptography.X509Certificates.X509NameType]::SimpleName,$false)}; " +
        "[pscustomobject]@{status=$s.Status.ToString();publisher=$p}|ConvertTo-Json -Compress";

    internal static async Task<ExecutableSignature> InspectAsync(string path, string expectedHash, CancellationToken cancellation)
    {
        if (!OperatingSystem.IsWindows()) return new("unverified", Reason: "需由 Windows 驗證");
        if (expectedHash.Length != 64 || !expectedHash.All(Uri.IsHexDigit) || !Path.IsPathFullyQualified(path) || !path.EndsWith(".exe", StringComparison.OrdinalIgnoreCase))
            return new("unverified", Reason: "程式身分資料不完整");
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellation);
        timeout.CancelAfter(TimeSpan.FromSeconds(8));
        var token = timeout.Token;
        Process? process = null;
        try {
            // Deny writes/deletion while Windows examines this file. Hash it
            // before and after verification against the backend request identity.
            await using var lockedFile = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read, 65536, FileOptions.Asynchronous | FileOptions.SequentialScan);
            if (!await MatchesAsync(lockedFile, expectedHash, token)) return new("changed", Reason: "程式檔案已變更");
            var start = new ProcessStartInfo(Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), "WindowsPowerShell", "v1.0", "powershell.exe")) {
                UseShellExecute = false, CreateNoWindow = true, WindowStyle = ProcessWindowStyle.Hidden,
                RedirectStandardOutput = true, RedirectStandardError = true,
                StandardOutputEncoding = Encoding.UTF8, StandardErrorEncoding = Encoding.UTF8
            };
            foreach (var arg in new[] { "-NoProfile", "-NonInteractive", "-Command", Script }) start.ArgumentList.Add(arg);
            // Resolve the Windows validation module from system modules only.
            start.Environment["PSModulePath"] = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), "WindowsPowerShell", "v1.0", "Modules");
            start.Environment["USB_LINK_SIGNATURE_PATH"] = path;
            process = Process.Start(start);
            if (process == null) return new("unverified", Reason: "驗證元件無法啟動");
            var output = ReadBoundedAsync(process.StandardOutput, token);
            var errors = ReadBoundedAsync(process.StandardError, token);
            await Task.WhenAll(process.WaitForExitAsync(token), output, errors);
            var result = await output;
            if (process.ExitCode != 0) return new("unverified", Reason: "Windows 驗證失敗");
            if (!await MatchesAsync(lockedFile, expectedHash, token)) return new("changed", Reason: "驗證期間檔案已變更");
            return Parse(result);
        } catch (OperationCanceledException) { return new("unverified", Reason: "驗證逾時或已取消"); }
          catch { return new("unverified", Reason: "無法讀取檔案或驗證元件"); }
        finally {
            if (process != null) {
                try { if (!process.HasExited) process.Kill(entireProcessTree: true); } catch { }
                process.Dispose();
            }
        }
    }
    static async Task<bool> MatchesAsync(FileStream file, string expectedHash, CancellationToken token)
    {
        file.Position = 0;
        if (file.Length < 64 || file.Length > 1L << 30) return false;
        var hash = await SHA256.HashDataAsync(file, token);
        return Convert.ToHexString(hash).Equals(expectedHash, StringComparison.OrdinalIgnoreCase);
    }
    static async Task<string> ReadBoundedAsync(StreamReader reader, CancellationToken token)
    {
        var buffer = new char[1024]; var output = new StringBuilder();
        while (true) {
            var count = await reader.ReadAsync(buffer.AsMemory(), token);
            if (count == 0) return output.ToString();
            if (output.Length + count > 8192) throw new InvalidDataException("Signature result too large");
            output.Append(buffer, 0, count);
        }
    }
}
