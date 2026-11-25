using System.Diagnostics;
using System.Security.Cryptography;

namespace Suhang.Desktop;

internal sealed record FileAuditEntry(string Path, string Status, string Tone, string Detail = "", string Hash = "");

internal static class FileAudit
{
    internal static async Task ScanAsync(string input, bool signatures, bool recursive, string expectedHash,
        Func<IReadOnlyList<FileAuditEntry>, Task> report, CancellationToken token)
    {
        token.ThrowIfCancellationRequested();
        if (!Path.IsPathFullyQualified(input)) throw new IOException("請選擇或輸入完整路徑。");
        var root = Path.GetFullPath(input);
        var isFolder = File.GetAttributes(root).HasFlag(FileAttributes.Directory);
        if (signatures && !isFolder) throw new IOException("請選擇包含 EXE 檔案的資料夾。");
        if (expectedHash.Length > 0 && (isFolder || expectedHash.Length != 64 || !expectedHash.All(Uri.IsHexDigit)))
            throw new IOException("比對值僅適用於單一檔案，請輸入完整的 64 碼 SHA-256。");

        using var worker = signatures ? new ProcessSignatureWorker() : null;
        var batch = new List<FileAuditEntry>(64);
        var timer = Stopwatch.StartNew();
        async Task FlushAsync()
        {
            if (batch.Count == 0) return;
            await report(batch.ToArray()).ConfigureAwait(false);
            batch.Clear();
            timer.Restart();
        }

        try {
            foreach (var item in FindFiles(root, isFolder, signatures, recursive, token)) {
                token.ThrowIfCancellationRequested();
                batch.Add(item.Issue ?? await InspectAsync(item.Path, worker, expectedHash, token).ConfigureAwait(false));
                if (batch.Count == 64 || timer.ElapsedMilliseconds >= 180) await FlushAsync().ConfigureAwait(false);
            }
        } finally { await FlushAsync().ConfigureAwait(false); }
    }

    static async Task<FileAuditEntry> InspectAsync(string path, ProcessSignatureWorker? worker, string expected, CancellationToken token)
    {
        try {
            await using var file = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read, 128 * 1024,
                FileOptions.Asynchronous | FileOptions.SequentialScan);
            if (worker != null) {
                var trust = await worker.CheckAsync(path, ProcessInventory.FileIdentity(file, path), token, fileAudit: true).ConfigureAwait(false);
                token.ThrowIfCancellationRequested();
                var detail = string.Join(" · ", new[] { trust.Publisher, trust.Source, trust.Reason, trust.Code }.Where(value => value.Length > 0));
                return new(path, trust.Label, trust.Tone, detail);
            }

            var hash = Convert.ToHexStringLower(await SHA256.HashDataAsync(file, token).ConfigureAwait(false));
            if (expected.Length == 0) return new(path, "已計算", "Ok", Hash: hash);
            return hash.Equals(expected, StringComparison.OrdinalIgnoreCase)
                ? new(path, "SHA-256 相符", "Ok", Hash: hash)
                : new(path, "SHA-256 不符", "Error", "預期值 " + expected, hash);
        } catch (Exception e) when (e is IOException or UnauthorizedAccessException) {
            return Unreadable(path, e);
        }
    }

    static IEnumerable<(string Path, FileAuditEntry? Issue)> FindFiles(string root, bool isFolder, bool signatures, bool recursive, CancellationToken token)
    {
        if (!isFolder) { yield return (root, null); yield break; }
        var pending = new Stack<string>();
        pending.Push(root);
        while (pending.TryPop(out var directory)) {
            token.ThrowIfCancellationRequested();
            if (directory != root && IsReparseDirectory(directory, out var directoryIssue)) {
                if (directoryIssue != null) yield return (directory, directoryIssue);
                continue;
            }
            IEnumerator<string>? entries = null;
            FileAuditEntry? openIssue = null;
            try { entries = Directory.EnumerateFileSystemEntries(directory).GetEnumerator(); }
            catch (Exception e) when (e is IOException or UnauthorizedAccessException) { openIssue = Unreadable(directory, e); }
            if (entries == null) { yield return (directory, openIssue); continue; }
            using var files = entries;
            while (true) {
                token.ThrowIfCancellationRequested();
                bool hasNext = false;
                FileAuditEntry? issue = null;
                try { hasNext = files.MoveNext(); }
                catch (Exception e) when (e is IOException or UnauthorizedAccessException) { issue = Unreadable(directory, e); }
                if (issue != null) yield return (directory, issue);
                if (!hasNext) break;
                var path = files.Current;
                FileAttributes attrs = 0;
                try { attrs = File.GetAttributes(path); }
                catch (Exception e) when (e is IOException or UnauthorizedAccessException) { issue = Unreadable(path, e); }
                if (issue != null) { yield return (path, issue); continue; }
                if (attrs.HasFlag(FileAttributes.Directory)) {
                    if (recursive) pending.Push(path);
                    continue;
                }
                if (signatures && !Path.GetExtension(path).Equals(".exe", StringComparison.OrdinalIgnoreCase)) continue;
                if (attrs.HasFlag(FileAttributes.ReparsePoint)) {
                    try { if (new FileInfo(path).LinkTarget != null) issue = SkippedLink(path); }
                    catch (Exception e) when (e is IOException or UnauthorizedAccessException) { issue = Unreadable(path, e); }
                }
                yield return (path, issue);
            }
        }
    }

    static bool IsReparseDirectory(string path, out FileAuditEntry? issue)
    {
        try {
            issue = File.GetAttributes(path).HasFlag(FileAttributes.ReparsePoint) ? SkippedLink(path) : null;
        } catch (Exception e) when (e is IOException or UnauthorizedAccessException) { issue = Unreadable(path, e); }
        return issue != null;
    }

    static FileAuditEntry SkippedLink(string path) => new(path, "已略過連結", "Warn", "請直接選擇此路徑來檢查連結指向的內容。");
    static FileAuditEntry Unreadable(string path, Exception e) => new(path, "無法讀取", "Error", e.Message);
}
