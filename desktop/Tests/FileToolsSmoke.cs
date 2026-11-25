#if USBLINK_DESIGN_TOOLS
using System.Buffers.Binary;
using System.Text;

namespace Suhang.Desktop;

internal static class FileToolsSmoke
{
    const string AbcHash = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";

    internal static int Run()
    {
        try {
            var scratch = Directory.CreateTempSubdirectory("usblink-file-tools-");
            try { RunAsync(scratch.FullName).GetAwaiter().GetResult(); }
            finally { scratch.Delete(recursive: true); }
            Console.WriteLine("File tools smoke passed.");
            return 0;
        } catch (Exception e) { Console.Error.WriteLine(e); return 1; }
    }

    static async Task RunAsync(string scratch)
    {
        const string target = @"D:\暫存\測試";
        var buffer = FolderJunction.MountPointData(target);
        var substituteLength = BinaryPrimitives.ReadUInt16LittleEndian(buffer.AsSpan(10));
        var printOffset = BinaryPrimitives.ReadUInt16LittleEndian(buffer.AsSpan(12));
        var printLength = BinaryPrimitives.ReadUInt16LittleEndian(buffer.AsSpan(14));
        Check(BinaryPrimitives.ReadUInt32LittleEndian(buffer) == 0xA0000003 &&
            BinaryPrimitives.ReadUInt16LittleEndian(buffer.AsSpan(4)) == buffer.Length - 8 &&
            printOffset == substituteLength + sizeof(char) &&
            Encoding.Unicode.GetString(buffer, 16, substituteLength) == @"\??\" + target &&
            Encoding.Unicode.GetString(buffer, 16 + printOffset, printLength) == target,
            "Mount point payload contains both UTF-16 paths at the documented offsets.");

        var root = Directory.CreateDirectory(Path.Combine(scratch, "files")).FullName;
        var file = Path.Combine(root, "檔案 [1].txt");
        File.WriteAllText(file, "abc");
        var sub = Directory.CreateDirectory(Path.Combine(root, "nested")).FullName;
        var empty = Path.Combine(sub, "empty");
        File.WriteAllBytes(empty, []);
        Check((await Scan(file, expected: AbcHash.ToUpperInvariant())).Single() is { Hash: AbcHash, Tone: "Ok" }, "Single file matched.");
        Check((await Scan(file, expected: new string('0', 64))).Single() is { Hash: AbcHash, Tone: "Error" }, "Single file mismatch was reported.");
        Check((await Scan(root, recursive: false)).Single().Path == file, "Non-recursive scan checked the top level.");
        var entries = await Scan(root);
        Check(entries.Count == 2 && entries.Any(e => e.Path == empty && e.Hash == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"), "Recursive scan included every file and the empty file.");

        var alias = Path.Combine(root, "alias");
        if (OperatingSystem.IsWindows()) {
            var link = Path.Combine(scratch, "junction");
            FolderJunction.Create(root, link);
            try {
                Check(File.ReadAllText(Path.Combine(link, Path.GetFileName(file))) == "abc", "Junction reads the source.");
                File.WriteAllText(Path.Combine(link, "via-link"), "same data");
                Check(File.ReadAllText(Path.Combine(root, "via-link")) == "same data", "Junction writes reach the source.");
                Reject(() => FolderJunction.Create(scratch, link));
                Reject(() => FolderJunction.Create(root, alias));
                Reject(() => FolderJunction.Create(root, sub));
                Reject(() => FolderJunction.Create(root, file));
                Check(File.ReadAllText(file) == "abc" && File.Exists(empty), "Existing files survived rejected requests.");
                FolderJunction.Create(sub, Path.Combine(root, "nested-alias"));
                try { Check((await Scan(root)).Count(e => e.Status == "已略過連結") == 1, "Junction children are reported without traversal."); }
                finally { Directory.Delete(Path.Combine(root, "nested-alias")); }
            } finally { Directory.Delete(link); }
        } else {
            Directory.CreateSymbolicLink(alias, root);
            Check((await Scan(root)).Count(e => e.Status == "已略過連結") == 1, "Link loop was reported without traversal.");
            Check((await Scan(alias)).Count(e => e.Tone == "Ok") == 2, "Explicitly chosen link is scanned.");
        }

        using var cancelled = new CancellationTokenSource();
        cancelled.Cancel();
        try { await Scan(root, token: cancelled.Token); }
        catch (OperationCanceledException) { return; }
        throw new InvalidOperationException("Pre-cancelled scans stop before reading results.");
    }

    static async Task<List<FileAuditEntry>> Scan(string path, bool recursive = true, string expected = "", CancellationToken token = default)
    {
        var entries = new List<FileAuditEntry>();
        await FileAudit.ScanAsync(path, false, recursive, expected, batch => { entries.AddRange(batch); return Task.CompletedTask; }, token);
        return entries;
    }

    static void Reject(Action operation)
    {
        try { operation(); }
        catch (IOException) { return; }
        throw new InvalidOperationException("Unsafe junction destination was accepted.");
    }

    static void Check(bool test, string message) { if (!test) throw new InvalidOperationException(message); }
}
#endif
