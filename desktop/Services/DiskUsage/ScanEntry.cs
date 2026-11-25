namespace Suhang.Desktop.DiskUsage;

internal readonly record struct ScanEntry(string Name, string Path, bool Directory, long Length,
    FileAttributes Attributes, DateTime Write);
