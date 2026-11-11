namespace Suhang.Desktop.DiskUsage;

internal sealed record ScanProgress(ScanPhase Phase, long Files, long Directories, long Bytes, long Errors,
    string CurrentPath, TimeSpan Elapsed, double? Fraction);
