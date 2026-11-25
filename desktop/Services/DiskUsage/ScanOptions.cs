namespace Suhang.Desktop.DiskUsage;

internal sealed record ScanOptions(int MaxDegreeOfParallelism = 0, long SmallFileFloor = 256 * 1024,
    int TopFilesPerDirectory = 128, bool UseAllocatedSize = true);
