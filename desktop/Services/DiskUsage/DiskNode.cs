namespace Suhang.Desktop.DiskUsage;

internal sealed class DiskNode
{
    internal string Name { get; set; } = "";
    internal string FullPath { get; set; } = "";
    internal NodeKind Kind { get; set; }
    internal long Size { get; set; }
    internal long LogicalSize { get; set; }
    internal long FileCount { get; set; }
    internal long DirectoryCount { get; set; }
    internal DateTime LastWriteUtc { get; set; }
    internal FileCategory Category { get; set; }
    internal NodeIssue Issue { get; set; }
    internal DiskNode? Parent { get; set; }
    internal IReadOnlyList<DiskNode> Children { get; set; } = Array.Empty<DiskNode>();
    internal string Extension { get; set; } = "";

    internal object Gate = new();
    internal long Revision;
    internal DateTime OwnWriteUtc;
    internal long[]? CategorySizes;

    internal DiskNode Copy(DiskNode? parent) => new() {
        Name=Name, FullPath=FullPath, Kind=Kind, Size=Size, LogicalSize=LogicalSize, FileCount=FileCount,
        DirectoryCount=DirectoryCount, LastWriteUtc=LastWriteUtc, Category=Category, Issue=Issue,
        Extension=Extension, Parent=parent, OwnWriteUtc=OwnWriteUtc
    };

    internal static DiskNode Aggregate(DiskNode parent, long size, long logical, long files, long directories = 0) => new() {
        Kind=NodeKind.Aggregate, Parent=parent, Size=size, LogicalSize=logical, FileCount=files, DirectoryCount=directories,
        Gate=parent.Gate
    };
}
