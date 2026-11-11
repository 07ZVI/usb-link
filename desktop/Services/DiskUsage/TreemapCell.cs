namespace Suhang.Desktop.DiskUsage;

internal sealed record TreemapCell(DiskNode Node, RectD Bounds, RectD ContentBounds,
    int Depth, bool IsLeaf, bool HasHeader, string Key);
