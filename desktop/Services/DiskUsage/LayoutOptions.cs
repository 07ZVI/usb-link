namespace Suhang.Desktop.DiskUsage;

internal sealed record LayoutOptions(int MaxDepth = 8, double MinCellArea = 900, double HeaderHeight = 18,
    double Padding = 2, double MinHeaderCell = 64, DiskFilter? Filter = null, long FreeBytes = 0);
