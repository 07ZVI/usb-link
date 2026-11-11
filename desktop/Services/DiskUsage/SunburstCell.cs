namespace Suhang.Desktop.DiskUsage;

// Start and Sweep are fractions of the full turn (0..1), clockwise from 12 o'clock. Depth 1 is the innermost ring.
internal sealed record SunburstCell(DiskNode Node, double Start, double Sweep, int Depth, string Key);
