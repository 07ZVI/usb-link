namespace Suhang.Desktop.DiskUsage;

internal sealed record DriveSpace(string Name, string Label, string Format, long TotalBytes, long FreeBytes,
    bool Removable, bool Network, bool Ready);
