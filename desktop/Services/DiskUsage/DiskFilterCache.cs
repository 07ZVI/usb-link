namespace Suhang.Desktop.DiskUsage;

internal sealed class DiskFilterCache
{
    internal long Revision=-1, Size;
    internal (DiskNode Node,long Size)[] Children=Array.Empty<(DiskNode,long)>();
}
