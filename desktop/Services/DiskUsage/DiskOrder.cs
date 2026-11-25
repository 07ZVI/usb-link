namespace Suhang.Desktop.DiskUsage;

internal sealed class DiskOrder : IComparer<DiskNode>
{
    internal static readonly DiskOrder Instance = new();
    public int Compare(DiskNode? x, DiskNode? y) {
        if(ReferenceEquals(x,y))return 0;
        if(x==null)return 1;if(y==null)return -1;
        var size=y.Size.CompareTo(x.Size);
        if(size!=0)return size;
        return CompareNames(x,y);
    }
    internal static int CompareNames(DiskNode x,DiskNode y) {
        var name=StringComparer.Ordinal.Compare(x.Name,y.Name);
        if(name!=0)return name;
        var path=StringComparer.Ordinal.Compare(x.FullPath,y.FullPath);
        return path!=0?path:x.Kind.CompareTo(y.Kind);
    }
}
