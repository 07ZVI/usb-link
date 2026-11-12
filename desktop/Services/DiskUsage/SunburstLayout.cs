namespace Suhang.Desktop.DiskUsage;

internal static class SunburstLayout
{
    // Rings around `root` (the center disc is the renderer's). Children narrower than `minSweep` fold into one
    // Aggregate slice per parent, so a ring never holds hair-thin slivers and a huge folder costs only what is drawn.
    internal static IReadOnlyList<SunburstCell> Build(DiskNode root,int maxDepth,double minSweep,DiskFilter? filter=null) {
        if(maxDepth<1||!double.IsFinite(minSweep)||minSweep<0)throw new ArgumentOutOfRangeException(nameof(minSweep));
        lock(root.Gate) {
            var result=new List<SunburstCell>();
            if(Size(root,filter)<=0||root.Kind!=NodeKind.Directory)return result;
            var pending=new Stack<(DiskNode Node,double Start,double Sweep,int Depth)>();
            pending.Push((root,0,1,0));
            while(pending.TryPop(out var item)) {
                var total=Size(item.Node,filter);if(total<=0)continue;
                var placed=new List<(DiskNode Node,long Size)>();long kept=0,logical=0,files=0,directories=0;
                IEnumerable<(DiskNode Node,long Size)> source=filter?.Children(item.Node)??item.Node.Children.Select(n=>(n,n.Size));
                foreach(var (node,size) in source) {
                    if(size<=0||size/(double)total*item.Sweep<minSweep)break;
                    if(node.Kind==NodeKind.Aggregate)continue;
                    placed.Add((node,size));kept+=size;logical+=node.LogicalSize;files+=node.FileCount;
                    directories+=node.DirectoryCount+(node.Kind==NodeKind.Directory?1:0);
                }
                if(total>kept)placed.Add((DiskNode.Aggregate(item.Node,total-kept,Math.Max(0,item.Node.LogicalSize-logical),
                    Math.Max(0,item.Node.FileCount-files),Math.Max(0,item.Node.DirectoryCount-directories)),total-kept));
                var start=item.Start;var children=new List<(DiskNode,double,double)>();
                foreach(var (node,size) in placed) {
                    var sweep=item.Sweep*size/total;
                    result.Add(new(node,start,sweep,item.Depth+1,Key(node,item.Node)));
                    if(node.Kind==NodeKind.Directory&&item.Depth+1<maxDepth&&node.Children.Count>0)children.Add((node,start,sweep));
                    start+=sweep;
                }
                for(var i=children.Count-1;i>=0;i--)pending.Push((children[i].Item1,children[i].Item2,children[i].Item3,item.Depth+1));
            }
            return result;
        }
    }
    static long Size(DiskNode node,DiskFilter? filter) => filter?.MatchedSize(node)??node.Size;
    static string Key(DiskNode node,DiskNode parent) => node.Kind==NodeKind.Aggregate?parent.FullPath+"#agg":node.FullPath;
}
