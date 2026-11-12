namespace Suhang.Desktop.DiskUsage;

internal static class TreemapLayout
{
    internal static IReadOnlyList<TreemapCell> Build(DiskNode root,RectD bounds,LayoutOptions options) {
        if(!Valid(bounds)||bounds.Width<=0||bounds.Height<=0)return Array.Empty<TreemapCell>();
        if(options.MaxDepth<0||!Finite(options.MinCellArea)||!Finite(options.HeaderHeight)||!Finite(options.Padding)||!Finite(options.MinHeaderCell))
            throw new ArgumentOutOfRangeException(nameof(options));
        lock(root.Gate) {
            var result=new List<TreemapCell>();
            var pending=new Stack<(DiskNode Node,RectD Rect,int Depth,string Key,bool Root)>();
            var weight=Size(root,options.Filter)+(double)Math.Max(0,options.FreeBytes);
            if(weight<=0)return result;
            pending.Push((root,bounds,0,Key(root,root.Parent),true));
            while(pending.TryPop(out var item)) {
                var node=item.Node;var rect=item.Rect;
                // A folder whose only content is one folder is drawn as that folder: no header and no inset, so chains
                // like bin/Release/net10.0 do not spend a title strip per level.
                var chain=node.Kind==NodeKind.Directory&&options.Filter==null&&node.Children.Count==1&&node.Children[0].Kind==NodeKind.Directory&&!(item.Root&&options.FreeBytes>0);
                var header=!chain&&node.Kind==NodeKind.Directory&&rect.Width>=options.MinHeaderCell&&rect.Height>=options.MinHeaderCell&&options.HeaderHeight>0;
                var padding=chain?0:options.Padding;
                var content=new RectD(rect.X+Math.Min(padding,rect.Width/2),rect.Y+Math.Min(padding,rect.Height/2),
                    Math.Max(0,rect.Width-2*padding),Math.Max(0,rect.Height-2*padding));
                if(header) { var height=Math.Min(options.HeaderHeight,content.Height);content=content with {Y=content.Y+height,Height=content.Height-height}; }
                var subdivide=node.Kind==NodeKind.Directory&&item.Depth<options.MaxDepth&&content.Width>0&&content.Height>0&&
                    content.Width*content.Height>=options.MinCellArea&&(node.Children.Count>0||item.Root&&options.FreeBytes>0);
                var children=subdivide?Select(node,content,options,item.Root):new List<(DiskNode Node,long Size)>();
                subdivide&=children.Count>0;
                result.Add(new(node,rect,subdivide?content:rect,item.Depth,!subdivide,subdivide&&header,item.Key));
                if(!subdivide)continue;
                var placed=Squarify(children,content);
                for(var i=placed.Count-1;i>=0;i--) {
                    var (child,childRect)=placed[i];
                    pending.Push((child,childRect,item.Depth+1,Key(child,node),false));
                }
            }
            return result;
        }
    }
    static long Size(DiskNode node,DiskFilter? filter) => filter?.MatchedSize(node)??node.Size;
    static string Key(DiskNode node,DiskNode? parent) => node.Kind switch {
        NodeKind.Aggregate=>(parent?.FullPath??"")+"#agg",NodeKind.FreeSpace=>"#free",_=>node.FullPath
    };
    static bool Finite(double number) => double.IsFinite(number)&&number>=0;
    static bool Valid(RectD bounds) => double.IsFinite(bounds.X)&&double.IsFinite(bounds.Y)&&Finite(bounds.Width)&&Finite(bounds.Height)&&
        double.IsFinite(bounds.X+bounds.Width)&&double.IsFinite(bounds.Y+bounds.Height)&&double.IsFinite(bounds.Width*bounds.Height);

    static List<(DiskNode Node,long Size)> Select(DiskNode parent,RectD content,LayoutOptions options,bool root) {
        var total=Size(parent,options.Filter);var free=root?Math.Max(0,options.FreeBytes):0;
        var area=content.Width*content.Height;var denominator=total+(double)free;
        var selected=new List<(DiskNode Node,long Size)>();long kept=0,logical=0,files=0,directories=0;
        IEnumerable<(DiskNode Node,long Size)> source=options.Filter is {} filter?filter.Children(parent):parent.Children.Select(n=>(n,n.Size));
        foreach(var (node,size) in source) {
            if(size<=0||size/denominator*area<options.MinCellArea)break;
            if(node.Kind==NodeKind.Aggregate)continue;
            selected.Add((node,size));kept+=size;logical+=node.LogicalSize;files+=node.FileCount;
            directories+=node.DirectoryCount+(node.Kind==NodeKind.Directory?1:0);
        }
        if(total>kept)selected.Add((DiskNode.Aggregate(parent,total-kept,Math.Max(0,parent.LogicalSize-logical),
            Math.Max(0,parent.FileCount-files),Math.Max(0,parent.DirectoryCount-directories)),total-kept));
        if(free>0)selected.Add((new DiskNode { Kind=NodeKind.FreeSpace,Size=free,Parent=parent,Gate=parent.Gate },free));
        selected.Sort((a,b)=> { var order=b.Size.CompareTo(a.Size);return order!=0?order:DiskOrder.CompareNames(a.Node,b.Node); });
        return selected;
    }

    // Bruls' squarified rows: add the next descending area while the worst
    // aspect ratio improves, then place that row against the shorter side.
    static List<(DiskNode Node,RectD Bounds)> Squarify(List<(DiskNode Node,long Size)> children,RectD bounds) {
        var result=new List<(DiskNode,RectD)>(children.Count);
        var total=children.Sum(c=>(double)c.Size);var scale=bounds.Width*bounds.Height/total;
        var index=0;
        while(index<children.Count) {
            var end=index+1;var sum=children[index].Size*scale;
            var min=sum;var max=sum;var side=Math.Min(bounds.Width,bounds.Height);
            var worst=Worst(sum,min,max,side);
            while(end<children.Count) {
                var next=children[end].Size*scale;
                var candidate=Worst(sum+next,Math.Min(min,next),Math.Max(max,next),side);
                if(candidate>worst)break;
                sum+=next;min=Math.Min(min,next);max=Math.Max(max,next);worst=candidate;end++;
            }
            var column=bounds.Width>=bounds.Height;
            var thickness=column?sum/bounds.Height:sum/bounds.Width;
            thickness=Math.Min(thickness,column?bounds.Width:bounds.Height);
            if(end==children.Count)thickness=column?bounds.Width:bounds.Height;
            var position=column?bounds.Y:bounds.X;
            for(var i=index;i<end;i++) {
                var length=i==end-1?(column?bounds.Y+bounds.Height:bounds.X+bounds.Width)-position:children[i].Size*scale/thickness;
                var rect=column?new RectD(bounds.X,position,thickness,Math.Max(0,length)):new RectD(position,bounds.Y,Math.Max(0,length),thickness);
                result.Add((children[i].Node,rect));position+=length;
            }
            bounds=column?bounds with { X=bounds.X+thickness,Width=Math.Max(0,bounds.Width-thickness) }:
                bounds with { Y=bounds.Y+thickness,Height=Math.Max(0,bounds.Height-thickness) };
            index=end;
        }
        return result;
    }
    static double Worst(double sum,double min,double max,double side) => min<=0||side<=0?double.PositiveInfinity:
        Math.Max(side*side*max/(sum*sum),sum*sum/(side*side*min));
}
