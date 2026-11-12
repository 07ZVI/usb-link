namespace Suhang.Desktop.DiskUsage;

internal sealed class ScanDirectory
{
    internal readonly DiskNode Node;
    readonly ScanOptions options;
    readonly PriorityQueue<DiskNode,DiskNode> top = new(Comparer<DiskNode>.Create((a,b)=>DiskOrder.Instance.Compare(b,a)));
    DiskNode? aggregate;
    internal ScanDirectory(DiskNode node,ScanOptions options) { Node=node;this.options=options; }

    internal void AddFile(DiskNode file) {
        var keep=file.Size>=options.SmallFileFloor||file.Issue!=NodeIssue.None;
        if(options.TopFilesPerDirectory>0) {
            if(top.Count<options.TopFilesPerDirectory) { top.Enqueue(file,file);keep=true; }
            else if(DiskOrder.Instance.Compare(file,top.Peek())<0) {
                var evicted=top.DequeueEnqueue(file,file);keep=true;
                if(evicted.Size<options.SmallFileFloor&&evicted.Issue==NodeIssue.None) {
                    ((DiskChildren)Node.Children).Remove(evicted);Fold(evicted);
                }
            }
        }
        if(keep)((DiskChildren)Node.Children).Add(file);else Fold(file);
    }
    void Fold(DiskNode file) {
        var children=(DiskChildren)Node.Children;
        if(aggregate==null) { aggregate=DiskNode.Aggregate(Node,0,0,0);aggregate.CategorySizes=new long[Enum.GetValues<FileCategory>().Length]; }
        else children.Remove(aggregate);
        aggregate.Size+=file.Size;aggregate.LogicalSize+=file.LogicalSize;aggregate.FileCount+=file.FileCount;
        aggregate.CategorySizes![(int)file.Category]+=file.Size;
        if(file.LastWriteUtc>aggregate.LastWriteUtc)aggregate.LastWriteUtc=file.LastWriteUtc;
        children.Add(aggregate);
        file.Parent=null;
    }
}
