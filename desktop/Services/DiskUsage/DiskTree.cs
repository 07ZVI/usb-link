namespace Suhang.Desktop.DiskUsage;

internal sealed class DiskTree
{
    readonly ScanOptions options;
    readonly SemaphoreSlim rescan=new(1,1);
    WindowsDiskMetadata metadata;
    internal DiskNode Root { get; }
    internal DriveSpace? Space { get; }
    internal int Version { get; private set; }
    internal DiskTree(DiskNode root,DriveSpace? space,ScanOptions options,WindowsDiskMetadata metadata) {
        Root=root;Space=space;this.options=options;this.metadata=metadata;
    }

    internal bool Remove(DiskNode node) {
        lock(Root.Gate) {
            if(ReferenceEquals(node,Root)||!Attached(node))return false;
            var parent=node.Parent!;
            metadata.Forget(node);
            ((DiskChildren)parent.Children).Remove(node);node.Parent=null;
            RebuildAncestors(parent);Version++;return true;
        }
    }
    internal async Task RescanAsync(DiskNode directory,IProgress<ScanProgress>? progress,CancellationToken ct) {
        await rescan.WaitAsync(ct).ConfigureAwait(false);
        try {
            WindowsDiskMetadata next;int version;
            lock(Root.Gate) {
                if(directory.Kind!=NodeKind.Directory||!Attached(directory))throw new ArgumentException("資料夾不在此掃描樹中。",nameof(directory));
                version=Version;next=metadata.ForRescan(directory.FullPath);
            }
            var scanned=await new DiskScanner(directory.FullPath,options,next).ScanAsync(progress,ct).ConfigureAwait(false);
            lock(Root.Gate) {
                ct.ThrowIfCancellationRequested();
                if(version!=Version||!Attached(directory))throw new InvalidOperationException("掃描樹已變更，請重新掃描。");
                var parent=directory.Parent;
                if(parent!=null)((DiskChildren)parent.Children).Remove(directory);
                var fresh=scanned.Root;
                foreach(var old in directory.Children)old.Parent=null;
                directory.Children=fresh.Children;directory.Size=fresh.Size;directory.LogicalSize=fresh.LogicalSize;
                directory.FileCount=fresh.FileCount;directory.DirectoryCount=fresh.DirectoryCount;
                directory.LastWriteUtc=fresh.LastWriteUtc;directory.OwnWriteUtc=fresh.OwnWriteUtc;
                directory.Category=fresh.Category;directory.CategorySizes=fresh.CategorySizes;directory.Issue=fresh.Issue;directory.Revision++;
                var pending=new Stack<DiskNode>();
                foreach(var child in directory.Children) { child.Parent=directory;pending.Push(child); }
                while(pending.TryPop(out var node)) { node.Gate=Root.Gate;foreach(var child in node.Children)pending.Push(child); }
                if(parent!=null) { ((DiskChildren)parent.Children).Add(directory);RebuildAncestors(parent); }
                metadata=next;Version++;
            }
        } finally { rescan.Release(); }
    }
    internal DiskNode? Find(string fullPath) {
        string path;
        try { path=DiskPaths.Canonical(fullPath); } catch { return null; }
        lock(Root.Gate) {
            if(DiskPaths.Equal(path,Root.FullPath))return Root;
            if(!DiskPaths.Within(path,Root.FullPath))return null;
            var current=Root;
            foreach(var segment in Path.GetRelativePath(Root.FullPath,path).Split(Path.DirectorySeparatorChar)) {
                current=current.Children.FirstOrDefault(n=>n.FullPath.Length>0&&string.Equals(n.Name,segment,DiskPaths.Comparison));
                if(current==null)return null;
            }
            return current;
        }
    }
    bool Attached(DiskNode node) {
        while(!ReferenceEquals(node,Root)) {
            if(node.Parent is not {} parent||parent.Children is not DiskChildren children||!children.Contains(node))return false;
            node=parent;
        }
        return true;
    }

    internal static void Adjust(DiskNode node,long size,long logical,long files,long directories,DateTime write,FileCategory category,long categoryBytes) {
        while(true) {
            var parent=node.Parent;
            if(parent!=null)((DiskChildren)parent.Children).Remove(node);
            node.Size+=size;node.LogicalSize+=logical;node.FileCount+=files;node.DirectoryCount+=directories;
            if(write>node.LastWriteUtc)node.LastWriteUtc=write;
            node.CategorySizes![(int)category]+=categoryBytes;SetCategory(node);node.Revision++;
            if(parent==null)return;
            ((DiskChildren)parent.Children).Add(node);node=parent;
        }
    }
    static void SetCategory(DiskNode node) {
        var best=0;
        for(var i=1;i<node.CategorySizes!.Length;i++)if(node.CategorySizes[i]>node.CategorySizes[best])best=i;
        node.Category=(FileCategory)best;
    }
    static void RebuildAncestors(DiskNode node) {
        while(true) {
            var parent=node.Parent;
            if(parent!=null)((DiskChildren)parent.Children).Remove(node);
            node.Size=node.LogicalSize=node.FileCount=node.DirectoryCount=0;node.LastWriteUtc=DateTime.MinValue;
            Array.Clear(node.CategorySizes!);
            foreach(var child in node.Children) {
                node.Size+=child.Size;node.LogicalSize+=child.LogicalSize;node.FileCount+=child.FileCount;
                node.DirectoryCount+=child.DirectoryCount+(child.Kind==NodeKind.Directory?1:0);
                var write=child.Kind==NodeKind.Directory&&child.OwnWriteUtc>child.LastWriteUtc?child.OwnWriteUtc:child.LastWriteUtc;
                if(write>node.LastWriteUtc)node.LastWriteUtc=write;
                if(child.CategorySizes is {} categories)for(var i=0;i<categories.Length;i++)node.CategorySizes![i]+=categories[i];
                else node.CategorySizes![(int)child.Category]+=child.Size;
            }
            SetCategory(node);node.Revision++;
            if(parent==null)return;
            ((DiskChildren)parent.Children).Add(node);node=parent;
        }
    }
}
