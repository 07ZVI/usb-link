using System.Diagnostics;
using Suhang.Desktop.DiskUsage;

namespace Suhang.Desktop;

internal static class DiskUsageSmoke
{
    internal static int Run() {
        var temporary=Path.Combine(Path.GetTempPath(),"usb-link-disk-"+Guid.NewGuid().ToString("N"));
        try {
            Directory.CreateDirectory(temporary);
            RunAsync(temporary).GetAwaiter().GetResult();
            Console.Error.WriteLine("DISK_USAGE_SMOKE_PASS: scan, folding, permissions, links, cancellation, snapshots, mutations, layout, filters, actions");
            return 0;
        } catch(Exception e) { Console.Error.WriteLine("DISK_USAGE_SMOKE_FAIL: "+e);return 1; }
        finally { if(Directory.Exists(temporary))Directory.Delete(temporary,true); }
    }
    static async Task RunAsync(string temporary) {
        var root=Path.Combine(temporary,"scan");Directory.CreateDirectory(root);
        var nested=Path.Combine(root,"nested");Directory.CreateDirectory(nested);
        long expected=0;
        for(var i=0;i<64;i++) { Write(Path.Combine(root,$"small-{i:D3}.txt"),i);expected+=i; }
        Write(Path.Combine(nested,"movie.MP4"),4097);expected+=4097;
        Write(Path.Combine(nested,"empty"),0);
        var options=new ScanOptions(MaxDegreeOfParallelism:3,SmallFileFloor:128,TopFilesPerDirectory:3,UseAllocatedSize:false);
        var scanner=new DiskScanner(root,options);var initial=scanner.CaptureSnapshot();
        var reports=new Reports();
        var tree=await scanner.ScanAsync(reports,CancellationToken.None);
        Check(tree.Root.Size==expected&&tree.Root.LogicalSize==expected&&tree.Root.FileCount==66&&tree.Root.DirectoryCount==1,"exact totals");
        Exact(tree.Root);
        Check(tree.Root.Category==FileCategory.Video,"dominant category includes folded files");
        Check(tree.Root.Children.Count(n=>n.Kind==NodeKind.File)==3,"top files retained");
        var folded=tree.Root.Children.Single(n=>n.Kind==NodeKind.Aggregate);
        Check(folded.FileCount==61&&folded.Size==Enumerable.Range(0,61).Sum(),"folded totals");
        Check(tree.Root.Children.Where(n=>n.Kind==NodeKind.File).Select(n=>n.Size).SequenceEqual(new long[] {63,62,61}),"largest top files");
        var floor=await new DiskScanner(root,new(SmallFileFloor:32,TopFilesPerDirectory:0,UseAllocatedSize:false)).ScanAsync(null,CancellationToken.None);
        Check(floor.Root.Children.Count(n=>n.Kind==NodeKind.File)==32&&floor.Root.Size==expected,"floor retention without top files");Exact(floor.Root);
        Check(initial.Root.Size==0&&initial.Root.Children.Count==0,"snapshot independence before scan");
        Check(reports.Last?.Phase==ScanPhase.Completed&&reports.Last.Fraction==null,"terminal progress");
        var bounded=scanner.CaptureSnapshot(2,2);
        Check(bounded.Root.Children.Count<=2&&bounded.Root.Size==bounded.Root.Children.Sum(n=>n.Size),"snapshot child limit and omitted aggregate");
        var previous=bounded.Root.Size;
        var directory=tree.Find(nested)!;var movie=tree.Find(Path.Combine(nested,"movie.MP4"))!;
        Check(directory.LastWriteUtc==directory.Children.Max(n=>n.LastWriteUtc),"directory newest descendant timestamp");
        Check(movie.Extension==".mp4"&&movie.Category==FileCategory.Video,"extension classification");
        Check(!tree.Remove(tree.Root)&&tree.Remove(movie)&&!tree.Remove(movie)&&tree.Version==1,"remove root/detached protection");
        Check(tree.Root.Size==expected-4097&&directory.Size==0&&tree.Root.FileCount==65,"remove ancestor math");
        Check(tree.Root.Category==FileCategory.Document,"folded category survives removal");
        Check(bounded.Root.Size==previous,"snapshot independence after mutations");
        Check(DiskFilter.TryParse("type:video",out var cached,out _)&&cached!.MatchedSize(tree.Root)==0,"filter initial cache");
        Write(Path.Combine(nested,"second.mp4"),1000);
        await tree.RescanAsync(directory,null,CancellationToken.None);
        Check(tree.Version==2&&tree.Root.Size==expected+1000&&tree.Root.FileCount==67,"rescan ancestor math");
        Check(cached!.MatchedSize(tree.Root)==5097,"filter mutation invalidation");
        Exact(tree.Root);
        Check(tree.Remove(directory)&&tree.Root.DirectoryCount==0&&tree.Root.Size==expected-4097,"remove subtree counts");
        await tree.RescanAsync(tree.Root,null,CancellationToken.None);
        Check(tree.Root.Size==expected+1000&&tree.Root.DirectoryCount==1&&tree.Version==4,"root rescan");
        await PermissionsAndLinks(root,temporary);
        if(OperatingSystem.IsWindows()) {
            var longPath=root;
            for(var i=0;i<8;i++)longPath=Path.Combine(longPath,new string('x',40)+i);
            Directory.CreateDirectory(DiskPaths.Native(longPath));Write(DiskPaths.Native(Path.Combine(longPath,"long.txt")),123);
            var longTree=await new DiskScanner(DiskPaths.Native(longPath),new(UseAllocatedSize:false)).ScanAsync(null,CancellationToken.None);
            Check(longTree.Root.Size==123&&longTree.Find(DiskPaths.Native(Path.Combine(longPath,"long.txt")))!=null,"extended long-path enumeration and lookup");
        }
        await CancellationAndSnapshots(temporary);
        Filters();Layouts();Sunbursts();Actions(root,temporary);
        Check(DriveCatalog.List()!=null,"drive catalog never throws");
        try { _=new DiskScanner(Path.Combine(root,"missing"));throw new InvalidOperationException("missing root accepted"); }
        catch(ArgumentException) { }
    }
    static async Task PermissionsAndLinks(string root,string temporary) {
        var denied=Path.Combine(root,"denied");Directory.CreateDirectory(denied);Write(Path.Combine(denied,"secret"),777);
        if(!OperatingSystem.IsWindows()) {
            var original=File.GetUnixFileMode(denied);
            try {
                File.SetUnixFileMode(denied,UnixFileMode.None);
                var reports=new Reports();var tree=await new DiskScanner(root).ScanAsync(reports,CancellationToken.None);
                var node=tree.Find(denied)!;
                if(node.Issue==NodeIssue.AccessDenied)Check(reports.Last!.Errors>=1&&node.Size==0,"access denied tolerated");
                else {
                    var permitted=false;try { permitted=Directory.EnumerateFileSystemEntries(denied).Any(); }catch(UnauthorizedAccessException) { }
                    Check(permitted,"access-denied node must be reported");
                    Console.Error.WriteLine("DISK_USAGE_SMOKE_NOTE: permission test bypassed by host privileges");
                }
            } finally { File.SetUnixFileMode(denied,original); }
        }
        var link=Path.Combine(root,"loop");var fileLink=Path.Combine(root,"file-link");
        try { Directory.CreateSymbolicLink(link,root);File.CreateSymbolicLink(fileLink,Path.Combine(root,"small-000.txt")); }
        catch(UnauthorizedAccessException) when(OperatingSystem.IsWindows()) {
            Console.Error.WriteLine("DISK_USAGE_SMOKE_NOTE: Windows symlink creation needs Developer Mode or privilege");return;
        }
        var scanned=await new DiskScanner(root,new(TopFilesPerDirectory:0)).ScanAsync(null,CancellationToken.None);
        Check(scanned.Find(link) is {Issue:NodeIssue.Link,Size:0,Children.Count:0},"directory symlink skipped");
        Check(scanned.Find(fileLink) is {Issue:NodeIssue.Link,Size:0},"file symlink retained as issue");
        var rootLink=await new DiskScanner(link).ScanAsync(null,CancellationToken.None);
        Check(rootLink.Root.Issue==NodeIssue.Link&&rootLink.Root.FileCount==0,"linked scan root skipped");
        Write(Path.Combine(temporary,"outside"),5);
        Check(FileActions.Open(Path.Combine(link,"nested"),root).Status==ActionStatus.OutsideRoot,"action rejects linked ancestor");
        Directory.Delete(link);File.Delete(fileLink);
    }
    static async Task CancellationAndSnapshots(string temporary) {
        var root=Path.Combine(temporary,"many");Directory.CreateDirectory(root);
        for(var i=0;i<100;i++) {
            var directory=Path.Combine(root,i.ToString());Directory.CreateDirectory(directory);
            for(var j=0;j<120;j++)Write(Path.Combine(directory,j+".dat"),j);
        }
        var scanner=new DiskScanner(root,new(UseAllocatedSize:false));
        using var ct=new CancellationTokenSource();var reports=new Reports();
        var running=scanner.ScanAsync(reports,ct.Token);
        ScanSnapshot snapshot;
        do { snapshot=scanner.CaptureSnapshot(2,4);if(snapshot.Progress.Files>0)break;await Task.Delay(1); }while(!running.IsCompleted);
        Check(!running.IsCompleted&&snapshot.Progress.Files>0,"cancel during active enumeration");
        var size=snapshot.Root.Size;
        var clock=Stopwatch.StartNew();ct.Cancel();
        try { await running;throw new InvalidOperationException("cancellation did not throw"); }catch(OperationCanceledException) { }
        Check(clock.ElapsedMilliseconds<=250,"cancellation latency: "+clock.ElapsedMilliseconds+" ms");
        Check(reports.Last?.Phase==ScanPhase.Canceled,"last report canceled");
        Check(snapshot.Root.Size==size,"active snapshot remains detached");
        Console.Error.WriteLine($"DISK_USAGE_SMOKE_CANCEL: {clock.Elapsed.TotalMilliseconds:F1} ms");
        var completeScanner=new DiskScanner(root,new(UseAllocatedSize:false));clock.Restart();
        var complete=completeScanner.ScanAsync(null,CancellationToken.None);var samples=0;var maximum=0d;
        while(!complete.IsCompleted) {
            var timer=Stopwatch.StartNew();var sample=completeScanner.CaptureSnapshot(3,8);maximum=Math.Max(maximum,timer.Elapsed.TotalMilliseconds);
            Check(sample.Root.Children.Count<=8,"live snapshot bound");samples++;await Task.Delay(1);
        }
        var result=await complete;
        Check(result.Root.FileCount==12000&&result.Root.Size==100L*Enumerable.Range(0,120).Sum(),"parallel scan complete");Exact(result.Root);
        var capped=completeScanner.CaptureSnapshot(6,256);var pending=new Stack<DiskNode>();pending.Push(capped.Root);var nodes=0;
        while(pending.TryPop(out var node)) { nodes++;foreach(var child in node.Children)pending.Push(child); }
        Check(nodes<=8192&&capped.Root.Size==result.Root.Size,"snapshot global work bound");
        Console.Error.WriteLine($"DISK_USAGE_SMOKE_SCAN: {result.Root.FileCount} files, {clock.Elapsed.TotalSeconds:F3} s, {result.Root.FileCount/clock.Elapsed.TotalSeconds:F0} files/s; {samples} snapshots, max {maximum:F2} ms");
        using var canceled=new CancellationTokenSource();canceled.Cancel();reports=new();
        try { await new DiskScanner(root).ScanAsync(reports,canceled.Token);throw new InvalidOperationException("pre-canceled scan accepted"); }
        catch(OperationCanceledException) { Check(reports.Last?.Phase==ScanPhase.Canceled,"pre-canceled terminal phase"); }
    }
    static void Filters() {
        var file=new DiskNode {Name="Report.MP4",FullPath="/Report.MP4",Kind=NodeKind.File,Size=2L*1024*1024*1024,LogicalSize=9,FileCount=1,
            Category=FileCategory.Video,LastWriteUtc=DateTime.UtcNow.AddDays(-40)};
        foreach(var text in new[] {"*.mp4", "rep", "r?port*", ">100MB;<=2GB >=1.5GB", "older:30d newer:2y", "type:video|audio", "!*.zip", "*.zip|*.MP4", "!type:audio"}) {
            Check(DiskFilter.TryParse(text,out var filter,out var error)&&error==null&&filter!.Matches(file),"valid filter: "+text);
        }
        foreach(var text in new[] {"*.zip", "<1GB", "newer:12h", "type:audio", "!rep", "type:video !*.mp4"})
            Check(DiskFilter.TryParse(text,out var filter,out _)&&!filter!.Matches(file),"nonmatching filter: "+text);
        foreach(var text in new[] {">12XB", ">=1..5GB", ">-1B", "older:12q", "newer:999999999999y", "type:movie", "type:99", "!", "a||b", "wat:30d", "type:video|"})
            Check(!DiskFilter.TryParse(text,out var filter,out var error)&&filter==null&&!string.IsNullOrEmpty(error),"invalid filter: "+text);
        Check(DiskFilter.TryParse(" ; \t",out var empty,out var noError)&&empty==null&&noError==null,"empty filter");
        var aggregate=DiskNode.Aggregate(file,1024,1024,100);
        foreach(var term in new[] {"*.mp4","!*.zip","type:video|audio","older:30d"})
            Check(DiskFilter.TryParse(term,out var filter,out _)&&!filter!.Matches(aggregate),"aggregate cannot match: "+term);
        Check(DiskFilter.TryParse(">=1KB <2KB",out var sizes,out _)&&sizes!.Matches(aggregate),"aggregate size terms");
        Check(Enum.GetValues<FileCategory>().All(c=>FileCategories.Label(c).Length>0),"category labels");
        Check(FileCategories.Classify(".DLL")==FileCategory.System&&FileCategories.Classify(".unknown")==FileCategory.Other,"system/unknown extension");
    }
    static void Layouts() {
        var random=new Random(73191);var root=RandomTree(random,"/root",null,0);
        Check(DiskFilter.TryParse("type:video|audio >10B",out var filter,out _),"layout filter parse");
        foreach(var options in new[] {new LayoutOptions(MinCellArea:0),new LayoutOptions(),new LayoutOptions(MinCellArea:3000,FreeBytes:99999),
            new LayoutOptions(MaxDepth:2,MinCellArea:100),new LayoutOptions(Filter:filter,MinCellArea:50)}) {
            foreach(var bounds in new[] {new RectD(13,27,1200,800),new RectD(-10,9,31,20),new RectD(0,0,800,1200)}) {
                var cells=TreemapLayout.Build(root,bounds,options);var again=TreemapLayout.Build(root,bounds,options);
                Check(cells.Select(c=>(c.Key,c.Bounds,c.ContentBounds,c.Depth,c.HasHeader,c.IsLeaf)).SequenceEqual(
                    again.Select(c=>(c.Key,c.Bounds,c.ContentBounds,c.Depth,c.HasHeader,c.IsLeaf))),"deterministic layout");
                Check(cells.Select(c=>c.Key).Distinct().Count()==cells.Count,"unique keys");
                var parents=new Stack<TreemapCell>();var siblings=new Dictionary<string,List<TreemapCell>>();
                foreach(var cell in cells) {
                    while(parents.Count>cell.Depth)parents.Pop();
                    Check(cell.Depth<=options.MaxDepth&&cell.Bounds.Width>0&&cell.Bounds.Height>0,"depth and nonzero size");
                    if(cell.Depth>0) {
                        Check(parents.Count==cell.Depth,"parent before child");var parent=parents.Peek();
                        Check(Contains(parent.ContentBounds,cell.Bounds),"child containment");
                        if(!siblings.TryGetValue(parent.Key,out var group))siblings[parent.Key]=group=new();group.Add(cell);
                    }
                    if(cell.IsLeaf)Check(cell.ContentBounds==cell.Bounds,"leaf content bounds");
                    else Check(cell.ContentBounds.Width*cell.ContentBounds.Height>=options.MinCellArea,"subdivision threshold");
                    parents.Push(cell);
                }
                foreach(var (key,group) in siblings) {
                    var parent=cells.Single(c=>c.Key==key);var area=parent.ContentBounds.Width*parent.ContentBounds.Height;
                    var total=group.Sum(c=>(double)(c.Node.Kind is NodeKind.Aggregate or NodeKind.FreeSpace?c.Node.Size:options.Filter?.MatchedSize(c.Node)??c.Node.Size));
                    Check(total==(options.Filter?.MatchedSize(parent.Node)??parent.Node.Size)+(double)(parent.Depth==0?options.FreeBytes:0),"layout preserves all weighted bytes");
                    for(var i=0;i<group.Count;i++) {
                        var bytes=group[i].Node.Kind is NodeKind.Aggregate or NodeKind.FreeSpace?group[i].Node.Size:options.Filter?.MatchedSize(group[i].Node)??group[i].Node.Size;
                        Check(Math.Abs(group[i].Bounds.Width*group[i].Bounds.Height-area*bytes/total)<Math.Max(1e-6,area*1e-10),"area proportionality");
                        for(var j=i+1;j<group.Count;j++)Check(!Overlap(group[i].Bounds,group[j].Bounds),"siblings overlap");
                    }
                }
                if(options.FreeBytes>0&&cells.Count>1)Check(cells.Any(c=>c.Key=="#free"&&c.Node.Size==options.FreeBytes),"free space cell");
            }
        }
        var tied=new DiskNode {FullPath="/ties",Kind=NodeKind.Directory,Size=20};
        var b=new DiskNode {Name="b",FullPath="/ties/b",Kind=NodeKind.File,Size=10,Parent=tied};
        var a=new DiskNode {Name="a",FullPath="/ties/a",Kind=NodeKind.File,Size=10,Parent=tied};
        tied.Children=new[] {a,b};var tieCells=TreemapLayout.Build(tied,new(0,0,200,200),new(MinCellArea:0));
        Check(tieCells[1].Node.Name=="a","ordinal tie break");
        var squares=new DiskNode {FullPath="/squares",Kind=NodeKind.Directory,Size=4};
        squares.Children=Enumerable.Range(0,4).Select(i=>new DiskNode {Name=i.ToString(),FullPath="/squares/"+i,Kind=NodeKind.File,Size=1,Parent=squares}).ToArray();
        var squared=TreemapLayout.Build(squares,new(0,0,200,200),new(MinCellArea:0,HeaderHeight:0,Padding:0));
        Check(squared.Skip(1).All(c=>Math.Abs(c.Bounds.Width-100)<1e-6&&Math.Abs(c.Bounds.Height-100)<1e-6),"squarified equal squares");
        var huge=new DiskNode {FullPath="/huge",Kind=NodeKind.Directory,Size=10000000,FileCount=5000000};
        var guarded=new GuardedChildren(huge);huge.Children=guarded;
        var drawn=TreemapLayout.Build(huge,new(0,0,1000,1000),new());
        Check(guarded.Visits<=2&&drawn.Count<=3,"layout visits only drawable prefix");
        Check(TreemapLayout.Build(new(),new(0,0,1,1),new()).Count==0,"zero size skipped");
    }
    static void Sunbursts() {
        var random=new Random(52417);var root=RandomTree(random,"/sun",null,0);
        Check(DiskFilter.TryParse("type:video|audio",out var filter,out _),"sunburst filter parse");
        foreach(var (depth,min,f) in new[] {(1,0d,(DiskFilter?)null),(4,.004,null),(7,0,null),(3,.01,filter),(6,.002,filter)}) {
            var cells=SunburstLayout.Build(root,depth,min,f);var again=SunburstLayout.Build(root,depth,min,f);
            Check(cells.Select(c=>(c.Key,c.Start,c.Sweep,c.Depth)).SequenceEqual(again.Select(c=>(c.Key,c.Start,c.Sweep,c.Depth))),"sunburst deterministic");
            Check(cells.Select(c=>c.Key).Distinct().Count()==cells.Count,"sunburst unique keys");
            Check(cells.All(c=>c.Depth>=1&&c.Depth<=depth&&c.Sweep>0&&c.Start>=-1e-12&&c.Start+c.Sweep<=1+1e-9),"sunburst bounds");
            Check(cells.Where(c=>c.Node.Kind!=NodeKind.Aggregate).All(c=>c.Sweep>=min-1e-12),"sunburst minimum sweep");
            Check(Math.Abs(cells.Where(c=>c.Depth==1).Sum(c=>c.Sweep)-1)<1e-9,"sunburst first ring is whole");
            long Bytes(DiskNode n) => n.Kind==NodeKind.Aggregate?n.Size:f?.MatchedSize(n)??n.Size;
            var total=(double)Bytes(root);
            foreach(var cell in cells) {
                Check(Math.Abs(cell.Sweep-Bytes(cell.Node)/total)<1e-9,"sunburst angle proportional to bytes");
                var kids=cells.Where(c=>c.Depth==cell.Depth+1&&c.Node.Parent==cell.Node).ToList();
                if(kids.Count==0)continue;
                Check(Math.Abs(kids.Sum(k=>k.Sweep)-cell.Sweep)<1e-9,"sunburst children fill parent");
                Check(kids.All(k=>k.Start>=cell.Start-1e-12&&k.Start+k.Sweep<=cell.Start+cell.Sweep+1e-9),"sunburst child containment");
            }
        }
        var huge=new DiskNode {FullPath="/huge",Kind=NodeKind.Directory,Size=10000000,FileCount=5000000};
        var guarded=new GuardedChildren(huge);huge.Children=guarded;
        Check(SunburstLayout.Build(huge,5,.003).Count<=3&&guarded.Visits<=2,"sunburst visits only drawable prefix");
        Check(SunburstLayout.Build(new(){Kind=NodeKind.Directory},3,0).Count==0,"sunburst zero size skipped");
    }
    static DiskNode RandomTree(Random random,string path,DiskNode? parent,int depth) {
        var node=new DiskNode {Name=Path.GetFileName(path),FullPath=path,Kind=NodeKind.Directory,Parent=parent};
        var children=new List<DiskNode>();
        for(var i=0;i<random.Next(3,9);i++) {
            var child=depth<3&&random.Next(3)==0?RandomTree(random,path+"/d"+i,node,depth+1):new DiskNode {
                Name="f"+i,FullPath=path+"/f"+i,Parent=node,Kind=NodeKind.File,Size=random.Next(0,50000),FileCount=1,
                Category=(FileCategory)random.Next(3)
            };
            children.Add(child);node.Size+=child.Size;node.LogicalSize+=child.Size;node.FileCount+=child.FileCount;
            node.DirectoryCount+=child.DirectoryCount+(child.Kind==NodeKind.Directory?1:0);
        }
        children.Sort(DiskOrder.Instance);node.Children=children;return node;
    }
    static void Actions(string root,string temporary) {
        foreach(var action in new Func<string,string,ActionResult>[] {FileActions.Open,FileActions.Reveal,FileActions.MoveToRecycleBin}) {
            foreach(var path in new[] {root,Path.GetPathRoot(root)!,Path.Combine(root,"..","outside"),temporary,root+"-sibling"})
                Check(action(path,root).Status==ActionStatus.OutsideRoot,"reject outside/root action");
            Check(action(Path.Combine(root,"absent"),root).Status==ActionStatus.NotFound,"missing action target");
        }
        Check(FileActions.Open(Path.Combine(root,"small-001.txt"),root).Status==ActionStatus.NotSupported,"never launch files");
        if(!OperatingSystem.IsWindows())Check(FileActions.MoveToRecycleBin(Path.Combine(root,"small-001.txt"),root).Status==ActionStatus.NotSupported,"no non-Windows deletion");
        Check(DiskPaths.Within(Path.Combine(root,"nested","..","small-001.txt"),root),"canonical parent segments");
        Check(DiskPaths.Equal(root,root+Path.DirectorySeparatorChar),"canonical trailing separator");
        if(OperatingSystem.IsWindows())Check(DiskPaths.Equal(root,DiskPaths.Native(root)),"extended Windows paths");
    }
    static void Exact(DiskNode node) {
        if(node.Kind!=NodeKind.Directory)return;
        Check(node.Size==node.Children.Sum(n=>n.Size)&&node.LogicalSize==node.Children.Sum(n=>n.LogicalSize)&&
            node.FileCount==node.Children.Sum(n=>n.FileCount)&&node.DirectoryCount==node.Children.Sum(n=>n.DirectoryCount+(n.Kind==NodeKind.Directory?1:0)),"directory sum exactness");
        Check(node.Children.SequenceEqual(node.Children.OrderBy(n=>n,DiskOrder.Instance)),"children sorted");
        foreach(var child in node.Children) { Check(ReferenceEquals(child.Parent,node),"parent link");Exact(child); }
    }
    static bool Contains(RectD parent,RectD child) => child.X>=parent.X-1e-6&&child.Y>=parent.Y-1e-6&&
        child.X+child.Width<=parent.X+parent.Width+1e-6&&child.Y+child.Height<=parent.Y+parent.Height+1e-6;
    static bool Overlap(RectD a,RectD b) => Math.Min(a.X+a.Width,b.X+b.Width)-Math.Max(a.X,b.X)>1e-6&&
        Math.Min(a.Y+a.Height,b.Y+b.Height)-Math.Max(a.Y,b.Y)>1e-6;
    static void Write(string path,long length) { using var stream=File.Create(path);stream.SetLength(length); }
    static void Check(bool valid,string message) { if(!valid)throw new InvalidOperationException(message); }
    sealed class Reports : IProgress<ScanProgress> {
        internal ScanProgress? Last;
        public void Report(ScanProgress value) => Last=value;
    }
    sealed class GuardedChildren(DiskNode parent) : IReadOnlyList<DiskNode> {
        internal int Visits;
        public int Count=>5000000;
        public DiskNode this[int index]=>throw new InvalidOperationException("linear index access");
        public IEnumerator<DiskNode> GetEnumerator() {
            Visits++;yield return new() {Name="large",FullPath="/huge/large",Size=5000001,Kind=NodeKind.File,Parent=parent};
            Visits++;yield return new() {Name="small",FullPath="/huge/small",Size=1,Kind=NodeKind.File,Parent=parent};
            throw new InvalidOperationException("layout traversed invisible tail");
        }
        System.Collections.IEnumerator System.Collections.IEnumerable.GetEnumerator()=>GetEnumerator();
    }
}
