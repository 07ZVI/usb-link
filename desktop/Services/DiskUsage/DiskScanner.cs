using System.Diagnostics;
using System.IO.Enumeration;
using System.Threading.Channels;

namespace Suhang.Desktop.DiskUsage;

internal sealed class DiskScanner
{
    readonly object gate=new(), reportGate=new();
    readonly ScanOptions options;
    readonly DiskNode root;
    readonly DriveSpace? space;
    readonly HashSet<string> mounts;
    readonly Stopwatch elapsed=new();
    readonly WindowsDiskMetadata metadata;
    ScanPhase phase=ScanPhase.Enumerating;
    string currentPath;
    long errors;
    double fraction;
    int started;

    internal DiskScanner(string rootPath,ScanOptions? options=null) : this(rootPath,options,null) { }
    internal DiskScanner(string rootPath,ScanOptions? options,WindowsDiskMetadata? metadata) {
        string path;
        try { path=DiskPaths.Canonical(rootPath);if(!Directory.Exists(DiskPaths.Native(path)))throw new ArgumentException("資料夾不存在。",nameof(rootPath)); }
        catch(Exception e) when(e is not ArgumentException) { throw new ArgumentException("資料夾不存在。",nameof(rootPath),e); }
        this.options=options??new();
        if(this.options.MaxDegreeOfParallelism<0||this.options.SmallFileFloor<0||this.options.TopFilesPerDirectory<0)
            throw new ArgumentOutOfRangeException(nameof(options));
        var drives=DriveCatalog.List();
        mounts=OperatingSystem.IsWindows()?new():new(drives.Select(d=>DiskPaths.Canonical(d.Name)),StringComparer.Ordinal);
        currentPath=path;space=DriveCatalog.Find(path,drives);this.metadata=metadata??new(space);
        root=NewDirectory(Path.GetFileName(path) is {Length:>0} name?name:path,path,DateTime.MinValue,null);
    }

    internal async Task<DiskTree> ScanAsync(IProgress<ScanProgress>? progress,CancellationToken ct) {
        if(Interlocked.Exchange(ref started,1)!=0)throw new InvalidOperationException("掃描器只能執行一次。");
        elapsed.Start();
        using var lifetime=CancellationTokenSource.CreateLinkedTokenSource(ct);
        var token=lifetime.Token;
        var queue=Channel.CreateUnbounded<DiskNode>(new() { SingleWriter=false,SingleReader=false });
        long pending=1;
        queue.Writer.TryWrite(root);
        var degree=options.MaxDegreeOfParallelism>0?options.MaxDegreeOfParallelism:
            space is {Removable:true} or {Network:true}||OperatingSystem.IsWindows()&&root.FullPath.StartsWith(@"\\",StringComparison.Ordinal)?
                2:Math.Max(1,Math.Min(8,Environment.ProcessorCount));
        var workers=Enumerable.Range(0,degree).Select(_=>Task.Run(async ()=> {
            try {
                await foreach(var directory in queue.Reader.ReadAllAsync(token)) {
                    Enumerate(directory,child=> { Interlocked.Increment(ref pending);queue.Writer.TryWrite(child); },token);
                    if(Interlocked.Decrement(ref pending)==0)queue.Writer.TryComplete();
                }
            } catch(Exception e) { queue.Writer.TryComplete(e);throw; }
        },CancellationToken.None)).ToArray();
        var work=Task.WhenAll(workers);
        var ticker=Task.Run(async ()=> {
            try { while(true) { await Task.Delay(100,token);Report(ScanPhase.Enumerating,progress); } }
            catch(OperationCanceledException) { }
        },CancellationToken.None);
        try {
            Report(ScanPhase.Enumerating,progress);
            await work.WaitAsync(ct).ConfigureAwait(false);
            ct.ThrowIfCancellationRequested();
            Report(ScanPhase.Completed,progress);
            return new(root,space,options,metadata);
        } catch(OperationCanceledException) when(ct.IsCancellationRequested) {
            Report(ScanPhase.Canceled,progress);throw new OperationCanceledException(ct);
        } catch { Report(ScanPhase.Failed,progress);throw; }
        finally {
            lifetime.Cancel();
            // A filesystem driver may stall a synchronous metadata request. Do not
            // make cancellation wait for that driver; workers check before publishing.
            _=work.ContinueWith(t=> { _=t.Exception; },TaskScheduler.Default);
            _=ticker.ContinueWith(t=> { _=t.Exception; },TaskScheduler.Default);
        }
    }

    void Enumerate(DiskNode directory,Action<DiskNode> enqueue,CancellationToken ct) {
        try {
            ct.ThrowIfCancellationRequested();
            var issue=DiskPaths.CheckDirectory(directory.FullPath,root.FullPath);
            if(issue!=NodeIssue.None) { lock(gate) { ct.ThrowIfCancellationRequested();directory.Issue=issue; }return; }
            if(ReferenceEquals(directory,root)) {
                var write=Directory.GetLastWriteTimeUtc(DiskPaths.Native(directory.FullPath));
                lock(gate) { ct.ThrowIfCancellationRequested();directory.OwnWriteUtc=write; }
            }
            var state=new ScanDirectory(directory,options);
            var batch=new List<(ScanEntry Entry,long Size)>(32);
            var entries=new FileSystemEnumerable<ScanEntry>(DiskPaths.Native(directory.FullPath),(ref FileSystemEntry e)=> {
                var attributes=e.Attributes;
                var link=DiskPaths.Issue(attributes)==NodeIssue.Link;
                return new(e.FileName.ToString(),e.ToFullPath(),e.IsDirectory,link?0:e.Length,attributes,link?DateTime.MinValue:e.LastWriteTimeUtc.UtcDateTime);
            },new EnumerationOptions { RecurseSubdirectories=false,IgnoreInaccessible=false,AttributesToSkip=0,ReturnSpecialDirectories=false,BufferSize=64*1024 });
            foreach(var entry in entries) {
                ct.ThrowIfCancellationRequested();
                var size=entry.Directory||DiskPaths.Issue(entry.Attributes)!=NodeIssue.None?0:
                    OperatingSystem.IsWindows()&&options.UseAllocatedSize?metadata.Size(entry.Path,entry.Length,entry.Attributes):entry.Length;
                batch.Add((entry,size));
                if(batch.Count==32)Publish();
            }
            Publish();
            void Publish() {
                ct.ThrowIfCancellationRequested();
                lock(gate) {
                    ct.ThrowIfCancellationRequested();currentPath=directory.FullPath;
                    foreach(var (entry,size) in batch) {
                        var problem=DiskPaths.Issue(entry.Attributes);
                        var path=DiskPaths.Canonical(entry.Path);
                        // Unix mount points have no ReparsePoint attribute.
                        if(entry.Directory&&mounts.Contains(path))problem=NodeIssue.Link;
                        var node=entry.Directory?NewDirectory(entry.Name,path,entry.Write,directory):new DiskNode {
                            Name=entry.Name,FullPath=path,Kind=NodeKind.File,Size=size,LogicalSize=entry.Length,FileCount=1,
                            LastWriteUtc=entry.Write,Extension=Path.GetExtension(entry.Name).ToLowerInvariant(),Parent=directory,Gate=gate
                        };
                        node.Issue=problem;
                        if(entry.Directory) {
                            ((DiskChildren)directory.Children).Add(node);
                            DiskTree.Adjust(directory,0,0,0,1,entry.Write,FileCategory.Other,0);
                            if(problem==NodeIssue.None)enqueue(node);
                        } else {
                            node.Category=FileCategories.Classify(node.Extension);state.AddFile(node);
                            DiskTree.Adjust(directory,size,entry.Length,1,0,entry.Write,node.Category,size);
                        }
                    }
                }
                batch.Clear();
            }
        } catch(Exception e) when(e is UnauthorizedAccessException or System.Security.SecurityException or IOException) {
            ct.ThrowIfCancellationRequested();
            lock(gate) {
                ct.ThrowIfCancellationRequested();
                directory.Issue=e is UnauthorizedAccessException or System.Security.SecurityException?NodeIssue.AccessDenied:NodeIssue.Error;
                directory.Revision++;errors++;
            }
        }
    }

    DiskNode NewDirectory(string name,string path,DateTime write,DiskNode? parent) => new() {
        Name=name,FullPath=path,Kind=NodeKind.Directory,Parent=parent,Gate=gate,Children=new DiskChildren(),
        OwnWriteUtc=write,CategorySizes=new long[Enum.GetValues<FileCategory>().Length]
    };
    ScanProgress Progress() {
        double? value=null;
        if(space is {Ready:true}&&DiskPaths.Equal(root.FullPath,space.Name)&&space.TotalBytes>space.FreeBytes) {
            fraction=Math.Max(fraction,Math.Clamp(root.Size/(double)(space.TotalBytes-space.FreeBytes),0,1));value=fraction;
        }
        return new(phase,root.FileCount,root.DirectoryCount,root.Size,errors,currentPath,elapsed.Elapsed,value);
    }
    void Report(ScanPhase next,IProgress<ScanProgress>? progress) {
        lock(reportGate) {
            ScanProgress report;
            lock(gate) {
                if(phase!=ScanPhase.Enumerating)return;
                phase=next;if(next!=ScanPhase.Enumerating)elapsed.Stop();report=Progress();
            }
            progress?.Report(report);
        }
    }
    internal ScanSnapshot CaptureSnapshot(int maxDepth=6,int maxChildrenPerNode=64) {
        if(maxDepth<0||maxChildrenPerNode<0)throw new ArgumentOutOfRangeException(nameof(maxDepth));
        lock(gate) {
            // Depth/fanout limits alone still permit millions of copies. Reserve
            // siblings before descending and bound each 250 ms preview's work.
            var remaining=8191;
            var copy=root.Copy(null);Fill(root,copy,0);return new(copy,Progress());
            void Fill(DiskNode source,DiskNode target,int depth) {
                if(depth>=maxDepth||remaining==0||maxChildrenPerNode==0||source.Children.Count==0)return;
                var limit=Math.Min(remaining,maxChildrenPerNode);
                var truncated=source.Children.Count>limit;
                var children=new List<DiskNode>();var descend=new List<(DiskNode Source,DiskNode Target)>();
                long size=0,logical=0,files=0,dirs=0;
                foreach(var child in source.Children) {
                    if(truncated&&child.Kind==NodeKind.Aggregate)continue;
                    if(children.Count>=(truncated?limit-1:limit))break;
                    var detached=child.Copy(target);detached.Gate=target.Gate;remaining--;
                    children.Add(detached);descend.Add((child,detached));
                    size+=child.Size;logical+=child.LogicalSize;files+=child.FileCount;
                    dirs+=child.DirectoryCount+(child.Kind==NodeKind.Directory?1:0);
                }
                if(truncated) {
                    children.Add(DiskNode.Aggregate(target,source.Size-size,source.LogicalSize-logical,source.FileCount-files,source.DirectoryCount-dirs));remaining--;
                }
                children.Sort(DiskOrder.Instance);target.Children=children.ToArray();
                foreach(var pair in descend)Fill(pair.Source,pair.Target,depth+1);
            }
        }
    }
}
