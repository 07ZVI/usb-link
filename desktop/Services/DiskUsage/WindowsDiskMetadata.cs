using System.Collections.Concurrent;
using System.Runtime.InteropServices;
using System.Text;
using Microsoft.Win32.SafeHandles;

namespace Suhang.Desktop.DiskUsage;

internal sealed class WindowsDiskMetadata
{
    readonly ConcurrentDictionary<string,long> clusters = new(StringComparer.OrdinalIgnoreCase);
    readonly ConcurrentDictionary<(uint Volume,ulong Index),string> links = new();
    readonly bool hardLinks;
    internal WindowsDiskMetadata(DriveSpace? space,bool? hardLinks=null) =>
        this.hardLinks=hardLinks??(space is { Network:false }&&space.Format.Equals("NTFS",StringComparison.OrdinalIgnoreCase));

    internal WindowsDiskMetadata ForRescan(string path) {
        var copy=new WindowsDiskMetadata(null,hardLinks);
        foreach(var item in clusters)copy.clusters[item.Key]=item.Value;
        foreach(var item in links)if(!DiskPaths.Within(item.Value,path,true))copy.links[item.Key]=item.Value;
        return copy;
    }
    internal void Forget(DiskNode node) {
        foreach(var item in links) {
            var removed=node.Kind==NodeKind.Aggregate?
                DiskPaths.Equal(Path.GetDirectoryName(item.Value)!,node.Parent!.FullPath)&&
                    !node.Parent.Children.Any(child=>child.Kind==NodeKind.File&&DiskPaths.Equal(child.FullPath,item.Value)):
                DiskPaths.Within(item.Value,node.FullPath,true);
            if(removed)links.TryRemove(item.Key,out _);
        }
    }

    internal long Size(string path,long length,FileAttributes attributes) {
        if(length==0)return 0;
        var cluster=clusters.GetOrAdd(Path.GetPathRoot(path)!,_=>ClusterSize(path));
        var rounded=length>long.MaxValue-cluster+1?long.MaxValue:(length+cluster-1)/cluster*cluster;
        var special=(attributes&(FileAttributes.Compressed|FileAttributes.SparseFile))!=0;
        if(!special&&!hardLinks)return rounded;
        // Metadata access only. No recall, no traversal of a final reparse point, and
        // no delete sharing while GetCompressedFileSizeW uses the validated name.
        using var handle=CreateFileW(DiskPaths.Native(path),0,1,IntPtr.Zero,3,0x00200000|0x00100000,IntPtr.Zero);
        if(handle.IsInvalid||!GetFileInformationByHandle(handle,out var info))return rounded;
        if(DiskPaths.Issue((FileAttributes)info.Attributes)!=NodeIssue.None)return 0;
        if(info.Links>1) {
            var key=(info.VolumeSerial,((ulong)info.IndexHigh<<32)|info.IndexLow);
            if(!DiskPaths.Equal(links.GetOrAdd(key,path),path))return 0;
        }
        if(!special)return rounded;
        Marshal.SetLastPInvokeError(0);
        var low=GetCompressedFileSizeW(DiskPaths.Native(path),out var high);
        return low==uint.MaxValue&&Marshal.GetLastPInvokeError()!=0?rounded:(long)Math.Min(((ulong)high<<32)|low,long.MaxValue);
    }
    static long ClusterSize(string path) {
        var volume=new StringBuilder(32768);
        return GetVolumePathNameW(DiskPaths.Native(path),volume,volume.Capacity)&&
            GetDiskFreeSpaceW(volume.ToString(),out var sectors,out var bytes,out _,out _)?Math.Max(1,(long)sectors*bytes):4096;
    }

    [DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true),DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    static extern SafeFileHandle CreateFileW(string path,uint access,uint share,IntPtr security,uint creation,uint flags,IntPtr template);
    [DllImport("kernel32.dll",SetLastError=true),DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    [return:MarshalAs(UnmanagedType.Bool)]
    static extern bool GetFileInformationByHandle(SafeFileHandle handle,out WindowsFileInfo information);
    [DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true),DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    static extern uint GetCompressedFileSizeW(string path,out uint high);
    [DllImport("kernel32.dll",CharSet=CharSet.Unicode),DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    [return:MarshalAs(UnmanagedType.Bool)]
    static extern bool GetVolumePathNameW(string path,StringBuilder volume,int length);
    [DllImport("kernel32.dll",CharSet=CharSet.Unicode),DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    [return:MarshalAs(UnmanagedType.Bool)]
    static extern bool GetDiskFreeSpaceW(string root,out uint sectors,out uint bytes,out uint free,out uint total);
}
