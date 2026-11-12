using System.Runtime.InteropServices;
using System.Runtime.Versioning;

namespace Suhang.Desktop.DiskUsage;

[SupportedOSPlatform("windows")]
internal static class WindowsRecycleBin
{
    internal static ActionResult Move(string path,string root) {
        if(!OperatingSystem.IsWindowsVersionAtLeast(6,2))return new(ActionStatus.NotSupported,"此 Windows 版本不支援僅回收操作。");
        if(Thread.CurrentThread.GetApartmentState()==ApartmentState.STA)return Run(path,root);
        ActionResult result=new(ActionStatus.Failed,"無法啟動資源回收筒操作。");
        var thread=new Thread(()=>result=Run(path,root)) {Name="USB Link recycle bin"};
        thread.SetApartmentState(ApartmentState.STA);thread.Start();thread.Join();return result;
    }
    static ActionResult Run(string path,string root) {
        ShellFileOperation? operation=null;ShellItem? item=null;
        try {
            var rejection=FileActions.Validate(path,root,out var canonical);
            if(rejection!=null)return rejection;
            var type=Type.GetTypeFromCLSID(new Guid("3AD05575-8857-4850-9277-11B85BDB8E09"),true)!;
            operation=(ShellFileOperation)Activator.CreateInstance(type)!;
            // SHFileOperation + ALLOWUNDO can permanently delete when recycling
            // is unavailable. RECYCLEONDELETE + NOERRORUI/EARLYFAILURE has no
            // permanent-delete fallback and accepts shell items for long paths.
            operation.SetOperationFlags(0x40|0x10|0x4|0x400|0x2000|0x80000|0x100000);
            var iid=typeof(ShellItem).GUID;
            Marshal.ThrowExceptionForHR(SHCreateItemFromParsingName(DiskPaths.Native(canonical),IntPtr.Zero,ref iid,out item));
            operation.DeleteItem(item,IntPtr.Zero);operation.PerformOperations();operation.GetAnyOperationsAborted(out var aborted);
            return aborted?new(ActionStatus.Failed,"未完成移至資源回收筒。"):new(ActionStatus.Done,null);
        } catch(Exception e) { return new(ActionStatus.Failed,e.Message); }
        finally {
            if(item!=null)Marshal.FinalReleaseComObject(item);
            if(operation!=null)Marshal.FinalReleaseComObject(operation);
        }
    }
    [DllImport("shell32.dll",CharSet=CharSet.Unicode,PreserveSig=true),DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    static extern int SHCreateItemFromParsingName(string path,IntPtr context,ref Guid iid,[MarshalAs(UnmanagedType.Interface)] out ShellItem item);
}
