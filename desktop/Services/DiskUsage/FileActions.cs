using System.Diagnostics;

namespace Suhang.Desktop.DiskUsage;

internal static class FileActions
{
    internal static ActionResult Reveal(string path,string scanRoot) => Act(path,scanRoot,false,false);
    internal static ActionResult Open(string path,string scanRoot) => Act(path,scanRoot,true,false);
    internal static ActionResult MoveToRecycleBin(string path,string scanRoot) => Act(path,scanRoot,false,true);

    static ActionResult Act(string path,string scanRoot,bool open,bool recycle) {
        var rejection=Validate(path,scanRoot,out var canonical);
        if(rejection!=null)return rejection;
        try {
            if(open&&(File.GetAttributes(DiskPaths.Native(canonical))&FileAttributes.Directory)==0)
                return new(ActionStatus.NotSupported,"僅能開啟資料夾。");
            if(recycle) {
                if(!OperatingSystem.IsWindows())return new(ActionStatus.NotSupported,"此平台不支援移至資源回收筒。");
                return WindowsRecycleBin.Move(canonical,scanRoot);
            }
            var process=new ProcessStartInfo { UseShellExecute=false };
            if(OperatingSystem.IsWindows()) {
                process.FileName=Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows),"explorer.exe");
                if(!open)process.ArgumentList.Add("/select,");
                process.ArgumentList.Add(canonical);
            } else if(OperatingSystem.IsMacOS()) {
                process.FileName="/usr/bin/open";if(!open)process.ArgumentList.Add("-R");process.ArgumentList.Add(canonical);
            } else {
                process.FileName="xdg-open";process.ArgumentList.Add(open?canonical:Path.GetDirectoryName(canonical)!);
            }
            using var started=Process.Start(process);
            return started==null?new(ActionStatus.Failed,"無法啟動檔案管理員。"):new(ActionStatus.Done,null);
        } catch(Exception e) { return new(ActionStatus.Failed,e.Message); }
    }
    internal static ActionResult? Validate(string path,string scanRoot,out string canonical) {
        canonical="";
        try {
            canonical=DiskPaths.Canonical(path);var root=DiskPaths.Canonical(scanRoot);
            if(!DiskPaths.Within(canonical,root)||DiskPaths.Equal(canonical,Path.GetPathRoot(canonical)!))
                return new(ActionStatus.OutsideRoot,"路徑必須位於掃描資料夾內，且不可為根目錄。");
            if(!Directory.Exists(DiskPaths.Native(root)))return new(ActionStatus.NotFound,"掃描資料夾不存在。");
            if(DiskPaths.CheckDirectory(canonical,root)!=NodeIssue.None)
                return new(ActionStatus.OutsideRoot,"無法操作連結或離線預留位置。");
            return null;
        } catch(Exception e) when(e is FileNotFoundException or DirectoryNotFoundException) { return new(ActionStatus.NotFound,"路徑不存在。"); }
        catch(Exception e) when(e is ArgumentException or NotSupportedException or PathTooLongException) { return new(ActionStatus.OutsideRoot,"無效路徑。"); }
        catch(Exception e) { return new(ActionStatus.Failed,e.Message); }
    }
}
