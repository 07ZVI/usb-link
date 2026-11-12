namespace Suhang.Desktop.DiskUsage;

internal static class DriveCatalog
{
    internal static IReadOnlyList<DriveSpace> List() {
        var result=new List<DriveSpace>();
        try {
            foreach(var drive in DriveInfo.GetDrives()) {
                try {
                    var ready=drive.IsReady;
                    result.Add(new(drive.Name,ready?drive.VolumeLabel:"",ready?drive.DriveFormat:"",
                        ready?drive.TotalSize:0,ready?drive.TotalFreeSpace:0,
                        drive.DriveType==DriveType.Removable,drive.DriveType==DriveType.Network,ready));
                } catch { /* A disconnected or inaccessible volume is not a scan failure. */ }
            }
        } catch { }
        return result;
    }

    internal static DriveSpace? Find(string path,IReadOnlyList<DriveSpace>? drives=null) => (drives??List()).Where(d=>DiskPaths.Within(path,d.Name,true))
        .OrderByDescending(d=>d.Name.Length).FirstOrDefault();
}
