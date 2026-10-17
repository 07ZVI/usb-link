using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

namespace Suhang.Desktop;

internal sealed record ProcessShape(int Pid, int ParentPid, int Threads, int? Session, string Name);
internal sealed record ProcessAssessment(string Label, string Tone, string Reason, bool Attention, int Priority, bool SignatureApplicable = true);

internal static class ProcessIdentity
{
    internal static ProcessAssessment Assess(RunningProgram p)
    {
        if (p.Trust.Status is "invalid" or "revoked") return new("簽章異常，需核對", "Error", p.Risk, true, 0);
        if (p.Pid == 0 && p.Path == "")
            return new("Windows 閒置計量", "Muted", "PID 0 是 CPU 閒置時間的系統計量項目，沒有一般 EXE；不適用檔案簽章。", false, 5, false);
        if (p.Pid == 4 && p.Name == "System" && p.Path == "" && p.Shape is { Name: "System" })
            return new("Windows 核心進程", "Ok", "Windows 快照確認為 System、PID 4，代表核心與驅動程式執行緒；沒有一般使用者模式 EXE。這不等於已檢查所有驅動或排除核心遭入侵。", false, 5, false);
        if (p.Path == "" && p.Name == "Registry" && p.Shape is { Name: "Registry", ParentPid: 4, Threads: 0, Session: 0 })
            return new("符合 Registry 核心特徵", "Muted", "Registry 承載 Windows 註冊表 hive 資料。已核對系統快照名稱、父 PID 4、工作階段 0、零執行緒及無一般 EXE 路徑；符合特殊核心物件特徵，不因缺少 EXE 簽章而視為可疑。這是結構判斷，不是安全保證。", false, 5, false);
        var name = p.Name;
        if (new[]{"System.exe","Registry.exe"}.Contains(name, StringComparer.OrdinalIgnoreCase) ||
            (name.Equals("Registry",StringComparison.OrdinalIgnoreCase) && p.Path != ""))
            return new("需核對系統同名程式", "Warn", "這是可執行檔，不能套用 System / Registry 特殊核心物件規則。名稱可能被仿冒；請核對完整路徑、已驗證簽署者與安裝來源。" + p.Trust.Reason, true, 1);
        if (p.Trust.Status is "expired" or "untrusted") return new("憑證需核對", "Error", p.Risk, true, 1);
        if (p.Trust.Status == "valid") {
            return new(p.Trust.VerifiedMicrosoft ? "Microsoft 簽章已驗證" : "簽署者已驗證", "Ok",
                "已驗證磁碟檔案的內嵌或目錄簽章與簽署者；不代表已驗證執行中的記憶體、外掛或程式行為。", false, 5);
        }
        if (p.Trust.Status == "unsigned" && ProcessInventory.IsTemporaryPath(p.Path))
            return new("暫存程式，需核對來源", "Warn", p.Risk, true, 2);
        if (p.Trust.WindowsProtected == true)
            return new("Windows 保護檔案，待驗證", "Warn", "Windows Resource Protection 將此路徑列為系統保護檔案，是 Windows 來源線索；這個 API 不驗證目前檔案內容，不能取代有效簽章或完整性檢查。" + p.Trust.Reason, true, 3);
        if (name is "Registry" or "Memory Compression" or "Secure System")
            return new("可能為核心物件，未確認", "Muted", name == "Registry"
                ? "Registry 通常承載註冊表資料；目前未取得完整的父進程、工作階段、執行緒或路徑依據，因此保留未確認。僅名稱相同不足以信任。"
                : "此名稱可出現在 Windows 特殊核心或隔離環境；本次沒有足夠的系統身分資料，不能僅靠名稱判定安全。", true, 3);
        return new(p.Trust.Status == "pending" ? "來源驗證中" : "來源尚未確認", p.Trust.Tone,
            p.Trust.Reason + (p.Path.Length > 0 ? " 名稱、所在資料夾或公司欄位都不足以證明 Windows 來源。" : ""), p.Trust.Attention, p.Trust.Priority);
    }
}

// Toolhelp provides parent/thread/name evidence independently of executable access.
internal static class ProcessShapes
{
    internal static Dictionary<int, ProcessShape> Read()
    {
        var result = new Dictionary<int,ProcessShape>();
        using var snapshot = CreateToolhelp32Snapshot(2, 0);
        if (snapshot.IsInvalid) return result;
        var entry = new Entry { Size = (uint)Marshal.SizeOf<Entry>(), Name = "" };
        if (!Process32First(snapshot,ref entry)) return result;
        do {
            int? session = ProcessIdToSessionId(entry.Pid,out var value) ? (int)value : null;
            result[(int)entry.Pid] = new((int)entry.Pid,(int)entry.Parent,(int)entry.Threads,session,entry.Name);
        } while(Process32Next(snapshot,ref entry));
        return result;
    }
    [StructLayout(LayoutKind.Sequential,CharSet=CharSet.Unicode)] internal struct Entry {
        internal uint Size, Usage, Pid;
        internal nuint Heap;
        internal uint Module, Threads, Parent;
        internal int Priority;
        internal uint Flags;
        [MarshalAs(UnmanagedType.ByValTStr,SizeConst=260)] internal string Name;
    }
    [DllImport("kernel32.dll"),DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    static extern SafeFileHandle CreateToolhelp32Snapshot(uint flags,uint pid);
    [DllImport("kernel32.dll",EntryPoint="Process32FirstW",CharSet=CharSet.Unicode),DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    [return:MarshalAs(UnmanagedType.Bool)] static extern bool Process32First(SafeFileHandle snapshot,ref Entry entry);
    [DllImport("kernel32.dll",EntryPoint="Process32NextW",CharSet=CharSet.Unicode),DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    [return:MarshalAs(UnmanagedType.Bool)] static extern bool Process32Next(SafeFileHandle snapshot,ref Entry entry);
    [DllImport("kernel32.dll"),DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    [return:MarshalAs(UnmanagedType.Bool)] static extern bool ProcessIdToSessionId(uint pid,out uint session);
}
