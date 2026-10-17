using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text;
using Avalonia;
using Avalonia.Controls;
using Avalonia.Controls.ApplicationLifetimes;
using Avalonia.Media;
using Avalonia.Media.Imaging;
using Avalonia.Styling;
using Avalonia.VisualTree;

namespace Suhang.Desktop;

public sealed partial class Dashboard
{
    async void RunProcessSmoke()
    {
        try {
            void Require(bool condition, string message) { if (!condition) throw new InvalidOperationException(message); }
            if (Program.StandaloneTasks) {
                Require(taskWindow?.IsVisible == true && !IsVisible, $"standalone visibility: task={taskWindow?.IsVisible}, dashboard={IsVisible}");
                taskWindow!.Close(); Require(taskWindow == null && processTimer == null && processInventory == null, "standalone close must release task window");
                Console.WriteLine("PROCESS_STANDALONE_SMOKE_OK");
                (Application.Current?.ApplicationLifetime as IClassicDesktopStyleApplicationLifetime)?.Shutdown(0);
                return;
            }
            foreach (var (code, status) in new[] {
                (0u,"valid"),(0x800B0100u,"unsigned"),(0x80096010u,"invalid"),(0x800B010Cu,"revoked"),
                (0x800B0101u,"expired"),(0x800B0109u,"untrusted"),(0x800B0111u,"untrusted"),
                (0x80092013u,"unverified"),(0x800B010Eu,"unverified"),(0xDEADBEEFu,"unverified")
            }) {
                var trust = ProcessTrust.FromCode(code); Require(trust.Status == status, "trust code classification");
                Require(trust.Status == "valid" || !trust.Reason.Contains("驗證通過"), "unknown trust must not claim validity");
                if (status is "invalid" or "revoked" or "expired" or "untrusted") Require(trust.Tone == "Error", "invalid certificate must be red");
            }
            Require(NativeProcessSignature.LocalDriveRoot(@"C:\Windows\app.exe")==@"C:\" && NativeProcessSignature.LocalDriveRoot(@"\\?\C:\app.exe")==@"C:\" && NativeProcessSignature.LocalDriveRoot(@"\\?\UNC\host\app.exe")==null && NativeProcessSignature.LocalDriveRoot(@"\\?\GLOBALROOT\Device\app.exe")==null && NativeProcessSignature.LocalDriveRoot(@"\\host\app.exe")==null, "local path namespaces");
            Require(NativeProcessSignature.IsMicrosoftOrganization(new System.Security.Cryptography.X509Certificates.X500DistinguishedName("CN=Microsoft Windows, O=Microsoft Corporation")),"Microsoft organization RDN");
            Require(!NativeProcessSignature.IsMicrosoftOrganization(new System.Security.Cryptography.X509Certificates.X500DistinguishedName("CN=Microsoft Windows, O=Other Company")),"publisher name alone is insufficient");
            Require(!NativeProcessSignature.IsMicrosoftOrganization(new System.Security.Cryptography.X509Certificates.X500DistinguishedName("CN=\"x,O=Microsoft Corporation\", O=Other Company")),"CN text cannot impersonate the organization RDN");
            Require(ProcessRate.Format(1048576)=="1.0 MB/s" && ProcessRate.Format(1024)=="1.0 KB/s" && ProcessRate.Format(0)=="0.0 KB/s", "rate unit boundary");
            Require(ProcessRate.Format(null)=="—" && ProcessRate.Format(double.NaN)=="—" && ProcessRate.Format(-1)=="—", "unknown rates must not become zero");
            var sample = new RunningProgram(800,10,"test.exe","","",null,null,new("unverified"));
            var ledger = new ProcessIoLedger();
            Require(ledger.Sample([sample],0,true,false)[0].DiskRead==null,"first interval is unknown");
            ledger.Add(800,1,read:1048576,receive:1024,send:2048);
            var measured = ledger.Sample([sample],Stopwatch.Frequency,true,false)[0];
            Require(measured.DiskRead==1048576 && measured.Network==3072,"independent disk and TCP/UDP direction counters");
            ledger.Add(800,1,read:1024); // Delivery can lag behind the previous sampling boundary.
            Require(ledger.Sample([sample],2*Stopwatch.Frequency,true,false)[0].DiskRead==1024,"late delivery within the same process lifetime must not be dropped");
            var reused = sample with {Started=11};
            Require(ledger.Sample([reused],3*Stopwatch.Frequency,true,false)[0].DiskRead==null,"PID reuse needs a new baseline");
            ledger.Add(800,Stopwatch.Frequency,read:4096);
            Require(ledger.Sample([reused],4*Stopwatch.Frequency,true,false)[0].DiskRead==0,"late event from an earlier PID lifetime must be rejected");
            ledger.Add(800,5*Stopwatch.Frequency,read:8192);
            Require(ledger.Sample([reused],5*Stopwatch.Frequency,true,true)[0].DiskRead==null,"lost events invalidate the interval");
            Require(ledger.Sample([reused],6*Stopwatch.Frequency,false,false)[0].DiskRead==null,"unavailable ETW must never report zero");
            var registry=sample with {Pid=120,Name="Registry",Shape=new(120,4,0,0,"Registry")};
            Require(!registry.Assessment.Attention && registry.SignatureLabel=="不適用（核心物件）" && registry.Assessment.Reason.Contains("註冊表"),"minimal registry process explanation");
            Require((registry with {Shape=null}).Assessment.Attention && (registry with {Shape=new(120,99,0,0,"Registry")}).Assessment.Attention,"name alone or wrong parent cannot establish a kernel object");
            Require((registry with {Path=@"C:\Temp\Registry.exe",Name="Registry.exe"}).Assessment.Attention,"executable cannot impersonate the Registry object");
            Require((sample with {Pid=4,Name="System",Shape=new(4,0,100,0,"System")}).Assessment.Label=="Windows 核心進程","reserved System PID identity");
            Require((sample with {Name="System",Shape=new(800,0,100,0,"System")}).Assessment.Attention,"System name with another PID is insufficient");
            Require((sample with {Trust=new("unsigned",WindowsProtected:true,ClaimedCompany:"Microsoft Corporation")}).Assessment.Attention,"WRP and version company cannot override missing signatures");
            Require((sample with {Trust=new("invalid",WindowsProtected:true)}).Assessment.Tone=="Error","protection metadata cannot override tampering");
            Require(Marshal.SizeOf<ProcessShapes.Entry>()==(IntPtr.Size==8?568:556),"Toolhelp ABI");
            Require(ProcessInventory.CpuPercent(10000000, 0, Stopwatch.Frequency, 4) == 25, "CPU normalization");
            Require(ProcessInventory.CpuPercent(1, 2, Stopwatch.Frequency, 4) == null, "counter reset must not display negative CPU");
            Require(ProcessInventory.CpuPercent(100000000, 0, 0, 4) == null, "initial CPU sample");
            Require(ProcessInventory.Clean("Example\n\u202e") == "Example", "process publisher spoofing controls");
            Require((NativeProcessSignature.TrustFlags & 0x1000) != 0 && (NativeProcessSignature.TrustFlags & 0x800) == 0,
                "local-only verification must retain timestamp semantics");
            Require(Marshal.SizeOf<NativeProcessSignature.TrustData>() == (IntPtr.Size == 8 ? 88 : 52), "WinTrust ABI");
            using (var stream = new MemoryStream(Encoding.UTF8.GetBytes(new string('x', 64))))
            using (var reader = new StreamReader(stream)) {
                try { await ProcessSignatureWorker.ReadLineAsync(reader, 32, CancellationToken.None); throw new InvalidOperationException("unbounded worker output"); }
                catch (InvalidDataException) { }
            }
            using (var worker = new ProcessSignatureWorker()) {
                var result = await worker.CheckAsync(@"C:\Windows\Example.exe", "fixture", CancellationToken.None);
                if (!OperatingSystem.IsWindows()) Require(result.Status == "unverified" && result.Reason.Contains("Windows"), "real child pipe on non-Windows");
            }
            var folder = Environment.GetEnvironmentVariable("USB_LINK_PROCESS_EVIDENCE") ?? System.IO.Path.Combine(System.IO.Path.GetTempPath(), "usb-link-process-preview");
            Directory.CreateDirectory(folder);
            for (var attempt = 0; attempt < 3; attempt++) {
                OpenTaskManager(); Require(processInventory == null, "preview must not inspect host processes");
                Require(runningPrograms.Length == 9 && processList.ItemCount == 9, "all running fixtures shown");
                var invalid = runningPrograms.Single(p => p.Trust.Status == "invalid");
                Require(invalid.Risk.StartsWith("可疑"), "tampered executable explanation");
                Require((invalid with { Trust = ProcessTrust.FromCode(0x800B0100) }).Risk.Contains("暫存"), "temporary unsigned executable explanation");
                Require(!runningPrograms.Single(p => p.Trust.Status == "unsigned").Risk.StartsWith("可疑"), "ordinary unsigned program must not claim maliciousness");
                Require(FilterProcesses(runningPrograms, "Microsoft", false, "trust", false).Length == 1, "publisher search");
                Require(FilterProcesses(runningPrograms, "7312", false, "trust", false).Single() == invalid, "PID search");
                Require(FilterProcesses(runningPrograms, "", true, "trust", false).Length == 4, "attention excludes valid and pending");
                Require(FilterProcesses(runningPrograms, "", false, "cpu", true)[0].Name == "Browser.exe", "CPU sorting");
                Require(FilterProcesses(runningPrograms, "", false, "memory", true)[0].Name == "Browser.exe", "memory sorting");
                Require(FilterProcesses(runningPrograms,"",false,"disk",true)[0].Name=="explorer.exe","disk sorting");
                Require(FilterProcesses(runningPrograms,"",false,"network",true)[0].Name=="Browser.exe","network sorting");
                processList.SelectedItem=runningPrograms.Single(p=>p.Name=="Registry");
                Require(processDetailReason.Text!.Contains("註冊表")&&processDetailText.Text!.Contains("父 PID 4"),"Registry evidence in the details panel");
                processSearch.Text = "7312";
                await Avalonia.Threading.Dispatcher.UIThread.InvokeAsync(() => { }, Avalonia.Threading.DispatcherPriority.Background);
                Require(processList.ItemCount == 1, "live search updates table");
                processSearch.Text = "";
                await Avalonia.Threading.Dispatcher.UIThread.InvokeAsync(() => { }, Avalonia.Threading.DispatcherPriority.Background);
                processAttention.IsChecked = true; Require(processList.ItemCount == 4, "live attention filter");
                processAttention.IsChecked = false; processList.SelectedItem = invalid; RenderProcesses();
                Require(processList.SelectedItem is RunningProgram selected && selected.Pid == invalid.Pid && processDetailReason.Text!.Contains("可疑"), "refresh preserves selection and details");
                processList.SelectedItem = runningPrograms[0];
                Require(processDetailText.Text!.Contains("時間戳記") && processDetailTitle.Text!.Contains("簽章有效"), "expired leaf with accepted timestamp remains valid");
                processList.SelectedItem = invalid;
                if (attempt == 0) {
                    taskWindow!.UpdateLayout();
                    var red = taskWindow.GetVisualDescendants().OfType<TextBlock>().First(t => t.Text == "簽章無效");
                    Require(red.Foreground is SolidColorBrush b && b.Color == Color.Parse("#C42B1C"), "visible invalid signature color");
                    CaptureProcessPreview(folder, "task-manager-light.png");
                    taskWindow.RequestedThemeVariant = ThemeVariant.Dark;
                    await Avalonia.Threading.Dispatcher.UIThread.InvokeAsync(() => { }, Avalonia.Threading.DispatcherPriority.Background);
                    taskWindow.UpdateLayout();
                    CaptureProcessPreview(folder, "task-manager-dark.png");
                    taskWindow.RequestedThemeVariant = ThemeVariant.Light;
                    taskWindow.Width = 840; taskWindow.Height = 600;
                    await Avalonia.Threading.Dispatcher.UIThread.InvokeAsync(() => { }, Avalonia.Threading.DispatcherPriority.Background);
                    taskWindow.UpdateLayout(); CaptureProcessPreview(folder, "task-manager-compact.png");
                    Require(processRefresh.IsEffectivelyVisible && processSearch.IsEffectivelyVisible, "compact table controls");
                    taskWindow.Width = 1220; taskWindow.Height = 800;
                    var fixture = runningPrograms[0];
                    runningPrograms = Enumerable.Range(0, 1500).Select(i => fixture with { Pid = 10000 + i, Started = i, Name = "Program " + i }).ToArray();
                    RenderProcesses(); taskWindow.UpdateLayout();
                    Require(processList.ItemCount == 1500, "large process inventory not truncated");
                    Require(processList.GetVisualDescendants().OfType<ListBoxItem>().Count() < 100, "large process inventory virtualized");
                }
                taskWindow!.Close(); Require(taskWindow == null && processTimer == null && processInventory == null, "window lifecycle cleanup");
            }
            Console.WriteLine("PROCESS_UI_SMOKE_OK: classification, real worker pipe, sorting, search, attention, selection, themes, 1500 rows and lifecycle");
            (Application.Current?.ApplicationLifetime as IClassicDesktopStyleApplicationLifetime)?.Shutdown(0);
        } catch (Exception e) {
            Console.Error.WriteLine("PROCESS_UI_SMOKE_FAILED: " + e);
            (Application.Current?.ApplicationLifetime as IClassicDesktopStyleApplicationLifetime)?.Shutdown(1);
        }
    }
    void CaptureProcessPreview(string folder, string name) {
        using var bitmap = new RenderTargetBitmap(new PixelSize((int)taskWindow!.Bounds.Width, (int)taskWindow.Bounds.Height), new Vector(96, 96));
        bitmap.Render(taskWindow); bitmap.Save(System.IO.Path.Combine(folder, name));
    }
}

// Read-only Windows acceptance probe.
// It deliberately fails when signature/ABI/catalog validation cannot be established.
internal static class ProcessNativeSmoke
{
    internal static int Run() {
        if (!OperatingSystem.IsWindows()) { Console.Error.WriteLine("PROCESS_NATIVE_SMOKE_REQUIRES_WINDOWS"); return 2; }
        try {
            using var inventory = new ProcessInventory();
            RunningProgram[]? census = null;
            var initial = inventory.Capture(rows => census = rows);
            if (census == null || census.Length != initial.Length || census.Any(p => p.Identity != "" || p.Path.Length > 0 && p.Trust.Status != "pending"))
                throw new InvalidOperationException("initial process list must precede file verification");
            Thread.Sleep(150); var rows = inventory.Capture();
            var self = rows.Single(p => p.Pid == Environment.ProcessId);
            if (initial.Length == 0 || self.Path.Length == 0 || self.Started == 0 || self.Memory == null || self.Cpu == null)
                throw new InvalidOperationException("minimum-rights process inventory");
            var system = System.IO.Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), "kernel32.dll");
            using (var file = new FileStream(system, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete)) {
                var result = NativeProcessSignature.Inspect(system, ProcessInventory.FileIdentity(file, system));
                if (result.Status != "valid" || result.Publisher.Length == 0 || result.Hash.Length != 64)
                    throw new InvalidOperationException("Windows system signature: " + result.Status + " " + result.Code + " " + result.Reason);
                Console.WriteLine("PROCESS_NATIVE_SYSTEM_SIGNATURE_OK: " + result.Source);
            }
            using (var worker = new ProcessSignatureWorker()) {
                var trust = worker.CheckAsync(self.Path, self.Identity, CancellationToken.None).GetAwaiter().GetResult();
                if (trust.Hash.Length != 64 || trust.Status == "pending") throw new InvalidOperationException("native child verifier");
            }
            Console.WriteLine("PROCESS_NATIVE_SMOKE_OK: process inventory, CPU, memory, native trust and child pipe"); return 0;
        } catch (Exception e) { Console.Error.WriteLine("PROCESS_NATIVE_SMOKE_FAILED: " + e.Message); return 1; }
    }
}
