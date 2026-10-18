using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text;
using Avalonia;
using Avalonia.Automation;
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
            var dashboardTexts = this.GetVisualDescendants().OfType<TextBlock>().Select(t => t.Text).ToArray();
            Require(dashboardTexts.Contains("安全管理") && !dashboardTexts.Contains("工作管理員") && !dashboardTexts.Contains("退出程序"), "the dashboard has the security row but neither a task manager row nor an exit button");
            Require(this.GetVisualDescendants().OfType<Button>().All(b => (AutomationProperties.GetName(b) ?? "") is not ("工作管理員" or "退出程序")), "no dashboard button for the task manager or exit");
            ProgramIcons.Clear();
            var sampleIcon = TaskManagerView.PreviewIcon(0xFF000000, 0xFFFFFFFF);
            for (var i = 0; i < ProgramIcons.Capacity + 88; i++) ProgramIcons.Put($@"C:\lru\{i}.exe", sampleIcon);
            Require(ProgramIcons.CachedCount == ProgramIcons.Capacity && !ProgramIcons.TryGet(@"C:\lru\0.exe", out _) && ProgramIcons.TryGet($@"C:\lru\{ProgramIcons.Capacity + 87}.exe", out var recent) && recent != null, "icon cache is a bounded LRU");
            ProgramIcons.Clear();
            var missing = new ProgramIconView(@"C:\Missing\Nothing.exe"); var unnamed = new ProgramIconView("");
            await Task.Delay(100); await Avalonia.Threading.Dispatcher.UIThread.InvokeAsync(() => { }, Avalonia.Threading.DispatcherPriority.Background);
            Require(missing.IsGeneric && unnamed.IsGeneric && missing.Child is not Image, "programs without an icon keep the generic program icon");
            for (var attempt = 0; attempt < 3; attempt++) {
                OpenSecurity(); var tm = taskManager!; var window = securityWindow!;
                Require(securityTabs!.SelectedIndex == TasksTab && ((TabItem)securityTabs.Items[0]!).Header as string == "工作管理員", "the task manager is the first security tab");
                Require(tm.Inventory == null && !tm.IsSampling, "preview must not inspect host processes");
                Require(Enumerable.Range(0, 5).Select(i => ((TabItem)securityTabs.Items[i]!).Header as string).SequenceEqual(new[] { "工作管理員", "USB 網關", "全機手動規則", "目前連線", "USB 裝置" }), "tab order");
                Require(window.GetVisualDescendants().OfType<Button>().All(b => (AutomationProperties.GetName(b) ?? "") != "工作管理員"), "no separate task manager header button");
                Require(tm.Programs.Length == 9 && tm.List.ItemCount == 9, "all running fixtures shown");
                window.UpdateLayout();
                var icons = tm.List.GetVisualDescendants().OfType<ProgramIconView>().ToArray();
                Require(icons.Length == 9 && icons.Count(i => i.IsGeneric) == 7 && icons.Count(i => i.Child is Image) == 2, $"two cached shell icons and the generic fallback for the rest ({icons.Count(i => i.IsGeneric)} generic of {icons.Length})");
                var invalid = tm.Programs.Single(p => p.Trust.Status == "invalid");
                Require(invalid.Risk.StartsWith("可疑"), "tampered executable explanation");
                Require((invalid with { Trust = ProcessTrust.FromCode(0x800B0100) }).Risk.Contains("暫存"), "temporary unsigned executable explanation");
                Require(!tm.Programs.Single(p => p.Trust.Status == "unsigned").Risk.StartsWith("可疑"), "ordinary unsigned program must not claim maliciousness");
                Require(TaskManagerView.Filter(tm.Programs, "Microsoft", false, "trust", false).Length == 1, "publisher search");
                Require(TaskManagerView.Filter(tm.Programs, "7312", false, "trust", false).Single() == invalid, "PID search");
                Require(TaskManagerView.Filter(tm.Programs, "", true, "trust", false).Length == 4, "attention excludes valid and pending");
                Require(TaskManagerView.Filter(tm.Programs, "", false, "cpu", true)[0].Name == "Browser.exe", "CPU sorting");
                Require(TaskManagerView.Filter(tm.Programs, "", false, "memory", true)[0].Name == "Browser.exe", "memory sorting");
                Require(TaskManagerView.Filter(tm.Programs,"",false,"disk",true)[0].Name=="explorer.exe","disk sorting");
                Require(TaskManagerView.Filter(tm.Programs,"",false,"network",true)[0].Name=="Browser.exe","network sorting");
                tm.List.SelectedItem=tm.Programs.Single(p=>p.Name=="Registry");
                Require(tm.DetailReason.Text!.Contains("註冊表")&&tm.DetailText.Text!.Contains("父 PID 4"),"Registry evidence in the details panel");
                tm.Search.Text = "7312";
                await Avalonia.Threading.Dispatcher.UIThread.InvokeAsync(() => { }, Avalonia.Threading.DispatcherPriority.Background);
                Require(tm.List.ItemCount == 1, "live search updates table");
                tm.Search.Text = "no-such-program";
                await Avalonia.Threading.Dispatcher.UIThread.InvokeAsync(() => { }, Avalonia.Threading.DispatcherPriority.Background);
                Require(tm.List.ItemCount == 0 && tm.Empty.IsVisible, "empty search shows the empty state");
                tm.Search.Text = "";
                await Avalonia.Threading.Dispatcher.UIThread.InvokeAsync(() => { }, Avalonia.Threading.DispatcherPriority.Background);
                Require(tm.List.ItemCount == 9 && !tm.Empty.IsVisible, "clearing the search restores the list");
                tm.Attention.IsChecked = true; Require(tm.List.ItemCount == 4, "live attention filter");
                tm.Attention.IsChecked = false; tm.List.SelectedItem = invalid; tm.Render();
                Require(tm.List.SelectedItem is RunningProgram selected && selected.Pid == invalid.Pid && tm.DetailReason.Text!.Contains("可疑"), "refresh preserves selection and details");
                tm.List.SelectedItem = tm.Programs[0];
                Require(tm.DetailText.Text!.Contains("時間戳記") && tm.DetailPill.Label.Text!.Contains("簽章有效"), "expired leaf with accepted timestamp remains valid");
                tm.List.SelectedItem = invalid;
                if (attempt == 0) {
                    securityTabs.SelectedIndex = GatewayTab; window.UpdateLayout();
                    Require(securityCount.IsVisible && !tm.View.IsAttachedToVisualTree() && !tm.IsSampling, "the task view detaches and stops with its tab");
                    securityTabs.SelectedIndex = TasksTab; window.UpdateLayout();
                    Require(!securityCount.IsVisible && tm.View.IsAttachedToVisualTree() && tm.List.ItemCount == 9, "the task view returns with its rows");
                    window.UpdateLayout();
                    var red = window.GetVisualDescendants().OfType<TextBlock>().First(t => t.Text == "簽章無效");
                    Require(red.Foreground is SolidColorBrush b && b.Color == Color.Parse(Program.DarkPreview ? "#FF99A4" : "#C42B1C"), "visible invalid signature color");
                    CaptureProcessPreview(folder, "security-tasks-light.png");
                    window.RequestedThemeVariant = ThemeVariant.Dark;
                    await Avalonia.Threading.Dispatcher.UIThread.InvokeAsync(() => { }, Avalonia.Threading.DispatcherPriority.Background);
                    window.UpdateLayout();
                    CaptureProcessPreview(folder, "security-tasks-dark.png");
                    window.RequestedThemeVariant = ThemeVariant.Light;
                    window.Width = 900; window.Height = 640;
                    await Avalonia.Threading.Dispatcher.UIThread.InvokeAsync(() => { }, Avalonia.Threading.DispatcherPriority.Background);
                    window.UpdateLayout(); CaptureProcessPreview(folder, "security-tasks-compact.png");
                    Require(tm.Reverify.IsEffectivelyVisible && tm.Search.IsEffectivelyVisible, "compact table controls");
                    window.Width = window.MinWidth; window.Height = window.MinHeight;
                    tm.List.SelectedItem = invalid;
                    await Task.Delay(300);
                    await Avalonia.Threading.Dispatcher.UIThread.InvokeAsync(() => { }, Avalonia.Threading.DispatcherPriority.Background);
                    window.UpdateLayout(); CaptureProcessPreview(folder, "security-tasks-min.png");
                    Require(window.Bounds.Height <= window.MinHeight + 1, $"minimum window height applied ({window.Bounds.Height})");
                    var fullRows = tm.List.GetVisualDescendants().OfType<ListBoxItem>().Count(r => r.Bounds.Height > 0 && r.TranslatePoint(new Point(0, r.Bounds.Height), tm.List) is { } bottom && bottom.Y <= tm.List.Bounds.Height + 1);
                    Require(fullRows >= 8, $"table keeps at least 8 rows at the minimum window size (got {fullRows})");
                    Require(tm.DetailScroll.Bounds.Height <= tm.List.Bounds.Height, "detail panel must not outgrow the table");
                    var detailToggle = window.GetVisualDescendants().OfType<Button>().Single(b => (AutomationProperties.GetName(b) ?? "").StartsWith("顯示或隱藏"));
                    detailToggle.RaiseEvent(new Avalonia.Interactivity.RoutedEventArgs(Button.ClickEvent));
                    await Avalonia.Threading.Dispatcher.UIThread.InvokeAsync(() => { }, Avalonia.Threading.DispatcherPriority.Background);
                    window.UpdateLayout(); CaptureProcessPreview(folder, "security-tasks-min-details.png");
                    Require(tm.DetailText.IsEffectivelyVisible && tm.DetailScroll.Bounds.Height <= tm.DetailScroll.MaxHeight + 1 && tm.DetailScroll.MaxHeight <= tm.List.Bounds.Height, "expanded details scroll inside their share instead of squeezing the table");
                    detailToggle.RaiseEvent(new Avalonia.Interactivity.RoutedEventArgs(Button.ClickEvent));
                    window.Width = 1220; window.Height = 800;
                    var fixture = tm.Programs[0];
                    tm.Programs = Enumerable.Range(0, 1500).Select(i => fixture with { Pid = 10000 + i, Started = i, Name = "Program " + i }).ToArray();
                    tm.Render(); window.UpdateLayout();
                    Require(tm.List.ItemCount == 1500, "large process inventory not truncated");
                    Require(tm.List.GetVisualDescendants().OfType<ListBoxItem>().Count() < 100, "large process inventory virtualized");
                }
                window.Close(); Require(securityWindow == null && taskManager == null && !tm.IsSampling && tm.Inventory == null, "window lifecycle cleanup");
            }
            Console.WriteLine("PROCESS_UI_SMOKE_OK: classification, real worker pipe, sorting, search, attention, selection, themes, 1500 rows and lifecycle");
            (Application.Current?.ApplicationLifetime as IClassicDesktopStyleApplicationLifetime)?.Shutdown(0);
        } catch (Exception e) {
            Console.Error.WriteLine("PROCESS_UI_SMOKE_FAILED: " + e);
            (Application.Current?.ApplicationLifetime as IClassicDesktopStyleApplicationLifetime)?.Shutdown(1);
        }
    }
    void CaptureProcessPreview(string folder, string name) {
        var window = securityWindow!;
        using var bitmap = new RenderTargetBitmap(new PixelSize((int)window.Bounds.Width, (int)window.Bounds.Height), new Vector(96, 96));
        bitmap.Render(window); bitmap.Save(System.IO.Path.Combine(folder, name));
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
