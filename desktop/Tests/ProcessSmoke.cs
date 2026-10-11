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
                Require(runningPrograms.Length == 7 && processList.ItemCount == 7, "all running fixtures shown");
                var invalid = runningPrograms.Single(p => p.Trust.Status == "invalid");
                Require(invalid.Risk.StartsWith("可疑"), "tampered executable explanation");
                Require((invalid with { Trust = ProcessTrust.FromCode(0x800B0100) }).Risk.Contains("暫存"), "temporary unsigned executable explanation");
                Require(!runningPrograms.Single(p => p.Trust.Status == "unsigned").Risk.StartsWith("可疑"), "ordinary unsigned program must not claim maliciousness");
                Require(FilterProcesses(runningPrograms, "Microsoft", false, "trust", false).Length == 1, "publisher search");
                Require(FilterProcesses(runningPrograms, "7312", false, "trust", false).Single() == invalid, "PID search");
                Require(FilterProcesses(runningPrograms, "", true, "trust", false).Length == 4, "attention excludes valid and pending");
                Require(FilterProcesses(runningPrograms, "", false, "cpu", true)[0].Name == "Browser.exe", "CPU sorting");
                Require(FilterProcesses(runningPrograms, "", false, "memory", true)[0].Name == "Browser.exe", "memory sorting");
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
            var initial = inventory.Capture(); Thread.Sleep(150); var rows = inventory.Capture();
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
