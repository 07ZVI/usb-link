using System.Text.Json;
using Avalonia;
using Avalonia.Controls;
using Avalonia.Controls.ApplicationLifetimes;
using Avalonia.Controls.Shapes;
using Avalonia.Input;
using Avalonia.Layout;
using Avalonia.Media;
using Avalonia.Styling;
using Avalonia.Themes.Fluent;
using Avalonia.Threading;
using Path = Avalonia.Controls.Shapes.Path;

namespace Suhang.Desktop;

internal static class Program
{
    public static bool Preview = false;
    public static bool SecurityPreview = false;
    public static bool SecuritySmoke = false;
    public static bool SMBWireSmoke = false;
    public static bool SMBRetryWireSmoke = false;
    public static bool ConnectionSmoke = false;
    public static bool SecurityWireSmoke = false;
    public static bool ProcessPreview = false;
    public static bool ProcessSmoke = false;
    public static bool StandaloneTasks;
    // Same renderer and controls; opt-in isolates IPC/lifetime memory effects.
    public static readonly bool BoundedIpc = Environment.GetEnvironmentVariable("SUHANG_DESKTOP_BOUNDED_IPC") == "1";
    [STAThread]
    public static void Main(string[] args)
    {
        if (args.Contains("--process-signature-worker")) { Environment.ExitCode = ProcessSignatureWorker.Run(); return; }
#if USBLINK_DESIGN_TOOLS
        if (args.Contains("--process-native-smoke")) { Environment.ExitCode = ProcessNativeSmoke.Run(); return; }
        Preview = args.Contains("--preview");
        ProcessPreview = Preview && args.Contains("--process-preview");
        ProcessSmoke = Preview && args.Contains("--process-smoke");
        SecurityPreview = Preview && args.Contains("--security-preview");
        SecuritySmoke = Preview && args.Contains("--security-smoke");
        SMBRetryWireSmoke = !Preview && args.Contains("--smb-retry-wire-smoke");
        SMBWireSmoke = !Preview && (args.Contains("--smb-wire-smoke") || SMBRetryWireSmoke);
        ConnectionSmoke = Preview && args.Contains("--connection-smoke");
        SecurityWireSmoke = !Preview && args.Contains("--security-wire-smoke");
#else
        if (args.Any(arg => arg.Contains("preview", StringComparison.Ordinal) || arg.Contains("smoke", StringComparison.Ordinal))) return;
#endif
        StandaloneTasks = args.Contains("--task-manager");
        LaunchTelemetry.Mark("renderer-main");
        AppBuilder.Configure<App>().UsePlatformDetect().StartWithClassicDesktopLifetime(args);
    }
}
