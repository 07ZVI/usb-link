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
    public static bool Preview;
    public static bool SecurityPreview;
    public static bool SecuritySmoke;
    public static bool SMBWireSmoke;
    public static bool SMBRetryWireSmoke;
    public static bool ConnectionSmoke;
    public static bool SecurityWireSmoke;
    public static bool ProcessPreview;
    public static bool ProcessSmoke;
    public static bool StandaloneTasks;
    // Same renderer and controls; opt-in isolates IPC/lifetime memory effects.
    public static readonly bool BoundedIpc = Environment.GetEnvironmentVariable("SUHANG_DESKTOP_BOUNDED_IPC") == "1";
    [STAThread]
    public static void Main(string[] args)
    {
        if (args.Contains("--process-signature-worker")) { Environment.ExitCode = ProcessSignatureWorker.Run(); return; }
        if (args.Contains("--process-native-smoke")) { Environment.ExitCode = ProcessNativeSmoke.Run(); return; }
        Preview = args.Contains("--preview");
        ProcessPreview = Preview && args.Contains("--process-preview");
        ProcessSmoke = Preview && args.Contains("--process-smoke");
        StandaloneTasks = args.Contains("--task-manager");
        SecurityPreview = Preview && args.Contains("--security-preview");
        SecuritySmoke = Preview && args.Contains("--security-smoke");
        SMBRetryWireSmoke = !Preview && args.Contains("--smb-retry-wire-smoke");
        SMBWireSmoke = !Preview && (args.Contains("--smb-wire-smoke") || SMBRetryWireSmoke);
        ConnectionSmoke = Preview && args.Contains("--connection-smoke");
        SecurityWireSmoke = !Preview && args.Contains("--security-wire-smoke");
        LaunchTelemetry.Mark("renderer-main");
        AppBuilder.Configure<App>().UsePlatformDetect().StartWithClassicDesktopLifetime(args);
    }
}
