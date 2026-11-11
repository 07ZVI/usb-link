using Avalonia.Controls;
using Avalonia.Threading;

namespace Suhang.Desktop;

public sealed partial class Dashboard
{
    // Design tools only (--maximized, --open=name): reproduce window placement for screenshots.
    void PreviewWindowArgs()
    {
#if USBLINK_DESIGN_TOOLS
        if (Program.MaximizedPreview) WindowState = WindowState.Maximized;
        Action? open = Program.OpenPreview switch
        {
            "security" => () => OpenSecurity(GatewayTab),
            "tasks" => () => OpenSecurity(TasksTab),
            "smb" => OpenSMBManager,
            "disk" => OpenDiskUsage,
            "details" => OpenDetails,
            "dialog" => () => AppWindow.Confirm(this, "取消共享？", "資料夾與檔案會保留，之後可以再次添加。", "取消共享", () => { }, danger: true),
            _ => null,
        };
        if (open != null) Dispatcher.UIThread.Post(open, DispatcherPriority.Background);
        // --shot=<dir>: after 2.5 s render every open window to <dir>/<n>.png and exit.
        if (Environment.GetCommandLineArgs().FirstOrDefault(a => a.StartsWith("--shot=", StringComparison.Ordinal))?[7..] is { Length: > 0 } dir)
            DispatcherTimer.RunOnce(() => {
                System.IO.Directory.CreateDirectory(dir);
                var windows = ((Avalonia.Controls.ApplicationLifetimes.IClassicDesktopStyleApplicationLifetime)Avalonia.Application.Current!.ApplicationLifetime!).Windows;
                for (var i = 0; i < windows.Count; i++)
                {
                    var w = windows[i];
                    using var bitmap = new Avalonia.Media.Imaging.RenderTargetBitmap(new Avalonia.PixelSize((int)w.Bounds.Width, (int)w.Bounds.Height), new Avalonia.Vector(96, 96));
                    bitmap.Render(w); bitmap.Save(System.IO.Path.Combine(dir, i + ".png"));
                }
                Environment.Exit(0);
            }, TimeSpan.FromMilliseconds(2500));
#endif
    }
}
