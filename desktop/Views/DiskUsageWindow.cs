using Avalonia;
using Avalonia.Controls;
using Avalonia.Media.Imaging;
using Avalonia.Styling;
using Avalonia.Threading;

namespace Suhang.Desktop;

public sealed partial class Dashboard
{
    PageHost? diskWindow;
    DiskUsageView? diskUsage;

    /// Opens the disk space analyzer, or brings the open one forward. It reads only folders the user picks here.
    void OpenDiskUsage()
    {
        if (diskWindow != null) { diskWindow.Activate(); return; }
        var window = diskWindow = NewPage("disk", "磁碟空間", 760, 580, keepAlive: true);
        string? autoRoot = null;
#if USBLINK_DESIGN_TOOLS
        // Previews scan a real folder: --disk-root=<path>, else the working directory.
        if (Program.OpenPreview == "disk")
            autoRoot = Environment.GetCommandLineArgs().FirstOrDefault(a => a.StartsWith("--disk-root=", StringComparison.Ordinal))?[12..] ?? Environment.CurrentDirectory;
#endif
        var view = diskUsage = new DiskUsageView(this, autoRoot);
        window.Content = view.View;
        window.Closed += (_, _) => { view.Dispose(); window.Content = null; diskUsage = null; diskWindow = null; };
        window.Show(this);
        view.Activate();
#if USBLINK_DESIGN_TOOLS
        if (Environment.GetCommandLineArgs().FirstOrDefault(a => a.StartsWith("--disk-shots=", StringComparison.Ordinal))?[13..] is { Length: > 0 } dir) _ = DiskShots(window, view, dir);
#endif
    }

#if USBLINK_DESIGN_TOOLS
    /// Design tools only: renders the window to PNGs (scanning, finished, filtered, dark) and exits.
    static async Task DiskShots(PageHost page, DiskUsageView view, string dir)
    {
        var window = page.Owner;
        Directory.CreateDirectory(dir);
        async Task Shot(string name, int wait)
        {
            await Task.Delay(wait);
            await Dispatcher.UIThread.InvokeAsync(() => {
                using var bitmap = new RenderTargetBitmap(new PixelSize((int)window.Bounds.Width, (int)window.Bounds.Height), new Vector(96, 96));
                bitmap.Render(window); bitmap.Save(System.IO.Path.Combine(dir, name + ".png"));
            });
        }
        await Shot("1-scanning", 450);
        await view.WaitScanAsync(TimeSpan.FromSeconds(60));
        await Shot("2-done", 1400);
        await Dispatcher.UIThread.InvokeAsync(() => { if (view.Map.Cells.Where(c => c.Node.Kind == DiskUsage.NodeKind.Directory).OrderByDescending(c => c.Node.Size).FirstOrDefault() is { } c) view.Map.Select(c.Node); });
        await Shot("3-selected", 600);
        await Dispatcher.UIThread.InvokeAsync(() => view.SetQuery(">5MB"));
        await Shot("4-filter", 900);
        await Dispatcher.UIThread.InvokeAsync(() => { Application.Current!.RequestedThemeVariant = ThemeVariant.Dark; });
        await Shot("5-dark", 900);
        await Dispatcher.UIThread.InvokeAsync(() => { view.SetQuery(""); if (view.ViewNode?.Children.FirstOrDefault(c => c.Kind == DiskUsage.NodeKind.Directory) is { } d) view.ZoomTo(d.FullPath); });
        await Shot("6-zoom", 1000);
        await Dispatcher.UIThread.InvokeAsync(() => { Application.Current!.RequestedThemeVariant = ThemeVariant.Light; view.GoTop(); view.SetMode(DiskUsageView.Mode.Sunburst); });
        await Shot("7-sunburst", 1200);
        await Dispatcher.UIThread.InvokeAsync(() => Application.Current!.RequestedThemeVariant = ThemeVariant.Dark);
        await Shot("8-sunburst-dark", 900);
        await Dispatcher.UIThread.InvokeAsync(() => { Application.Current!.RequestedThemeVariant = ThemeVariant.Light; view.SetMode(DiskUsageView.Mode.List); });
        await Shot("9-list", 900);
        await Dispatcher.UIThread.InvokeAsync(() => view.SetLargestFiles(true));
        await Shot("10-largest", 900);
        await Dispatcher.UIThread.InvokeAsync(() => { var home = new DiskUsageView(window); page.Content = home.View; home.Activate(); });
        await Shot("0-home", 1200);
        await Dispatcher.UIThread.InvokeAsync(() => Environment.Exit(0));
    }
#endif
}
