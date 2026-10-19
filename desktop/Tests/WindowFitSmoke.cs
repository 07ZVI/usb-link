#if USBLINK_DESIGN_TOOLS
using Avalonia;
using Avalonia.Controls;
using Avalonia.Threading;

namespace Suhang.Desktop;

public sealed partial class Dashboard
{
    // Design-tools smoke: every window stays inside a simulated small work area, and the dashboard needs no scrolling at
    // the logical work area of a 1920x1080 display at 175% (about 1097x590 DIPs after the taskbar).
    void VerifyWindowFit()
    {
        try
        {
            ResizeAndSettle(1097, 590); FitSettled();
            foreach (var (width, height) in new[] { (1097.0, 590.0), (1093.0, 580.0), (1000.0, 560.0) })
            {
                ResizeAndSettle(width, height); FitSettled();
                if (compactLayout != false || bodyScroll.Extent.Height > bodyScroll.Viewport.Height + 1)
                    throw new InvalidOperationException($"dashboard must not scroll vertically at {width}x{height} (compact={compactLayout}, extent={bodyScroll.Extent.Height}, viewport={bodyScroll.Viewport.Height}, left={leftDensity}, right={rightDensity})");
            }
            ResizeAndSettle(1040, 780); FitSettled();
            if (leftDensity != 0 || rightDensity != 0) throw new InvalidOperationException("a roomy window must keep the full layout");

            // 1366x768 at 125%, minus a 40 px taskbar, then a work area smaller than every minimum size.
            foreach (var (area, scaling) in new[] { (new PixelRect(0, 0, 1366, 728), 1.25), (new PixelRect(0, 0, 700, 420), 1.0) })
            {
                WindowFit.TestWorkArea = area; WindowFit.TestScaling = scaling;
                try
                {
                    var work = new Size(area.Width / scaling, area.Height / scaling);
                    OpenSecurity(); OpenSMBManager(); OpenDetails();
                    AppWindow.Confirm(this, "取消共享？", "資料夾與檔案會保留，之後可以再次添加。", "取消共享", () => { }, danger: true);
                    Pump(300);
                    var windows = OwnedWindows.ToArray();
                    if (windows.Length < 4) throw new InvalidOperationException("expected security, SMB, diagnostics and confirm windows, got " + windows.Length);
                    foreach (var window in windows) AssertWindowFits(window, work, area, scaling);
                    // A window dropped half off the screen's corner is brought back by the next re-check.
                    var task = windows.First(w => w.Title!.Contains("安全管理"));
                    task.Position = new PixelPoint(area.Right - 40, area.Bottom - 20); Pump(150);
                    WindowFit.Refit(task); Pump(150);
                    AssertWindowFits(task, work, area, scaling);
                    foreach (var window in windows) window.Close();
                    Pump(100);
                }
                finally { WindowFit.TestWorkArea = null; WindowFit.TestScaling = 1; }
            }
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine("window fit smoke failed: " + ex.Message);
            (Application.Current?.ApplicationLifetime as Avalonia.Controls.ApplicationLifetimes.IClassicDesktopStyleApplicationLifetime)?.Shutdown(1);
            throw;
        }
    }

    // The fit runs from the dispatcher after layout; settle it the way a real resize would.
    void FitSettled()
    {
        UpdateLayout(); UpdateResponsiveLayout(); Pump(60); FitBodyToViewport(); UpdateLayout();
    }

    static void Pump(int milliseconds)
    {
        var frame = new DispatcherFrame();
        DispatcherTimer.RunOnce(() => frame.Continue = false, TimeSpan.FromMilliseconds(milliseconds));
        Dispatcher.UIThread.PushFrame(frame);
    }

    static void AssertWindowFits(Window window, Size work, PixelRect area, double scaling)
    {
        var name = window.Title ?? "window";
        if (window.MinWidth > work.Width + .5 || window.MinHeight > work.Height + .5)
            throw new InvalidOperationException($"{name}: minimum size {window.MinWidth}x{window.MinHeight} exceeds the work area {work}");
        var frame = window.FrameSize ?? window.ClientSize;
        if (frame.Width * scaling > area.Width + 1 || frame.Height * scaling > area.Height + 1)
            throw new InvalidOperationException($"{name}: frame {frame} exceeds the work area {work}");
        var position = window.Position;
        if (position.X < area.X || position.Y < area.Y || position.X + frame.Width * scaling > area.Right + 1 || position.Y + frame.Height * scaling > area.Bottom + 1)
            throw new InvalidOperationException($"{name}: frame at {position} size {frame} leaves the work area {area}");
    }
}
#endif
