using System.Runtime.CompilerServices;
using Avalonia;
using Avalonia.Controls;
using Avalonia.Controls.ApplicationLifetimes;
using Avalonia.Platform;

namespace Suhang.Desktop;

/// Keeps every window inside the work area (screen minus taskbar) of the screen it is on.
/// Sizes are device-independent units; the screen reports physical pixels, so each screen's
/// scaling converts between them. Windows that do not fit shrink (and so do their minimum
/// sizes) instead of spilling off screen, and are re-checked when moved to another screen or
/// when its scaling changes.
internal static class WindowFit
{
    sealed class State
    {
        public double MinWidth, MinHeight;
        public bool Fixing, Opened, CustomChrome;
        public PixelRect LastArea; public double LastScaling;
    }

    static readonly ConditionalWeakTable<Window, State> States = new();

    /// What a decorated window adds around its client area when the real frame is not known yet
    /// (a Windows 11 title bar is about 32 DIPs, plus the resize borders).
    const double FallbackChromeWidth = 16, FallbackChromeHeight = 48, CustomChromeWidth = 16, CustomChromeHeight = 16;
    /// How much of a moved window must stay on screen for the title bar to remain reachable.
    const double ReachableWidth = 120, ReachableHeight = 40;

#if USBLINK_DESIGN_TOOLS
    /// Smoke tests simulate a small work area (physical pixels and scaling) without a real monitor.
    internal static PixelRect? TestWorkArea; internal static double TestScaling = 1;
#endif

    /// Pure arithmetic: the largest client size that keeps the whole frame inside `work`.
    internal static Size FitClient(Size requested, Size work, Size chrome) =>
        new(Math.Min(requested.Width, Math.Max(1, work.Width - chrome.Width)), Math.Min(requested.Height, Math.Max(1, work.Height - chrome.Height)));

    /// Pure arithmetic: shift `frame` (pixels) the least distance that puts it inside `area`;
    /// a frame larger than the area is aligned to the top-left corner.
    internal static PixelPoint ClampInto(PixelPoint position, PixelSize frame, PixelRect area)
    {
        var x = Math.Min(position.X, area.Right - frame.Width); x = Math.Max(x, area.X);
        var y = Math.Min(position.Y, area.Bottom - frame.Height); y = Math.Max(y, area.Y);
        return new PixelPoint(x, y);
    }

    static bool Reachable(PixelPoint position, PixelSize frame, PixelRect area, double scaling)
    {
        var grabW = (int)(ReachableWidth * scaling); var grabH = (int)(ReachableHeight * scaling);
        return position.X + frame.Width >= area.X + grabW && position.X <= area.Right - grabW
            && position.Y >= area.Y && position.Y <= area.Bottom - grabH;
    }

    static (PixelRect Area, double Scaling)? Resolve(Window window, Window? reference)
    {
#if USBLINK_DESIGN_TOOLS
        if (TestWorkArea is { } forced) return (forced, TestScaling);
#endif
        try
        {
            var screens = (reference ?? window).Screens;
            Screen? screen = null;
            if (reference is { IsVisible: true }) screen = screens.ScreenFromWindow(reference);
            if (screen == null && window.IsVisible) screen = screens.ScreenFromWindow(window);
            screen ??= screens.Primary ?? screens.All.FirstOrDefault();
            return screen == null ? null : (screen.WorkingArea, screen.Scaling > 0 ? screen.Scaling : 1);
        }
        catch (Exception) { return null; }
    }

    static Window? MainWindow => (Application.Current?.ApplicationLifetime as IClassicDesktopStyleApplicationLifetime)?.MainWindow;

    static Size Chrome(Window window, State state)
    {
        if (window.IsVisible && window.FrameSize is { } frame && window.ClientSize.Width > 0)
            return new Size(Math.Max(0, frame.Width - window.ClientSize.Width), Math.Max(0, frame.Height - window.ClientSize.Height));
        return state.CustomChrome ? new Size(CustomChromeWidth, CustomChromeHeight) : new Size(FallbackChromeWidth, FallbackChromeHeight);
    }

    /// Registers a window with its intended minimum size, clamps it for the screen it will open on
    /// and keeps it clamped for its lifetime. `customChrome` marks windows that draw their own title bar.
    public static void Attach(Window window, double minWidth, double minHeight, bool customChrome = false, bool placeOnOpen = true)
    {
        var state = States.GetOrCreateValue(window);
        state.MinWidth = minWidth; state.MinHeight = minHeight; state.CustomChrome = customChrome;
        Apply(window, state, opening: false, window.Owner as Window ?? MainWindow);
        if (placeOnOpen && window.WindowStartupLocation == WindowStartupLocation.Manual) PlaceInitially(window, state);
        window.Opened += (_, _) => { state.Opened = true; Apply(window, state, opening: true, window.Owner as Window); Remember(window, state); };
        window.ScalingChanged += (_, _) => { if (state.Opened) Apply(window, state, opening: true, null, keepCentre: true); Remember(window, state); };
        window.PositionChanged += (_, _) => { if (state.Opened) OnMoved(window, state); };
    }

    /// Re-checks a window that is shown again (for example from the tray) after displays changed.
    public static void Refit(Window window)
    {
        if (States.TryGetValue(window, out var state)) { Apply(window, state, opening: true, null, keepCentre: true); Remember(window, state); }
    }

    static void Remember(Window window, State state)
    {
        if (Resolve(window, null) is { } now) { state.LastArea = now.Area; state.LastScaling = now.Scaling; }
    }

    static void OnMoved(Window window, State state)
    {
        if (state.Fixing || Resolve(window, null) is not { } now) return;
        if (now.Area == state.LastArea && now.Scaling == state.LastScaling) return;
        Remember(window, state);
        Apply(window, state, opening: false, null);
    }

    /// Fits size and minimum size to the work area. With `opening` the window is also placed
    /// fully inside it (centred over its owner when it has one); otherwise it is only moved
    /// when its title bar would be out of reach, so dragging across screens is not fought.
    static void Apply(Window window, State state, bool opening, Window? reference, bool keepCentre = false)
    {
        if (state.Fixing) return;
        state.Fixing = true;
        try
        {
            if (Resolve(window, reference) is not { } screen) return;
            var (area, scaling) = screen;
            var work = new Size(area.Width / scaling, area.Height / scaling);
            var chrome = Chrome(window, state);
            var fit = FitClient(new Size(double.PositiveInfinity, double.PositiveInfinity), work, chrome);
            window.MinWidth = Math.Min(state.MinWidth, fit.Width); window.MinHeight = Math.Min(state.MinHeight, fit.Height);
            if (window.WindowState != WindowState.Normal) return;
            if (!double.IsNaN(window.Width)) window.Width = Math.Min(window.Width, fit.Width);
            if (!double.IsNaN(window.Height)) window.Height = Math.Min(window.Height, fit.Height);
            // A window that sizes to its content cannot be shrunk by value; cap it instead.
            if (window.SizeToContent.HasFlag(SizeToContent.Width)) window.MaxWidth = fit.Width;
            if (window.SizeToContent.HasFlag(SizeToContent.Height)) window.MaxHeight = fit.Height;
            if (!window.IsVisible) return;
            var client = window.ClientSize;
            // The window also grows to its (re-fitted) minimum size, so place it with the size it will end up with.
            var shrunk = new Size(Math.Max(Math.Min(client.Width, fit.Width), window.MinWidth), Math.Max(Math.Min(client.Height, fit.Height), window.MinHeight));
            if (shrunk.Width < client.Width && !double.IsNaN(window.Width)) window.Width = shrunk.Width;
            if (shrunk.Height < client.Height && !double.IsNaN(window.Height)) window.Height = shrunk.Height;
            var frameDips = new Size(shrunk.Width + chrome.Width, shrunk.Height + chrome.Height);
            if (window.FrameSize is { } real && shrunk == client) frameDips = real;
            var frame = new PixelSize((int)Math.Ceiling(frameDips.Width * scaling), (int)Math.Ceiling(frameDips.Height * scaling));
            var position = window.Position;
            if (opening && !keepCentre && window.Owner is Window { IsVisible: true, WindowState: not WindowState.Minimized } owner && owner.Screens.ScreenFromWindow(owner) != null)
            {
                var ownerScaling = owner.RenderScaling;
                var ownerFrame = owner.FrameSize ?? owner.ClientSize;
                position = new PixelPoint(
                    owner.Position.X + (int)((ownerFrame.Width * ownerScaling - frame.Width) / 2),
                    owner.Position.Y + (int)((ownerFrame.Height * ownerScaling - frame.Height) / 2));
                position = ClampInto(position, frame, area);
            }
            else if (opening) position = ClampInto(position, frame, area);
            else if (!Reachable(position, frame, area, scaling)) position = ClampInto(position, frame, area);
            if (position != window.Position) window.Position = position;
        }
        finally { state.Fixing = false; }
    }

    /// Before the first show: centre over the main window, or on the screen, inside the work area.
    static void PlaceInitially(Window window, State state)
    {
        var reference = MainWindow is { IsVisible: true, WindowState: not WindowState.Minimized } main && main != window ? main : null;
        if (Resolve(window, reference) is not { } screen) return;
        var (area, scaling) = screen;
        var chrome = Chrome(window, state);
        var width = double.IsNaN(window.Width) ? window.MinWidth : window.Width; var height = double.IsNaN(window.Height) ? window.MinHeight : window.Height;
        var frame = new PixelSize((int)Math.Ceiling((width + chrome.Width) * scaling), (int)Math.Ceiling((height + chrome.Height) * scaling));
        PixelPoint position;
        if (reference != null)
        {
            var ownerFrame = reference.FrameSize ?? reference.ClientSize; var s = reference.RenderScaling;
            position = new PixelPoint(reference.Position.X + (int)((ownerFrame.Width * s - frame.Width) / 2), reference.Position.Y + (int)((ownerFrame.Height * s - frame.Height) / 2));
        }
        else position = new PixelPoint(area.X + (area.Width - frame.Width) / 2, area.Y + (area.Height - frame.Height) / 2);
        window.Position = ClampInto(position, frame, area);
    }
}
