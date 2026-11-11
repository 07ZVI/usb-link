using Avalonia;
using Avalonia.Animation;
using Avalonia.Controls;
using Avalonia.Input;
using Avalonia.Layout;
using Avalonia.Media;
using Avalonia.Platform.Storage;
using Avalonia.Styling;

namespace Suhang.Desktop;

/// One tool page inside the dashboard window (Mole-style: one window, a centered pill switcher on top, each tool its own
/// tinted page). It keeps the members the tools used on their former windows — Title, Content, Activate, Close, Closed —
/// so opening and tearing down a tool works as before; dialogs it owns belong to the dashboard window.
internal sealed class PageHost : ThemeVariantScope
{
    readonly Dashboard shell;
    public string Key { get; }
    public string Title { get; }
    /// Kept (hidden) when another page is shown instead of being closed: the disk scan survives a look at other pages.
    public bool KeepAlive { get; init; }
    /// The window's minimum client size while this page is shown (the tool windows' former minimums plus the switcher).
    public Size MinimumSize { get; init; }
    public event EventHandler? Closed;

    internal PageHost(Dashboard shell, string key, string name) { this.shell = shell; Key = key; Title = "USB Link · " + name; }

    public Control? Content { get => Child; set => Child = value; }
    public Window Owner => shell;
    public IReadOnlyList<Window> OwnedWindows => shell.OwnedWindows;
    public IStorageProvider StorageProvider => shell.StorageProvider;
    public void Activate() => shell.ShowPage(this);
    public void Show(Window _) => shell.ShowPage(this);
    public void Close() => shell.ClosePage(this);
    internal void RaiseClosed() => Closed?.Invoke(this, EventArgs.Empty);

    public static implicit operator Window?(PageHost? page) => page?.shell;
}

public sealed partial class Dashboard
{
    /// The switcher's pages in order: key, label and the window tint token while it is shown.
    static readonly (string Key, string Label, string Tint)[] Pages =
        [("home", "總覽", "PageHome"), ("share", "共享", "PageShare"), ("security", "安全", "PageSecurity"), ("disk", "磁碟", "PageDisk"), ("details", "設定", "PageDetails")];
    readonly Grid pages = new();
    readonly List<PageHost> hosted = new();
    PageHost? current;
    readonly Dictionary<string, (Border Pill, TextBlock Text)> navItems = new();
    Control overviewPage = null!;

    internal PageHost NewPage(string key, string name, double minWidth, double minHeight, bool keepAlive = false) =>
        new(this, key, name) { KeepAlive = keepAlive, MinimumSize = new Size(minWidth, minHeight) };
    static readonly Size OverviewMinimum = new(520, 420);

    void ApplyMinimum(Size size)
    {
        WindowFit.SetMinimum(this, size.Width, size.Height);
    }

    internal void ShowPage(PageHost page)
    {
        if (ReferenceEquals(current, page)) { Activate(); return; }
        Leave();
        if (!hosted.Contains(page)) { hosted.Add(page); pages.Children.Add(page); }
        page.IsVisible = true; overviewPage.IsVisible = false; current = page;
        SelectNav(page.Key); ApplyMinimum(new Size(Math.Max(OverviewMinimum.Width, page.MinimumSize.Width), Math.Max(OverviewMinimum.Height, page.MinimumSize.Height)));
        if (!IsVisible) Show();
        // A new window used to lay itself out on Show; a page must be laid out before callers look into it.
        UpdateLayout();
        Activate();
    }

    internal void ShowOverview() { Leave(); overviewPage.IsVisible = true; SelectNav("home"); ApplyMinimum(OverviewMinimum); }

    internal void ClosePage(PageHost page)
    {
        if (!hosted.Remove(page)) return;
        pages.Children.Remove(page); page.IsVisible = false;
        if (ReferenceEquals(current, page)) { current = null; overviewPage.IsVisible = true; SelectNav("home"); ApplyMinimum(OverviewMinimum); }
        page.RaiseClosed();
    }

    /// Closes every tool page (tray hide, program exit): the same teardown the tool windows had.
    void CloseAllPages() { foreach (var page in hosted.ToArray()) ClosePage(page); }

    void Leave()
    {
        if (current is not { } page) return;
        current = null;
        if (page.KeepAlive) page.IsVisible = false; else ClosePage(page);
    }

    void Navigate(string key)
    {
        switch (key)
        {
            case "share": OpenSMBManager(); break;
            case "security": OpenSecurity(); break;
            case "disk": OpenDiskUsage(); break;
            case "details": OpenDetails(); break;
            default: ShowOverview(); break;
        }
    }

    void SelectNav(string key)
    {
        foreach (var (k, (pill, text)) in navItems)
        {
            var on = k == key;
            if (on) pill.Res(Border.BackgroundProperty, "PrimaryFill"); else pill.Background = Brushes.Transparent;
            text.Res(TextBlock.ForegroundProperty, on ? "PrimaryInk" : "Muted");
            text.FontWeight = on ? FontWeight.SemiBold : FontWeight.Normal;
        }
        ApplySky();
    }

    bool skyHooked;
    /// The window's sky: a soft diagonal from paper to gold (light) or espresso to amber (dark), behind every page.
    void ApplySky()
    {
        if (!skyHooked) { skyHooked = true; ActualThemeVariantChanged += (_, _) => ApplySky(); }
        Color C(string key) => this.TryFindResource(key, ActualThemeVariant, out var v) && v is SolidColorBrush b ? b.Color : Colors.Gray;
        Background = new LinearGradientBrush {
            StartPoint = new RelativePoint(0, 0, RelativeUnit.Relative), EndPoint = new RelativePoint(1, 1, RelativeUnit.Relative),
            GradientStops = { new GradientStop(C("BgFrom"), 0), new GradientStop(C("BgFrom"), .35), new GradientStop(C("BgTo"), 1) } };
    }

    /// The centered pill switcher (Mole's top bar), sized like a large segmented control: 28-pt segments, 2-pt inset,
    /// a 32-pt capsule around them.
    Control NavBar()
    {
        var row = new StackPanel { Orientation = Orientation.Horizontal, Spacing = Scale.Hair };
        foreach (var (key, label, _) in Pages)
        {
            var text = Label(label, Scale.Body, key: "Muted");
            text.HorizontalAlignment = HorizontalAlignment.Center;
            text.VerticalAlignment = VerticalAlignment.Center;
            var pill = new Border { Child = text, Height = 28, Padding = new Thickness(14, 0), CornerRadius = new CornerRadius(14), MinWidth = 60, Cursor = new Cursor(StandardCursorType.Hand), Background = Brushes.Transparent };
            pill.Transitions = [new BrushTransition { Property = Border.BackgroundProperty, Duration = TimeSpan.FromMilliseconds(180) }];
            Avalonia.Automation.AutomationProperties.SetName(pill, label);
            var k = key;
            pill.PointerEntered += (_, _) => { if (navItems[k].Text.FontWeight != FontWeight.SemiBold) pill.Res(Border.BackgroundProperty, "IdleSoft"); };
            pill.PointerExited += (_, _) => { if (navItems[k].Text.FontWeight != FontWeight.SemiBold) pill.Background = Brushes.Transparent; };
            pill.PointerPressed += (_, e) => { if (e.GetCurrentPoint(pill).Properties.IsLeftButtonPressed) { Navigate(k); e.Handled = true; } };
            navItems[key] = (pill, text); row.Children.Add(pill);
        }
        var bar = new Border { Child = row, Padding = new Thickness(Scale.Hair), CornerRadius = new CornerRadius(16), BorderThickness = new Thickness(1), HorizontalAlignment = HorizontalAlignment.Center, VerticalAlignment = VerticalAlignment.Center }
            .Res(Border.BackgroundProperty, "Card");
        return bar;
    }
}
