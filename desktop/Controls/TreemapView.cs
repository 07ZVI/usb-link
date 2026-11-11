using System.Diagnostics;
using System.Globalization;
using Avalonia;
using Avalonia.Controls;
using Avalonia.Input;
using Avalonia.Media;
using Avalonia.Styling;
using Suhang.Desktop.DiskUsage;

namespace Suhang.Desktop;

/// Draws the disk treemap and owns its motion. Geometry comes from `TreemapLayout` (backend); cells are matched across
/// layouts by `TreemapCell.Key`, so zooming, scanning and deleting glide instead of jumping. Nothing here measures files.
internal sealed class TreemapView : Control
{
    sealed class Item
    {
        public TreemapCell Cell = null!;
        public Rect From, To, Current;
        public double Start, Appear = 1, Hover, Dim;
        public bool Gone;
        public FormattedText? Title, Detail, Right;
        public bool Big;
    }

    public event Action<DiskNode?>? SelectionChanged;
    public event Action<DiskNode>? Opened;
    public event Action<DiskNode, Point>? MenuRequested;
    public event Action<DiskNode?, Point>? HoverChanged;

    /// False in smoke tests and previews that screenshot: cells jump straight to their place.
    internal static bool Animated = true;
    const double Glide = 520, Fade = 320;
    static readonly double Clock0 = Stopwatch.GetTimestamp();
    static double Now() => (Stopwatch.GetTimestamp() - Clock0) * 1000d / Stopwatch.Frequency;

    DiskNode? root;
    LayoutOptions options = new();
    Dictionary<string, Item> items = new();
    readonly List<Item> order = new(), ghosts = new();
    Item? hover;
    bool frameQueued, byAge, themeReady;
    string? selectedKey;
    Size laidOut;

    /// Cells for which this returns true are dimmed (filter misses). Null: nothing is dimmed.
    public Func<DiskNode, bool>? Dimmed { get => dimmed; set { dimmed = value; RequestFrame(); } }
    Func<DiskNode, bool>? dimmed;
    /// Paths of folders being read right now; their outline pulses.
    public IReadOnlySet<string> Scanning { get => scanning; set { scanning = value; RequestFrame(); } }
    IReadOnlySet<string> scanning = new HashSet<string>();
    public bool ColorByAge { get => byAge; set { byAge = value; RequestFrame(); } }
    public DiskNode? Root => root;
    public DiskNode? Selected { get; private set; }
    internal int CellCount => order.Count;
    internal IReadOnlyList<TreemapCell> Cells => order.Select(i => i.Cell).ToArray();

    // Theme colors, resolved once per theme.
    Color mapBg, surface, stroke, strokeStrong, ink, muted, accent, ageNew, ageOld;
    readonly Color[] category = new Color[10];
    readonly Dictionary<Color, IBrush> gradients = new();
    IBrush hatchLight = Brushes.Transparent, hatchFree = Brushes.Transparent;
    Typeface regular, semibold;

    public TreemapView()
    {
        ClipToBounds = true; Focusable = true; Cursor = new Cursor(StandardCursorType.Arrow);
        ActualThemeVariantChanged += (_, _) => { themeReady = false; Relayout(false); };
    }

    // ---------- model ----------

    public void SetView(DiskNode? view, LayoutOptions layout, bool animate = true)
    {
        root = view; options = layout; Relayout(animate && Animated);
    }
    public void Select(DiskNode? node)
    {
        selectedKey = node is null ? null : node.Kind switch { NodeKind.Aggregate or NodeKind.FreeSpace => null, _ => node.FullPath };
        Selected = selectedKey is null ? null : node;
        RequestFrame(); SelectionChanged?.Invoke(Selected);
    }

    protected override void OnPropertyChanged(AvaloniaPropertyChangedEventArgs change)
    {
        base.OnPropertyChanged(change);
        if (change.Property == BoundsProperty && Bounds.Size != laidOut) Relayout(Animated && laidOut.Width > 0);
    }

    void ResolveTheme()
    {
        if (themeReady) return;
        Color C(string key) => this.TryFindResource(key, ActualThemeVariant, out var v) && v is SolidColorBrush b ? b.Color : Colors.Magenta;
        (mapBg, surface, stroke, strokeStrong, ink, muted, accent, ageNew, ageOld) =
            (C("MapBg"), C("Surface"), C("Stroke"), C("StrokeStrong"), C("Ink"), C("Muted"), C("Accent"), C("AgeNew"), C("AgeOld"));
        for (var i = 0; i < category.Length; i++) category[i] = C("Cat" + (FileCategory)i);
        gradients.Clear();
        hatchLight = Hatch(A(ink, .065)); hatchFree = Hatch(A(ink, .07));
        var family = new FontFamily(Palette.FontStack);
        regular = new Typeface(family); semibold = new Typeface(family, FontStyle.Normal, FontWeight.SemiBold);
        themeReady = true;
    }

    internal static Color Mix(Color a, Color b, double t) => Color.FromArgb(
        (byte)Math.Round(a.A + (b.A - a.A) * t), (byte)Math.Round(a.R + (b.R - a.R) * t),
        (byte)Math.Round(a.G + (b.G - a.G) * t), (byte)Math.Round(a.B + (b.B - a.B) * t));
    internal static Color A(Color c, double alpha) => Color.FromArgb((byte)Math.Round(255 * alpha), c.R, c.G, c.B);
    /// `top` at `amount` over opaque `under`.
    internal static Color Over(Color top, Color under, double amount) => Color.FromRgb(
        (byte)Math.Round(under.R + (top.R - under.R) * amount), (byte)Math.Round(under.G + (top.G - under.G) * amount), (byte)Math.Round(under.B + (top.B - under.B) * amount));

    internal static IBrush Hatch(Color line)
    {
        var drawing = new GeometryDrawing { Pen = new Pen(new SolidColorBrush(line), 1), Geometry = Geometry.Parse("M0,8 L8,0 M-1,1 L1,-1 M7,9 L9,7") };
        return new DrawingBrush(drawing) { TileMode = TileMode.Tile, Stretch = Stretch.None,
            SourceRect = new RelativeRect(0, 0, 8, 8, RelativeUnit.Absolute), DestinationRect = new RelativeRect(0, 0, 8, 8, RelativeUnit.Absolute) };
    }

    IBrush Gradient(Color c)
    {
        if (!gradients.TryGetValue(c, out var brush))
            gradients[c] = brush = new LinearGradientBrush {
                StartPoint = new RelativePoint(0, 0, RelativeUnit.Relative), EndPoint = new RelativePoint(1, 1, RelativeUnit.Relative),
                GradientStops = { new GradientStop(Over(Colors.White, c, .05), 0), new GradientStop(Over(Colors.Black, c, .08), 1) } };
        return brush;
    }

    Color CategoryColor(DiskNode n) => category[(int)n.Category];
    Color AgeColor(DiskNode n) => Mix(ageNew, ageOld, Math.Clamp((DateTime.UtcNow - n.LastWriteUtc).TotalDays / 540, 0, 1));

    // ---------- layout and motion ----------

    void Relayout(bool animate)
    {
        laidOut = Bounds.Size;
        if (root is null || Bounds.Width < 16 || Bounds.Height < 16)
        {
            order.Clear(); items.Clear(); ghosts.Clear(); hover = null; InvalidateVisual(); return;
        }
        ResolveTheme();
        var cells = TreemapLayout.Build(root, new RectD(0, 0, Bounds.Width, Bounds.Height), options);
        var now = Now(); var next = new Dictionary<string, Item>(cells.Count);
        order.Clear();
        foreach (var cell in cells)
        {
            var to = new Rect(cell.Bounds.X, cell.Bounds.Y, cell.Bounds.Width, cell.Bounds.Height);
            if (!items.Remove(cell.Key, out var item))
            {
                var from = animate ? to.Deflate(Math.Min(to.Width, to.Height) * .03) : to;
                item = new Item { From = from, Current = from, Appear = animate ? 0 : 1 };
            }
            else { item.From = item.Current; }
            item.Cell = cell; item.To = to; item.Start = animate ? now : now - Glide * 2;
            BuildLabels(item); next[cell.Key] = item; order.Add(item);
        }
        ghosts.RemoveAll(g => now - g.Start > Fade);
        if (animate) foreach (var old in items.Values) { old.Gone = true; old.Start = now; old.To = old.From = old.Current; ghosts.Add(old); }
        items = next;
        if (hover != null && !items.ContainsValue(hover)) hover = null;
        if (!animate) foreach (var i in order) i.Current = i.To;
        RequestFrame();
    }

    void BuildLabels(Item item)
    {
        item.Title = item.Detail = item.Right = null; item.Big = false;
        var cell = item.Cell; var n = cell.Node; var w = item.To.Width - 2; var h = item.To.Height - 2;
        FormattedText Text(string text, double size, Typeface face, Color color, double width) =>
            new(text, CultureInfo.CurrentUICulture, FlowDirection.LeftToRight, face, size, new SolidColorBrush(color))
            { MaxTextWidth = Math.Max(1, width), MaxLineCount = 1, Trimming = TextTrimming.CharacterEllipsis };
        var name = DiskText.Name(n);
        if (cell.HasHeader)
        {
            item.Right = Text(DiskText.Size(n.Size), 11, regular, muted, 90);
            item.Title = Text(name, 12, semibold, ink, w - 28 - item.Right.Width);
        }
        else if (w >= 62 && h >= 32)
        {
            var onFill = n.Kind is NodeKind.File or NodeKind.Directory;
            var fill = onFill ? FillColor(n) : surface;
            // Light fills (honey, sand) take espresso text; deeper ones take white, so every tile stays legible.
            var dark = onFill && Luma(fill) > .6;
            var main = !onFill ? muted : dark ? Color.FromRgb(0x2B, 0x21, 0x16) : Colors.White;
            var soft = !onFill ? muted : A(main, dark ? .68 : .82);
            var size = DiskText.Size(n.Size);
            var pct = n.Kind != NodeKind.FreeSpace && root is { Size: > 0 } ? DiskText.Percent(n.Size, root.Size) : "";
            if (w >= 120 && h >= 84)
            {
                // A big tile reads like a storage card: the size as its number, the name and share under it,
                // anchored to the bottom-left corner so the label never floats in an empty block.
                item.Big = true;
                item.Detail = Text(size, Math.Clamp(Math.Min(w / 7, h / 4), 15, 26), semibold, main, w - 20);
                item.Title = Text(pct == "" ? name : name + "  ·  " + pct, 12, regular, soft, w - 20);
            }
            else
            {
                item.Title = Text(name, 12, semibold, main, w - 14);
                item.Detail = Text(size + (h >= 62 && pct != "" ? " · " + pct : ""), 11, regular, soft, w - 14);
            }
        }
    }

    static double Luma(Color c) => (.299 * c.R + .587 * c.G + .114 * c.B) / 255;
    Color FillColor(DiskNode n)
    {
        var c = byAge ? AgeColor(n) : CategoryColor(n);
        return n.Kind == NodeKind.Directory ? Over(c, surface, .72) : c;
    }

    void RequestFrame()
    {
        if (frameQueued || TopLevel.GetTopLevel(this) is not { } top) { if (!frameQueued) InvalidateVisual(); return; }
        frameQueued = true; top.RequestAnimationFrame(_ => Frame());
    }

    void Frame()
    {
        frameQueued = false; var now = Now(); var busy = scanning.Count > 0;
        foreach (var i in order)
        {
            var t = Math.Clamp((now - i.Start) / Glide, 0, 1); var e = 1 - Math.Pow(1 - t, 4);
            i.Current = new Rect(i.From.X + (i.To.X - i.From.X) * e, i.From.Y + (i.To.Y - i.From.Y) * e,
                i.From.Width + (i.To.Width - i.From.Width) * e, i.From.Height + (i.To.Height - i.From.Height) * e);
            if (i.Appear < 1) i.Appear = Math.Min(1, i.Appear + .075 + (1 - i.Appear) * .1);
            var hoverTarget = ReferenceEquals(i, hover) ? 1 : 0; i.Hover += (hoverTarget - i.Hover) * .35;
            var dimTarget = dimmed is { } f && Dimmable(i) && f(i.Cell.Node) ? 1 : 0; i.Dim += (dimTarget - i.Dim) * .22;
            if (t < 1 || i.Appear < 1 || Math.Abs(hoverTarget - i.Hover) > .01 || Math.Abs(dimTarget - i.Dim) > .01) busy = true;
            else { i.Hover = hoverTarget; i.Dim = dimTarget; }
        }
        for (var g = ghosts.Count - 1; g >= 0; g--)
        {
            var t = (now - ghosts[g].Start) / Fade;
            if (t >= 1) ghosts.RemoveAt(g); else { ghosts[g].Appear = 1 - t; busy = true; }
        }
        InvalidateVisual();
        if (busy) RequestFrame();
    }
    static bool Dimmable(Item i) => !(i.Cell.HasHeader || i.Cell.Node.Kind == NodeKind.FreeSpace);

    // ---------- drawing ----------

    public override void Render(DrawingContext context)
    {
        ResolveTheme();
        context.DrawRectangle(new SolidColorBrush(mapBg), null, new Rect(Bounds.Size));
        foreach (var g in ghosts) Draw(context, g);
        foreach (var i in order) Draw(context, i);
    }

    void Draw(DrawingContext cx, Item item)
    {
        var rect = item.Current.Deflate(1);
        if (rect.Width < 2 || rect.Height < 2) return;
        var opacity = item.Appear * (1 - item.Dim * .84);
        if (opacity < .01) return;
        var node = item.Cell.Node; var radius = Math.Min(8, Math.Min(rect.Width, rect.Height) / 3);
        if (node.Kind == NodeKind.Directory && !item.Cell.IsLeaf && !item.Cell.HasHeader) return; // folder drawn as its only child
        var rounded = new RoundedRect(rect, radius);
        using var _ = cx.PushOpacity(opacity);
        var isSelected = selectedKey != null && node.FullPath == selectedKey;
        var pulse = scanning.Count > 0 && item.Cell.HasHeader && scanning.Contains(node.FullPath) ? .5 + .5 * Math.Sin(Now() / 260) : 0;

        switch (node.Kind)
        {
            case NodeKind.FreeSpace:
                cx.DrawRectangle(new SolidColorBrush(surface), new Pen(new SolidColorBrush(strokeStrong), 1), rect, radius, radius);
                cx.DrawRectangle(hatchFree, null, rect.Deflate(1), radius, radius);
                break;
            case NodeKind.Aggregate:
                cx.DrawRectangle(new SolidColorBrush(Over(CategoryColor(node), surface, .14)), new Pen(new SolidColorBrush(stroke), 1), rect, radius, radius);
                cx.DrawRectangle(hatchLight, null, rect.Deflate(1), radius, radius);
                break;
            default:
                var c = byAge ? AgeColor(node) : CategoryColor(node);
                if (item.Cell.HasHeader)
                {
                    var tint = byAge ? Over(ink, surface, .06) : Over(c, surface, .15);
                    var rim = byAge ? strokeStrong : A(c, .38);
                    cx.DrawRectangle(new SolidColorBrush(tint), new Pen(new SolidColorBrush(rim), 1), rect, radius, radius);
                    cx.DrawRectangle(new SolidColorBrush(c), null, new Rect(rect.X + 8, rect.Y + 7, 8, 8), 3, 3);
                }
                else
                {
                    var fill = FillColor(node);
                    cx.DrawRectangle(byAge ? new SolidColorBrush(fill) : Gradient(fill), null, rect, radius, radius);
                }
                break;
        }

        if (item.Hover > .01)
        {
            if (!item.Cell.HasHeader && node.Kind != NodeKind.FreeSpace) cx.DrawRectangle(new SolidColorBrush(A(Colors.White, .15 * item.Hover)), null, rect, radius, radius);
            cx.DrawRectangle(null, new Pen(new SolidColorBrush(A(accent, item.Hover)), 2), rect.Deflate(1), radius, radius);
        }
        if (pulse > 0) cx.DrawRectangle(null, new Pen(new SolidColorBrush(A(accent, .25 + .6 * pulse)), 1.5), rect, radius, radius);
        if (isSelected) cx.DrawRectangle(null, new Pen(new SolidColorBrush(accent), 2), rect.Deflate(1), radius, radius);

        if (item.Title is { } title && !item.Gone)
        {
            if (item.Big && item.Detail is { } number)
            {
                var pad = 10;
                var nameY = rect.Bottom - pad - title.Height;
                cx.DrawText(number, new Point(rect.X + pad, nameY - number.Height + 1));
                cx.DrawText(title, new Point(rect.X + pad, nameY));
                return;
            }
            var origin = item.Cell.HasHeader ? new Point(rect.X + 22, rect.Y + 3) : new Point(rect.X + 7, rect.Y + 6);
            if (item.Cell.HasHeader || rect.Width >= 56 && rect.Height >= 28) cx.DrawText(title, origin);
            if (item.Detail is { } detail && !item.Cell.HasHeader) cx.DrawText(detail, new Point(rect.X + 7, rect.Y + 6 + 16));
            if (item.Right is { } right) cx.DrawText(right, new Point(rect.Right - 8 - right.Width, rect.Y + 4));
        }
    }

    // ---------- pointer ----------

    Item? Hit(Point p)
    {
        for (var i = order.Count - 1; i >= 0; i--) if (order[i].Current.Contains(p)) return order[i];
        return null;
    }

    protected override void OnPointerMoved(PointerEventArgs e)
    {
        base.OnPointerMoved(e);
        var p = e.GetPosition(this); var hit = Hit(p);
        if (!ReferenceEquals(hit, hover)) { hover = hit; RequestFrame(); }
        HoverChanged?.Invoke(hit?.Cell.Node, p);
        Cursor = hit is { Cell.Node.Kind: NodeKind.Directory } ? new Cursor(StandardCursorType.Hand) : new Cursor(StandardCursorType.Arrow);
    }

    protected override void OnPointerExited(PointerEventArgs e)
    {
        base.OnPointerExited(e);
        if (hover != null) { hover = null; RequestFrame(); }
        HoverChanged?.Invoke(null, default);
    }

    protected override void OnPointerPressed(PointerPressedEventArgs e)
    {
        base.OnPointerPressed(e);
        Focus();
        var point = e.GetCurrentPoint(this); var hit = Hit(point.Position)?.Cell.Node;
        if (point.Properties.IsRightButtonPressed)
        {
            if (hit is { Kind: NodeKind.File or NodeKind.Directory }) { Select(hit); MenuRequested?.Invoke(hit, point.Position); }
            e.Handled = true; return;
        }
        if (!point.Properties.IsLeftButtonPressed) return;
        if (e.ClickCount >= 2 && hit is { Kind: NodeKind.Directory }) { Opened?.Invoke(hit); e.Handled = true; return; }
        Select(hit);
    }

}

/// Shared number and name formatting for the disk views (1 KB = 1024 B, as in the task manager).
internal static class DiskText
{
    internal static string Size(long bytes) => bytes switch {
        >= 1L << 30 => (bytes / 1073741824d).ToString(bytes >= 10L << 30 ? "0.0" : "0.00", CultureInfo.InvariantCulture) + " GB",
        >= 1L << 20 => (bytes / 1048576d).ToString(bytes >= 100L << 20 ? "0" : "0.0", CultureInfo.InvariantCulture) + " MB",
        >= 1L << 10 => Math.Round(bytes / 1024d).ToString(CultureInfo.InvariantCulture) + " KB",
        _ => bytes.ToString(CultureInfo.InvariantCulture) + " B" };
    internal static string Percent(long part, long whole) => whole <= 0 ? "—" : part * 100d / whole is var p && p < .1 ? "<0.1%" : p.ToString(p < 10 ? "0.0" : "0", CultureInfo.InvariantCulture) + "%";
    internal static string Count(long n) => n.ToString("N0", CultureInfo.InvariantCulture);
    internal static string Name(DiskNode n) => n.Kind switch {
        NodeKind.Aggregate => Count(n.FileCount) + " 個小項目", NodeKind.FreeSpace => "可用空間", _ => n.Name };
    internal static string Ago(DateTime utc)
    {
        var days = (DateTime.UtcNow - utc).TotalDays;
        return utc == default ? "—" : days < 1 ? "今天" : days < 30 ? Math.Round(days) + " 天前" : days < 365 ? Math.Round(days / 30) + " 個月前" : (days / 365).ToString("0.0", CultureInfo.InvariantCulture) + " 年前";
    }
    internal static string Category(FileCategory c) => FileCategories.Label(c);
}
