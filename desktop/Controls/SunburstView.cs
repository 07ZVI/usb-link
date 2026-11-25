using System.Globalization;
using Avalonia;
using Avalonia.Controls;
using Avalonia.Input;
using Avalonia.Media;
using Suhang.Desktop.DiskUsage;
using static Suhang.Desktop.TreemapView;

namespace Suhang.Desktop;

/// Rings around the current folder (DaisyDisk-style): each ring is one level deeper, each slice's angle is its share of
/// its parent. Geometry comes from `SunburstLayout`; slices are matched by key across layouts, so zooming in makes the
/// chosen folder's children sweep inward to fill the first ring. The center disc names the hovered item, or the folder.
internal sealed class SunburstView : Control
{
    sealed class Item
    {
        public SunburstCell Cell = null!;
        public Arc From, To, Current;
        public double Start, Appear = 1, Hover, Dim;
        public bool Gone;
        public FormattedText? Title, Detail;
        public double LabelAt = .5; // where along the slice (0..1 of its sweep) the label sits
    }
    record struct Arc(double Start, double Sweep, double Inner, double Outer)
    {
        public static Arc Lerp(Arc a, Arc b, double t) => new(a.Start + (b.Start - a.Start) * t, a.Sweep + (b.Sweep - a.Sweep) * t, a.Inner + (b.Inner - a.Inner) * t, a.Outer + (b.Outer - a.Outer) * t);
    }

    public event Action<DiskNode?>? SelectionChanged;
    public event Action<DiskNode>? Opened;
    public event Action<DiskNode, Point>? MenuRequested;
    public event Action<DiskNode?, Point>? HoverChanged;
    /// Raised after the rings are rebuilt, so the side list can pick up the new branch colours.
    public event Action? LaidOut;

    const double Glide = 560, Fade = 300, HoleShare = .27, Gap = 1.4;
    DiskNode? root;
    int depth = 5; double minSweep = .003;
    Dictionary<string, Item> items = new();
    readonly List<Item> order = new(), ghosts = new();
    Item? hover; bool centerHover;
    bool frameQueued, byAge, themeReady;
    string? selectedKey;
    Size laidOut;
    Point center; double radius, hole, ring;

    public Func<DiskNode, bool>? Dimmed { get => dimmed; set { dimmed = value; RequestFrame(); } }
    Func<DiskNode, bool>? dimmed;
    public IReadOnlySet<string> Scanning { get => scanning; set { scanning = value; RequestFrame(); } }
    IReadOnlySet<string> scanning = new HashSet<string>();
    public bool ColorByAge { get => byAge; set { byAge = value; RequestFrame(); } }
    /// Paths waiting in the 待清理 collector: drawn struck through with a red hatch until removed or recycled.
    public IReadOnlySet<string> Marked { get => marked; set { marked = value; RequestFrame(); } }
    IReadOnlySet<string> marked = new HashSet<string>();
    Color error; IBrush hatchMarked = Brushes.Transparent;
    bool IsMarked(DiskNode n) { if (marked.Count == 0) return false; for (var x = n; x != null; x = x.Parent) if (marked.Contains(x.FullPath)) return true; return false; }
    /// Lights the slice for `node` as if hovered, so the inspector's list can point into the rings.
    public void Highlight(DiskNode? node) { hover = node == null ? null : order.FirstOrDefault(i => i.Cell.Node.FullPath == node.FullPath && i.Cell.Node.Kind == node.Kind); RequestFrame(); }

    public DiskNode? Selected { get; private set; }
    internal int CellCount => order.Count;
    internal IReadOnlyList<SunburstCell> Cells => order.Select(i => i.Cell).ToArray();

    Color mapBg, surface, stroke, strokeStrong, ink, muted, subtle, accent, ageNew, ageOld;
    readonly Color[] category = new Color[10];
    IBrush hatch = Brushes.Transparent;
    Typeface regular, semibold;

    public SunburstView()
    {
        ClipToBounds = true; Focusable = true;
        ActualThemeVariantChanged += (_, _) => { themeReady = false; Relayout(false); };
    }

    public void SetView(DiskNode? view, int rings, double minimumSweep, bool animate = true)
    {
        root = view; depth = Math.Max(1, rings); minSweep = minimumSweep; Relayout(animate && Animated);
    }
    public void Select(DiskNode? node)
    {
        selectedKey = node is { Kind: NodeKind.File or NodeKind.Directory } ? node.FullPath : null;
        Selected = selectedKey is null ? null : node;
        RequestFrame(); SelectionChanged?.Invoke(Selected);
    }

    protected override void OnPropertyChanged(AvaloniaPropertyChangedEventArgs change)
    {
        base.OnPropertyChanged(change);
        if (change.Property == BoundsProperty && Bounds.Size != laidOut) Relayout(Animated && laidOut.Width < 40);
        else if (change.Property == IsVisibleProperty && IsVisible) RequestFrame();
    }

    void ResolveTheme()
    {
        if (themeReady) return;
        Color C(string key) => this.TryFindResource(key, ActualThemeVariant, out var v) && v is SolidColorBrush b ? b.Color : Colors.Magenta;
        (mapBg, surface, stroke, strokeStrong, ink, muted, subtle, accent, ageNew, ageOld) =
            (C("MapBg"), C("Surface"), C("Stroke"), C("StrokeStrong"), C("Ink"), C("Muted"), C("Subtle"), C("Accent"), C("AgeNew"), C("AgeOld"));
        for (var i = 0; i < category.Length; i++) category[i] = C("Cat" + (FileCategory)i);
        hatch = Hatch(A(ink, .09));
        error = C("Error"); hatchMarked = Hatch(A(error, .6));
        var family = new FontFamily(Palette.FontStack);
        regular = new Typeface(family); semibold = new Typeface(family, FontStyle.Normal, FontWeight.SemiBold);
        themeReady = true;
    }

    // ---------- layout and motion ----------

    void Relayout(bool animate)
    {
        laidOut = Bounds.Size;
        if (root is null || Bounds.Width < 40 || Bounds.Height < 40) { order.Clear(); items.Clear(); ghosts.Clear(); hover = null; InvalidateVisual(); return; }
        ResolveTheme();
        center = new Point(Bounds.Width / 2, Bounds.Height / 2);
        radius = Math.Max(30, Math.Min(Bounds.Width, Bounds.Height) / 2 - 18);
        hole = radius * HoleShare; ring = (radius - hole) / depth;
        var cells = SunburstLayout.Build(root, depth, minSweep);
        branch.Clear(); sibling.Clear();
        var counters = new Dictionary<string, int>();
        foreach (var cell in cells)
        {
            if (cell.Node.Kind == NodeKind.Aggregate) continue;
            if (cell.Depth == 1) branch[cell.Node.FullPath] = branch.Count;
            var parent = cell.Node.Parent?.FullPath ?? "";
            counters.TryGetValue(parent, out var k); counters[parent] = k + 1; sibling[cell.Key] = k;
        }
        var now = Now(); var next = new Dictionary<string, Item>(cells.Count);
        order.Clear();
        foreach (var cell in cells)
        {
            var to = new Arc(cell.Start, cell.Sweep, hole + (cell.Depth - 1) * ring, hole + cell.Depth * ring);
            if (!items.Remove(cell.Key, out var item))
                item = new Item { From = animate ? to with { Outer = to.Inner + (to.Outer - to.Inner) * .35, Sweep = to.Sweep * .92 } : to, Appear = animate ? 0 : 1 };
            else item.From = item.Current;
            item.Current = item.From; item.Cell = cell; item.To = to; item.Start = animate ? now : now - Glide * 2;
            BuildLabels(item); next[cell.Key] = item; order.Add(item);
        }
        ghosts.RemoveAll(g => now - g.Start > Fade);
        if (animate) foreach (var old in items.Values) { old.Gone = true; old.Start = now; old.From = old.To = old.Current; ghosts.Add(old); }
        items = next;
        if (hover != null && !items.ContainsValue(hover)) hover = null;
        if (!animate) foreach (var i in order) i.Current = i.To;
        RequestFrame();
        LaidOut?.Invoke();
    }

    void BuildLabels(Item item)
    {
        item.Title = item.Detail = null; item.LabelAt = .5;
        var a = item.To; var n = item.Cell.Node;
        var mid = (a.Inner + a.Outer) / 2; var arc = 2 * mid * Math.Sin(Math.Min(Math.PI / 2, a.Sweep * Math.PI));
        var thick = a.Outer - a.Inner;
        // Labels are horizontal, so the room they get depends on where along the slice they sit: near the top and bottom
        // of the rings the arc runs left-right, at the sides only the ring's thickness does. Try several spots along the
        // slice and keep the one that fits the longest text, so big slices are always named.
        if (thick < 14 || arc < 30) return;
        var fill = n.Kind == NodeKind.Aggregate ? Over(muted, surface, .14) : Fill(n, item.Cell.Depth, sibling.TryGetValue(item.Cell.Key, out var k) ? k : 0);
        var ink = Luma(fill) > .62 ? Color.FromRgb(0x2B, 0x21, 0x16) : Colors.White;
        FormattedText Text(string text, double size, Typeface face, Color color, double width) =>
            new(text, CultureInfo.CurrentUICulture, FlowDirection.LeftToRight, face, size, new SolidColorBrush(color)) { MaxTextWidth = Math.Max(1, width), MaxLineCount = 1, Trimming = TextTrimming.CharacterEllipsis };
        bool Inside(Point p)
        {
            var dx = p.X - center.X; var dy = p.Y - center.Y; var r = Math.Sqrt(dx * dx + dy * dy);
            var t = Math.Atan2(dx, -dy) / (2 * Math.PI); if (t < 0) t += 1;
            if (t < a.Start - 1e-6) t += 1;
            return r >= a.Inner + 1.5 && r <= a.Outer - 1.5 && t >= a.Start && t <= a.Start + a.Sweep;
        }
        bool Fits(Point at, double w, double h) =>
            Inside(new Point(at.X - w / 2, at.Y - h / 2)) && Inside(new Point(at.X + w / 2, at.Y - h / 2)) &&
            Inside(new Point(at.X - w / 2, at.Y + h / 2)) && Inside(new Point(at.X + w / 2, at.Y + h / 2));
        var name = DiskText.Name(n); var size = DiskText.Size(n.Size);
        var spots = a.Sweep > .04 ? new[] { .5, .35, .65, .2, .8, .1, .9 } : new[] { .5 };
        var bestWidth = 0.0; var full = Text(name, 11.5, semibold, ink, 1000).Width + 2;
        foreach (var f in spots)
        {
            var at = Polar(center, mid, a.Start + a.Sweep * f);
            for (var width = 150.0; width >= 30 && width > bestWidth; width *= .82)
            {
                var title = Text(name, width < 60 ? 10.5 : 11.5, semibold, ink, width);
                var detail = Text(size, 10.5, regular, A(ink, .8), width);
                var fit = Fits(at, Math.Max(title.Width, detail.Width), title.Height + detail.Height) ? 2 : Fits(at, title.Width, title.Height) ? 1 : 0;
                if (fit == 0) continue;
                // Prefer a full name over a longer box; a name that fits untrimmed ends the search.
                bestWidth = width; item.LabelAt = f; item.Title = title; item.Detail = fit == 2 ? detail : null;
                break;
            }
            if (item.Title != null && bestWidth >= full) break;
        }
    }

    static double Luma(Color c) => (.299 * c.R + .587 * c.G + .114 * c.B) / 255;

    void RequestFrame()
    {
        if (frameQueued || TopLevel.GetTopLevel(this) is not { } top) { if (!frameQueued) InvalidateVisual(); return; }
        frameQueued = true; top.RequestAnimationFrame(_ => Frame());
    }

    void Frame()
    {
        frameQueued = false; var now = Now(); var busy = scanning.Count > 0;
        var lit = Lineage(hover);
        foreach (var i in order)
        {
            var t = Math.Clamp((now - i.Start) / Glide, 0, 1); var e = 1 - Math.Pow(1 - t, 4);
            i.Current = Arc.Lerp(i.From, i.To, e);
            if (i.Appear < 1) i.Appear = Math.Min(1, i.Appear + .07 + (1 - i.Appear) * .1);
            var hoverTarget = ReferenceEquals(i, hover) ? 1 : lit.Contains(i.Cell.Key) ? .45 : 0; i.Hover += (hoverTarget - i.Hover) * .35;
            var dimTarget = dimmed is { } f && f(i.Cell.Node) ? 1 : 0; i.Dim += (dimTarget - i.Dim) * .22;
            if (t < 1 || i.Appear < 1 || Math.Abs(hoverTarget - i.Hover) > .01 || Math.Abs(dimTarget - i.Dim) > .01) busy = true;
            else { i.Hover = hoverTarget; i.Dim = dimTarget; }
        }
        for (var g = ghosts.Count - 1; g >= 0; g--)
        {
            var t = (now - ghosts[g].Start) / Fade;
            if (t >= 1) ghosts.RemoveAt(g); else { ghosts[g].Appear = 1 - t; busy = true; }
        }
        InvalidateVisual();
        if (busy && IsVisible) RequestFrame();
    }

    /// Keys of the hovered slice's ancestors inside the rings: they light up faintly so the path to the center reads.
    HashSet<string> Lineage(Item? item)
    {
        var set = new HashSet<string>();
        if (item == null || root == null) return set;
        for (var n = item.Cell.Node.Parent; n != null && !ReferenceEquals(n, root); n = n.Parent) set.Add(n.FullPath);
        return set;
    }

    // ---------- drawing ----------

    static Point Polar(Point c, double r, double turn) { var a = turn * 2 * Math.PI; return new Point(c.X + r * Math.Sin(a), c.Y - r * Math.Cos(a)); }

    Geometry Slice(Arc a)
    {
        var g = new StreamGeometry();
        using var cx = g.Open();
        var full = a.Sweep >= .9999; var sweep = Math.Min(a.Sweep, .99995); var mid = a.Start + sweep / 2; var end = a.Start + sweep;
        cx.BeginFigure(Polar(center, a.Outer, a.Start), true);
        cx.ArcTo(Polar(center, a.Outer, mid), new Size(a.Outer, a.Outer), 0, false, SweepDirection.Clockwise);
        cx.ArcTo(Polar(center, a.Outer, end), new Size(a.Outer, a.Outer), 0, false, SweepDirection.Clockwise);
        if (full) { cx.EndFigure(true); cx.BeginFigure(Polar(center, a.Inner, end), true); }
        else cx.LineTo(Polar(center, a.Inner, end));
        cx.ArcTo(Polar(center, a.Inner, mid), new Size(a.Inner, a.Inner), 0, false, SweepDirection.CounterClockwise);
        cx.ArcTo(Polar(center, a.Inner, a.Start), new Size(a.Inner, a.Inner), 0, false, SweepDirection.CounterClockwise);
        cx.EndFigure(true);
        return g;
    }

    // Branch hues in a fixed order, picked so neighbours differ in hue rather than only in shade (DaisyDisk's rings).
    static readonly FileCategory[] BranchOrder = { FileCategory.Application, FileCategory.Video, FileCategory.Document, FileCategory.Archive,
        FileCategory.Image, FileCategory.DiskImage, FileCategory.Code, FileCategory.Audio, FileCategory.System, FileCategory.Other };
    readonly Dictionary<string, int> branch = new();
    readonly Dictionary<string, int> sibling = new();

    /// The hue of the first-ring slice that holds `node` (or the node itself), so the side list can match the rings.
    public Color? BranchColor(DiskNode node)
    {
        ResolveTheme();
        if (byAge || node.Kind == NodeKind.Aggregate) return null;
        return branch.TryGetValue(node.FullPath, out var i) ? category[(int)BranchOrder[i % BranchOrder.Length]] : null;
    }

    Color Fill(DiskNode n, int level, int sibling)
    {
        if (byAge) return Mix(ageNew, ageOld, Math.Clamp((DateTime.UtcNow - n.LastWriteUtc).TotalDays / 540, 0, 1));
        // Each first-ring slice owns a hue; its descendants keep it and pale outward, alternating siblings a little
        // lighter and darker so neighbouring slices in the same branch still separate.
        var top = n; while (top.Parent != null && !ReferenceEquals(top.Parent, root)) top = top.Parent;
        var hue = category[(int)BranchOrder[(branch.TryGetValue(top.FullPath, out var i) ? i : 0) % BranchOrder.Length]];
        var pale = Math.Min(.6, (level - 1) * .17) + (sibling % 2 == 1 ? .07 : 0);
        var c = Over(surface, hue, pale);
        return n.Kind == NodeKind.File ? Over(Colors.Black, c, .06) : c;
    }

    public override void Render(DrawingContext context)
    {
        ResolveTheme();
        context.DrawRectangle(new SolidColorBrush(mapBg), null, new Rect(Bounds.Size));
        if (root == null || radius <= 0) return;
        // A faint guide for every ring keeps the shape whole where slices fold away.
        var guide = new Pen(new SolidColorBrush(A(ink, .05)), 1);
        for (var d = 1; d <= depth; d++) context.DrawEllipse(null, guide, center, hole + d * ring, hole + d * ring);
        var gap = new Pen(new SolidColorBrush(mapBg), Gap);
        foreach (var g in ghosts) Draw(context, g, gap);
        foreach (var i in order) Draw(context, i, gap);
        DrawCenter(context);
    }

    void Draw(DrawingContext cx, Item item, Pen gap)
    {
        var a = item.Current;
        if (a.Sweep * 2 * Math.PI * a.Outer < .6 || a.Outer - a.Inner < 1) return;
        var opacity = item.Appear * (1 - item.Dim * .82);
        if (opacity < .01) return;
        var node = item.Cell.Node; var geometry = Slice(a);
        using var _ = cx.PushOpacity(opacity);
        if (node.Kind == NodeKind.Aggregate)
        {
            cx.DrawGeometry(new SolidColorBrush(Over(muted, surface, .14)), gap, geometry);
            cx.DrawGeometry(hatch, null, geometry);
        }
        else cx.DrawGeometry(new SolidColorBrush(Fill(node, item.Cell.Depth, sibling.TryGetValue(item.Cell.Key, out var k) ? k : 0)), gap, geometry);
        if (node.Kind is NodeKind.File or NodeKind.Directory && IsMarked(node))
        {
            cx.DrawGeometry(new SolidColorBrush(A(surface, .45)), null, geometry);
            cx.DrawGeometry(hatchMarked, null, geometry);
        }
        if (item.Hover > .01) cx.DrawGeometry(new SolidColorBrush(A(Colors.White, .22 * item.Hover)), null, geometry);
        if (scanning.Count > 0 && node.Kind == NodeKind.Directory && scanning.Contains(node.FullPath))
            cx.DrawGeometry(null, new Pen(new SolidColorBrush(A(accent, .3 + .5 * (.5 + .5 * Math.Sin(Now() / 260)))), 1.5), geometry);
        if (selectedKey != null && node.FullPath == selectedKey && node.Kind != NodeKind.Aggregate)
            cx.DrawGeometry(null, new Pen(new SolidColorBrush(accent), 2.5), geometry);

        if (item.Title is { } title && !item.Gone && item.Appear > .5)
        {
            var mid = (a.Inner + a.Outer) / 2; var at = Polar(center, mid, a.Start + a.Sweep * item.LabelAt);
            var h = title.Height + (item.Detail?.Height ?? 0);
            cx.DrawText(title, new Point(at.X - title.Width / 2, at.Y - h / 2));
            if (item.Detail is { } detail) cx.DrawText(detail, new Point(at.X - detail.Width / 2, at.Y - h / 2 + title.Height));
        }
    }

    void DrawCenter(DrawingContext cx)
    {
        var r = hole - 6; if (r < 16 || root == null) return;
        var lift = centerHover && root.Parent != null;
        cx.DrawEllipse(new SolidColorBrush(lift ? Over(accent, surface, .08) : surface), new Pen(new SolidColorBrush(lift ? A(accent, .6) : strokeStrong), 1), center, r, r);
        var shown = hover?.Cell.Node ?? root;
        FormattedText T(string s, double size, Typeface face, Color c) => new(s, CultureInfo.CurrentUICulture, FlowDirection.LeftToRight, face, size, new SolidColorBrush(c)) { MaxTextWidth = r * 1.6, MaxLineCount = 1, Trimming = TextTrimming.CharacterEllipsis, TextAlignment = TextAlignment.Center };
        var big = Math.Clamp(r / 3.6, 15, 28);
        var name = T(shown == root ? (root.Name == "" ? root.FullPath : root.Name) : DiskText.Name(shown), Math.Clamp(r / 7, 11, 14), semibold, ink);
        var size = T(DiskText.Size(shown.Size), big, semibold, ink);
        var note = shown == root
            ? T(lift ? "↑ 回到上一層" : DiskText.Count(root.FileCount) + " 個檔案", 11, regular, lift ? accent : muted)
            : T(DiskText.Percent(shown.Size, root.Size) + " · " + (shown.Kind == NodeKind.Directory ? DiskText.Count(shown.FileCount) + " 個檔案" : DiskText.Category(shown.Category)), 11, regular, muted);
        var total = name.Height + size.Height + note.Height + 4; var y = center.Y - total / 2; var x = center.X - r * .8;
        cx.DrawText(name, new Point(x, y)); y += name.Height + 1;
        cx.DrawText(size, new Point(x, y)); y += size.Height + 3;
        cx.DrawText(note, new Point(x, y));
    }

    // ---------- pointer ----------

    (Item? Item, bool Center) Hit(Point p)
    {
        var dx = p.X - center.X; var dy = p.Y - center.Y; var r = Math.Sqrt(dx * dx + dy * dy);
        if (r <= hole - 6) return (null, true);
        var turn = Math.Atan2(dx, -dy) / (2 * Math.PI); if (turn < 0) turn += 1;
        for (var i = order.Count - 1; i >= 0; i--)
        {
            var a = order[i].Current;
            if (r >= a.Inner && r < a.Outer && turn >= a.Start && turn < a.Start + a.Sweep) return (order[i], false);
        }
        return (null, false);
    }

    protected override void OnPointerMoved(PointerEventArgs e)
    {
        base.OnPointerMoved(e);
        var p = e.GetPosition(this); var (hit, inCenter) = Hit(p);
        if (!ReferenceEquals(hit, hover) || inCenter != centerHover) { hover = hit; centerHover = inCenter; RequestFrame(); }
        HoverChanged?.Invoke(hit?.Cell.Node, p);
        Cursor = hit is { Cell.Node.Kind: NodeKind.Directory } || inCenter && root?.Parent != null ? new Cursor(StandardCursorType.Hand) : new Cursor(StandardCursorType.Arrow);
    }

    protected override void OnPointerExited(PointerEventArgs e)
    {
        base.OnPointerExited(e);
        if (hover != null || centerHover) { hover = null; centerHover = false; RequestFrame(); }
        HoverChanged?.Invoke(null, default);
    }

    protected override void OnPointerPressed(PointerPressedEventArgs e)
    {
        base.OnPointerPressed(e);
        Focus();
        var point = e.GetCurrentPoint(this); var (item, inCenter) = Hit(point.Position); var hit = item?.Cell.Node;
        if (point.Properties.IsRightButtonPressed)
        {
            if (hit is { Kind: NodeKind.File or NodeKind.Directory }) { Select(hit); MenuRequested?.Invoke(hit, point.Position); }
            e.Handled = true; return;
        }
        if (!point.Properties.IsLeftButtonPressed) return;
        if (inCenter) { if (root?.Parent is { } up) Opened?.Invoke(up); e.Handled = true; return; }
        // One click on a folder zooms into it (DaisyDisk); a file is selected and shown in the inspector.
        if (hit is { Kind: NodeKind.Directory }) { Opened?.Invoke(hit); e.Handled = true; return; }
        Select(hit);
    }

    static readonly double Clock0 = System.Diagnostics.Stopwatch.GetTimestamp();
    static double Now() => (System.Diagnostics.Stopwatch.GetTimestamp() - Clock0) * 1000d / System.Diagnostics.Stopwatch.Frequency;
}
