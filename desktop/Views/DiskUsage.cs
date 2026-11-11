using Avalonia;
using Avalonia.Animation;
using Avalonia.Animation.Easings;
using Avalonia.Controls;
using Avalonia.Controls.Primitives;
using Avalonia.Input;
using Avalonia.Layout;
using Avalonia.LogicalTree;
using Avalonia.Media;
using Avalonia.Media.Transformation;
using Avalonia.Platform.Storage;
using Avalonia.Threading;
using Suhang.Desktop.DiskUsage;

namespace Suhang.Desktop;

/// The disk space analyzer: pick a drive or folder, watch the treemap fill while it is read, then zoom, filter and
/// inspect. It is a plain control hosted by a window (like `TaskManagerView`); nothing runs until `Activate`.
/// Reading and layout live in `Services/DiskUsage`; this class only drives them and draws the chrome around `TreemapView`.
internal sealed class DiskUsageView : IDisposable
{
    public Control View { get; }
    readonly Window owner;
    readonly string? autoRoot;
    readonly Grid root = new(), homePage = new(), workPage = new();
    readonly TreemapView map = new();
    readonly SunburstView sun = new() { IsVisible = false };
    readonly DiskListView list = new() { IsVisible = false };
    readonly StackPanel inspector = new() { Spacing = 16 }, crumbs = new() { Orientation = Orientation.Horizontal, Spacing = 2 }, drives = new();
    readonly TextBox search = new() { Watermark = "篩選，例如 *.mp4  >100MB  older:90d" };
    readonly TextBlock hint = Label("", Scale.Secondary, key: "Muted"), statFiles = Label("", Scale.Secondary, key: "Muted"), statSize = Label("", Scale.Secondary, key: "Muted"),
        statTime = Label("", Scale.Secondary, key: "Muted"), statPath = Label("", Scale.Secondary, key: "Subtle"), statFree = Label("", Scale.Secondary, key: "Muted");
    readonly Border freeFill = new() { CornerRadius = new CornerRadius(3), HorizontalAlignment = HorizontalAlignment.Left, Height = 6 };
    readonly Border progressFill = new() { Height = 3, HorizontalAlignment = HorizontalAlignment.Left, Width = 0, Opacity = 0 };
    readonly Border progressTrack = new() { Height = 3 };
    readonly Border tip = new() { Opacity = 0, IsHitTestVisible = false, CornerRadius = new CornerRadius(Scale.CardRadius), Padding = new Thickness(12, 12), BorderThickness = new Thickness(1), MinWidth = 190, MaxWidth = 300 };
    readonly Canvas overlay = new() { IsHitTestVisible = false };
    readonly Border emptyMap = new() { IsVisible = false, IsHitTestVisible = false };
    readonly Notice problem = new();
    readonly Button back, forward, up, rescan;
    readonly Slider detail = new() { Minimum = 1, Maximum = 5, Value = 3, Width = 96, TickFrequency = 1, IsSnapToTickEnabled = true, VerticalAlignment = VerticalAlignment.Center };
    readonly Border inspectorHost = new();
    Control detailBox = null!, listModeBox = null!;
    readonly HashSet<FileCategory> categories = new();
    readonly List<string> backStack = new(), forwardStack = new();
    static readonly (double MinArea, int Depth)[] Detail = [(3400, 3), (1900, 4), (950, 6), (480, 8), (230, 10)];
    /// Sunburst rings and the narrowest slice (degrees) per detail step.
    static readonly (int Rings, double MinDegrees)[] RingDetail = [(3, 1.6), (4, 1.1), (5, .8), (6, .55), (7, .4)];
    internal enum Mode { Treemap, Sunburst, List }
    Mode mode = Mode.Treemap; bool largestFiles;
    Action<int> setMode = _ => { }, setListMode = _ => { };
    const string TreemapIcon = "M4 4.5h16v15H4z M11 4.5v15 M11 12h9 M15.5 12v7.5",
        SunburstIcon = "M12 3a9 9 0 1 1 0 18a9 9 0 1 1 0-18z M12 8a4 4 0 1 1 0 8a4 4 0 1 1 0-8z M12 3v5 M19.8 16.5l-4.3-2.5 M4.2 16.5l4.3-2.5",
        ListIcon = "M9 6.5h11 M9 12h11 M9 17.5h11 M4.5 6.5h.5 M4.5 12h.5 M4.5 17.5h.5";

    DiskScanner? scanner; DiskTree? tree; CancellationTokenSource? cts;
    DiskNode? top, view; DiskNode? selected;
    string scanRoot = "", viewPath = "";
    DriveSpace? space;
    DiskFilter? filter; string filterError = "";
    DispatcherTimer? snapshotTimer, searchTimer;
    ScanProgress last = new(ScanPhase.Completed, 0, 0, 0, 0, "", TimeSpan.Zero, null);
    bool scanning, disposed, activated;
    int session;

    public DiskUsageView(Window owner, string? autoRoot = null)
    {
        this.owner = owner; this.autoRoot = autoRoot;
        back = IconButton(BackIcon, "上一個位置", () => Step(backStack, forwardStack));
        forward = IconButton(Icons.Chevron, "下一個位置", () => Step(forwardStack, backStack));
        up = IconButton(Icons.Up, "上一層", () => { if (view?.Parent is { } p) Go(p); });
        rescan = Action("重新掃描", () => { if (scanRoot != "") StartScan(scanRoot); }, Icons.Retry);

        BuildHome();
        BuildWork();
        root.Children.Add(homePage); root.Children.Add(workPage);
        workPage.IsVisible = false;
        View = root;

        map.SelectionChanged += n => { selected = n; RenderInspector(); };
        map.Opened += n => Go(n);
        map.HoverChanged += ShowTip;
        map.MenuRequested += ShowMenu;
        sun.SelectionChanged += n => { selected = n; RenderInspector(); };
        sun.Opened += n => Go(n);
        sun.HoverChanged += ShowTip;
        sun.MenuRequested += ShowMenu;
        list.SelectionChanged += n => { selected = n; RenderInspector(); };
        list.Opened += n => Go(n);
        list.MenuRequested += ShowMenu;
        search.TextChanged += (_, _) => { searchTimer?.Stop(); searchTimer = new DispatcherTimer { Interval = TimeSpan.FromMilliseconds(160) }; searchTimer.Tick += (_, _) => { searchTimer!.Stop(); ApplyFilter(); }; searchTimer.Start(); };
        detail.PropertyChanged += (_, e) => { if (e.Property == RangeBase.ValueProperty) Render(true); };
        workPage.KeyDown += (_, e) => {
            if (e.Source is Control input && (input is TextBox || input.GetLogicalAncestors().OfType<TextBox>().Any())) return;
            if (e.Key == Key.Back || e.KeyModifiers == KeyModifiers.Alt && e.Key == Key.Up) { if (view?.Parent is { } p) Go(p); e.Handled = true; }
            else if (e.KeyModifiers == KeyModifiers.Alt && e.Key == Key.Left) { Step(backStack, forwardStack); e.Handled = true; }
            else if (e.KeyModifiers == KeyModifiers.Alt && e.Key == Key.Right) { Step(forwardStack, backStack); e.Handled = true; }
            else if (e.Key == Key.Delete && selected is { } n) { AskDelete(n); e.Handled = true; }
            else if (e.Key == Key.Escape && selected != null) { Active(null); e.Handled = true; }
        };
        root.SizeChanged += (_, e) => inspectorHost.IsVisible = e.NewSize.Width >= 880;
    }

    // ---------- lifecycle ----------

    public void Activate()
    {
        if (disposed || activated) return;
        activated = true; RefreshDrives();
        if (autoRoot != null) StartScan(autoRoot);
    }

    public void Dispose()
    {
        disposed = true; session++;
        cts?.Cancel(); snapshotTimer?.Stop(); searchTimer?.Stop();
    }

    // ---------- home: choose what to analyze ----------

    const string BackIcon = "M14.5 6l-6 6l6 6", Disk = Icons.Laptop;
    void BuildHome()
    {
        var title = Label("要分析哪裡的空間？", Scale.LargeTitle, FontWeight.Bold);
        var sub = Hint("用方塊圖、環狀圖或清單呈現每個資料夾與檔案占用的空間。掃描只讀取檔名與大小，不會開啟檔案內容，也不會變更任何東西。");
        sub.MaxWidth = 560; sub.HorizontalAlignment = HorizontalAlignment.Left;
        var wrap = new WrapPanel { Orientation = Orientation.Horizontal, ItemSpacing = 16, LineSpacing = 16 };
        drives.Children.Add(wrap);
        var trust = Row(8, Icons.Make(Icons.Shield, 14, "Subtle"), Label("只在本機執行，不連線；刪除一律移到資源回收筒。", Scale.Secondary, key: "Subtle"));
        var column = Column(24, Column(6, title, sub), drives, trust);
        column.Margin = new Thickness(40, 28, 40, 24); column.MaxWidth = 980; column.HorizontalAlignment = HorizontalAlignment.Left;
        homePage.Children.Add(new ScrollViewer { Content = column, HorizontalScrollBarVisibility = ScrollBarVisibility.Disabled });
    }

    void RefreshDrives()
    {
        var wrap = (WrapPanel)drives.Children[0]; wrap.Children.Clear();
        var index = 0;
        foreach (var d in DriveCatalog.List().Where(d => d.Ready && d.TotalBytes > 0)) wrap.Children.Add(DriveCard(d, index++));
        wrap.Children.Add(PickCard(index));
    }

    Control Lift(Button card, int index)
    {
        card.RenderTransform = TransformOperations.Parse("translateY(14px)"); card.Opacity = 0;
        card.Transitions = [new DoubleTransition { Property = Visual.OpacityProperty, Duration = TimeSpan.FromMilliseconds(420), Easing = new CubicEaseOut() },
            new TransformOperationsTransition { Property = Visual.RenderTransformProperty, Duration = TimeSpan.FromMilliseconds(260), Easing = new CubicEaseOut() }];
        card.AttachedToVisualTree += (_, _) => DispatcherTimer.RunOnce(() => { card.Opacity = 1; card.RenderTransform = TransformOperations.Parse("translateY(0px)"); }, TimeSpan.FromMilliseconds(40 + index * 70));
        card.PointerEntered += (_, _) => card.RenderTransform = TransformOperations.Parse("translateY(-3px)");
        card.PointerExited += (_, _) => card.RenderTransform = TransformOperations.Parse("translateY(0px)");
        return card;
    }

    Control DriveCard(DriveSpace d, int index)
    {
        var used = Math.Max(0, d.TotalBytes - d.FreeBytes); var fraction = Math.Clamp(used / (double)d.TotalBytes, 0, 1);
        var ring = new DonutChart(74, 9).Set([(fraction > .85 ? "Warn" : "Accent", used, 1)], DiskText.Percent(used, d.TotalBytes), "已用");
        var name = string.IsNullOrWhiteSpace(d.Label) ? d.Name.TrimEnd('\\', '/') : d.Name.TrimEnd('\\', '/') + "  " + d.Label;
        var kind = (d.Removable ? "可移除磁碟" : d.Network ? "網路磁碟" : "本機磁碟") + (d.Format == "" ? "" : " · " + d.Format);
        var title = Columns("Auto,*", Icons.Make(d.Removable ? Icons.Usb : Disk, 16, "Accent"), Label(name, Scale.Section, FontWeight.SemiBold));
        title.ColumnSpacing = 8; foreach (var c in title.Children) c.VerticalAlignment = VerticalAlignment.Center;
        ToolTip.SetTip(title, name);
        var free = Label("可用 " + DiskText.Size(d.FreeBytes), Scale.Body, FontWeight.SemiBold, fraction > .85 ? "Warn" : "Ink");
        var facts = Column(4, title, Label(kind, Scale.Secondary, key: "Muted"), WithMargin(free, new Thickness(0, 6, 0, 0)), Label("共 " + DiskText.Size(d.TotalBytes) + " · 已用 " + DiskText.Size(used), Scale.Secondary, key: "Muted"));
        facts.VerticalAlignment = VerticalAlignment.Center;
        var body = Columns("Auto,*", ring, facts); body.ColumnSpacing = 16;
        var card = CardButton(body, 300);
        card.Click += (_, _) => StartScan(d.Name, d);
        return Lift(card, index);
    }

    Control PickCard(int index)
    {
        var inner = Column(8, Icons.Make(Icons.Plus, 22, "Muted"), Label("選擇資料夾…", Scale.Body, key: "Muted"));
        foreach (var c in inner.Children) c.HorizontalAlignment = HorizontalAlignment.Center;
        inner.VerticalAlignment = VerticalAlignment.Center;
        var card = CardButton(inner, 300); card.MinHeight = 108;
        card.Click += async (_, _) => {
            var picked = await owner.StorageProvider.OpenFolderPickerAsync(new FolderPickerOpenOptions { Title = "選擇要分析的資料夾", AllowMultiple = false });
            if (picked.Count > 0 && picked[0].TryGetLocalPath() is { Length: > 0 } path) StartScan(path);
        };
        return Lift(card, index);
    }

    static Button CardButton(Control content, double width) => new Button {
        Content = content, Width = width, Padding = new Thickness(20), CornerRadius = new CornerRadius(Scale.CardRadius + 2), BorderThickness = new Thickness(1),
        HorizontalContentAlignment = HorizontalAlignment.Stretch, VerticalContentAlignment = VerticalAlignment.Stretch, VerticalAlignment = VerticalAlignment.Top,
    }.Res(Button.BackgroundProperty, "Card");

    // ---------- work page ----------

    void BuildWork()
    {
        // Row 1: where you are and what to look for. Row 2: how to look at it.
        var nav = Row(0, back, forward, up);
        var crumbBox = new Border { Child = crumbs, CornerRadius = new CornerRadius(Scale.PillRadius), BorderThickness = new Thickness(1), Padding = new Thickness(6, 2), MinWidth = 160, ClipToBounds = true, Height = Scale.ControlHeight }
            .Res(Border.BackgroundProperty, "Field").Res(Border.BorderBrushProperty, "Stroke");
        crumbs.VerticalAlignment = VerticalAlignment.Center;
        var clear = IconButton(Icons.Close, "清除篩選", () => search.Text = "");
        clear.Width = clear.Height = Scale.ControlHeight - 6;
        search.MinHeight = 0; search.BorderThickness = new Thickness(0); search.Background = Brushes.Transparent; search.Padding = new Thickness(Scale.Snug, 0); search.VerticalContentAlignment = VerticalAlignment.Center;
        var searchBox = new Border { Child = Columns("Auto,*,Auto", Icons.Make(Icons.Search, Scale.IconInline, "Subtle"), search, clear), CornerRadius = new CornerRadius(Scale.PillRadius), BorderThickness = new Thickness(1), Padding = new Thickness(12, 0, 2, 0), Height = Scale.ControlHeight, Width = 340 }
            .Res(Border.BackgroundProperty, "Field").Res(Border.BorderBrushProperty, "Stroke");
        foreach (var c in ((Grid)searchBox.Child!).Children) c.VerticalAlignment = VerticalAlignment.Center;
        var top = Columns("Auto,*,Auto,Auto", nav, crumbBox, searchBox, rescan);
        top.ColumnSpacing = 12;
        foreach (var c in top.Children) c.VerticalAlignment = VerticalAlignment.Center;

        var views = Segmented([("方塊", TreemapIcon), ("環狀", SunburstIcon), ("清單", ListIcon)], 82, 0, i => SetMode((Mode)i), out setMode, "顯示方式");
        var colors = Segmented([("類型", null), ("修改時間", null)], 74, 0, i => { map.ColorByAge = sun.ColorByAge = list.ColorByAge = i == 1; }, out _, "著色方式");
        listModeBox = Segmented([("資料夾內容", null), ("最大檔案", null)], 88, 0, i => { largestFiles = i == 1; Render(false); }, out setListMode, "清單內容");
        listModeBox.IsVisible = false;
        detailBox = Row(8, Label("細節", Scale.Secondary, key: "Muted"), detail);
        var right = Row(16, listModeBox, Row(8, Label("著色", Scale.Secondary, key: "Muted"), colors), detailBox);
        var second = Columns("Auto,*,Auto", views, WithMargin(hint, new Thickness(16, 0, 12, 0)), right);
        foreach (var c in second.Children) c.VerticalAlignment = VerticalAlignment.Center;
        var toolbar = Column(12, top, second);

        progressTrack.Child = progressFill; progressFill.Res(Border.BackgroundProperty, "Accent");
        progressFill.Transitions = [new DoubleTransition { Property = Layoutable.WidthProperty, Duration = TimeSpan.FromMilliseconds(260) },
            new DoubleTransition { Property = Visual.OpacityProperty, Duration = TimeSpan.FromMilliseconds(400) }];
        progressTrack.SizeChanged += (_, _) => ApplyProgress();

        // Map, tooltip and empty state share one rounded ground.
        emptyMap.Child = EmptyState.Make(Icons.Folder, "這個位置沒有檔案", "已讀取的資料夾是空的，或內容無法存取。");
        emptyMap.VerticalAlignment = VerticalAlignment.Center; emptyMap.HorizontalAlignment = HorizontalAlignment.Center;
        tip.Res(Border.BackgroundProperty, "Surface").Res(Border.BorderBrushProperty, "StrokeStrong");
        tip.Transitions = [new DoubleTransition { Property = Visual.OpacityProperty, Duration = TimeSpan.FromMilliseconds(120) }];
        overlay.Children.Add(tip);
        var ground = new Border { CornerRadius = new CornerRadius(Scale.CardRadius), ClipToBounds = true, Child = new Grid { Children = { map, sun, list, emptyMap, overlay } } }.Res(Border.BackgroundProperty, "MapBg");
        ground.PointerExited += (_, _) => tip.Opacity = 0;

        inspector.Margin = new Thickness(0, 0, 16, 0);
        inspectorHost.Child = new ScrollViewer { Content = inspector, HorizontalScrollBarVisibility = ScrollBarVisibility.Disabled };
        inspectorHost.Width = 312; inspectorHost.Padding = new Thickness(20, 16, 16, 12); inspectorHost.BorderThickness = new Thickness(1); inspectorHost.CornerRadius = new CornerRadius(Scale.CardRadius);
        inspectorHost.Res(Border.BackgroundProperty, "Card");

        var body = Columns("*,12,Auto", ground, Gap(), inspectorHost);
        statPath.MaxWidth = 460; statPath.HorizontalAlignment = HorizontalAlignment.Right;
        var track = new Border { Width = 120, Height = 6, CornerRadius = new CornerRadius(3), Child = freeFill, ClipToBounds = true }.Res(Border.BackgroundProperty, "IdleSoft");
        freeFill.Res(Border.BackgroundProperty, "Accent");
        freeFill.Transitions = [new DoubleTransition { Property = Layoutable.WidthProperty, Duration = TimeSpan.FromMilliseconds(500), Easing = new CubicEaseOut() }];
        var status = Columns("Auto,Auto,Auto,*,Auto,Auto", statFiles, statSize, statTime, statPath, statFree, track);
        status.ColumnSpacing = 20;
        foreach (var c in status.Children) c.VerticalAlignment = VerticalAlignment.Center;
        hint.TextWrapping = TextWrapping.NoWrap;
        var page = Rows("Auto,Auto,*,Auto,Auto", toolbar, WithMargin(progressTrack, new Thickness(0, 12, 0, 0)), body, WithMargin(problem, new Thickness(0, 8, 0, 0)), WithMargin(status, new Thickness(2, 12, 2, 0)));
        page.Margin = new Thickness(0, 4, 0, 0);
        workPage.Children.Add(page);
    }

    /// A segmented control with a sliding pill. `set` moves the pill without raising `changed`.
    static Control Segmented((string Text, string? Icon)[] options, double width, int initial, Action<int> changed, out Action<int> set, string name)
    {
        var grid = new Grid { Height = Scale.ControlHeight - 6 };
        var pill = new Border { Width = width, CornerRadius = new CornerRadius((Scale.ControlHeight - 6) / 2), HorizontalAlignment = HorizontalAlignment.Left, Margin = new Thickness(initial * width, 0, 0, 0), BoxShadow = BoxShadows.Parse("0 2 6 0 #26000000") }
            .Res(Border.BackgroundProperty, "PrimaryFill");
        pill.Transitions = [new ThicknessTransition { Property = Layoutable.MarginProperty, Duration = TimeSpan.FromMilliseconds(260), Easing = new CubicEaseOut() }];
        grid.Children.Add(pill);
        var labels = new List<TextBlock>(); var glyphs = new List<Avalonia.Controls.Shapes.Path?>();
        void Move(int index)
        {
            pill.Margin = new Thickness(index * width, 0, 0, 0);
            for (var k = 0; k < labels.Count; k++)
            {
                var ink = k == index ? "PrimaryInk" : "Muted";
                labels[k].FontWeight = k == index ? FontWeight.SemiBold : FontWeight.Normal; labels[k].Res(TextBlock.ForegroundProperty, ink);
                glyphs[k]?.Res(Avalonia.Controls.Shapes.Shape.StrokeProperty, ink);
            }
        }
        for (var i = 0; i < options.Length; i++)
        {
            var index = i; var (text, icon) = options[i];
            var label = Label(text, Scale.Secondary, key: "Muted"); labels.Add(label);
            var glyph = icon is null ? null : Icons.Make(icon, 14, "Muted");
            glyphs.Add(glyph?.GetLogicalDescendants().OfType<Avalonia.Controls.Shapes.Path>().FirstOrDefault());
            var b = new Button { Content = glyph is null ? label : Row(6, glyph, label), Width = width, Background = Brushes.Transparent, BorderThickness = new Thickness(0),
                HorizontalContentAlignment = HorizontalAlignment.Center, HorizontalAlignment = HorizontalAlignment.Left, Margin = new Thickness(i * width, 0, 0, 0), CornerRadius = new CornerRadius((Scale.ControlHeight - 6) / 2), Padding = new Thickness(4, 0) };
            Avalonia.Automation.AutomationProperties.SetName(b, name + "：" + text);
            b.Click += (_, _) => { Move(index); changed(index); };
            grid.Children.Add(b);
        }
        Move(initial); set = Move;
        return new Border { Child = grid, Padding = new Thickness(Scale.Hair), CornerRadius = new CornerRadius(Scale.PillRadius), BorderThickness = new Thickness(1), Width = width * options.Length + 6, HorizontalAlignment = HorizontalAlignment.Left }
            .Res(Border.BackgroundProperty, "Field").Res(Border.BorderBrushProperty, "Stroke");
    }

    internal void SetMode(Mode next)
    {
        if (next == mode) return;
        mode = next; setMode((int)next); tip.Opacity = 0;
        map.IsVisible = mode == Mode.Treemap; sun.IsVisible = mode == Mode.Sunburst; list.IsVisible = mode == Mode.List;
        detailBox.IsVisible = mode != Mode.List; listModeBox.IsVisible = mode == Mode.List;
        Render(true);
        Active(selected);
    }

    /// Mirrors the selection into the visible view without re-running the inspector twice.
    void Active(DiskNode? node)
    {
        switch (mode) { case Mode.Sunburst: sun.Select(node); break; case Mode.List: list.Select(node); break; default: map.Select(node); break; }
    }
    Control ActiveView => mode switch { Mode.Sunburst => sun, Mode.List => list, _ => map };

    // ---------- scanning ----------

    internal void StartScan(string path, DriveSpace? known = null)
    {
        if (disposed) return;
        problem.Hide();
        DiskScanner next;
        try { next = new DiskScanner(path); }
        catch (Exception ex) { problem.Show("Error", ex is ArgumentException ? "找不到這個資料夾。" : ex.Message); return; }
        cts?.Cancel(); snapshotTimer?.Stop(); session++;
        var mine = session; var source = cts = new CancellationTokenSource();
        scanner = next; scanRoot = path; space = known ?? DriveCatalog.Find(path); tree = null; top = view = selected = null; viewPath = path;
        backStack.Clear(); forwardStack.Clear(); categories.Clear(); search.Text = ""; filter = null; filterError = ""; map.Dimmed = sun.Dimmed = list.Dimmed = null;
        homePage.IsVisible = false; workPage.IsVisible = true; scanning = true; last = last with { Files = 0, Bytes = 0, Elapsed = TimeSpan.Zero };
        progressFill.Opacity = 1; ApplyProgress(); UpdateChrome(); UpdateStatus();
        workPage.Focus();
        snapshotTimer = new DispatcherTimer { Interval = TimeSpan.FromMilliseconds(250) };
        snapshotTimer.Tick += (_, _) => { if (session == mine && scanning) ApplySnapshot(next.CaptureSnapshot()); };
        snapshotTimer.Start();
        _ = RunScan(next, mine, source.Token);
    }

    async Task RunScan(DiskScanner next, int mine, CancellationToken token)
    {
        var progress = new Progress<ScanProgress>(p => { if (session == mine) { last = p; UpdateStatus(); ApplyProgress(); } });
        try
        {
            var result = await next.ScanAsync(progress, token);
            if (session != mine) return;
            tree = result; top = result.Root; scanning = false; snapshotTimer?.Stop();
            view = Resolve(top, viewPath) ?? top; viewPath = view.FullPath;
            selected = selected == null ? null : Resolve(top, selected.FullPath); Active(selected);
            last = last with { Phase = ScanPhase.Completed, Files = top.FileCount, Bytes = top.Size, Fraction = 1 };
            progressFill.Opacity = 0; ApplyProgress(); Render(true); UpdateStatus();
        }
        catch (OperationCanceledException) { if (session == mine) { scanning = false; snapshotTimer?.Stop(); progressFill.Opacity = 0; UpdateChrome(); } }
        catch (Exception ex)
        {
            if (session != mine) return;
            scanning = false; snapshotTimer?.Stop(); progressFill.Opacity = 0; problem.Show("Error", "掃描沒有完成：" + ex.Message); UpdateChrome();
        }
    }

    void ApplySnapshot(ScanSnapshot snap)
    {
        top = snap.Root; last = snap.Progress with { Phase = ScanPhase.Enumerating };
        view = Resolve(top, viewPath) ?? top; if (selected != null) selected = Resolve(top, selected.FullPath);
        Render(true); UpdateStatus(); ApplyProgress();
    }

    void ApplyProgress()
    {
        var f = scanning ? last.Fraction ?? 0 : 1;
        progressFill.Width = progressTrack.Bounds.Width * Math.Clamp(f, 0, 1);
    }

    static bool Same(string a, string b) => string.Equals(a.TrimEnd('\\', '/'), b.TrimEnd('\\', '/'), OperatingSystem.IsWindows() ? StringComparison.OrdinalIgnoreCase : StringComparison.Ordinal);
    static DiskNode? Resolve(DiskNode from, string path)
    {
        var comparison = OperatingSystem.IsWindows() ? StringComparison.OrdinalIgnoreCase : StringComparison.Ordinal;
        var node = from;
        while (true)
        {
            if (Same(node.FullPath, path)) return node;
            DiskNode? next = null;
            foreach (var c in node.Children)
                if (c.Kind == NodeKind.Directory && (Same(c.FullPath, path) || path.StartsWith(c.FullPath.TrimEnd('\\', '/') + Path.DirectorySeparatorChar, comparison))) { next = c; break; }
                else if (c.Kind == NodeKind.File && Same(c.FullPath, path)) return c;
            if (next == null) return null;
            node = next;
        }
    }

    // ---------- navigation and rendering ----------

    LayoutOptions Options()
    {
        var (min, depth) = Detail[(int)Math.Round(detail.Value) - 1];
        var free = view != null && top != null && ReferenceEquals(view, top) && space is { TotalBytes: > 0 } && Same(space.Name, scanRoot) ? space.FreeBytes : 0;
        return new LayoutOptions(depth, min, 22, 3, 84, null, free);
    }

    void Render(bool animate)
    {
        if (view == null) return;
        var step = (int)Math.Round(detail.Value) - 1;
        switch (mode)
        {
            case Mode.Sunburst: sun.SetView(view, RingDetail[step].Rings, RingDetail[step].MinDegrees / 360, animate); break;
            case Mode.List: list.SetView(view, largestFiles); break;
            default: map.SetView(view, Options(), animate); break;
        }
        emptyMap.IsVisible = view.Size <= 0 && !scanning;
        UpdateChrome(); RenderInspector(); UpdateSummary();
    }

    void Go(DiskNode node, bool history = true)
    {
        if (view == null || node.Kind != NodeKind.Directory || ReferenceEquals(node, view)) return;
        if (history) { backStack.Add(viewPath); forwardStack.Clear(); }
        view = node; viewPath = node.FullPath; selected = null; Active(null); Render(true);
    }

    void Step(List<string> from, List<string> to)
    {
        if (from.Count == 0 || top == null) return;
        var path = from[^1]; from.RemoveAt(from.Count - 1);
        var target = Resolve(top, path);
        if (target == null) return;
        to.Add(viewPath); Go(target, false);
    }

    void UpdateChrome()
    {
        back.IsEnabled = backStack.Count > 0; forward.IsEnabled = forwardStack.Count > 0; up.IsEnabled = view?.Parent != null;
        rescan.IsEnabled = scanRoot != "" && !scanning;
        crumbs.Children.Clear();
        var chain = new List<DiskNode>();
        for (var n = view; n != null; n = n.Parent) chain.Insert(0, n);
        var from = Math.Max(0, chain.Count - 4);
        if (from > 0) crumbs.Children.Add(Label("…", Scale.Body, key: "Subtle"));
        for (var i = from; i < chain.Count; i++)
        {
            var node = chain[i]; var current = i == chain.Count - 1;
            if (i > from || from > 0) crumbs.Children.Add(Label("›", Scale.Caption, key: "Subtle"));
            var b = new Button { Content = Label(node.Name == "" ? node.FullPath : node.Name, Scale.Body, current ? FontWeight.SemiBold : FontWeight.Normal, current ? "Ink" : "Muted"), Padding = new Thickness(8, 4),
                Background = Brushes.Transparent, BorderThickness = new Thickness(0), CornerRadius = new CornerRadius(Scale.ControlRadius), MaxWidth = 170 };
            b.Click += (_, _) => Go(node);
            crumbs.Children.Add(b);
        }
        statFree.Text = space is { TotalBytes: > 0 } s ? "可用 " + DiskText.Size(s.FreeBytes) + " / " + DiskText.Size(s.TotalBytes) : "";
        freeFill.Width = space is { TotalBytes: > 0 } s2 ? 120 * Math.Clamp(1 - s2.FreeBytes / (double)s2.TotalBytes, 0, 1) : 0;
    }

    void UpdateStatus()
    {
        var files = scanning ? last.Files : top?.FileCount ?? 0; var bytes = scanning ? last.Bytes : top?.Size ?? 0;
        statFiles.Text = DiskText.Count(files) + " 個檔案"; statSize.Text = DiskText.Size(bytes);
        statTime.Text = scanning ? last.Elapsed.TotalSeconds.ToString("0.0") + " 秒" : last.Elapsed > TimeSpan.Zero ? "耗時 " + last.Elapsed.TotalSeconds.ToString("0.0") + " 秒" : "";
        statPath.Text = scanning && last.CurrentPath != "" ? "正在讀取 " + last.CurrentPath : last.Errors > 0 && !scanning ? DiskText.Count(last.Errors) + " 個位置無法存取" : "";
        if (scanning) map.Scanning = sun.Scanning = Ancestors(last.CurrentPath);
        else if (map.Scanning.Count > 0) map.Scanning = sun.Scanning = new HashSet<string>();
        UpdateChrome();
    }

    HashSet<string> Ancestors(string current)
    {
        var set = new HashSet<string>(OperatingSystem.IsWindows() ? StringComparer.OrdinalIgnoreCase : StringComparer.Ordinal);
        try { for (var p = current; !string.IsNullOrEmpty(p) && p.Length >= scanRoot.Length; p = Path.GetDirectoryName(p)) set.Add(p); } catch { }
        return set;
    }

    // ---------- filter ----------

    void ApplyFilter()
    {
        var text = search.Text ?? "";
        if (categories.Count > 0) text += " type:" + string.Join("|", categories.Select(c => c.ToString().ToLowerInvariant()));
        if (!DiskFilter.TryParse(text, out var next, out var error)) { filterError = error ?? "無法解讀篩選條件"; UpdateSummary(); return; }
        filterError = ""; filter = next;
        map.Dimmed = sun.Dimmed = list.Dimmed = next is null ? null : n => n.Kind switch { NodeKind.Directory => next.MatchedSize(n) == 0, NodeKind.File => !next.Matches(n), _ => true };
        UpdateSummary(); RenderInspector();
    }

    void UpdateSummary()
    {
        hint.Inlines?.Clear();
        if (filterError != "") { hint.Text = filterError; hint.Res(TextBlock.ForegroundProperty, "Error"); return; }
        hint.Res(TextBlock.ForegroundProperty, "Muted");
        if (filter != null && view != null) { var m = filter.MatchedSize(view); hint.Text = "符合 " + DiskText.Size(m) + " · 占 " + view.Name + " 的 " + DiskText.Percent(m, view.Size); }
        else hint.Text = mode switch {
            Mode.Sunburst => "雙擊資料夾放大 · 點中央回上一層 · 越外圈越深層，扇形越寬占用越多",
            Mode.List => largestFiles ? "此資料夾之下最大的檔案 · 右鍵開啟更多動作" : "雙擊資料夾進入 · 點欄位標題排序 · 右鍵開啟更多動作",
            _ => "雙擊資料夾放大 · 右鍵開啟更多動作 · 方塊越大，占用越多" };
    }

    // ---------- tooltip and menu ----------

    void ShowTip(DiskNode? node, Point at)
    {
        if (node == null || view == null) { tip.Opacity = 0; return; }
        var color = node.Kind == NodeKind.FreeSpace ? "StrokeStrong" : "Cat" + node.Category;
        var rows = new Grid { ColumnDefinitions = new ColumnDefinitions("Auto,*"), ColumnSpacing = 16 };
        void Add(string k, string v) { var r = rows.RowDefinitions.Count; rows.RowDefinitions.Add(new RowDefinition(GridLength.Auto)); var a = Label(k, Scale.Secondary, key: "Muted"); var b = Label(v, Scale.Secondary); b.HorizontalAlignment = HorizontalAlignment.Right; Grid.SetRow(a, r); Grid.SetRow(b, r); Grid.SetColumn(b, 1); rows.Children.Add(a); rows.Children.Add(b); }
        Add("大小", DiskText.Size(node.Size)); Add("占目前資料夾", DiskText.Percent(node.Size, view.Size));
        if (node.Kind != NodeKind.FreeSpace)
        {
            Add(node.Kind == NodeKind.File ? "檔案" : "檔案數", DiskText.Count(node.FileCount)); Add("類型", DiskText.Category(node.Category)); Add("最近修改", DiskText.Ago(node.LastWriteUtc));
            if (node.Issue == NodeIssue.AccessDenied) Add("狀態", "無法存取");
        }
        var title = Label(DiskText.Name(node), Scale.Body, FontWeight.SemiBold); title.TextWrapping = TextWrapping.Wrap; title.TextTrimming = TextTrimming.None;
        tip.Child = Column(6, Row(8, new Border { Width = 9, Height = 9, CornerRadius = new CornerRadius(3) }.Res(Border.BackgroundProperty, color), title), rows);
        tip.Measure(new Size(300, double.PositiveInfinity));
        var size = tip.DesiredSize;
        Canvas.SetLeft(tip, Math.Max(4, Math.Min(at.X + 16, ActiveView.Bounds.Width - size.Width - 6)));
        Canvas.SetTop(tip, Math.Max(4, Math.Min(at.Y + 18, ActiveView.Bounds.Height - size.Height - 6)));
        tip.Opacity = 1;
    }

    void ShowMenu(DiskNode node, Point at)
    {
        tip.Opacity = 0;
        var flyout = new MenuFlyout();
        MenuItem Item(string text, string icon, Action run, bool danger = false)
        {
            var item = new MenuItem { Header = text, Icon = Icons.Make(icon, 15, danger ? "Error" : "Muted") };
            if (danger) item.Foreground = (IBrush?)owner.FindResource("Error") ?? Brushes.Red;
            item.Click += (_, _) => run(); return item;
        }
        flyout.Items.Add(Item("在檔案總管顯示", Icons.Folder, () => Report(FileActions.Reveal(node.FullPath, scanRoot), "")));
        if (node.Kind == NodeKind.Directory)
        {
            flyout.Items.Add(Item("放大到此資料夾", Icons.Plus, () => Go(node)));
            flyout.Items.Add(Item("重新掃描此資料夾", Icons.Retry, () => RescanFolder(node)));
        }
        flyout.Items.Add(Item("複製路徑", Icons.Copy, async () => { if (TopLevel.GetTopLevel(map)?.Clipboard is { } c) await c.SetTextAsync(node.FullPath); problem.Show("Ok", "已複製路徑。"); }));
        flyout.Items.Add(new Separator());
        flyout.Items.Add(Item("移到資源回收筒…", Icons.Trash, () => AskDelete(node), danger: true));
        flyout.ShowAt(ActiveView, true);
    }

    // ---------- actions ----------

    void Report(ActionResult result, string success)
    {
        if (result.Status == ActionStatus.Done) { if (success != "") problem.Show("Ok", success); else problem.Hide(); return; }
        problem.Show("Warn", result.Status switch {
            ActionStatus.NotSupported => "這個系統不支援這項動作。", ActionStatus.NotFound => "找不到這個項目，可能已被移動或刪除。",
            ActionStatus.OutsideRoot => "這個項目不在掃描範圍內。", _ => result.Message ?? "動作沒有完成。" });
    }

    void AskDelete(DiskNode node)
    {
        if (scanning || tree == null || node.Kind is not (NodeKind.File or NodeKind.Directory) || node.Parent == null) return;
        var detailText = node.FullPath + "\n" + DiskText.Size(node.Size) + (node.Kind == NodeKind.Directory ? " · " + DiskText.Count(node.FileCount) + " 個檔案" : "");
        AppWindow.Confirm(owner, "移到資源回收筒？", "可以從資源回收筒還原，不會永久刪除。", "移到資源回收筒", () => {
            if (disposed || scanning || tree?.Find(node.FullPath) is not { } live || !ReferenceEquals(live, node)) return;
            var result = FileActions.MoveToRecycleBin(node.FullPath, scanRoot);
            if (result.Status != ActionStatus.Done) { Report(result, ""); return; }
            space = DriveCatalog.Find(scanRoot);
            if (ReferenceEquals(view, node) && node.Parent != null) { view = node.Parent; viewPath = view.FullPath; }
            tree.Remove(node); selected = null; Active(null); Render(true); UpdateStatus();
            problem.Show("Ok", "已移到資源回收筒。");
        }, danger: true, detail: detailText);
    }

    async void RescanFolder(DiskNode node)
    {
        if (tree == null || scanning) return;
        var mine = session; var source = cts = new CancellationTokenSource();
        scanning = true; UpdateChrome();
        problem.Show("Busy", "正在重新掃描 " + node.Name + "…");
        try {
            await tree.RescanAsync(node, null, source.Token); if (session != mine) return;
            view = tree.Find(viewPath) ?? tree.Root; viewPath = view.FullPath;
            selected = selected == null ? null : tree.Find(selected.FullPath); Active(selected);
            problem.Show("Ok", "已更新 " + node.Name + "。");
        }
        catch (OperationCanceledException) { }
        catch (Exception ex) { if (session == mine) problem.Show("Warn", ex.Message); }
        finally { if (session == mine) { scanning = false; Render(true); UpdateStatus(); } }
    }

    // ---------- inspector ----------

    static long[] Breakdown(DiskNode n)
    {
        var sizes = new long[Enum.GetValues<FileCategory>().Length];
        void Walk(DiskNode x)
        {
            if (x.CategorySizes is { } c && x.Kind == NodeKind.Directory) { for (var i = 0; i < Math.Min(c.Length, sizes.Length); i++) sizes[i] += c[i]; return; }
            if (x.Kind == NodeKind.Directory) foreach (var k in x.Children) Walk(k); else sizes[(int)x.Category] += x.Size;
        }
        Walk(n); return sizes;
    }

    void RenderInspector()
    {
        inspector.Children.Clear();
        var n = selected ?? view; if (n == null) return;
        var isView = selected == null; var color = "Cat" + n.Category;
        var head = Column(6,
            Label(isView ? "目前資料夾" : "已選取", Scale.Caption, FontWeight.SemiBold, "Subtle"),
            Row(8, new Border { Width = 10, Height = 10, CornerRadius = new CornerRadius(3) }.Res(Border.BackgroundProperty, color), Label(n.Name == "" ? n.FullPath : n.Name, Scale.Title, FontWeight.SemiBold)),
            new SelectableTextBlock { Text = n.FullPath, FontSize = Scale.Secondary, TextWrapping = TextWrapping.Wrap }.Res(TextBlock.ForegroundProperty, "Muted"),
            Label(DiskText.Size(n.Size), Scale.LargeTitle + 4, FontWeight.Bold));
        var whole = space is { TotalBytes: > 0 } ? space.TotalBytes : top?.Size ?? 1;
        head.Children.Add(Meter(n.Size / (double)Math.Max(1, whole), "Accent", 6));
        var kv = new Grid { ColumnDefinitions = new ColumnDefinitions("*,Auto"), ColumnSpacing = 16, RowSpacing = 4 };
        void Pair(string k, string v) { var r = kv.RowDefinitions.Count; kv.RowDefinitions.Add(new RowDefinition(GridLength.Auto)); var a = Label(k, Scale.Secondary, key: "Muted"); var b = Label(v, Scale.Secondary); Grid.SetRow(a, r); Grid.SetRow(b, r); Grid.SetColumn(b, 1); kv.Children.Add(a); kv.Children.Add(b); }
        Pair(space is { TotalBytes: > 0 } ? "占整個磁碟" : "占掃描範圍", DiskText.Percent(n.Size, whole));
        if (n.Parent != null) Pair("占上層", DiskText.Percent(n.Size, n.Parent.Size));
        Pair("檔案", DiskText.Count(n.FileCount));
        if (n.Kind == NodeKind.Directory) Pair("子資料夾", DiskText.Count(n.DirectoryCount));
        Pair("最近修改", DiskText.Ago(n.LastWriteUtc));
        head.Children.Add(WithMargin(kv, new Thickness(0, 6, 0, 0)));
        inspector.Children.Add(head);

        var sizes = Breakdown(n); var total = Math.Max(1, sizes.Sum());
        var order = Enumerable.Range(0, sizes.Length).Where(i => sizes[i] > 0).OrderByDescending(i => sizes[i]).ToArray();
        if (order.Length > 0)
        {
            var donut = new DonutChart(132, 16).Set(order.Select(i => ("Cat" + (FileCategory)i, (double)sizes[i], categories.Count == 0 || categories.Contains((FileCategory)i) ? 1d : .25)),
                DiskText.Size(total), DiskText.Count(order.Length) + " 種類型");
            donut.HorizontalAlignment = HorizontalAlignment.Center; donut.Margin = new Thickness(0, 4, 0, 6);
            var legend = Column(2);
            foreach (var i in order)
            {
                var cat = (FileCategory)i; var on = categories.Contains(cat);
                var row = Columns("Auto,*,Auto,Auto", new Border { Width = 10, Height = 10, CornerRadius = new CornerRadius(3) }.Res(Border.BackgroundProperty, "Cat" + cat), Label(DiskText.Category(cat), Scale.Body),
                    Label(DiskText.Size(sizes[i]), Scale.Secondary, key: "Muted"), Label(DiskText.Percent(sizes[i], total), Scale.Secondary, FontWeight.SemiBold));
                row.ColumnSpacing = 12; ((Control)row.Children[3]).MinWidth = 40; ((TextBlock)row.Children[3]).TextAlignment = TextAlignment.Right;
                foreach (var c in row.Children) c.VerticalAlignment = VerticalAlignment.Center;
                var b = new Button { Content = row, Padding = new Thickness(8, 6), HorizontalAlignment = HorizontalAlignment.Stretch, HorizontalContentAlignment = HorizontalAlignment.Stretch, BorderThickness = new Thickness(0), CornerRadius = new CornerRadius(Scale.ControlRadius) };
                if (on) b.Res(Button.BackgroundProperty, "AccentSoft"); else b.Background = Brushes.Transparent;
                Avalonia.Automation.AutomationProperties.SetName(b, "只顯示" + DiskText.Category(cat));
                ToolTip.SetTip(b, on ? "再按一次取消篩選" : "只顯示" + DiskText.Category(cat));
                b.Click += (_, _) => { if (!categories.Remove(cat)) categories.Add(cat); ApplyFilter(); };
                legend.Children.Add(b);
            }
            inspector.Children.Add(Column(6, Label("類型分布", Scale.Caption, FontWeight.SemiBold, "Subtle"), donut, legend));
        }

        if (n.Kind == NodeKind.Directory && n.Children.Count > 0)
        {
            var biggest = n.Children.Where(c => c.Size > 0).Take(6).ToList();
            if (biggest.Count > 0)
            {
                var list = Column(2);
                foreach (var c in biggest)
                {
                    var line = Columns("*,Auto", Label(DiskText.Name(c), Scale.Body), Label(DiskText.Size(c.Size), Scale.Secondary, key: "Muted")); line.ColumnSpacing = 12;
                    var row = Column(4, line, Meter(c.Size / (double)Math.Max(1, biggest[0].Size), c.Kind == NodeKind.Aggregate ? "StrokeStrong" : "Cat" + c.Category, 4));
                    var b = new Button { Content = row, Padding = new Thickness(8, 6), HorizontalAlignment = HorizontalAlignment.Stretch, HorizontalContentAlignment = HorizontalAlignment.Stretch, Background = Brushes.Transparent, BorderThickness = new Thickness(0), CornerRadius = new CornerRadius(Scale.ControlRadius) };
                    b.Click += (_, _) => { if (c.Kind is NodeKind.File or NodeKind.Directory) Active(c); };
                    list.Children.Add(b);
                }
                inspector.Children.Add(Column(6, Label("最大的項目", Scale.Caption, FontWeight.SemiBold, "Subtle"), list));
            }
        }

        if (!isView && n.Kind is NodeKind.File or NodeKind.Directory)
        {
            var actions = new WrapPanel { ItemSpacing = 8, LineSpacing = 8 };
            actions.Children.Add(Action("在檔案總管顯示", () => Report(FileActions.Reveal(n.FullPath, scanRoot), ""), Icons.Folder));
            if (n.Kind == NodeKind.Directory) actions.Children.Add(Action("放大", () => Go(n), Icons.Plus));
            var del = Action("移到資源回收筒", () => AskDelete(n), Icons.Trash, danger: true); del.IsEnabled = !scanning;
            actions.Children.Add(del);
            inspector.Children.Add(actions);
        }
    }

    static Control Meter(double fraction, string brush, double height)
    {
        fraction = Math.Clamp(fraction, .01, 1);
        var grid = new Grid { Height = height, ColumnDefinitions = new ColumnDefinitions(), HorizontalAlignment = HorizontalAlignment.Stretch };
        grid.ColumnDefinitions.Add(new ColumnDefinition(fraction, GridUnitType.Star)); grid.ColumnDefinitions.Add(new ColumnDefinition(1 - fraction + .0001, GridUnitType.Star));
        grid.Children.Add(new Border { CornerRadius = new CornerRadius(height / 2) }.Res(Border.BackgroundProperty, brush));
        return new Border { Child = grid, CornerRadius = new CornerRadius(height / 2), ClipToBounds = true }.Res(Border.BackgroundProperty, "IdleSoft");
    }

    // ---------- test access ----------

    internal TreemapView Map => map;
    internal bool IsScanning => scanning;
    internal DiskNode? ViewNode => view;
    internal DiskTree? Tree => tree;
    internal Task WaitScanAsync(TimeSpan timeout) => Task.Run(async () => { var end = DateTime.UtcNow + timeout; while (scanning && DateTime.UtcNow < end) await Task.Delay(50); });
    internal void SetQuery(string text) { search.Text = text; searchTimer?.Stop(); ApplyFilter(); }
    internal string FilterError => filterError;
    internal void GoTop() { if (top != null) Go(top); }
    internal void SetLargestFiles(bool on) { largestFiles = on; setListMode(on ? 1 : 0); Render(false); }
    internal void ZoomTo(string path) { if (top != null && Resolve(top, path) is { Kind: NodeKind.Directory } n) Go(n); }
}
