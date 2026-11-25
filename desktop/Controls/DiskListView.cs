using Avalonia;
using Avalonia.Controls;
using Avalonia.Controls.Primitives;
using Avalonia.Input;
using Avalonia.Layout;
using Avalonia.Media;
using Suhang.Desktop.DiskUsage;
using static Suhang.Desktop.TreemapView;

namespace Suhang.Desktop;

/// The current folder as a ranked table (TreeSize/WizTree-style): one row per child with a share bar, or the largest
/// files anywhere below it. Same events as the treemap so the analyzer can swap views without rewiring.
internal sealed class DiskListView : Border
{
    public event Action<DiskNode?>? SelectionChanged;
    public event Action<DiskNode>? Opened;
    public event Action<DiskNode, Point>? MenuRequested;

    public enum Sort { Size, Name, Modified }
    const int MaxRows = 300, MaxFiles = 200;
    const string Columns = "30,*,150,84,60,84,92";
    readonly StackPanel rows = new();
    readonly ScrollViewer scroller;
    readonly Grid header;
    readonly List<(DiskNode Node, Border Row)> built = new();
    readonly TextBlock footer = Label("", Scale.Secondary, key: "Subtle");
    DiskNode? root; bool largest, byAge;
    Sort sort = Sort.Size; bool descending = true;
    Func<DiskNode, bool>? dimmed;
    public DiskNode? Selected { get; private set; }
    internal int RowCount => built.Count;

    public Func<DiskNode, bool>? Dimmed { get => dimmed; set { dimmed = value; foreach (var (n, r) in built) r.Opacity = Dim(n) ? .35 : 1; } }
    public bool ColorByAge { get => byAge; set { if (byAge == value) return; byAge = value; Rebuild(); } }

    public DiskListView()
    {
        header = HeaderRow();
        footer.Margin = new Thickness(16, 12, 0, 6);
        scroller = new ScrollViewer { Content = new StackPanel { Children = { rows, footer } }, HorizontalScrollBarVisibility = ScrollBarVisibility.Disabled, Padding = new Thickness(6, 0, 6, 6) };
        var rule = Rule(); rule.Margin = new Thickness(12, 0);
        Child = new Grid { RowDefinitions = new RowDefinitions("Auto,Auto,*"), Children = { header, rule, scroller } };
        Grid.SetRow(rule, 1); Grid.SetRow(scroller, 2);
        ActualThemeVariantChanged += (_, _) => Rebuild();
    }

    public void SetView(DiskNode? view, bool largestFiles)
    {
        var reset = !ReferenceEquals(view, root) && (view == null || root == null || view.FullPath != root.FullPath) || largestFiles != largest;
        root = view; largest = largestFiles;
        Rebuild();
        if (reset) scroller.Offset = default;
    }

    public void Select(DiskNode? node)
    {
        Selected = node is { Kind: NodeKind.File or NodeKind.Directory } ? node : null;
        foreach (var (n, r) in built) Paint(r, n, false);
        SelectionChanged?.Invoke(Selected);
    }

    bool Dim(DiskNode n) => dimmed is { } f && f(n);
    bool IsSelected(DiskNode n) => Selected != null && n.Kind != NodeKind.Aggregate && n.FullPath == Selected.FullPath;

    // ---------- rows ----------

    Grid HeaderRow()
    {
        var g = new Grid { ColumnDefinitions = new ColumnDefinitions(Columns), Margin = new Thickness(12, 8, 20, 6), ColumnSpacing = 12 };
        void Add(int col, string text, Sort? by, bool right = false)
        {
            Control c = Label(text, Scale.Caption, FontWeight.SemiBold, "Subtle");
            if (by is { } s)
            {
                var b = new Button { Content = c, Padding = new Thickness(4, 2), Background = Brushes.Transparent, BorderThickness = new Thickness(0), HorizontalAlignment = right ? HorizontalAlignment.Right : HorizontalAlignment.Left };
                b.Click += (_, _) => { if (sort == s) descending = !descending; else { sort = s; descending = s != Sort.Name; } Rebuild(); };
                c = b;
            }
            else { c.HorizontalAlignment = right ? HorizontalAlignment.Right : HorizontalAlignment.Left; c.Margin = new Thickness(4, 2); }
            c.VerticalAlignment = VerticalAlignment.Center;
            Grid.SetColumn(c, col); g.Children.Add(c);
        }
        Add(1, "名稱", Sort.Name); Add(2, "占用", null); Add(3, "大小", Sort.Size, true); Add(4, "比例", null, true); Add(5, "檔案", null, true); Add(6, "修改", Sort.Modified, true);
        return g;
    }

    void Rebuild()
    {
        rows.Children.Clear(); built.Clear(); footer.Text = "";
        foreach (var b in header.Children.OfType<Button>()) ((TextBlock)b.Content!).Text = Title((TextBlock)b.Content!);
        if (root == null) return;
        List<DiskNode> items; long hidden = 0;
        lock (root.Gate)
        {
            if (largest) items = LargestFiles(root, MaxFiles);
            else { items = root.Children.Where(c => c.Size > 0).ToList(); hidden = Math.Max(0, items.Count - MaxRows); }
        }
        IEnumerable<DiskNode> sorted = sort switch {
            Sort.Name => descending ? items.OrderByDescending(n => DiskText.Name(n), StringComparer.CurrentCultureIgnoreCase) : items.OrderBy(n => DiskText.Name(n), StringComparer.CurrentCultureIgnoreCase),
            Sort.Modified => descending ? items.OrderByDescending(n => n.LastWriteUtc) : items.OrderBy(n => n.LastWriteUtc),
            _ => descending ? items.OrderByDescending(n => n.Size) : items.OrderBy(n => n.Size),
        };
        var max = items.Count == 0 ? 1 : Math.Max(1, items.Max(n => n.Size));
        foreach (var n in sorted.Take(MaxRows)) { var r = BuildRow(n, max); built.Add((n, r)); rows.Children.Add(r); }
        footer.Text = items.Count == 0 ? (largest ? "這個位置沒有個別列出的檔案。" : "這個位置沒有檔案。")
            : largest ? "列出 " + root.Name + " 之下最大的 " + DiskText.Count(items.Count) + " 個檔案（小檔案已合併計算，不逐一列出）"
            : hidden > 0 ? "另有 " + DiskText.Count(hidden) + " 個較小的項目未列出" : "";
    }

    string Title(TextBlock t)
    {
        var plain = t.Text!.TrimEnd(' ', '↓', '↑');
        var mine = plain switch { "名稱" => Sort.Name, "大小" => Sort.Size, "修改" => Sort.Modified, _ => (Sort?)null };
        return mine == sort ? plain + (descending ? " ↓" : " ↑") : plain;
    }

    static List<DiskNode> LargestFiles(DiskNode from, int count)
    {
        var heap = new PriorityQueue<DiskNode, long>();
        var stack = new Stack<DiskNode>(); stack.Push(from);
        while (stack.TryPop(out var n))
            foreach (var c in n.Children)
                if (c.Kind == NodeKind.Directory) stack.Push(c);
                else if (c.Kind == NodeKind.File && c.Size > 0)
                {
                    if (heap.Count < count) heap.Enqueue(c, c.Size);
                    else if (heap.TryPeek(out _, out var least) && c.Size > least) heap.EnqueueDequeue(c, c.Size);
                }
        var list = new List<DiskNode>(heap.Count);
        while (heap.TryDequeue(out var n, out _)) list.Add(n);
        list.Reverse(); return list;
    }

    Border BuildRow(DiskNode n, long max)
    {
        var g = new Grid { ColumnDefinitions = new ColumnDefinitions(Columns), ColumnSpacing = 12 };
        var hue = "Cat" + n.Category;
        Control icon = n.Kind switch {
            NodeKind.Directory => Icons.Make(Icons.Folder, 17, hue),
            NodeKind.Aggregate => new Border { Width = 10, Height = 10, CornerRadius = new CornerRadius(3), BorderThickness = new Thickness(1) }.Res(Border.BorderBrushProperty, "StrokeStrong"),
            _ => new Border { Width = 10, Height = 10, CornerRadius = new CornerRadius(3) }.Res(Border.BackgroundProperty, hue),
        };
        if (byAge && n.Kind != NodeKind.Aggregate)
        {
            icon = n.Kind == NodeKind.Directory ? Icons.Make(Icons.Folder, 17, "Muted") : new Border { Width = 10, Height = 10, CornerRadius = new CornerRadius(3), Background = AgeBrush(n) };
        }
        icon.HorizontalAlignment = HorizontalAlignment.Center; icon.VerticalAlignment = VerticalAlignment.Center;

        var name = Label(DiskText.Name(n), Scale.Body, n.Kind == NodeKind.Directory ? FontWeight.SemiBold : FontWeight.Normal, n.Kind == NodeKind.Aggregate ? "Muted" : "Ink");
        Control nameCell = name;
        if (largest && root != null && n.Parent != null)
        {
            var rel = Path.GetRelativePath(root.FullPath, n.Parent.FullPath);
            nameCell = Column(2, name, Label(rel == "." ? "（此資料夾）" : rel, Scale.Caption, key: "Subtle"));
        }
        nameCell.VerticalAlignment = VerticalAlignment.Center;

        var share = Math.Clamp(n.Size / (double)max, 0, 1);
        var fill = new Border { CornerRadius = new CornerRadius(3), HorizontalAlignment = HorizontalAlignment.Left };
        if (byAge) fill.Background = AgeBrush(n); else fill.Res(Border.BackgroundProperty, n.Kind == NodeKind.Aggregate ? "StrokeStrong" : hue);
        var track = new Border { Height = 8, CornerRadius = new CornerRadius(3), Child = fill, ClipToBounds = true, VerticalAlignment = VerticalAlignment.Center }.Res(Border.BackgroundProperty, "IdleSoft");
        track.SizeChanged += (_, e) => fill.Width = Math.Max(share > 0 ? 3 : 0, e.NewSize.Width * share);

        TextBlock Right(string s, string key = "Muted") { var t = Label(s, Scale.Secondary, key: key); t.HorizontalAlignment = HorizontalAlignment.Right; t.VerticalAlignment = VerticalAlignment.Center; return t; }
        var size = Right(DiskText.Size(n.Size), "Ink"); size.FontWeight = FontWeight.SemiBold;
        var cells = new Control[] { icon, nameCell, track, size, Right(root is { Size: > 0 } ? DiskText.Percent(n.Size, root.Size) : "—"),
            Right(n.Kind == NodeKind.File ? "—" : DiskText.Count(n.FileCount)), Right(DiskText.Ago(n.LastWriteUtc)) };
        for (var i = 0; i < cells.Length; i++) { Grid.SetColumn(cells[i], i); g.Children.Add(cells[i]); }

        var row = new Border { Child = g, Padding = new Thickness(6, largest ? 6 : 7, 12, largest ? 6 : 7), CornerRadius = new CornerRadius(Scale.ControlRadius), Background = Brushes.Transparent, Opacity = Dim(n) ? .35 : 1 };
        row.Transitions = [new Avalonia.Animation.DoubleTransition { Property = Visual.OpacityProperty, Duration = TimeSpan.FromMilliseconds(180) }];
        Paint(row, n, false);
        row.PointerEntered += (_, _) => Paint(row, n, true);
        row.PointerExited += (_, _) => Paint(row, n, false);
        row.PointerPressed += (_, e) => {
            var pt = e.GetCurrentPoint(row);
            if (pt.Properties.IsRightButtonPressed) { if (n.Kind is NodeKind.File or NodeKind.Directory) { Select(n); MenuRequested?.Invoke(n, e.GetPosition(this)); } e.Handled = true; return; }
            if (!pt.Properties.IsLeftButtonPressed) return;
            if (e.ClickCount >= 2 && n.Kind == NodeKind.Directory) { Opened?.Invoke(n); e.Handled = true; return; }
            Select(n.Kind == NodeKind.Aggregate ? null : n); e.Handled = true;
        };
        row.Cursor = n.Kind == NodeKind.Directory ? new Cursor(StandardCursorType.Hand) : Cursor.Default;
        return row;
    }

    void Paint(Border row, DiskNode n, bool hover)
    {
        var key = IsSelected(n) ? "AccentSoft" : hover ? "IdleSoft" : null;
        row.Background = key != null && this.TryFindResource(key, ActualThemeVariant, out var v) && v is IBrush b ? b : Brushes.Transparent;
    }

    IBrush AgeBrush(DiskNode n)
    {
        Color C(string key) => this.TryFindResource(key, ActualThemeVariant, out var v) && v is SolidColorBrush b ? b.Color : Colors.Gray;
        return new SolidColorBrush(Mix(C("AgeNew"), C("AgeOld"), Math.Clamp((DateTime.UtcNow - n.LastWriteUtc).TotalDays / 540, 0, 1)));
    }
}
