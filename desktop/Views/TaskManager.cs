using Avalonia;
using Avalonia.Automation;
using Avalonia.Controls;
using Avalonia.Controls.Primitives;
using Avalonia.Controls.Presenters;
using Avalonia.Markup.Xaml.MarkupExtensions;
using Avalonia.Controls.Templates;
using Avalonia.Input;
using Avalonia.Layout;
using Avalonia.Media;
using Avalonia.Media.Imaging;
using Avalonia.Styling;
using Avalonia.Threading;
using Avalonia.VisualTree;

namespace Suhang.Desktop;

/// The task manager: running programs with their icon, resource use and signature verdict. It is a plain control
/// hosted as the first tab of the security window. Nothing runs until the tab is shown (`Activate`); hiding the tab
/// or minimizing the window stops sampling, and `Dispose` releases the process inventory.
internal sealed class TaskManagerView : IDisposable
{
    public Control View { get; }
    readonly bool preview;
    ProcessInventory? inventory;
    DispatcherTimer? timer;
    bool active, disposed, capturing, previewSeeded;
    int session;
    readonly ListBox list;
    readonly TextBox search;
    readonly CheckBox attention;
    readonly ToggleSwitch automatic;
    readonly TextBlock count, rateNote, detailTitle, detailReason, detailText, detailSummary;
    readonly Notice problem = new();
    readonly Border empty;
    readonly StatusPill detailPill;
    readonly Button reverify, copy;
    readonly ScrollViewer detailScroll;
    readonly Dictionary<string, TextBlock> headings = new();
    internal RunningProgram[] Programs { get; set; } = [];
    string sort = "assessment";
    bool descending;
    // Name stretches; the numeric columns are right-aligned so units line up.
    const string Columns8 = "*,56,60,84,88,88,170,110";
    const double TableMinWidth = 880, DetailShare = .3;
    static readonly (string Key, string Title, bool Numeric)[] ColumnSpecs = [
        ("name", "程式名稱", false), ("pid", "PID", true), ("cpu", "CPU", true), ("memory", "記憶體", true), ("disk", "磁碟讀取", true), ("network", "網路收發", true),
        ("assessment", "來源判斷", false), ("trust", "簽章", false)];

    internal ListBox List => list;
    internal TextBox Search => search;
    internal CheckBox Attention => attention;
    internal Button Reverify => reverify;
    internal Border Empty => empty;
    internal ScrollViewer DetailScroll => detailScroll;
    internal TextBlock DetailReason => detailReason;
    internal TextBlock DetailText => detailText;
    internal StatusPill DetailPill => detailPill;
    internal bool IsSampling => timer?.IsEnabled == true;
    internal ProcessInventory? Inventory => inventory;

    public TaskManagerView(bool preview)
    {
        this.preview = preview;
        count = Label("正在讀取執行中的程式…", Scale.Secondary, key: "Muted");
        rateNote = Label("", Scale.Caption, key: "Subtle"); rateNote.IsVisible = false;
        reverify = Action("重新驗證簽章", () => { inventory?.Reverify(); _ = CaptureAsync(); });
        (search, attention, automatic) = (new TextBox(), new CheckBox(), Switch());
        var toolbar = BuildToolbar();
        list = new ListBox();
        empty = new Border();
        var table = BuildTable();
        detailTitle = Label("", Scale.Section, FontWeight.SemiBold);
        detailPill = new StatusPill("", Scale.Caption);
        detailSummary = Hint("", "Muted", Scale.Secondary);
        detailReason = Hint("", "Ink", Scale.Body);
        detailText = new SelectableTextBlock { FontSize = Scale.Secondary, TextWrapping = TextWrapping.Wrap }.Res(TextBlock.ForegroundProperty, "Muted");
        copy = Action("複製路徑", CopyPathAsync, Icons.Copy);
        var details = BuildDetails();
        // The table takes the height; the detail panel sizes to its content but never beyond a share of the view, scrolling inside.
        detailScroll = new ScrollViewer { Content = details, HorizontalScrollBarVisibility = ScrollBarVisibility.Disabled, VerticalScrollBarVisibility = ScrollBarVisibility.Auto, MaxHeight = DetailShare * 400 };
        var footnote = Hint("依簽章、系統結構與 Windows 檔案保護判斷來源 · 本機驗證，不連線查詢吊銷 · — 表示未取得", "Subtle", Scale.Caption);
        ToolTip.SetTip(footnote, "選擇程式可查看依據 · 簽章快取最長 30 秒 · CPU 依全部邏輯核心計算 · 1 MB = 1024 KB");
        var notes = Column(2, count, rateNote, footnote);
        notes.Margin = new Thickness(0, 8, 0, 0);
        problem.Margin = new Thickness(0, 8, 0, 0);
        var root = Rows("Auto,*,Auto,Auto,Auto", toolbar, table, detailScroll, notes, problem);
        root.SizeChanged += (_, e) => detailScroll.MaxHeight = Math.Max(96, e.NewSize.Height * DetailShare);
        View = root;
        search.TextChanged += (_, _) => Render();
        attention.IsCheckedChanged += (_, _) => Render();
        list.SelectionChanged += (_, _) => RenderDetails();
        RenderDetails();
        if (!preview && !OperatingSystem.IsWindows()) {
            problem.Show("Warn", "工作管理員與 Authenticode 憑證驗證需在 Windows 執行。");
            count.Text = "未取得 Windows 進程資料。"; reverify.IsEnabled = automatic.IsEnabled = false;
            ShowEmpty("此功能只能在 Windows 使用", "目前的系統沒有提供進程與簽章資料。");
        }
    }

    // ---------- lifecycle ----------

    /// The tab became visible: start sampling (or show the fixtures in a preview).
    public void Activate()
    {
        if (disposed || active) return;
        active = true; session++;
        if (preview) { if (!previewSeeded) { previewSeeded = true; SeedPreview(); } return; }
        if (!OperatingSystem.IsWindows()) return;
        inventory = new ProcessInventory();
        timer = new DispatcherTimer { Interval = TimeSpan.FromSeconds(3) };
        timer.Tick += (_, _) => { if (automatic.IsChecked == true && IsShown) _ = CaptureAsync(); };
        timer.Start(); _ = CaptureAsync();
    }

    /// The tab was hidden: stop the timer and release the inventory (its sampler and signature workers).
    public void Deactivate()
    {
        if (!active) return;
        active = false; session++;
        timer?.Stop(); timer = null;
        inventory?.Dispose(); inventory = null;
        capturing = false; reverify.IsEnabled = OperatingSystem.IsWindows() || preview;
    }

    public void Dispose()
    {
        if (disposed) return;
        Deactivate(); disposed = true; Programs = [];
    }

    /// Sampling only while the tab is the visible one and its window is not minimized.
    bool IsShown => active && !disposed && View.IsAttachedToVisualTree() && TopLevel.GetTopLevel(View) is Window { WindowState: not WindowState.Minimized };

    // ---------- input ----------

    /// Ctrl+F focuses the search box and F5 refreshes; true when the key was used.
    public bool HandleKey(KeyEventArgs e)
    {
        if (e.Key == Key.F && e.KeyModifiers == KeyModifiers.Control) { search.Focus(); search.SelectAll(); return true; }
        if (e.Key == Key.F5) { _ = CaptureAsync(); return true; }
        return false;
    }

    public void Refresh() => _ = CaptureAsync();

    // ---------- building ----------

    Control BuildToolbar()
    {
        search.Watermark = "搜尋程式、PID、簽署者或路徑"; search.MinWidth = 160;
        search.InnerLeftContent = WithMargin(Icons.Make(Icons.Search, 14, "Subtle"), new Thickness(10, 0, 0, 0));
        AutomationProperties.SetName(search, "搜尋執行中的程式");
        attention.Content = "只看需注意項"; attention.VerticalAlignment = VerticalAlignment.Center;
        automatic.IsChecked = true;
        AutomationProperties.SetName(automatic, "每三秒更新進程列表");
        var toolbar = Columns("*,Auto,Auto,Auto", search, attention, Row(8, Label("自動更新", Scale.Secondary, key: "Muted"), automatic), reverify);
        toolbar.ColumnSpacing = 16; toolbar.Margin = new Thickness(0, 0, 0, 8);
        return toolbar;
    }

    Control BuildTable()
    {
        list.SelectionMode = SelectionMode.Single; list.Padding = new Thickness(0); list.BorderThickness = new Thickness(0); list.Background = Brushes.Transparent;
        AutomationProperties.SetName(list, "執行中的程式與簽章驗證結果");
        list.ItemTemplate = new FuncDataTemplate<RunningProgram>((item, _) => item == null ? new Border() : BuildRow(item));
        list.Styles.Add(new Style(x => x.OfType<ListBoxItem>()) {
            Setters = { new Setter(ListBoxItem.PaddingProperty, new Thickness(0)), new Setter(ListBoxItem.MinHeightProperty, 0.0), new Setter(ListBoxItem.HorizontalContentAlignmentProperty, HorizontalAlignment.Stretch) }
        });
        foreach (var state in new[] { ":selected", ":selected:pointerover", ":selected:pressed" })
            list.Styles.Add(new Style(x => x.OfType<ListBoxItem>().Class(state).Template().OfType<ContentPresenter>()) { Setters = { new Setter(ContentPresenter.BackgroundProperty, new DynamicResourceExtension("AccentSoft")) } });
        var header = new Grid { ColumnDefinitions = new ColumnDefinitions(Columns8), Margin = new Thickness(12, 0, 12, 0), ColumnSpacing = 8 };
        for (var i = 0; i < ColumnSpecs.Length; i++) {
            var (key, title, numeric) = ColumnSpecs[i];
            var label = Label(title, Scale.Secondary, FontWeight.SemiBold, "Muted"); headings[key] = label;
            // The name column starts after the program icon, like its rows.
            var button = new Button { Content = label, Background = Brushes.Transparent, BorderThickness = new Thickness(0), Padding = new Thickness(key == "name" ? ProgramIconView.Size + 8 : 0, 7, 0, 7), HorizontalAlignment = HorizontalAlignment.Stretch, HorizontalContentAlignment = numeric ? HorizontalAlignment.Right : HorizontalAlignment.Left };
            AutomationProperties.SetName(button, "依" + title + "排序");
            button.Click += (_, _) => {
                descending = sort == key ? !descending : key is "cpu" or "memory" or "disk" or "network";
                sort = key; Render();
            };
            Grid.SetColumn(button, i); header.Children.Add(button);
        }
        empty.VerticalAlignment = VerticalAlignment.Top; empty.Child = EmptyState.Make(Icons.Apps, "正在讀取執行中的程式…");
        var body = new Grid { Children = { list, empty } };
        var grid = Rows("Auto,*", new Border { Child = header, BorderThickness = new Thickness(0, 0, 0, 1) }.Res(Border.BackgroundProperty, "Field").Res(Border.BorderBrushProperty, "Stroke"), body);
        grid.MinWidth = TableMinWidth;
        var scroll = new ScrollViewer { Content = grid, HorizontalScrollBarVisibility = ScrollBarVisibility.Auto, VerticalScrollBarVisibility = ScrollBarVisibility.Disabled };
        // A horizontal ScrollViewer measures its content without a width limit; follow the viewport instead.
        scroll.SizeChanged += (_, e) => grid.Width = Math.Max(TableMinWidth, e.NewSize.Width);
        return new Border { Child = scroll, BorderThickness = new Thickness(1), CornerRadius = new CornerRadius(Scale.CardRadius), ClipToBounds = true }.Res(Border.BorderBrushProperty, "Stroke").Res(Border.BackgroundProperty, "Card");
    }

    Control BuildDetails()
    {
        // Path, publisher and certificate lines stay folded until asked for, so the collapsed panel is two lines tall.
        var technical = Column(6, detailSummary, detailText); technical.IsVisible = false;
        var toggle = Action("詳細資料 ▾", () => { }); var toggleLabel = (TextBlock)toggle.Content!;
        toggle.Click += (_, _) => { technical.IsVisible = !technical.IsVisible; toggleLabel.Text = technical.IsVisible ? "詳細資料 ▴" : "詳細資料 ▾"; };
        AutomationProperties.SetName(toggle, "顯示或隱藏路徑、憑證與技術細節");
        copy.IsEnabled = false;
        var heading = Columns("Auto,Auto,*,Auto,Auto", detailTitle, detailPill, Gap(), toggle, copy); heading.ColumnSpacing = 10;
        var card = Card(Column(4, heading, detailReason, technical), new Thickness(14, 10));
        card.Margin = new Thickness(0, 8, 0, 0); return card;
    }

    async void CopyPathAsync()
    {
        if (TopLevel.GetTopLevel(View)?.Clipboard is { } clipboard && list.SelectedItem is RunningProgram item) {
            await clipboard.SetTextAsync(item.Path);
            if (!disposed) count.Text = "已複製程式路徑。";
        }
    }

    void ShowEmpty(string title, string text)
    {
        empty.Child = EmptyState.Make(Icons.Apps, title, text); empty.IsVisible = true;
    }

    // ---------- sampling ----------

    async Task CaptureAsync()
    {
        if (!active || capturing || preview) return;
        var owner = session; var source = inventory; if (source == null) return;
        capturing = true; reverify.IsEnabled = false;
        var initialPending = true;
        try {
            Action<RunningProgram[]>? initial = Programs.Length == 0 ? rows => Dispatcher.UIThread.Post(() => {
                if (!initialPending || session != owner || inventory != source) return;
                Programs = rows; Render();
            }, DispatcherPriority.Normal) : null;
            var snapshot = await Task.Run(() => source.Capture(initial));
            if (session != owner) return;
            Programs = snapshot; ShowRateStatus(source.RateStatus); Render();
        } catch {
            if (session != owner) return;
            problem.Show("Warn", "無法更新進程列表，已保留上次結果。請按「重新整理」重試。");
        } finally {
            initialPending = false;
            if (session == owner) { capturing = false; reverify.IsEnabled = true; }
        }
    }

    /// The sampler's explanation is a footnote; only a failed or lost measurement is raised as a banner.
    void ShowRateStatus(string status)
    {
        var failed = status.Contains("系統管理員") || status.Contains("無法") || status.Contains("遺失") || status.Contains("停止");
        if (failed) problem.Show("Warn", status); else problem.Hide();
        rateNote.Text = failed ? "" : status; rateNote.IsVisible = !failed && status.Length > 0; ToolTip.SetTip(rateNote, status);
    }

    // ---------- rows ----------

    Control BuildRow(RunningProgram item)
    {
        TextBlock Cell(string text, string key = "Ink") => WithAlign(Label(text, Scale.Secondary, key: key), HorizontalAlignment.Right);
        var assessment = Row(7, new Border { Width = 7, Height = 7, CornerRadius = new CornerRadius(4) }.Res(Border.BackgroundProperty, item.Assessment.Tone == "Muted" ? "Idle" : item.Assessment.Tone),
            Label(item.Assessment.Label, Scale.Secondary, FontWeight.SemiBold, item.Assessment.Tone));
        var name = Columns("Auto,*", new ProgramIconView(item.Path), WithMargin(Label(item.Name, Scale.Body), new Thickness(8, 0, 0, 0)));
        name.Children[1].VerticalAlignment = VerticalAlignment.Center;
        var row = Columns(Columns8, name, Cell(item.Pid.ToString(), "Muted"), Cell(item.CpuText), Cell(item.MemoryText), Cell(item.DiskReadText), Cell(item.NetworkText),
            assessment, Label(item.SignatureLabel, Scale.Secondary, FontWeight.SemiBold, item.SignatureTone));
        row.ColumnSpacing = 8; row.Margin = new Thickness(12, 4);
        ToolTip.SetTip(row, item.Path + "\n" + item.SignatureLabel + (item.Trust.Publisher.Length > 0 ? " · " + item.Trust.Publisher : "") + "\n" + item.Assessment.Reason + "\n磁碟讀取：" + item.DiskReadText + "\n網路接收：" + ProcessRate.Format(item.NetworkReceive) + " · 發送：" + ProcessRate.Format(item.NetworkSend));
        AutomationProperties.SetName(row, $"{item.Name}，PID {item.Pid}，{item.Assessment.Label}，磁碟讀取 {item.DiskReadText}，網路收發 {item.NetworkText}，{item.SignatureLabel}，{item.Trust.Publisher}，{item.Assessment.Reason}");
        return new Border { Child = row, BorderThickness = new Thickness(0, 0, 0, 1) }.Res(Border.BorderBrushProperty, "Stroke");
    }

    internal static RunningProgram[] Filter(IEnumerable<RunningProgram> source, string search, bool attention, string sort, bool descending)
    {
        var rows = source.Where(p => (!attention || p.Assessment.Attention) && p.Matches(search.Trim()));
        Func<RunningProgram, IComparable> key = sort switch {
            "name" => p => p.Name.ToUpperInvariant(), "pid" => p => p.Pid,
            "cpu" => p => p.Cpu ?? -1, "memory" => p => p.Memory ?? -1,
            "disk" => p => p.DiskRead ?? -1, "network" => p => p.Network ?? -1,
            "assessment" => p => p.Assessment.Priority,
            "trust" => p => p.Assessment.SignatureApplicable ? p.Trust.Priority : 5,
            "publisher" => p => p.Trust.Publisher.ToUpperInvariant(), "reason" => p => p.Assessment.Reason,
            _ => p => p.Assessment.Priority
        };
        return (descending ? rows.OrderByDescending(key) : rows.OrderBy(key)).ThenBy(p => p.Name, StringComparer.OrdinalIgnoreCase).ThenBy(p => p.Pid).ToArray();
    }

    internal void Render()
    {
        if (disposed) return;
        var selected = list.SelectedItem as RunningProgram;
        var rows = Filter(Programs, search.Text ?? "", attention.IsChecked == true, sort, descending);
        // Replacing the source resets the scroll position: skip it when nothing visible changed and restore it otherwise.
        if (list.ItemsSource is not RunningProgram[] shown || !shown.SequenceEqual(rows)) {
            var scroller = list.Scroll as ScrollViewer; var offset = scroller?.Offset ?? default;
            list.ItemsSource = rows;
            if (scroller != null && offset.Y > 0) Dispatcher.UIThread.Post(() => scroller.Offset = offset, DispatcherPriority.Loaded);
        }
        list.SelectedItem = rows.FirstOrDefault(p => p.Pid == selected?.Pid && p.Started == selected.Started);
        foreach (var (key, label) in headings) {
            var title = label.Text!.TrimEnd(' ', '↑', '↓');
            label.Text = title + (key == sort ? descending ? " ↓" : " ↑" : "");
        }
        var needAttention = Programs.Count(p => p.Assessment.Attention);
        attention.Content = needAttention > 0 ? $"只看需注意項（{needAttention}）" : "只看需注意項";
        empty.IsVisible = rows.Length == 0;
        if (rows.Length == 0) {
            if (Programs.Length == 0) ShowEmpty("正在讀取執行中的程式…", "第一次讀取會先列出程式，簽章稍後陸續驗證。");
            else { empty.Child = EmptyState.Make(Icons.Search, "沒有符合條件的程式", "請調整搜尋文字，或取消「只看需注意項」。", Action("清除篩選", () => { search.Text = ""; attention.IsChecked = false; })); }
        }
        var pending = Programs.Count(p => p.Trust.Status == "pending");
        count.Text = preview ? "介面預覽 · 範例資料，不代表實際 Windows 進程或憑證狀態" :
            $"顯示 {rows.Length} / {Programs.Length} 個程式 · {Programs.Count(p => p.Trust.Status == "valid")} 個簽章有效 · {needAttention} 個需注意" + (pending > 0 ? $" · {pending} 個等待驗證" : "") + $" · 更新於 {DateTime.Now:HH:mm:ss}";
        RenderDetails();
    }

    void RenderDetails()
    {
        if (list.SelectedItem is not RunningProgram item) {
            detailTitle.Text = "選擇程式以查看簽章與憑證"; detailPill.IsVisible = false;
            detailReason.Text = detailText.Text = detailSummary.Text = ""; copy.IsEnabled = false; return;
        }
        var trust = item.Trust;
        copy.IsEnabled = item.Path.Length > 0;
        detailTitle.Text = $"{item.Name} · PID {item.Pid}";
        detailPill.IsVisible = true; detailPill.Set(item.SignatureTone == "Muted" ? "Idle" : item.SignatureTone, item.SignatureLabel);
        detailReason.Text = item.Assessment.Label + "：" + item.Assessment.Reason; detailReason.Res(TextBlock.ForegroundProperty, item.Assessment.Tone == "Muted" ? "Ink" : item.Assessment.Tone);
        var publisher = trust.Publisher.Length > 0 ? (trust.Status == "valid" ? "已驗證簽署者：" : "聲稱的簽署者：") + trust.Publisher : "";
        detailSummary.Text = "程式路徑：" + (item.Path.Length > 0 ? item.Path : "未取得一般 EXE 路徑") + (publisher.Length > 0 ? " · " + publisher : "");
        ToolTip.SetTip(detailSummary, detailSummary.Text);
        var lines = new List<string> { "磁碟讀取 " + item.DiskReadText + " · 網路接收 " + ProcessRate.Format(item.NetworkReceive) + " · 網路發送 " + ProcessRate.Format(item.NetworkSend) };
        if(item.Shape is { } shape) lines.Add($"系統快照：名稱 {shape.Name} · 父 PID {shape.ParentPid} · 執行緒 {shape.Threads} · 工作階段 {shape.Session?.ToString() ?? "未知"}");
        if(trust.WindowsProtected is bool wrp) lines.Add("Windows Resource Protection："+(wrp?"列為保護檔案，尚不代表內容完整":"未列為保護檔案，不代表不安全"));
        if(trust.ClaimedCompany!="")lines.Add("檔案聲稱的公司（可偽造）："+trust.ClaimedCompany);
        if(trust.ClaimedOriginalName!="")lines.Add("檔案聲稱的原始名稱（可偽造）："+trust.ClaimedOriginalName);
        if (trust.Subject.Length > 0) lines.Add("憑證主體：" + trust.Subject);
        if (trust.Issuer.Length > 0) lines.Add("憑證簽發者：" + trust.Issuer);
        if (trust.NotBefore.Length > 0) lines.Add("憑證有效期間：" + DisplayDate(trust.NotBefore) + " — " + DisplayDate(trust.NotAfter));
        if (trust.Timestamped) lines.Add(trust.Status == "valid" ? "時間戳記：Windows 已接受時間戳記簽章" : "時間戳記：存在，尚未通過整體驗證");
        if (trust.Thumbprint.Length > 0) lines.Add("憑證指紋（SHA-1）：" + trust.Thumbprint);
        if (trust.Source.Length > 0) lines.Add("簽章來源：" + trust.Source);
        if (trust.Hash.Length > 0) lines.Add("程式 SHA-256：" + trust.Hash);
        if (trust.CheckedAt.Length > 0) lines.Add("驗證時間：" + DisplayDate(trust.CheckedAt));
        if (trust.Code.Length > 0) lines.Add("Windows 驗證代碼（供技術支援）：" + trust.Code);
        detailText.Text = string.Join("\n", lines);
    }
    static string DisplayDate(string value) => DateTimeOffset.TryParse(value, out var time) ? time.ToLocalTime().ToString("yyyy-MM-dd HH:mm:ss zzz") : value;

    // ---------- previews ----------

    internal void SeedPreview()
    {
        var valid = ProcessTrust.FromCode(0) with {
            VerifiedMicrosoft=true, Publisher = "Microsoft Windows", Subject = "CN=Microsoft Windows, O=Microsoft Corporation", Issuer = "Microsoft Windows Production PCA",
            NotBefore = "2024-01-01T00:00:00Z", NotAfter = "2026-01-01T00:00:00Z", Source = "系統目錄簽章（SHA256）",
            Timestamped = true, CheckedAt = "2026-10-10T10:00:00Z", Thumbprint = new string('A', 40), Hash = new string('B', 64)
        };
        Programs = [
            new(1840, 1, "explorer.exe", @"C:\Windows\explorer.exe", "a", 0.4, 164 * 1048576, valid, 2.5*1048576, 128*1024, 32*1024),
            new(6124, 2, "Browser.exe", @"C:\Program Files\Example\Browser.exe", "b", 7.8, 820 * 1048576, valid with { Publisher = "Example Software", VerifiedMicrosoft=false }, 32*1024, 4*1048576, 256*1024),
            new(7312, 3, "UpdateHelper.exe", @"C:\Users\Example\AppData\Local\Temp\UpdateHelper.exe", "c", 1.2, 26 * 1048576, ProcessTrust.FromCode(0x80096010) with { Publisher = "Unknown publisher" }),
            new(4216, 4, "Tool.exe", @"C:\Tools\Tool.exe", "d", 0, 18 * 1048576, ProcessTrust.FromCode(0x800B0100)),
            new(8756, 5, "Legacy.exe", @"C:\Programs\Legacy.exe", "e", 0, 32 * 1048576, ProcessTrust.FromCode(0x800B0109) with { Publisher = "Example issuer" }),
            new(8880, 6, "Protected.exe", "", "", null, null, new("unverified", "受保護程序，無法讀取程式路徑。")),
            new(1200, 7, "Service.exe", @"C:\Windows\System32\Service.exe", "f", 0, 8 * 1048576, new("pending", "正在背景驗證。")),
            new(4,-4,"System","","",0.2,80*1048576,new("unverified","核心進程不適用一般 EXE 簽章。"),512*1024,0,0,new(4,0,210,0,"System")),
            new(120,8,"Registry","","",0,30*1048576,new("unverified","沒有一般 EXE。"),0,0,0,new(120,4,0,0,"Registry"))
        ];
        // Two synthetic shell icons, so previews show both an icon and the generic fallback.
        ProgramIcons.Put(@"C:\Windows\explorer.exe", PreviewIcon(0xFF3B82F6, 0xFFF59E0B));
        ProgramIcons.Put(@"C:\Program Files\Example\Browser.exe", PreviewIcon(0xFF10B981, 0xFF6366F1));
        Render(); list.SelectedItem = Programs[2];
    }

    /// A synthetic two-colour shell icon for previews and tests.
    internal static Bitmap PreviewIcon(uint top, uint bottom)
    {
        var bitmap = new WriteableBitmap(new PixelSize(32, 32), new Vector(96, 96), Avalonia.Platform.PixelFormat.Bgra8888, Avalonia.Platform.AlphaFormat.Premul);
        using var buffer = bitmap.Lock();
        for (var y = 0; y < 32; y++)
            for (var x = 0; x < 32; x++) {
                var inside = (x - 15.5) * (x - 15.5) + (y - 15.5) * (y - 15.5) <= 15 * 15;
                var color = inside ? y < 16 ? top : bottom : 0u;
                System.Runtime.InteropServices.Marshal.WriteInt32(buffer.Address + y * buffer.RowBytes + x * 4, (int)color);
            }
        return bitmap;
    }
}
