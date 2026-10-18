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
using Avalonia.Styling;
using Avalonia.Threading;

namespace Suhang.Desktop;

public sealed partial class Dashboard
{
    Window? taskWindow;
    ProcessInventory? processInventory;
    DispatcherTimer? processTimer;
    ListBox processList = null!;
    TextBox processSearch = null!;
    CheckBox processAttention = null!;
    ToggleSwitch processAutomatic = null!;
    TextBlock processCount = null!, processRateNote = null!, processDetailTitle = null!, processDetailReason = null!, processDetailText = null!, processDetailSummary = null!;
    Notice processProblem = null!;
    Border processEmpty = null!;
    StatusPill processDetailPill = null!;
    Button processRefresh = null!, processReverify = null!, processCopy = null!;
    RunningProgram[] runningPrograms = [];
    string processSort = "assessment";
    bool processDescending, processCapturing;
    readonly Dictionary<string, TextBlock> processHeadings = new();
    // Name stretches; the numeric columns are right-aligned so units line up.
    const string ProcessColumns = "*,56,60,84,88,88,170,110";
    const double ProcessTableMinWidth = 880, ProcessDetailShare = .3;
    ScrollViewer processDetailScroll = null!;
    static readonly (string Key, string Title, bool Numeric)[] ProcessColumnSpecs = [
        ("name", "程式名稱", false), ("pid", "PID", true), ("cpu", "CPU", true), ("memory", "記憶體", true), ("disk", "磁碟讀取", true), ("network", "網路收發", true),
        ("assessment", "來源判斷", false), ("trust", "簽章", false)];

    void OpenTaskManager()
    {
        if (taskWindow != null) { taskWindow.Activate(); return; }
        runningPrograms = []; processCapturing = false; processSort = "assessment"; processDescending = false; processHeadings.Clear();
        processCount = Label("正在讀取執行中的程式…", Scale.Secondary, key: "Muted");
        processRateNote = Label("", Scale.Caption, key: "Subtle"); processRateNote.IsVisible = false;
        processProblem = new Notice();
        processRefresh = Action("重新整理", () => _ = CaptureProcessesAsync(), Icons.Retry);
        processReverify = Action("重新驗證簽章", () => { processInventory?.Reverify(); _ = CaptureProcessesAsync(); });
        var table = BuildProcessTable();
        var window = taskWindow = AppWindow.Create("工作管理員", 1120, 760, 920, 560);
        window.Content = AppWindow.Page(AppWindow.Header("工作管理員", "依簽章、系統結構與 Windows 檔案保護判斷程式來源；選擇程式可查看依據。", processRefresh, processReverify),
            ProcessBody(BuildProcessToolbar(), table, BuildProcessDetails()),
            Column(2, processCount, processRateNote, Hint("本機驗證，不連線查詢吊銷 · 簽章快取最長 30 秒 · CPU 依全部邏輯核心計算 · 1 MB = 1024 KB · — 表示未取得", "Subtle", Scale.Caption)),
            processProblem);
        window.KeyDown += (_, e) => {
            if (e.Key == Key.F && e.KeyModifiers == KeyModifiers.Control) { processSearch.Focus(); processSearch.SelectAll(); e.Handled = true; }
            else if (e.Key == Key.F5) { _ = CaptureProcessesAsync(); e.Handled = true; }
        };
        processSearch.TextChanged += (_, _) => RenderProcesses();
        processAttention.IsCheckedChanged += (_, _) => RenderProcesses();
        processList.SelectionChanged += (_, _) => RenderProcessDetails();
        processTimer = new DispatcherTimer { Interval = TimeSpan.FromSeconds(3) };
        processTimer.Tick += (_, _) => { if (processAutomatic.IsChecked == true && window.WindowState != WindowState.Minimized) _ = CaptureProcessesAsync(); };
        window.Closed += (_, _) => {
            processTimer?.Stop(); processTimer = null;
            processInventory?.Dispose(); processInventory = null;
            window.Content = null; taskWindow = null; runningPrograms = [];
        };
        RenderProcessDetails();
        if (Program.StandaloneTasks) window.Show(); else window.Show(this);
        if (preview) { SeedProcessPreview(); return; }
        if (!OperatingSystem.IsWindows()) {
            processProblem.Show("Warn", "工作管理員與 Authenticode 憑證驗證需在 Windows 執行。");
            processCount.Text = "未取得 Windows 進程資料。"; processRefresh.IsEnabled = processReverify.IsEnabled = processAutomatic.IsEnabled = false;
            ShowProcessEmpty("此功能只能在 Windows 使用", "目前的系統沒有提供進程與簽章資料。");
            return;
        }
        processInventory = new ProcessInventory(); processTimer.Start(); _ = CaptureProcessesAsync();
    }

    /// The table takes the height; the detail panel sizes to its content but never beyond a share of the body, scrolling inside.
    Control ProcessBody(Control toolbar, Control table, Control details)
    {
        processDetailScroll = new ScrollViewer { Content = details, HorizontalScrollBarVisibility = ScrollBarVisibility.Disabled, VerticalScrollBarVisibility = ScrollBarVisibility.Auto, MaxHeight = ProcessDetailShare * 400 };
        var body = Rows("Auto,*,Auto", toolbar, table, processDetailScroll);
        body.SizeChanged += (_, e) => processDetailScroll.MaxHeight = Math.Max(96, e.NewSize.Height * ProcessDetailShare);
        return body;
    }

    Control BuildProcessToolbar()
    {
        processSearch = new TextBox { Watermark = "搜尋程式、PID、簽署者或路徑", MinWidth = 260, InnerLeftContent = WithMargin(Icons.Make(Icons.Search, 14, "Subtle"), new Thickness(10, 0, 0, 0)) };
        AutomationProperties.SetName(processSearch, "搜尋執行中的程式");
        processAttention = new CheckBox { Content = "只看需注意項", VerticalAlignment = VerticalAlignment.Center };
        processAutomatic = Switch(); processAutomatic.IsChecked = true;
        AutomationProperties.SetName(processAutomatic, "每三秒更新進程列表");
        var toolbar = Columns("*,Auto,Auto", processSearch, processAttention, Row(8, Label("自動更新", Scale.Secondary, key: "Muted"), processAutomatic));
        toolbar.ColumnSpacing = 20; toolbar.Margin = new Thickness(0, 0, 0, 6);
        return toolbar;
    }

    Control BuildProcessTable()
    {
        processList = new ListBox { SelectionMode = SelectionMode.Single, Padding = new Thickness(0), BorderThickness = new Thickness(0), Background = Brushes.Transparent };
        AutomationProperties.SetName(processList, "執行中的程式與簽章驗證結果");
        processList.ItemTemplate = new FuncDataTemplate<RunningProgram>((item, _) => item == null ? new Border() : ProcessRow(item));
        processList.Styles.Add(new Style(x => x.OfType<ListBoxItem>()) {
            Setters = { new Setter(ListBoxItem.PaddingProperty, new Thickness(0)), new Setter(ListBoxItem.MinHeightProperty, 0.0), new Setter(ListBoxItem.HorizontalContentAlignmentProperty, HorizontalAlignment.Stretch) }
        });
        foreach (var state in new[] { ":selected", ":selected:pointerover", ":selected:pressed" })
            processList.Styles.Add(new Style(x => x.OfType<ListBoxItem>().Class(state).Template().OfType<ContentPresenter>()) { Setters = { new Setter(ContentPresenter.BackgroundProperty, new DynamicResourceExtension("AccentSoft")) } });
        var headings = new Grid { ColumnDefinitions = new ColumnDefinitions(ProcessColumns), Margin = new Thickness(12, 0, 12, 0), ColumnSpacing = 8 };
        for (var i = 0; i < ProcessColumnSpecs.Length; i++) {
            var (key, title, numeric) = ProcessColumnSpecs[i];
            var label = Label(title, Scale.Secondary, FontWeight.SemiBold, "Muted"); processHeadings[key] = label;
            var button = new Button { Content = label, Background = Brushes.Transparent, BorderThickness = new Thickness(0), Padding = new Thickness(0, 7), HorizontalAlignment = HorizontalAlignment.Stretch, HorizontalContentAlignment = numeric ? HorizontalAlignment.Right : HorizontalAlignment.Left };
            AutomationProperties.SetName(button, "依" + title + "排序");
            button.Click += (_, _) => {
                processDescending = processSort == key ? !processDescending : key is "cpu" or "memory" or "disk" or "network";
                processSort = key; RenderProcesses();
            };
            Grid.SetColumn(button, i); headings.Children.Add(button);
        }
        processEmpty = new Border { VerticalAlignment = VerticalAlignment.Top, Child = EmptyState.Make(Icons.Apps, "正在讀取執行中的程式…") };
        var body = new Grid { Children = { processList, processEmpty } };
        var grid = Rows("Auto,*", new Border { Child = headings, BorderThickness = new Thickness(0, 0, 0, 1) }.Res(Border.BackgroundProperty, "Field").Res(Border.BorderBrushProperty, "Stroke"), body);
        grid.MinWidth = ProcessTableMinWidth;
        var scroll = new ScrollViewer { Content = grid, HorizontalScrollBarVisibility = ScrollBarVisibility.Auto, VerticalScrollBarVisibility = ScrollBarVisibility.Disabled };
        // A horizontal ScrollViewer measures its content without a width limit; follow the viewport instead.
        scroll.SizeChanged += (_, e) => grid.Width = Math.Max(ProcessTableMinWidth, e.NewSize.Width);
        return new Border { Child = scroll, BorderThickness = new Thickness(1), CornerRadius = new CornerRadius(Scale.CardRadius), ClipToBounds = true }.Res(Border.BorderBrushProperty, "Stroke").Res(Border.BackgroundProperty, "Card");
    }

    Control BuildProcessDetails()
    {
        processDetailTitle = Label("", Scale.Section, FontWeight.SemiBold);
        processDetailPill = new StatusPill("", Scale.Caption);
        processDetailSummary = Hint("", "Muted", Scale.Secondary);
        processDetailReason = Hint("", "Ink", Scale.Body);
        processDetailText = new SelectableTextBlock { FontSize = Scale.Secondary, TextWrapping = TextWrapping.Wrap }.Res(TextBlock.ForegroundProperty, "Muted");
        // Path, publisher and certificate lines stay folded until asked for, so the collapsed panel is two lines tall.
        var technical = Column(6, processDetailSummary, processDetailText); technical.IsVisible = false;
        var toggle = Action("詳細資料 ▾", () => { }); var toggleLabel = (TextBlock)toggle.Content!;
        toggle.Click += (_, _) => { technical.IsVisible = !technical.IsVisible; toggleLabel.Text = technical.IsVisible ? "詳細資料 ▴" : "詳細資料 ▾"; };
        AutomationProperties.SetName(toggle, "顯示或隱藏路徑、憑證與技術細節");
        processCopy = Action("複製路徑", async () => {
            var owner = taskWindow;
            if (owner?.Clipboard is { } clipboard && processList.SelectedItem is RunningProgram item) {
                await clipboard.SetTextAsync(item.Path);
                if (taskWindow == owner) processCount.Text = "已複製程式路徑。";
            }
        }, Icons.Copy);
        processCopy.IsEnabled = false;
        var heading = Columns("Auto,Auto,*,Auto,Auto", processDetailTitle, processDetailPill, Gap(), toggle, processCopy); heading.ColumnSpacing = 10;
        var card = Card(Column(4, heading, processDetailReason, technical), new Thickness(14, 10));
        card.Margin = new Thickness(0, 8, 0, 0); return card;
    }

    void ShowProcessEmpty(string title, string text)
    {
        processEmpty.Child = EmptyState.Make(Icons.Apps, title, text); processEmpty.IsVisible = true;
    }

    async Task CaptureProcessesAsync()
    {
        if (taskWindow == null || processCapturing || preview) return;
        var owner = taskWindow; var inventory = processInventory; if (inventory == null) return;
        processCapturing = true; processRefresh.IsEnabled = processReverify.IsEnabled = false;
        var initialPending = true;
        try {
            Action<RunningProgram[]>? initial = runningPrograms.Length == 0 ? rows => Dispatcher.UIThread.Post(() => {
                if (!initialPending || taskWindow != owner || processInventory != inventory) return;
                runningPrograms = rows; RenderProcesses();
            }, DispatcherPriority.Normal) : null;
            var snapshot = await Task.Run(() => inventory.Capture(initial));
            if (taskWindow != owner) return;
            runningPrograms = snapshot; ShowRateStatus(inventory.RateStatus); RenderProcesses();
        } catch {
            if (taskWindow != owner) return;
            processProblem.Show("Warn", "無法更新進程列表，已保留上次結果。請按「重新整理」重試。");
        } finally {
            initialPending = false;
            if (taskWindow == owner) { processCapturing = false; processRefresh.IsEnabled = processReverify.IsEnabled = true; }
        }
    }

    /// The sampler's explanation is a footnote; only a failed or lost measurement is raised as a banner.
    void ShowRateStatus(string status)
    {
        var failed = status.Contains("系統管理員") || status.Contains("無法") || status.Contains("遺失") || status.Contains("停止");
        if (failed) processProblem.Show("Warn", status); else processProblem.Hide();
        processRateNote.Text = failed ? "" : status; processRateNote.IsVisible = !failed && status.Length > 0; ToolTip.SetTip(processRateNote, status);
    }

    Control ProcessRow(RunningProgram item)
    {
        TextBlock Cell(string text, string key = "Ink") => WithAlign(Label(text, Scale.Secondary, key: key), HorizontalAlignment.Right);
        var assessment = Row(7, new Border { Width = 7, Height = 7, CornerRadius = new CornerRadius(4) }.Res(Border.BackgroundProperty, item.Assessment.Tone == "Muted" ? "Idle" : item.Assessment.Tone),
            Label(item.Assessment.Label, Scale.Secondary, FontWeight.SemiBold, item.Assessment.Tone));
        var row = Columns(ProcessColumns, Label(item.Name, Scale.Body), Cell(item.Pid.ToString(), "Muted"), Cell(item.CpuText), Cell(item.MemoryText), Cell(item.DiskReadText), Cell(item.NetworkText),
            assessment, Label(item.SignatureLabel, Scale.Secondary, FontWeight.SemiBold, item.SignatureTone));
        row.ColumnSpacing = 8; row.Margin = new Thickness(12, 6);
        ToolTip.SetTip(row, item.Path + "\n" + item.SignatureLabel + (item.Trust.Publisher.Length > 0 ? " · " + item.Trust.Publisher : "") + "\n" + item.Assessment.Reason + "\n磁碟讀取：" + item.DiskReadText + "\n網路接收：" + ProcessRate.Format(item.NetworkReceive) + " · 發送：" + ProcessRate.Format(item.NetworkSend));
        AutomationProperties.SetName(row, $"{item.Name}，PID {item.Pid}，{item.Assessment.Label}，磁碟讀取 {item.DiskReadText}，網路收發 {item.NetworkText}，{item.SignatureLabel}，{item.Trust.Publisher}，{item.Assessment.Reason}");
        return new Border { Child = row, BorderThickness = new Thickness(0, 0, 0, 1) }.Res(Border.BorderBrushProperty, "Stroke");
    }

    internal static RunningProgram[] FilterProcesses(IEnumerable<RunningProgram> source, string search, bool attention, string sort, bool descending)
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

    void RenderProcesses()
    {
        if (taskWindow == null) return;
        var selected = processList.SelectedItem as RunningProgram;
        var rows = FilterProcesses(runningPrograms, processSearch.Text ?? "", processAttention.IsChecked == true, processSort, processDescending);
        // Replacing the source resets the scroll position: skip it when nothing visible changed and restore it otherwise.
        if (processList.ItemsSource is not RunningProgram[] shown || !shown.SequenceEqual(rows)) {
            var scroller = processList.Scroll as ScrollViewer; var offset = scroller?.Offset ?? default;
            processList.ItemsSource = rows;
            if (scroller != null && offset.Y > 0) Dispatcher.UIThread.Post(() => scroller.Offset = offset, DispatcherPriority.Loaded);
        }
        processList.SelectedItem = rows.FirstOrDefault(p => p.Pid == selected?.Pid && p.Started == selected.Started);
        foreach (var (key, label) in processHeadings) {
            var title = label.Text!.TrimEnd(' ', '↑', '↓');
            label.Text = title + (key == processSort ? processDescending ? " ↓" : " ↑" : "");
        }
        var attention = runningPrograms.Count(p => p.Assessment.Attention);
        processAttention.Content = attention > 0 ? $"只看需注意項（{attention}）" : "只看需注意項";
        processEmpty.IsVisible = rows.Length == 0;
        if (rows.Length == 0) {
            if (runningPrograms.Length == 0) ShowProcessEmpty("正在讀取執行中的程式…", "第一次讀取會先列出程式，簽章稍後陸續驗證。");
            else { processEmpty.Child = EmptyState.Make(Icons.Search, "沒有符合條件的程式", "請調整搜尋文字，或取消「只看需注意項」。", Action("清除篩選", () => { processSearch.Text = ""; processAttention.IsChecked = false; })); }
        }
        var pending = runningPrograms.Count(p => p.Trust.Status == "pending");
        processCount.Text = preview ? "介面預覽 · 範例資料，不代表實際 Windows 進程或憑證狀態" :
            $"顯示 {rows.Length} / {runningPrograms.Length} 個程式 · {runningPrograms.Count(p => p.Trust.Status == "valid")} 個簽章有效 · {attention} 個需注意" + (pending > 0 ? $" · {pending} 個等待驗證" : "") + $" · 更新於 {DateTime.Now:HH:mm:ss}";
        RenderProcessDetails();
    }

    void RenderProcessDetails()
    {
        if (processList.SelectedItem is not RunningProgram item) {
            processDetailTitle.Text = "選擇程式以查看簽章與憑證"; processDetailPill.IsVisible = false;
            processDetailReason.Text = processDetailText.Text = processDetailSummary.Text = ""; processCopy.IsEnabled = false; return;
        }
        var trust = item.Trust;
        processCopy.IsEnabled = item.Path.Length > 0;
        processDetailTitle.Text = $"{item.Name} · PID {item.Pid}";
        processDetailPill.IsVisible = true; processDetailPill.Set(item.SignatureTone == "Muted" ? "Idle" : item.SignatureTone, item.SignatureLabel);
        processDetailReason.Text = item.Assessment.Label + "：" + item.Assessment.Reason; processDetailReason.Res(TextBlock.ForegroundProperty, item.Assessment.Tone == "Muted" ? "Ink" : item.Assessment.Tone);
        var publisher = trust.Publisher.Length > 0 ? (trust.Status == "valid" ? "已驗證簽署者：" : "聲稱的簽署者：") + trust.Publisher : "";
        processDetailSummary.Text = "程式路徑：" + (item.Path.Length > 0 ? item.Path : "未取得一般 EXE 路徑") + (publisher.Length > 0 ? " · " + publisher : "");
        ToolTip.SetTip(processDetailSummary, processDetailSummary.Text);
        var lines = new List<string> { "磁碟讀取 " + item.DiskReadText + " · 網路接收 " + ProcessRate.Format(item.NetworkReceive) + " · 網路發送 " + ProcessRate.Format(item.NetworkSend) };
        if(item.Shape is { } shape) lines.Add($"系統快照：名稱 {shape.Name} · 父 PID {shape.ParentPid} · 執行緒 {shape.Threads} · 工作階段 {shape.Session?.ToString() ?? "未知"}");
        if(trust.WindowsProtected is bool wrp) lines.Add("Windows Resource Protection："+(wrp?"列為保護檔案，尚不代表內容完整":"未列為保護檔案，不代表不安全"));
        if(trust.ClaimedCompany!="")lines.Add("檔案聲稱的公司（可偽造）："+trust.ClaimedCompany);
        if(trust.ClaimedOriginalName!="")lines.Add("檔案聲稱的原始名稱（可偽造）："+trust.ClaimedOriginalName);
        if (trust.Subject.Length > 0) lines.Add("憑證主體：" + trust.Subject);
        if (trust.Issuer.Length > 0) lines.Add("憑證簽發者：" + trust.Issuer);
        if (trust.NotBefore.Length > 0) lines.Add("憑證有效期間：" + DisplayProcessDate(trust.NotBefore) + " — " + DisplayProcessDate(trust.NotAfter));
        if (trust.Timestamped) lines.Add(trust.Status == "valid" ? "時間戳記：Windows 已接受時間戳記簽章" : "時間戳記：存在，尚未通過整體驗證");
        if (trust.Thumbprint.Length > 0) lines.Add("憑證指紋（SHA-1）：" + trust.Thumbprint);
        if (trust.Source.Length > 0) lines.Add("簽章來源：" + trust.Source);
        if (trust.Hash.Length > 0) lines.Add("程式 SHA-256：" + trust.Hash);
        if (trust.CheckedAt.Length > 0) lines.Add("驗證時間：" + DisplayProcessDate(trust.CheckedAt));
        if (trust.Code.Length > 0) lines.Add("Windows 驗證代碼（供技術支援）：" + trust.Code);
        processDetailText.Text = string.Join("\n", lines);
    }
    static string DisplayProcessDate(string value) => DateTimeOffset.TryParse(value, out var time) ? time.ToLocalTime().ToString("yyyy-MM-dd HH:mm:ss zzz") : value;

    void SeedProcessPreview()
    {
        var valid = ProcessTrust.FromCode(0) with {
            VerifiedMicrosoft=true, Publisher = "Microsoft Windows", Subject = "CN=Microsoft Windows, O=Microsoft Corporation", Issuer = "Microsoft Windows Production PCA",
            NotBefore = "2024-01-01T00:00:00Z", NotAfter = "2026-01-01T00:00:00Z", Source = "系統目錄簽章（SHA256）",
            Timestamped = true, CheckedAt = "2026-10-10T10:00:00Z", Thumbprint = new string('A', 40), Hash = new string('B', 64)
        };
        runningPrograms = [
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
        RenderProcesses(); processList.SelectedItem = runningPrograms[2];
    }
}
