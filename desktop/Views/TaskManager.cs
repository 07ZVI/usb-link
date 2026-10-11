using Avalonia;
using Avalonia.Automation;
using Avalonia.Controls;
using Avalonia.Controls.Primitives;
using Avalonia.Controls.Templates;
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
    TextBlock processCount = null!, processProblem = null!, processDetailTitle = null!, processDetailReason = null!, processDetailText = null!;
    Button processRefresh = null!, processReverify = null!, processCopy = null!;
    RunningProgram[] runningPrograms = [];
    string processSort = "trust";
    bool processDescending, processCapturing;
    readonly Dictionary<string, TextBlock> processHeadings = new();
    const string ProcessColumns = "190,65,70,95,140,170,*";

    void OpenTaskManager()
    {
        if (taskWindow != null) { taskWindow.Activate(); return; }
        runningPrograms = []; processCapturing = false; processSort = "trust"; processDescending = false; processHeadings.Clear();
        processSearch = new TextBox { Watermark = "搜尋程式、PID、簽署者或路徑", MinWidth = 240 };
        AutomationProperties.SetName(processSearch, "搜尋執行中的程式");
        processAttention = new CheckBox { Content = "只看需注意項", VerticalAlignment = VerticalAlignment.Center };
        processAutomatic = Switch(); processAutomatic.IsChecked = true;
        AutomationProperties.SetName(processAutomatic, "每三秒更新進程列表");
        processCount = Label("正在讀取執行中的程式…", 12, key: "Muted");
        processProblem = Label("", 12, key: "Warn"); processProblem.IsVisible = false; processProblem.TextWrapping = TextWrapping.Wrap;
        processDetailTitle = Label("選擇程式以查看簽章與憑證", 14, FontWeight.SemiBold);
        processDetailReason = Label("", 12); processDetailReason.TextWrapping = TextWrapping.Wrap;
        processDetailText = Label("", 12, key: "Muted"); processDetailText.TextWrapping = TextWrapping.Wrap;
        processList = new ListBox { SelectionMode = SelectionMode.Single, Padding = new Thickness(0), BorderThickness = new Thickness(0) };
        AutomationProperties.SetName(processList, "執行中的程式與簽章驗證結果");
        processList.ItemTemplate = new FuncDataTemplate<RunningProgram>((item, _) => item == null ? new Border() : ProcessRow(item));
        processList.Styles.Add(new Style(x => x.OfType<ListBoxItem>()) {
            Setters = { new Setter(ListBoxItem.PaddingProperty, new Thickness(0)), new Setter(ListBoxItem.HorizontalContentAlignmentProperty, HorizontalAlignment.Stretch) }
        });
        var headings = new Grid { ColumnDefinitions = new ColumnDefinitions(ProcessColumns), Margin = new Thickness(10, 0, 10, 0) };
        var columns = new[] { ("name", "程式名稱"), ("pid", "PID"), ("cpu", "CPU"), ("memory", "記憶體"), ("trust", "簽章 / 憑證"), ("publisher", "簽署者"), ("reason", "需要注意的原因") };
        for (var i = 0; i < columns.Length; i++) {
            var (key, title) = columns[i];
            var label = Label(title, 12, FontWeight.SemiBold, "Muted"); processHeadings[key] = label;
            var button = new Button { Content = label, Background = Brushes.Transparent, BorderThickness = new Thickness(0), Padding = new Thickness(0, 10), HorizontalAlignment = HorizontalAlignment.Stretch };
            AutomationProperties.SetName(button, "依" + title + "排序");
            button.Click += (_, _) => {
                processDescending = processSort == key ? !processDescending : key is "cpu" or "memory";
                processSort = key; RenderProcesses();
            };
            Grid.SetColumn(button, i); headings.Children.Add(button);
        }
        var table = Rows("Auto,*", new Border { Child = headings }.Res(Border.BackgroundProperty, "Field"), processList);
        table.MinWidth = 1040;
        var scroll = new ScrollViewer { Content = table, HorizontalScrollBarVisibility = ScrollBarVisibility.Auto, VerticalScrollBarVisibility = ScrollBarVisibility.Disabled };
        var tableBorder = new Border { Child = scroll, BorderThickness = new Thickness(1), CornerRadius = new CornerRadius(6) }.Res(Border.BorderBrushProperty, "Stroke").Res(Border.BackgroundProperty, "Card");
        processRefresh = Action("重新整理", () => _ = CaptureProcessesAsync(), Icons.Retry);
        processReverify = Action("重新驗證簽章", () => { processInventory?.Reverify(); _ = CaptureProcessesAsync(); });
        processCopy = Action("複製路徑", async () => {
            var owner = taskWindow;
            if (owner?.Clipboard is { } clipboard && processList.SelectedItem is RunningProgram item) {
                await clipboard.SetTextAsync(item.Path);
                if (taskWindow == owner) processCount.Text = "已複製程式路徑。";
            }
        });
        processCopy.IsEnabled = false;
        var details = Card(Column(6, Columns("*,Auto", processDetailTitle, processCopy), processDetailReason,
            new ScrollViewer { Content = processDetailText, MaxHeight = 170, HorizontalScrollBarVisibility = ScrollBarVisibility.Disabled }), new Thickness(14));
        var hint = Label("驗證磁碟上的程式檔案；有效簽章不保證程式安全。未簽署可為正常軟體，紅色項目請核對來源。", 12, key: "Muted");
        hint.TextWrapping = TextWrapping.Wrap;
        var footer = Label("本機驗證 · 不連線查詢吊銷 · 簽章快取最長 30 秒 · CPU 依全部邏輯核心計算", 11, key: "Subtle"); footer.TextWrapping = TextWrapping.Wrap;
        taskWindow = new Window {
            Title = "USB Link · 工作管理員", Width = 1220, Height = 800, MinWidth = 820, MinHeight = 580,
            FontFamily = new FontFamily(Palette.FontStack), WindowStartupLocation = WindowStartupLocation.CenterOwner
        };
        taskWindow.Res(BackgroundProperty, "Window");
        taskWindow.Content = new Border { Padding = new Thickness(24), Child = Rows("Auto,Auto,*,Auto,Auto",
            Column(8, Columns("*,Auto", Column(4, Label("工作管理員", 24, FontWeight.SemiBold), hint), Row(8, processRefresh, processReverify)), Gap(8)),
            Column(10, Columns("*,16,Auto,24,Auto", processSearch, Gap(), processAttention, Gap(), Row(8, Label("自動更新", 12, key: "Muted"), processAutomatic)), processProblem, Gap(8)),
            tableBorder, WithMargin(details, new Thickness(0, 12, 0, 10)), Column(4, processCount, footer)) };
        var ownerWindow = taskWindow;
        taskWindow.SizeChanged += (_, _) => { table.Width = Math.Max(1040, ownerWindow.ClientSize.Width - 50); };
        processSearch.TextChanged += (_, _) => RenderProcesses();
        processAttention.IsCheckedChanged += (_, _) => RenderProcesses();
        processList.SelectionChanged += (_, _) => RenderProcessDetails();
        processTimer = new DispatcherTimer { Interval = TimeSpan.FromSeconds(3) };
        processTimer.Tick += (_, _) => { if (processAutomatic.IsChecked == true && ownerWindow.WindowState != WindowState.Minimized) _ = CaptureProcessesAsync(); };
        taskWindow.Closed += (_, _) => {
            processTimer?.Stop(); processTimer = null;
            processInventory?.Dispose(); processInventory = null;
            ownerWindow.Content = null; taskWindow = null; runningPrograms = [];
        };
        if (Program.StandaloneTasks) taskWindow.Show();
        else taskWindow.Show(this);
        if (preview) { SeedProcessPreview(); return; }
        if (!OperatingSystem.IsWindows()) {
            processProblem.Text = "工作管理員與 Authenticode 憑證驗證需在 Windows 執行。"; processProblem.IsVisible = true;
            processCount.Text = "未取得 Windows 進程資料。"; processRefresh.IsEnabled = processReverify.IsEnabled = processAutomatic.IsEnabled = false;
            return;
        }
        processInventory = new ProcessInventory(); processTimer.Start(); _ = CaptureProcessesAsync();
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
            runningPrograms = snapshot; processProblem.IsVisible = false; RenderProcesses();
        } catch {
            if (taskWindow != owner) return;
            processProblem.Text = "無法更新進程列表，保留上次結果；請重新整理。"; processProblem.IsVisible = true;
        } finally {
            initialPending = false;
            if (taskWindow == owner) { processCapturing = false; processRefresh.IsEnabled = processReverify.IsEnabled = true; }
        }
    }

    Control ProcessRow(RunningProgram item)
    {
        var row = Columns(ProcessColumns, Label(item.Name, 13), Label(item.Pid.ToString(), 12, key: "Muted"),
            Label(item.CpuText, 12), Label(item.MemoryText, 12), Label(item.Trust.Label, 12, FontWeight.SemiBold, item.Trust.Tone),
            Label(item.Trust.Publisher.Length == 0 ? "—" : item.Trust.Publisher, 12, key: "Muted"),
            Label(item.Trust.Status == "valid" ? "—" : item.Risk, 12, key: item.Trust.Tone));
        row.Margin = new Thickness(10, 10, 10, 10);
        ToolTip.SetTip(row, item.Path + "\n" + item.Trust.Label + "\n" + item.Risk);
        AutomationProperties.SetName(row, $"{item.Name}，PID {item.Pid}，{item.Trust.Label}，{item.Trust.Publisher}，{item.Risk}");
        return new Border { Child = row, BorderThickness = new Thickness(0, 0, 0, 1) }.Res(Border.BorderBrushProperty, "Stroke");
    }

    internal static RunningProgram[] FilterProcesses(IEnumerable<RunningProgram> source, string search, bool attention, string sort, bool descending)
    {
        var rows = source.Where(p => (!attention || p.Trust.Attention) && p.Matches(search.Trim()));
        Func<RunningProgram, IComparable> key = sort switch {
            "name" => p => p.Name.ToUpperInvariant(), "pid" => p => p.Pid,
            "cpu" => p => p.Cpu ?? -1, "memory" => p => p.Memory ?? -1,
            "publisher" => p => p.Trust.Publisher.ToUpperInvariant(), "reason" => p => p.Risk,
            _ => p => p.Trust.Priority
        };
        return (descending ? rows.OrderByDescending(key) : rows.OrderBy(key)).ThenBy(p => p.Name, StringComparer.OrdinalIgnoreCase).ThenBy(p => p.Pid).ToArray();
    }

    void RenderProcesses()
    {
        if (taskWindow == null) return;
        var selected = processList.SelectedItem as RunningProgram;
        var rows = FilterProcesses(runningPrograms, processSearch.Text ?? "", processAttention.IsChecked == true, processSort, processDescending);
        processList.ItemsSource = rows;
        processList.SelectedItem = rows.FirstOrDefault(p => p.Pid == selected?.Pid && p.Started == selected.Started);
        foreach (var (key, label) in processHeadings) {
            var title = label.Text!.TrimEnd(' ', '↑', '↓');
            label.Text = title + (key == processSort ? processDescending ? " ↓" : " ↑" : "");
        }
        var pending = runningPrograms.Count(p => p.Trust.Status == "pending");
        processCount.Text = preview ? "介面預覽 · 範例資料，不代表實際 Windows 進程或憑證狀態" :
            $"顯示 {rows.Length} / {runningPrograms.Length} 個進程 · {runningPrograms.Count(p => p.Trust.Status == "valid")} 個簽章有效 · {runningPrograms.Count(p => p.Trust.Attention)} 個需注意 · {pending} 個等待驗證 · 更新 {DateTime.Now:HH:mm:ss}";
        if (!preview && rows.Length == 0) processCount.Text += " · 沒有符合條件的程式";
        RenderProcessDetails();
    }

    void RenderProcessDetails()
    {
        if (processList.SelectedItem is not RunningProgram item) {
            processDetailTitle.Text = "選擇程式以查看簽章與憑證"; processDetailReason.Text = processDetailText.Text = ""; processCopy.IsEnabled = false; return;
        }
        var trust = item.Trust;
        processCopy.IsEnabled = item.Path.Length > 0;
        processDetailTitle.Text = $"{item.Name} · PID {item.Pid} · {trust.Label}";
        processDetailReason.Text = item.Risk; processDetailReason.Res(TextBlock.ForegroundProperty, trust.Tone);
        var lines = new List<string> { "程式路徑：" + (item.Path.Length > 0 ? item.Path : "無法讀取") };
        if (trust.Publisher.Length > 0) lines.Add((trust.Status == "valid" ? "已驗證簽署者：" : "聲稱的簽署者：") + trust.Publisher);
        if (trust.Subject.Length > 0) lines.Add("憑證主體：" + trust.Subject);
        if (trust.Issuer.Length > 0) lines.Add("憑證簽發者：" + trust.Issuer);
        if (trust.NotBefore.Length > 0) lines.Add("憑證有效期間：" + DisplayProcessDate(trust.NotBefore) + " — " + DisplayProcessDate(trust.NotAfter));
        if (trust.Timestamped) lines.Add(trust.Status == "valid" ? "時間戳記：Windows 已接受時間戳記簽章" : "時間戳記：存在，尚未通過整體驗證");
        if (trust.Thumbprint.Length > 0) lines.Add("憑證指紋（SHA-1）：" + trust.Thumbprint);
        if (trust.Source.Length > 0) lines.Add("簽章來源：" + trust.Source);
        if (trust.Code.Length > 0) lines.Add("Windows 驗證代碼：" + trust.Code);
        if (trust.Hash.Length > 0) lines.Add("程式 SHA-256：" + trust.Hash);
        if (trust.CheckedAt.Length > 0) lines.Add("驗證時間：" + DisplayProcessDate(trust.CheckedAt));
        processDetailText.Text = string.Join("\n", lines);
    }
    static string DisplayProcessDate(string value) => DateTimeOffset.TryParse(value, out var time) ? time.ToLocalTime().ToString("yyyy-MM-dd HH:mm:ss zzz") : value;

    void SeedProcessPreview()
    {
        var valid = ProcessTrust.FromCode(0) with {
            Publisher = "Microsoft Windows", Subject = "CN=Microsoft Windows, O=Microsoft Corporation", Issuer = "Microsoft Windows Production PCA",
            NotBefore = "2024-01-01T00:00:00Z", NotAfter = "2026-01-01T00:00:00Z", Source = "系統目錄簽章（SHA256）",
            Timestamped = true, CheckedAt = "2026-10-10T10:00:00Z", Thumbprint = new string('A', 40), Hash = new string('B', 64)
        };
        runningPrograms = [
            new(1840, 1, "explorer.exe", @"C:\Windows\explorer.exe", "a", 0.4, 164 * 1048576, valid),
            new(6124, 2, "Browser.exe", @"C:\Program Files\Example\Browser.exe", "b", 7.8, 820 * 1048576, valid with { Publisher = "Example Software" }),
            new(7312, 3, "UpdateHelper.exe", @"C:\Users\Example\AppData\Local\Temp\UpdateHelper.exe", "c", 1.2, 26 * 1048576, ProcessTrust.FromCode(0x80096010) with { Publisher = "Unknown publisher" }),
            new(4216, 4, "Tool.exe", @"C:\Tools\Tool.exe", "d", 0, 18 * 1048576, ProcessTrust.FromCode(0x800B0100)),
            new(8756, 5, "Legacy.exe", @"C:\Programs\Legacy.exe", "e", 0, 32 * 1048576, ProcessTrust.FromCode(0x800B0109) with { Publisher = "Example issuer" }),
            new(8880, 6, "Protected.exe", "", "", null, null, new("unverified", "受保護程序，無法讀取程式路徑。")),
            new(1200, 7, "Service.exe", @"C:\Windows\System32\Service.exe", "f", 0, 8 * 1048576, new("pending", "正在背景驗證。"))
        ];
        RenderProcesses(); processList.SelectedItem = runningPrograms[2];
    }
}
