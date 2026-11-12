using System.Text.Json;
using Avalonia;
using Avalonia.Controls;
using Avalonia.Controls.ApplicationLifetimes;
using Avalonia.Controls.Shapes;
using Avalonia.Input;
using Avalonia.Layout;
using Avalonia.Media;
using Avalonia.Styling;
using Avalonia.Themes.Fluent;
using Avalonia.Threading;
using Path = Avalonia.Controls.Shapes.Path;

namespace Suhang.Desktop;

public sealed partial class Dashboard : Window
{
    enum Tone { Idle, Busy, Ok, Warn, Error }

    string WindowsHostIp = "10.6.9.1", ShareUrl = SMBServerAddress;

    readonly TextBlock addressValue = Label("10.6.9.1", Scale.Hero, FontWeight.SemiBold), shareUrlValue = Label(SMBServerAddress, Scale.Body);
    readonly TextBlock versionText = Label(Program.Preview ? "預覽" : "正在核對版本", Scale.Subheadline, key: "Muted");
    readonly StatusPill chip = new("等候裝置");
    TextBlock chipText => chip.Label;
    readonly TextBlock notice = Label("", Scale.Secondary), shareStatus = Label("請先連接 USB 裝置", Scale.Secondary, key: "Muted");
    readonly Border noticeBar = new() { CornerRadius = new CornerRadius(Scale.ControlRadius), Padding = new Thickness(Scale.Medium, Scale.Snug), IsVisible = false };
    DeviceStatusView macStatus = null!, ipadStatus = null!;
    readonly ToggleSwitch shareToggle = Switch(), startup = Switch(), networkOnly = Switch();
    readonly TextBlock networkOnlyStatus = Label("", Scale.Caption, key: "Subtle");
    string startupPendingID = "", networkOnlyPendingID = "";
    bool startupRequested, networkOnlyRequested, networkOnlyEnabled = true;
    readonly StackPanel detailRows = new() { Spacing = 0 };
    readonly Grid root = new();
    readonly Grid body = new();
    readonly ScrollViewer bodyScroll = new() { HorizontalScrollBarVisibility = Avalonia.Controls.Primitives.ScrollBarVisibility.Disabled };
    Control connectionCard = null!, settingsCard = null!, footerControl = null!;
    bool? compactLayout;
    PageHost? detailWindow;
    string detailText = "";
    bool shareEnabled, shareReady, nativeSMB;
 string nativeAccount="", shareProblem="";
    readonly bool preview = Program.Preview;
    bool backendEnded;
    readonly TextBlock automaticIsolationStatus = Label("", Scale.Secondary, key: "Muted"), programExitStatus = Label("", Scale.Secondary, key: "Warn");
    string programExitID = "", programExitPhase = "idle";
    bool programExitAwaiting, programExitCommitSent;
    DispatcherTimer? programExitConfirmationTimer;
    long programExitConfirmationGeneration;

    bool KeepInTray => !preview && !Program.NoBackendReader && OperatingSystem.IsWindows();

    // ---------- building blocks ----------

    // ---------- backend bridge ----------

    void Send(string action)
    {
        if (backendUnavailable && action != "stop") return;
        if (preview) { SetNotice("介面預覽，不會執行系統操作。"); return; }
        DesktopClient.SendRaw(JsonSerializer.Serialize(new { action })); 
    }
    async void Copy(string value, string what)
    {
        if (Clipboard is { } c) await c.SetTextAsync(value);
        SetNotice("已複製" + what + "：" + value);
    }
    void SetNotice(string text)
    {
        notice.Text = text;
        noticeBar.IsVisible = text != "";
    }

    public Dashboard()
    {
        Title = "USB Link"; Width = 1040; Height = 700; MinWidth = 520; MinHeight = 420;
        WindowStartupLocation = WindowStartupLocation.CenterScreen;
        WindowFit.Attach(this, 520, 420, customChrome: UsesCustomTitleBar, placeOnOpen: false);
        ConfigureWindowChrome();
        PropertyChanged += (_, e) => { if (e.Property == WindowStateProperty || e.Property == IsVisibleProperty) SyncTaskManager(); };
        FontFamily = new FontFamily(Palette.FontStack);
        // Each page tints the whole window (see Shell.cs), so the background is a solid token rather than Mica.
        this.Res(BackgroundProperty, "PageHome");

        noticeBar.Res(Border.BackgroundProperty, "AccentSoft");
        Avalonia.Automation.AutomationProperties.SetName(shareToggle, "檔案共享");
        Avalonia.Automation.AutomationProperties.SetName(startup, "登入 Windows 後自動啟動");
        Avalonia.Automation.AutomationProperties.SetName(networkOnly, "僅保留網路連線");
        Avalonia.Automation.AutomationProperties.SetName(networkOnlyStatus, "僅保留網路連線狀態");
        networkOnlyStatus.TextWrapping = TextWrapping.Wrap; networkOnlyStatus.TextTrimming = TextTrimming.None; networkOnlyStatus.IsVisible = false;
        noticeBar.Child = Row(8, Icons.Make(Icons.Info, 16, "Accent"), notice);

        // Window anatomy (docs/DESIGN.md): 20 margins, title bar row, 16 to the page, 12 between cards.
        root.RowDefinitions = new RowDefinitions("Auto,16,*");
        root.Margin = new Thickness(Scale.Margin, UsesCustomTitleBar ? 8 : Scale.Margin, Scale.Margin, Scale.Margin);
        AddAt(root, Header(), 0);
        connectionCard = ConnectionCard(); settingsCard = SettingsCard();
        hero = HeroCard();
        // The overview is the connection alone; sharing lives on its page and settings on the settings page.
        body.Children.Add(connectionCard);
        backendFailure.Res(TextBlock.ForegroundProperty, "Warn");
        backendFailureBanner = new Border { CornerRadius = new CornerRadius(Scale.CardRadius), Padding = new Thickness(Scale.Inset, Scale.Medium), Child = Columns("Auto,12,*", Icons.Make(Icons.Info, Scale.IconControl, "Warn"), Gap(), backendFailure) };
        backendFailureBanner.IsVisible = false;
        bodyScroll.Content = bodyHost = Column(Scale.Gutter, backendFailureBanner, hero, body);
        // Fill the available width up to BodyMaxWidth so responsive device rows
        // measure against the viewport rather than their own compact content.
        bodyHost.MaxWidth = BodyMaxWidth; bodyHost.HorizontalAlignment = HorizontalAlignment.Stretch; bodyHost.VerticalAlignment = VerticalAlignment.Center;
        // A wide window shows both columns at full height instead of leaving a gap above the footer.
        bodyScroll.PropertyChanged += (_, e) => { if (e.Property == ScrollViewer.ViewportProperty) ScheduleFit(); };
        backendFailureBanner.PropertyChanged += (_, e) => { if (e.Property == IsVisibleProperty) ScheduleFit(); };
        footerControl = Footer();
        overview = Rows("*,12,Auto", bodyScroll, Gap(), footerControl);
        overviewPage = overview;
        pages.Children.Add(overview);
        AddAt(root, pages, 2);
        SelectNav("home");

        // Keep controls in device-independent units so Windows DPI remains the
        // only scale. Reflow and scroll when the logical work area is smaller.
        UpdateResponsiveLayout();
        Content = root;
        SizeChanged += (_, _) => UpdateResponsiveLayout();

        shareToggle.Click += (_, _) => { Send(shareEnabled ? "share-off" : "share-on"); shareToggle.IsChecked = shareEnabled; };
        startup.Click += (_, _) => {
            if (preview) { Send("startup-on"); return; }
            if (startupPendingID != "") return;
            startupRequested = startup.IsChecked == true;
            startupPendingID = Guid.NewGuid().ToString("N");
            startup.IsEnabled = false;
            SetNotice("正在儲存並核對開機啟動設定…");
            DesktopClient.SendRaw(JsonSerializer.Serialize(new {
                action = startupRequested ? "startup-on" : "startup-off", id = startupPendingID
            }));
            
        };
        networkOnly.Click += (_, _) => {
            if (preview) { networkOnly.IsChecked = networkOnlyEnabled; return; }
            if (networkOnlyPendingID != "") return;
            networkOnlyRequested = networkOnly.IsChecked == true;
            networkOnlyPendingID = Guid.NewGuid().ToString("N");
            networkOnly.IsEnabled = false;
            SetNotice("正在儲存「僅保留網路連線」設定…");
            DesktopClient.SendRaw(JsonSerializer.Serialize(new {
                action = networkOnlyRequested ? "network-only-on" : "network-only-off", id = networkOnlyPendingID
            }));
        };
        Opened += (_, _) => { PreviewWindowArgs(); UpdateResponsiveLayout(); if (!preview) { DesktopClient.SendRaw("{\"action\":\"ready\"}");  } if (Program.SecurityPreview) SeedSecurityPreview(); if (Program.SecuritySmoke) Dispatcher.UIThread.Post(RunSecuritySmoke, DispatcherPriority.Background); if (Program.SMBWireSmoke) Dispatcher.UIThread.Post(OpenSMBManager, DispatcherPriority.Background); if (Program.ConnectionSmoke) Dispatcher.UIThread.Post(RunConnectionSmoke, DispatcherPriority.Background); if (Program.SecurityWireSmoke) Dispatcher.UIThread.Post(StartSecurityWireSmoke, DispatcherPriority.Background); if (Program.ProcessPreview) Dispatcher.UIThread.Post(() => OpenSecurity(TasksTab), DispatcherPriority.Background); if (Program.ProcessSmoke) Dispatcher.UIThread.Post(RunProcessSmoke, DispatcherPriority.Background); };
        Closed += (_, _) => CancelProgramExitConfirmation();

        ApplyConnectionSummary(0);
        if (preview) SeedPreview();
        else if (!Program.NoBackendReader) _ = Task.Run(ReadBackend);
    }

    static void AddAt(Grid grid, Control child, int row) { Grid.SetRow(child, row); grid.Children.Add(child); }

    StackPanel bodyHost = null!;
    Grid overview = null!;
    Control hero = null!;
    readonly Orb heroOrb = new(92);
    Border hostCard = null!, settingsBorder = null!;
    Grid connectionColumn = null!, settingsList = null!;
    // Density levels: 0 roomy, 1 compact, 2 dense. Each column picks the roomiest level whose natural height fits
    // the window, so the dashboard needs no scrolling; the ScrollViewer is only the fallback below the densest level.
    int leftDensity = -1, rightDensity = -1, chromeDensity = -1;
    bool fitting, fitScheduled;

    // Density changes re-measure the body, which must not happen inside the layout pass that reports the viewport.
    void ScheduleFit()
    {
        if (fitScheduled) return;
        fitScheduled = true;
        Dispatcher.UIThread.Post(() => { fitScheduled = false; FitBodyToViewport(); }, DispatcherPriority.Loaded);
    }

    const double BodyMaxWidth = 1120, ChartMin = 140, ChartMax = 400, ChartCompact = 200;

    /// Settles the layout for the current viewport: synchronous, so smoke tests can call it after resizing.
    /// Every section keeps its natural height; the roomiest density whose total fits the window wins.
    internal void FitBodyToViewport()
    {
        if (fitting) return;
        fitting = true;
        try
        {
            ApplyChrome();
            var banner = backendFailureBanner.IsVisible ? backendFailureBanner.Bounds.Height + Scale.Gutter : 0;
            var available = Math.Max(0, bodyScroll.Viewport.Height - banner);
            if (compactLayout == false && available > 0 && bodyScroll.Viewport.Width > 0)
            {
                // Measure each density with the chart at its minimum; the chart then takes whatever height is left.
                trafficChart.Height = ChartMin;
                var natural = 0.0;
                for (var level = 0; level <= 2; level++)
                {
                    ApplyLeft(level); ApplyRight(level, false); UpdateLayout();
                    natural = hero.DesiredSize.Height + bodyHost.Spacing + body.DesiredSize.Height;
                    if (natural <= available + .5) break;
                }
                trafficChart.Height = Math.Floor(Math.Clamp(ChartMin + available - natural - 1, ChartMin, ChartMax));
            }
            else { ApplyLeft(0); ApplyRight(0, false); trafficChart.Height = ChartCompact; }
        }
        finally { fitting = false; }
    }

    /// New content (a benchmark result, a notice) can make the sections taller; tighten again only then.
    void RefitIfOverflow()
    {
        if (compactLayout != false || (leftDensity >= 2 && rightDensity >= 2)) return;
        var banner = backendFailureBanner.IsVisible ? backendFailureBanner.Bounds.Height + Scale.Gutter : 0;
        if (hero.DesiredSize.Height + bodyHost.Spacing + body.DesiredSize.Height > bodyScroll.Viewport.Height - banner + .5) FitBodyToViewport();
    }

    /// Outer margins and row gaps follow the window height alone, so they cannot feed back into the measuring.
    void ApplyChrome()
    {
        var level = compactLayout != false ? 0 : ClientSize.Height < 600 ? 2 : ClientSize.Height < 720 ? 1 : 0;
        if (level == chromeDensity) return;
        chromeDensity = level;
        var custom = UsesCustomTitleBar;
        root.Margin = new Thickness(Scale.Margin, custom ? 8 : level == 2 ? Scale.Medium : Scale.Margin, Scale.Margin, level == 2 ? Scale.Medium : Scale.Margin);
        root.RowDefinitions = new RowDefinitions(level switch { 0 => "Auto,16,*", 1 => "Auto,12,*", _ => "Auto,8,*" });
        overview.RowDefinitions = new RowDefinitions(level switch { 0 => "*,12,Auto", 1 => "*,8,Auto", _ => "*,8,Auto" });
    }

    void ApplyLeft(int level)
    {
        if (leftDensity == level) return;
        leftDensity = level;
        bodyHost.Spacing = level switch { 0 => Scale.XLarge, 1 => Scale.Large, _ => Scale.Medium };
        hostCard.Padding = new Thickness(Scale.Tight, level == 0 ? Scale.Medium : Scale.Tight, Scale.Tight, 0);
        heroOrb.Width = heroOrb.Height = level switch { 0 => 128, 1 => 104, _ => 72 };
        heroDevices.IsVisible = level < 2;
        macStatus.SetDensity(level); ipadStatus.SetDensity(level);
    }

    void ApplyRight(int level, bool equal)
    {
        if (rightDensity == level) return;
        rightDensity = level;
        RebuildBodyGrid();
    }

    void UpdateResponsiveLayout()
    {
        var compact = ClientSize.Width < 880;
        if (compactLayout == compact) { if (ClientSize.Height > 0) ApplyChromeIfChanged(); return; }
        compactLayout = compact;
        leftDensity = rightDensity = -1;
        RebuildBodyGrid();
        ScheduleFit();
    }

    void ApplyChromeIfChanged()
    {
        var level = compactLayout != false ? 0 : ClientSize.Height < 600 ? 2 : ClientSize.Height < 720 ? 1 : 0;
        if (level != chromeDensity) ScheduleFit();
    }

    void RebuildBodyGrid()
    {
        if (compactLayout is not { } compact) return;
        body.ColumnDefinitions = new ColumnDefinitions("*");
        body.RowDefinitions = new RowDefinitions("Auto");
    }

    async Task ReadBackend()
    {
        try
        {
            using var input = new StreamReader(Console.OpenStandardInput(), System.Text.Encoding.UTF8);
            string? line;
            while ((line = await input.ReadLineAsync()) != null)
            {
                using var json = JsonDocument.Parse(line);
                // Bound queued UI work even when a large list is being laid out.
                // Keep the document alive until the ordered update completes.
                await Dispatcher.UIThread.InvokeAsync(() => Update(json.RootElement), DispatcherPriority.Background);
            }
        }
        catch (Exception) { /* A broken parent pipe ends only the renderer. */ }
        finally { Dispatcher.UIThread.Post(() => { backendEnded = true; Close(); }); }
    }

    protected override void OnClosing(WindowClosingEventArgs e)
    {
        if (KeepInTray && !backendEnded && e.CloseReason is WindowCloseReason.WindowClosing or WindowCloseReason.Undefined)
        {
            e.Cancel = true;
            HideToTray();
        }
        base.OnClosing(e);
    }

    void HideToTray()
    {
        // Close owned editors to stop their polling and clear revealed passwords.
        // Only the already-built dashboard remains resident for the next tray click.
        foreach (var window in OwnedWindows.ToArray()) window.Close();
        CloseAllPages();
        Hide();
    }

    // ---------- sections ----------

    Control Header()
    {
        using var brandStream = Avalonia.Platform.AssetLoader.Open(new Uri("avares://USBLink.Desktop/Assets/usb-link.png"));
        var mark = new Image { Width = 28, Height = 28, Stretch = Stretch.Uniform,
            Source = new Avalonia.Media.Imaging.Bitmap(brandStream) };

        var version = new Border { CornerRadius = new CornerRadius(9), Padding = new Thickness(Scale.Snug, 1), Child = versionText }
            .Res(Border.BackgroundProperty, "IdleSoft");
        var name = Label("USB Link", Scale.Title3, FontWeight.SemiBold);
        var brand = Row(12, mark, name, version);
        brand.HorizontalAlignment = HorizontalAlignment.Left;
        var nav = NavBar();
        // Brand on the left, the switcher centered on the whole bar; the name gives way first when the window narrows.
        SizeChanged += (_, _) => { name.IsVisible = version.IsVisible = ClientSize.Width >= 900; };
        return WithWindowChrome(new Panel { Children = { brand, nav } });
    }

    /// The overview has no cards: a hero line (the host address every device dials, who is connected, the planet),
    /// one shared traffic chart, and one borderless row per device.
    Control HeroCard()
    {
        chip.ToneChanged += t => heroOrb.Tone = t;
        heroOrb.Tone = chip.Tone;
        var copyAddress = IconButton(Icons.Copy, "複製主機地址", () => Copy(WindowsHostIp, "主機地址"));
        copyAddress.Res(Button.BackgroundProperty, "IdleSoft"); copyAddress.VerticalAlignment = VerticalAlignment.Center;
        addressValue.FontWeight = FontWeight.Bold; addressValue.LetterSpacing = -1;
        var caption = Row(Scale.Medium, Label("Windows 主機地址", Scale.Callout, FontWeight.Medium, "Muted"), chip);
        var address = Row(Scale.Medium, addressValue, copyAddress);
        heroDevices.TextTrimming = TextTrimming.CharacterEllipsis;
        var text = Column(Scale.Snug, caption, address, heroDevices);
        text.VerticalAlignment = VerticalAlignment.Center;
        heroOrb.Width = heroOrb.Height = 128;
        heroOrb.VerticalAlignment = VerticalAlignment.Center; heroOrb.Margin = new Thickness(0, -12, 0, -12);
        var grid = Columns("*,Auto", text, heroOrb);
        grid.ColumnSpacing = Scale.Large;
        return hostCard = new Border { Child = grid, Padding = new Thickness(Scale.Tight, 0) };
    }

    readonly TextBlock heroDevices = Label("尚未連接裝置", Scale.Body, key: "Muted");
    readonly TrafficChart trafficChart = new() { Height = ChartMin };

    void UpdateHeroDevices(DeviceStatusSnapshot d)
    {
        var parts = new List<string>();
        if (d.Mac.Connected) parts.Add("Mac " + d.Mac.PeerIPv4);
        if (d.IPad.Connected) parts.Add("iPad " + d.IPad.PeerIPv4);
        heroDevices.Text = parts.Count > 0 ? "已連線：" + string.Join("　·　", parts.Select(p => p.Trim())) : "Mac 與 iPad 經 USB 連到這個地址";
    }

    // The chart with its title and legend, then the device rows split by hairlines.
    Control ConnectionCard()
    {
        macStatus = new DeviceStatusView("Mac", Send, Copy, "Accent");
        ipadStatus = new DeviceStatusView("iPad", Send, Copy, "Olive");
        trafficChart.Add(macStatus.History, "Accent"); trafficChart.Add(ipadStatus.History, "Olive");
        Control Key(string name, string tone) => Row(Scale.Snug,
            new Border { Width = 8, Height = 8, CornerRadius = new CornerRadius(4), VerticalAlignment = VerticalAlignment.Center }.Res(Border.BackgroundProperty, tone),
            Label(name, Scale.Callout, key: "Muted"));
        var legend = Row(Scale.Regular, Key("Mac", "Accent"), Key("iPad", "Olive"));
        legend.VerticalAlignment = VerticalAlignment.Center;
        var title = Row(Scale.Small, Label("傳輸速率", Scale.Title3, FontWeight.SemiBold), Label("MB/s · 傳送與接收合計", Scale.Callout, key: "Subtle"));
        var head = Columns("*,Auto", title, legend);
        Control Rule() => new Border { Height = 1 }.Res(Border.BackgroundProperty, "Stroke");
        connectionColumn = Rows("Auto,12,Auto,16,Auto,Auto,Auto,Auto", head, Gap(), trafficChart, Gap(), Rule(), macStatus.View, Rule(), ipadStatus.View);
        return connectionColumn;
    }

    Control SettingsCard()
    {
        var rows = new List<Control>();
        void Add(Control row) => rows.Add(row);
        Add(SettingRow.Toggle(Icons.Play, "開機自動啟動", "登入 Windows 後在背景待命", startup, tone: "TileGray"));
        Add(SettingRow.Toggle(Icons.Globe, "僅保留網路連線", "避免 iPad 出現「信任這部電腦」提示", networkOnly,
            "封鎖 Windows 對此 iPad 的照片匯入與儲存空間瀏覽，避免出現「信任這部電腦」提示。\n關閉此開關、結束程式或解除安裝時會還原。", networkOnlyStatus, tone: "TileOrange"));
        var title = WithMargin(Label("一般", Scale.Title3, FontWeight.SemiBold), new Thickness(Scale.Medium, 0, 0, Scale.Tight));
        settingsList = SettingRow.List(rows.ToArray());
        // Rows keep their natural height (grouped-list rows do not stretch); the tool tiles sit on the card's floor.
        return settingsBorder = Card(Rows("Auto,Auto", title, settingsList), new Thickness(Scale.Tight, Scale.Medium, Scale.Tight, Scale.Tight));
    }



    Control Footer()
    {
        // Exiting is deliberate and restores settings first; it lives in the tray icon's menu, not on the dashboard.
        var background = Label("關閉視窗後縮至托盤，連線繼續運作 · 要退出請用托盤圖示選單的「退出程序」", Scale.Secondary, key: "Subtle");
        background.VerticalAlignment = VerticalAlignment.Center; background.TextWrapping = TextWrapping.Wrap; background.TextTrimming = TextTrimming.None;
        background.HorizontalAlignment = HorizontalAlignment.Right; background.TextAlignment = TextAlignment.Right;

        background.MaxWidth = 440;
        var grid = Columns("*,Auto", noticeBar, background);
        noticeBar.HorizontalAlignment = HorizontalAlignment.Left;
        noticeBar.Margin = new Thickness(0, 0, Scale.Regular, 0);
        automaticIsolationStatus.TextWrapping = programExitStatus.TextWrapping = TextWrapping.Wrap;
        automaticIsolationStatus.IsVisible = programExitStatus.IsVisible = false;
        return Column(6, automaticIsolationStatus, programExitStatus, grid);
    }

    void RequestProgramExit()
    {
        if (preview) { SetNotice("介面預覽，不會停止連線或修改系統。"); return; }
        if (programExitAwaiting) return;
        foreach (var window in OwnedWindows.ToArray()) window.Close();
        CloseAllPages();
        if (programExitID == "" || programExitPhase == "failed") programExitID = Guid.NewGuid().ToString("N");
        programExitPhase = "requesting";
        programExitAwaiting = true; programExitCommitSent = false;
        bodyScroll.IsEnabled = false;
        programExitStatus.Text = "正在要求停止連線，核對恢復完成後才會退出…";
        programExitStatus.IsVisible = true;
        // Restoration is core work and continues unchanged; the user only needs the window gone.
        // Send first so the request never waits on the window teardown.
        SendProgramExitRequest("exit-program");
        HideForProgramExit();
    }

    // Hidden, not closed: the same window returns with its failure text if the restore does not complete.
    bool exitHidden;
    void HideForProgramExit()
    {
        exitHidden = true;
        if (!preview) Hide(); // The preview harness keeps its window for screenshots.
    }
    void ShowAfterProgramExitProblem()
    {
        if (!exitHidden) return;
        exitHidden = false;
        Show(); WindowState = WindowState.Normal; WindowFit.Refit(this); Activate();
    }

    void CancelProgramExitConfirmation()
    {
        programExitConfirmationTimer?.Stop(); programExitConfirmationTimer = null;
        programExitConfirmationGeneration++;
    }

    void SendProgramExitRequest(string action)
    {
        CancelProgramExitConfirmation();
        var generation = programExitConfirmationGeneration;
        var id = programExitID;
        // This bounds acknowledgement waiting, never the native restore work.
        programExitConfirmationTimer = new DispatcherTimer { Interval = TimeSpan.FromSeconds(30) };
        programExitConfirmationTimer.Tick += (_, _) => ExpireProgramExitConfirmation(id, generation);
        programExitConfirmationTimer.Start();
        try { if (!preview) DesktopClient.SendRaw(JsonSerializer.Serialize(new { action, id })); }
        catch { ExpireProgramExitConfirmation(id, generation); }
    }

    void ExpireProgramExitConfirmation(string id, long generation)
    {
        if (id != programExitID || generation != programExitConfirmationGeneration || !programExitAwaiting) return;
        CancelProgramExitConfirmation();
        programExitAwaiting = programExitCommitSent = false;
        programExitStatus.Text = "未能確認退出要求，程序仍保留。請從托盤圖示選單再次選擇「退出程序」重試；這不代表恢復已完成。";
        programExitStatus.IsVisible = true;
        ShowAfterProgramExitProblem();
    }

    // The switch shows the saved choice; the line below shows what was read back.
    void UpdateNetworkOnly(JsonElement n, bool stopping)
    {
        string NS(string k) => n.TryGetProperty(k, out var v) && v.ValueKind == JsonValueKind.String ? v.GetString() ?? "" : "";
        bool NB(string k) => n.TryGetProperty(k, out var v) && v.ValueKind == JsonValueKind.True;
        int NI(string k) => n.TryGetProperty(k, out var v) && v.ValueKind == JsonValueKind.Number && v.TryGetInt32(out var i) ? i : 0;
        bool rejected = networkOnlyPendingID != "" && NS("rejected_id") == networkOnlyPendingID;
        if (rejected || (networkOnlyPendingID != "" && NS("request_id") == networkOnlyPendingID && !NB("busy"))) networkOnlyPendingID = "";
        networkOnlyEnabled = NB("enabled");
        networkOnly.IsChecked = networkOnlyPendingID != "" ? networkOnlyRequested : NB("busy") ? NB("requested") : networkOnlyEnabled;
        networkOnly.IsEnabled = networkOnlyPendingID == "" && !NB("busy") && !stopping;
        var error = NS("error");
        var failure = error != "" || NB("restore_pending");
        string text;
        if (NB("restore_pending")) text = "照片介面尚未確認還原：" + (error != "" ? error : "待確認") + "。請重試或退出程序後再確認。";
        else if (failure) text = "未能完整封鎖：" + error + "。受影響的介面保持原狀。";
        else if (!networkOnlyEnabled) text = NB("restoring") ? "正在還原照片與儲存空間存取…" : "已關閉";
        else if (NB("effective")) text = $"已封鎖照片與儲存空間（已套用 {NI("known_applied")}/{NI("known_nodes")} 個介面）";
        else if (NI("known_nodes") > 0) text = $"已開啟，正在核對 {NI("known_nodes")} 個介面…";
        else text = "已開啟，首次連線時自動套用";
        networkOnlyStatus.Text = text;
        networkOnlyStatus.IsVisible = true;
        networkOnlyStatus.Res(TextBlock.ForegroundProperty, failure ? "Warn" : networkOnlyEnabled && NB("effective") ? "Ok" : "Subtle");
        if (rejected) SetNotice("上一項設定仍在處理，這次操作未執行；請稍候再試。");
    }

    void UpdateProgramLifecycle(JsonElement d)
    {
        if (d.TryGetProperty("default_network_isolation", out var isolation) && isolation.ValueKind == JsonValueKind.Object)
        {
            string S(string k) => isolation.TryGetProperty(k, out var v) && v.ValueKind == JsonValueKind.String ? v.GetString() ?? "" : "";
            bool B(string k) => isolation.TryGetProperty(k, out var v) && v.ValueKind == JsonValueKind.True;
            var phase = S("phase");
            var failure = S("error") != "" || phase == "recovery_pending";
            automaticIsolationStatus.IsVisible = true;
            automaticIsolationStatus.Text = failure ? "自動連線策略尚未完成，恢復狀態需要處理。Apple 服務：" + (B("amds_restored") ? "已恢復" : "待確認") + "；照片介面：" + (B("photo_restored") ? "已恢復" : "待確認") + "；舊照片策略：" + (B("policy_restored") ? "已恢復" : "待確認") + "。"
                : phase == "restored" && B("restored") ? "Apple 服務、照片介面與舊照片策略均已恢復。"
                : phase is "restoring" or "recovering_previous" || B("busy") ? "正在恢復 Apple 服務與照片介面，尚未確認完成。"
                : phase == "running" ? "自動連線策略 · Apple 服務：" + (B("amds_effective") ? "已暫停" : "待確認") + "；照片介面：" + (!networkOnlyEnabled ? "已關閉" : B("photo_effective") ? "已隔離" : "等候適用裝置") + "。退出程序時恢復。"
                : "自動連線策略尚未就緒，恢復狀態待確認。";
            automaticIsolationStatus.Res(TextBlock.ForegroundProperty, failure ? "Warn" : "Muted");
        }
        if (!d.TryGetProperty("program_exit", out var exit) || exit.ValueKind != JsonValueKind.Object) return;
        string E(string k) => exit.TryGetProperty(k, out var v) && v.ValueKind == JsonValueKind.String ? v.GetString() ?? "" : "";
        var phaseExit = E("phase");
        if (phaseExit == "idle" || programExitAwaiting && E("request_id") != programExitID) return; // Queued status cannot complete another request.
        if (!programExitCommitSent) CancelProgramExitConfirmation();
        programExitPhase = phaseExit;
        programExitStatus.IsVisible = true;
        programExitStatus.Text = phaseExit == "failed" ? "恢復尚未完成，程序仍保留，USB 連線已停止。可從托盤圖示選單再次選擇「退出程序」重試恢復。"
            : phaseExit == "ready" ? programExitAwaiting ? "已停止連線並確認恢復，正在完成退出。" : "恢復已確認，退出尚未完成；可從托盤圖示選單再次選擇「退出程序」重試確認。"
            : phaseExit == "restoring" ? "USB 連線已停止，正在恢復 Apple 服務、照片介面與網路設定…"
            : "正在停止 USB 連線，完成後會恢復設定…";
        if (phaseExit == "failed") { CancelProgramExitConfirmation(); programExitAwaiting = programExitCommitSent = false; }
        if (phaseExit == "failed") ShowAfterProgramExitProblem();
        if (phaseExit == "ready" && programExitAwaiting && !programExitCommitSent && E("request_id") == programExitID)
        {
            programExitCommitSent = true;
            SendProgramExitRequest("exit-program-commit");
        }
    }

    static TextBlock WithWrap(TextBlock t, double width) { t.TextWrapping = TextWrapping.Wrap; t.MaxWidth = width; return t; }

    // ---------- diagnostics window ----------

    void OpenDetails()
    {
        if (detailWindow != null) { detailWindow.Activate(); return; }
        var copy = Action("複製全部", () => Copy(detailText, "診斷內容"), Icons.Copy);
        var diagnostics = Card(detailRows, new Thickness(4));
        var debugDetails = new Expander { Header = "詳細診斷 / 調試資訊", IsExpanded = false, HorizontalAlignment = HorizontalAlignment.Stretch, Content = diagnostics };
        // Settings page: the general switches first, then the connection diagnostics that used to be their own tab.
        var diagnosticsTitle = WithMargin(Label("連線診斷", Scale.Title3, FontWeight.SemiBold), new Thickness(Scale.Tight, Scale.Small, 0, 0));
        // What scale the window really renders at, next to what Windows reports for this screen, so a display-scaling
        // problem can be read off the page instead of guessed.
        var scaleNote = Label("", Scale.Callout, key: "Muted");
        void ShowScale()
        {
            var screen = Screens.ScreenFromWindow(this)?.Scaling ?? 0;
            scaleNote.Text = $"介面縮放：{RenderScaling * 100:0}%　·　此螢幕的 Windows 顯示縮放：{(screen > 0 ? (screen * 100).ToString("0") + "%" : "未知")}";
            // macOS reports screens in points, so only Windows can disagree meaningfully.
            scaleNote.Res(TextBlock.ForegroundProperty, OperatingSystem.IsWindows() && screen > 0 && Math.Abs(screen - RenderScaling) > .01 ? "Warn" : "Muted");
        }
        ShowScale(); ScalingChanged += (_, _) => ShowScale();
        var content = Column(Scale.Gutter, settingsCard, WithMargin(scaleNote, new Thickness(Scale.Tight, 0, 0, 0)), diagnosticsTitle, InternetSection(), debugDetails, Gap(4));
#if USBLINK_LOCAL_DIAGNOSTICS
        content.Children.Insert(3, LocalDiagnosticsSection());
#endif
        var scroll = new ScrollViewer { Content = content, HorizontalScrollBarVisibility = Avalonia.Controls.Primitives.ScrollBarVisibility.Disabled };
        detailWindow = NewPage("details", "設定", 520, 420);
        detailWindow.Content = AppWindow.Page(AppWindow.Hero("OrbDetails", "設定", "開機啟動、網路連線與連線診斷 · 診斷每秒更新", copy), scroll);
        detailWindow.Closed += (_, _) =>
        {
            scroll.Content = null; diagnostics.Child = null;
#if USBLINK_LOCAL_DIAGNOSTICS
            localDiagnosticsRefresh = null;
            localTrustExperimentRefresh = null;
#endif
            content.Children.Clear(); detailWindow = null;
        };
        RenderDetails();
        detailWindow.Show(this);
    }

    void RenderDetails()
    {
#if USBLINK_LOCAL_DIAGNOSTICS
        localDiagnosticsRefresh?.Invoke();
#endif
        var lines = new List<string>();
        if (detailText.Trim() == "")
        {
            lines.Add("尚無診斷資料；連接裝置後會自動更新。");
        }
        else
        {
            foreach (var raw in detailText.Replace("\r", "").Split('\n'))
            {
                var line = raw.Trim();
                if (line != "" || lines.Count > 0) lines.Add(line);
            }
        }
        // Keep unchanged rows and their layout when only counters change.
        for (var index = 0; index < lines.Count; index++)
        {
            var line = lines[index];
            if (index < detailRows.Children.Count && detailRows.Children[index].Tag is DiagnosticLineView previous && previous.Update(line)) continue;
            var current = new DiagnosticLineView(line);
            if (index < detailRows.Children.Count) detailRows.Children[index] = current.View;
            else detailRows.Children.Add(current.View);
        }
        while (detailRows.Children.Count > lines.Count) detailRows.Children.RemoveAt(detailRows.Children.Count - 1);
    }

    // ---------- state ----------

    static Tone ToneOf(string title, string device)
    {
        if (title.Contains("問題")) return Tone.Error;
        if (title.Contains("已停止") || title.Contains("拒絕") || title.Contains("暫停")) return Tone.Warn;
        if (title == "" || title.Contains("等候 USB")) return Tone.Idle;
        if (title.StartsWith("正在") || title.Contains("等候")) return Tone.Busy;
        return device == "" ? Tone.Busy : Tone.Ok;
    }

    void ApplyConnectionSummary(int connected, int connecting = 0, bool error = false)
    {
        var color = connected > 0 ? "Ok" : connecting > 0 ? "Warn" : error ? "Error" : "Idle";
        chip.Set(color, connected > 0 ? $"已連線 · {connected} 台裝置" : connecting > 0 ? $"正在連線 · {connecting} 台裝置" : error ? "連線異常" : "等候裝置");
    }

    void SeedPreview()
    {
        using var json = JsonDocument.Parse("""
        {"event":"status","windows_ipv4":"10.6.9.1","devices":[
          {"device":"Mac","title":"Mac USB 已連接","connected":true,"peer_ipv4":"10.6.9.2","peer_address_state":"已確認","tx":1027.2,"rx":25.6,"speed":"USB 協商速率：SuperSpeed","latency":"HTTP 往返 · 1.2 ms","benchmark_available":true,"benchmark_url":"http://10.6.9.1:10690/speed/","benchmark_summary":"在 Mac 瀏覽器開啟下方網址測速，無需安裝程式。"},
          {"device":"iPad","title":"iPad 的 USB IPv4 通信已驗證","connected":true,"peer_ipv4":"10.6.9.3","peer_address_state":"已確認","tx":512,"rx":12.8,"speed":"USB 協商速率：SuperSpeed","latency":"HTTP 往返 · 2.4 ms","benchmark_url":"http://10.6.9.1:58723/speed/","benchmark_summary":"在 iPad 瀏覽器開啟下方網址測速，無需安裝程式。"}
        ],"detail":"Mac USB\n通信驗證：已驗證 IPv4 往返\n\niPad USB\n通信驗證：已驗證 IPv4 往返","share_ready":true,"share_enabled":true,"startup":true,"network_only":{"enabled":true,"effective":true,"known_nodes":1,"known_applied":1}}
        """);
        Update(json.RootElement);
        macStatus.SeedTraffic(128, 3); ipadStatus.SeedTraffic(64, 1.6);
        SetNotice("介面預覽數據，不代表實測速率。");
    }

    void UpdateShare()
    {
        shareToggle.IsChecked = shareEnabled;
        shareToggle.IsEnabled = shareReady || shareEnabled;
        shareStatus.Text = shareEnabled ? (shareReady ? "已開啟 · USB 對端可存取" : "已開啟 · 等候 USB 連線") : (shareReady ? "已就緒，尚未開啟" : "請先連接 USB 裝置");
        if(nativeSMB){shareToggle.IsEnabled=true;shareStatus.Text=shareProblem!=""?"Windows SMB · 需要處理":!shareReady?"Windows SMB · 服務未就緒":shareEnabled?"Windows SMB · 持續共享":"Windows SMB · 共享已關閉";}
        ToolTip.SetTip(shareStatus,shareProblem!=""?shareProblem:shareStatus.Text);
        shareStatus.Res(TextBlock.ForegroundProperty, shareProblem!=""?"Warn":shareEnabled && shareReady ? "Ok" : "Muted");
    }

    void Update(JsonElement d)
    {
        string S(string k) => d.TryGetProperty(k, out var v) && v.ValueKind == JsonValueKind.String ? v.GetString() ?? "" : "";
        bool B(string k) => d.TryGetProperty(k, out var v) && v.ValueKind == JsonValueKind.True;
        if (S("event") == "program-exit-request") { RequestProgramExit(); return; }
        if (S("event") == "program-exit-result")
        {
            if (S("request_id") != programExitID || programExitID == "") return;
            CancelProgramExitConfirmation();
            programExitAwaiting = programExitCommitSent = false;
            programExitStatus.Text = "未能確認退出要求，程序仍保留。請從托盤圖示選單再次選擇「退出程序」重試。";
            programExitStatus.IsVisible = true;
            ShowAfterProgramExitProblem();
            return;
        }
        if (S("event") == "program-exit-complete")
        {
            if (S("request_id") == programExitID && programExitCommitSent && !preview)
                (Application.Current?.ApplicationLifetime as IClassicDesktopStyleApplicationLifetime)?.Shutdown();
            return;
        }
        if (S("event") == "backend-unavailable") { if (!programExitCommitSent) ShowAfterProgramExitProblem(); MarkBackendUnavailable(S("code")); return; }
        if (S("event") == "shutdown") { (Application.Current?.ApplicationLifetime as IClassicDesktopStyleApplicationLifetime)?.Shutdown(); return; }
        if (S("event") == "show") { Show(); WindowState = WindowState.Normal; WindowFit.Refit(this); Activate(); return; }
#if USBLINK_LOCAL_DIAGNOSTICS
        if (S("event") == "local-control-result") { UpdateLocalControlResult(d); return; }
#endif
        if (backendUnavailable)
        {
            if (S("event") != "status" || S("version") == "") return;
#if USBLINK_LOCAL_DIAGNOSTICS
            localDiagnosticsPendingID = "";
            photoIsolationPendingID = "";
            ResetTrustExperimentWaits();
#endif
            backendUnavailable = false;
            backendFailureBanner.IsVisible = false;
            body.IsEnabled = true;
        }
#if USBLINK_LOCAL_DIAGNOSTICS
        UpdateLocalDiagnostics(d);
#endif
        UpdateInternet(d);
        if (S("version") != "") versionText.Text = verifiedBackendVersion = S("version");
        if (S("event") == "update-notice") { ShowUpdateNotice(d); return; }
        if (S("event") == "smb-account") { UpdateSMBAccount(d); return; }
        if (S("event") == "share-folders") { UpdateShareFolders(d); return; }
        if (S("event") == "gateway-request") { ShowGatewayRequest(d); return; }
        if (S("event") == "gateway") { UpdateGateway(d); return; }
        if (S("event") == "security") { UpdateSecurity(d); return; }
        if (d.TryGetProperty("network_only", out var networkOnlyState) && networkOnlyState.ValueKind == JsonValueKind.Object) UpdateNetworkOnly(networkOnlyState, B("stopping"));
        UpdateProgramLifecycle(d);
        // The custom caption remains usable while the core finishes stopping.
        bodyScroll.IsEnabled = !B("stopping") && programExitPhase == "idle" && !programExitAwaiting;
        footerControl.IsEnabled = !B("stopping") || programExitPhase != "idle";

        if (S("windows_ipv4") != "") { WindowsHostIp = S("windows_ipv4"); ShareUrl = S("share_url") != "" ? S("share_url") : "smb://" + WindowsHostIp; addressValue.Text = WindowsHostIp; shareUrlValue.Text = ShareUrl; }
        var devices = DeviceStatusSnapshot.Parse(d);
        macStatus.Update(devices.Mac); ipadStatus.Update(devices.IPad); UpdateHeroDevices(devices);
        ApplyConnectionSummary(devices.ConnectedCount, devices.ConnectingCount, devices.HasError);
        Dispatcher.UIThread.Post(RefitIfOverflow, DispatcherPriority.Loaded);

        SetNotice(S("notice"));
        var detail = S("detail");
        if(S("share_problem")!="")detail += "\r\nWindows SMB：" + S("share_problem");
        if (detail != detailText) { detailText = detail; if (detailWindow != null) RenderDetails(); }

        // Queued status from before the click must not roll back the visual choice.
        // Only the matching completed request returns to verified backend state.
        bool startupRejected = startupPendingID != "" && S("startup_rejected_id") == startupPendingID;
        if (startupRejected || (startupPendingID != "" && S("startup_request_id") == startupPendingID && !B("startup_busy")))
            startupPendingID = "";
        startup.IsChecked = startupPendingID != "" ? startupRequested
            : B("startup_busy") ? B("startup_requested") : B("startup");
        startup.IsEnabled = startupPendingID == "" && !B("startup_busy") && !B("stopping");
        if (startupPendingID != "") SetNotice("正在儲存並核對開機啟動設定…");
        else if (startupRejected) SetNotice("上一項開機設定仍在處理，這次操作未執行；請稍候再試。");
        shareReady = B("share_ready"); shareEnabled = B("share_enabled"); nativeSMB=B("native_smb"); nativeAccount=S("native_account"); shareProblem=S("share_problem");
        UpdateShare();
    }
}
