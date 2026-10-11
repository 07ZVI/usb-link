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

    readonly TextBlock addressValue = Label("10.6.9.1", 34, FontWeight.SemiBold), shareUrlValue = Label(SMBServerAddress, 13);
    readonly TextBlock versionText = Label(Program.Preview ? "預覽" : "正在核對版本", 11, key: "Muted");
    readonly TextBlock chipText = Label("等候裝置", 12, FontWeight.SemiBold), notice = Label("", 12), shareStatus = Label("請先連接 USB 裝置", 12, key: "Muted");
    readonly Border chip = new() { CornerRadius = new CornerRadius(12), Padding = new Thickness(10, 4, 12, 4) },
        chipDot = new() { Width = 8, Height = 8, CornerRadius = new CornerRadius(4) },
        noticeBar = new() { CornerRadius = new CornerRadius(6), Padding = new Thickness(10, 6), IsVisible = false };
    DeviceStatusView macStatus = null!, ipadStatus = null!;
    readonly ToggleSwitch shareToggle = Switch(), startup = Switch();
    string startupPendingID = "";
    bool startupRequested;
    readonly StackPanel detailRows = new() { Spacing = 0 };
    readonly Grid root = new();
    readonly Grid body = new();
    readonly ScrollViewer bodyScroll = new() { HorizontalScrollBarVisibility = Avalonia.Controls.Primitives.ScrollBarVisibility.Disabled };
    Control connectionCard = null!, shareCard = null!, settingsCard = null!, footerControl = null!;
    bool? compactLayout;
    Window? detailWindow;
    string detailText = "";
    bool shareEnabled, shareReady, nativeSMB;
 string nativeAccount="", shareProblem="";
    readonly bool preview = Program.Preview;

    // ---------- building blocks ----------

    static TextBlock Label(string text, double size = 14, FontWeight? weight = null, string key = "Ink")
    {
        var t = new TextBlock { Text = text, FontSize = size, FontWeight = weight ?? FontWeight.Normal, TextWrapping = TextWrapping.NoWrap, TextTrimming = TextTrimming.CharacterEllipsis };
        return t.Res(TextBlock.ForegroundProperty, key);
    }
    static ToggleSwitch Switch() => new() { OnContent = "", OffContent = "", MinWidth = 0, Padding = new Thickness(0), VerticalAlignment = VerticalAlignment.Center };
    static Border Card(Control child, Thickness? padding = null) => new Border
    {
        Child = child, BorderThickness = new Thickness(1), CornerRadius = new CornerRadius(8), Padding = padding ?? new Thickness(20),
    }.Res(Border.BackgroundProperty, "Card").Res(Border.BorderBrushProperty, "Stroke");
    static Border Rule() => new Border { Height = 1 }.Res(Border.BackgroundProperty, "Stroke");
    static Grid Columns(string defs, params Control[] children)
    {
        var g = new Grid { ColumnDefinitions = new ColumnDefinitions(defs) };
        for (var i = 0; i < children.Length; i++) { Grid.SetColumn(children[i], i); g.Children.Add(children[i]); }
        return g;
    }
    static Grid Rows(string defs, params Control[] children)
    {
        var g = new Grid { RowDefinitions = new RowDefinitions(defs) };
        for (var i = 0; i < children.Length; i++) { Grid.SetRow(children[i], i); g.Children.Add(children[i]); }
        return g;
    }
    static Control Gap(double h = 0) => new Border { Height = h };
    static StackPanel Row(double spacing, params Control[] children)
    {
        var p = new StackPanel { Orientation = Orientation.Horizontal, Spacing = spacing };
        foreach (var c in children) { c.VerticalAlignment = VerticalAlignment.Center; p.Children.Add(c); }
        return p;
    }
    static StackPanel Column(double spacing, params Control[] children)
    {
        var p = new StackPanel { Spacing = spacing };
        foreach (var c in children) p.Children.Add(c);
        return p;
    }
    Button Action(string text, Action onClick, string? icon = null, bool primary = false)
    {
        var label = Label(text, 13, primary ? FontWeight.SemiBold : FontWeight.Normal, primary ? "Window" : "Ink");
        Control content = icon is null ? label : Row(8, Icons.Make(icon, 16, primary ? "Window" : "Ink"), label);
        var b = new Button { Content = content, Padding = new Thickness(14, 7), CornerRadius = new CornerRadius(4), MinHeight = 34 };
        if (icon != null && text != "") Avalonia.Automation.AutomationProperties.SetName(b, text);
        b.BorderThickness = new Thickness(1);
        if (primary) b.Res(Button.BackgroundProperty, "Accent").Res(Button.BorderBrushProperty, "Accent");
        else b.Res(Button.BackgroundProperty, "Control").Res(Button.BorderBrushProperty, "Stroke");
        b.Click += (_, _) => onClick();
        return b;
    }
    Button IconButton(string icon, string tip, Action onClick)
    {
        var b = new Button { Content = Icons.Make(icon, 16, "Muted"), Padding = new Thickness(8), CornerRadius = new CornerRadius(4), Background = Brushes.Transparent, BorderThickness = new Thickness(0) };
        ToolTip.SetTip(b, tip);
        Avalonia.Automation.AutomationProperties.SetName(b, tip);
        b.Click += (_, _) => onClick();
        return b;
    }
    static Control Tile(string icon, string brush, string background, double size = 32)
    {
        var tile = new Border { Width = size, Height = size, CornerRadius = new CornerRadius(6), Child = Icons.Make(icon, size * .56, brush) };
        tile.Child!.HorizontalAlignment = HorizontalAlignment.Center; tile.Child.VerticalAlignment = VerticalAlignment.Center;
        return tile.Res(Border.BackgroundProperty, background);
    }

    // ---------- backend bridge ----------

    void Send(string action)
    {
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
        Title = "USB Link"; Width = 1040; Height = 780; MinWidth = 520; MinHeight = 420;
        ConfigureWindowChrome();
        FontFamily = new FontFamily(Palette.FontStack);
        // Windows 11 draws Mica behind the client area; older systems get the solid token.
        TransparencyLevelHint = new[] { WindowTransparencyLevel.Mica, WindowTransparencyLevel.None };
        this.Res(BackgroundProperty, "Window");
        PropertyChanged += (_, e) =>
        {
            if (e.Property == ActualTransparencyLevelProperty)
            {
                if (ActualTransparencyLevel == WindowTransparencyLevel.Mica) Background = Brushes.Transparent;
                else this.Res(BackgroundProperty, "Window");
            }
        };

        noticeBar.Res(Border.BackgroundProperty, "AccentSoft");
        Avalonia.Automation.AutomationProperties.SetName(shareToggle, "檔案共享");
        Avalonia.Automation.AutomationProperties.SetName(startup, "登入 Windows 後自動啟動");
        noticeBar.Child = Row(8, Icons.Make(Icons.Info, 16, "Accent"), notice);

        root.RowDefinitions = new RowDefinitions("Auto,16,*,12,Auto");
        root.Margin = new Thickness(24, UsesCustomTitleBar ? 8 : 18, 24, 16);
        AddAt(root, Header(), 0);
        connectionCard = ConnectionCard(); shareCard = ShareCard(); settingsCard = SettingsCard();
        body.Children.Add(connectionCard); body.Children.Add(shareCard); body.Children.Add(settingsCard);
        bodyScroll.Content = body;
        AddAt(root, bodyScroll, 2);
        footerControl = Footer();
        AddAt(root, footerControl, 4);

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
        Opened += (_, _) => { UpdateResponsiveLayout(); if (!preview) { DesktopClient.SendRaw("{\"action\":\"ready\"}");  } if (Program.SecurityPreview) SeedSecurityPreview(); if (Program.SecuritySmoke) Dispatcher.UIThread.Post(RunSecuritySmoke, DispatcherPriority.Background); if (Program.SMBWireSmoke) Dispatcher.UIThread.Post(OpenSMBAccount, DispatcherPriority.Background); if (Program.ConnectionSmoke) Dispatcher.UIThread.Post(RunConnectionSmoke, DispatcherPriority.Background); if (Program.SecurityWireSmoke) Dispatcher.UIThread.Post(StartSecurityWireSmoke, DispatcherPriority.Background); if (Program.ProcessPreview) Dispatcher.UIThread.Post(OpenTaskManager, DispatcherPriority.Background); if (Program.ProcessSmoke) Dispatcher.UIThread.Post(RunProcessSmoke, DispatcherPriority.Background); };
        if (Program.StandaloneTasks) Opened += (_, _) => Dispatcher.UIThread.Post(() => {
            OpenTaskManager(); taskWindow!.Closed += (_, _) => Close(); Hide();
        }, DispatcherPriority.Normal);
        Closed += (_, _) => taskWindow?.Close();

        ApplyConnectionSummary(0);
        if (preview) SeedPreview();
        else if (!Program.StandaloneTasks) _ = Task.Run(ReadBackend);
    }

    static void AddAt(Grid grid, Control child, int row) { Grid.SetRow(child, row); grid.Children.Add(child); }

    void UpdateResponsiveLayout()
    {
        var compact = ClientSize.Width < 880;
        if (compactLayout == compact) return;
        compactLayout = compact;
        body.ColumnDefinitions = new ColumnDefinitions(compact ? "*" : "1.25*,16,*");
        body.RowDefinitions = new RowDefinitions(compact ? "Auto,16,Auto,16,Auto" : "Auto,16,*");
        body.MinHeight = compact ? 0 : 560;
        Grid.SetRowSpan(connectionCard, compact ? 1 : 3);
        Grid.SetColumn(shareCard, compact ? 0 : 2); Grid.SetRow(shareCard, compact ? 2 : 0);
        Grid.SetColumn(settingsCard, compact ? 0 : 2); Grid.SetRow(settingsCard, compact ? 4 : 2);
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
                if (Program.BoundedIpc)
                {
                    // Keep the document alive until its ordered UI update completes.
                    // Backpressure retains at most one parsed snapshot and avoids
                    // cloning full security/share details into an unbounded queue.
                    await Dispatcher.UIThread.InvokeAsync(() => Update(json.RootElement));
                }
                else
                {
                    var message = json.RootElement.Clone(); Dispatcher.UIThread.Post(() => Update(message));
                }
            }
        }
        catch (Exception) { /* A broken parent pipe ends only the renderer. */ }
        finally { Dispatcher.UIThread.Post(Close); }
    }

    // ---------- sections ----------

    Control Header()
    {
        // Two sails, after the app icon.
        var mark = new Canvas { Width = 28, Height = 28 };
        mark.Children.Add(new Path { Data = Geometry.Parse("M13 3L13 22L3 22Z") }.Res(Shape.FillProperty, "Accent"));
        mark.Children.Add(new Path { Data = Geometry.Parse("M15 7L25 22L15 22Z") }.Res(Shape.FillProperty, "Cyan"));
        mark.Children.Add(new Path { Data = Geometry.Parse("M3 24.5h22"), StrokeThickness = 1.6, StrokeLineCap = PenLineCap.Round }.Res(Shape.StrokeProperty, "Accent"));

        var version = new Border { CornerRadius = new CornerRadius(4), Padding = new Thickness(6, 2), Child = versionText }
            .Res(Border.BackgroundProperty, "IdleSoft");
        var brand = Row(10, mark, Label("USB Link", 20, FontWeight.SemiBold), version);

        chip.Child = Row(7, chipDot, chipText);
        chip.VerticalAlignment = VerticalAlignment.Center;
        return WithWindowChrome(Columns("*,Auto", brand, chip));
    }

    Control ConnectionCard()
    {
        macStatus = new DeviceStatusView(this, "Mac");
        ipadStatus = new DeviceStatusView(this, "iPad");
        var address = Column(2, Label("Windows 主機地址", 12, key: "Muted"), addressValue);
        return Card(Rows("Auto,16,*,12,*", address, Gap(), macStatus.View, Gap(), ipadStatus.View), new Thickness(20));
    }

    Control ShareCard()
    {
        shareToggle.HorizontalAlignment = HorizontalAlignment.Right;
        var head = Columns("Auto,*,Auto",
            Tile(Icons.Folder, "Accent", "AccentSoft", 36),
            Column(1, Label("SMB 共享", 15, FontWeight.SemiBold), shareStatus),
            shareToggle);
        ((Control)head.Children[1]).Margin = new Thickness(12, 0, 8, 0);
        ((Control)head.Children[1]).VerticalAlignment = VerticalAlignment.Center;

        var url = shareUrlValue;
        url.VerticalAlignment = VerticalAlignment.Center;
        var field = new Border
        {
            CornerRadius = new CornerRadius(4), BorderThickness = new Thickness(1), Padding = new Thickness(10, 2, 2, 2),
            Child = Columns("Auto,*,Auto", Icons.Make(Icons.Link, 14, "Subtle"), WithMargin(url, new Thickness(8, 0, 0, 0)), IconButton(Icons.Copy, "複製地址", () => Copy(ShareUrl, "地址"))),
        }.Res(Border.BackgroundProperty, "Field").Res(Border.BorderBrushProperty, "Stroke");

        var open = Action("SMB 共享", OpenSMBManager, Icons.Folder);
        open.HorizontalAlignment = HorizontalAlignment.Stretch;
        open.HorizontalContentAlignment = HorizontalAlignment.Center;

        var help = Label("Mac：Finder ⌘K · iPad：文件 → 連接伺服器", 12, key: "Muted");
        var scope = Label("選「註冊使用者」並登入專用帳戶，可選擇共享資料夾。訪客請從「SMB 共享」複製完整地址。", 11, key: "Subtle");
        scope.TextWrapping = TextWrapping.Wrap; scope.MaxLines = 2;
        ToolTip.SetTip(scope, scope.Text);

        return Card(Column(12, head, field, open, help,scope));
    }

    static T WithMargin<T>(T c, Thickness m) where T : Control { c.Margin = m; return c; }

    Control SettingsCard()
    {
        var list = new StackPanel();
        void Add(Control row) { if (list.Children.Count > 0) list.Children.Add(WithMargin(Rule(), new Thickness(48, 0, 0, 0))); list.Children.Add(row); }
        Add(SettingRow(Icons.Clock, "登入 Windows 後自動啟動", "開機登入後在背景準備連線", startup, null));
        Add(SettingRow(Icons.Shield, "安全管理", "應用程式防火牆、連線與 USB 裝置", null, OpenSecurity));
        Add(SettingRow(Icons.Pulse, "工作管理員", "執行中的程式、資源用量與簽署憑證", null, OpenTaskManager));
        Add(SettingRow(Icons.Pulse, "連線診斷", "連線細節、網際網路共享與元件狀態", null, OpenDetails));
        var title = WithMargin(Label("設定與維護", 15, FontWeight.SemiBold), new Thickness(8, 0, 0, 6));
        return Card(Column(0, title, list), new Thickness(12, 16, 12, 8));
    }

    Control SettingRow(string icon, string title, string description, Control? trailing, Action? onClick)
    {
        var text = Column(1, Label(title, 13), Label(description, 11, key: "Subtle"));
        text.VerticalAlignment = VerticalAlignment.Center; text.Margin = new Thickness(12, 0, 8, 0);
        var end = trailing ?? Icons.Make(Icons.Chevron, 14, "Subtle");
        end.VerticalAlignment = VerticalAlignment.Center;
        var grid = Columns("Auto,*,Auto", Tile(icon, "Muted", "IdleSoft", 30), text, end);
        if (onClick is null)
            return new Border { Padding = new Thickness(8, 9), Child = grid };
        var b = new Button
        {
            Content = grid, HorizontalAlignment = HorizontalAlignment.Stretch, HorizontalContentAlignment = HorizontalAlignment.Stretch,
            Padding = new Thickness(8, 9), Background = Brushes.Transparent, BorderThickness = new Thickness(0), CornerRadius = new CornerRadius(6),
        };
        b.Click += (_, _) => onClick();
        Avalonia.Automation.AutomationProperties.SetName(b, title);
        return b;
    }

    Control Footer()
    {
        var background = Label("關閉視窗後，連線會繼續在背景運作。", 12, key: "Subtle");
        background.VerticalAlignment = VerticalAlignment.Center;

        var stopLabel = Label("退出介面", 12, key: "Error");
        var stop = new Button
        {
            Content = Row(6, Icons.Make(Icons.Power, 14, "Error"), stopLabel), Padding = new Thickness(10, 6),
            Background = Brushes.Transparent, BorderThickness = new Thickness(0), CornerRadius = new CornerRadius(4),
        };
        // The boot service owns connections independently of the login UI.
        var confirm = Action("退出介面", () => Send("stop"), primary: true);
        var flyout = new Flyout
        {
            Placement = PlacementMode.TopEdgeAlignedRight,
            Content = Column(10,
                Label("退出連線介面？", 14, FontWeight.SemiBold),
                WithWrap(Label("介面與托盤會關閉，USB 連線和共享繼續在背景運作。", 12, key: "Muted"), 260),
                WithAlign(confirm, HorizontalAlignment.Right)),
        };
        confirm.Click += (_, _) => flyout.Hide();
        stop.Flyout = flyout;

        var right = Row(12, background, stop);
        var grid = Columns("*,Auto", noticeBar, right);
        noticeBar.HorizontalAlignment = HorizontalAlignment.Left;
        noticeBar.Margin = new Thickness(0, 0, 16, 0);
        return grid;
    }

    static TextBlock WithWrap(TextBlock t, double width) { t.TextWrapping = TextWrapping.Wrap; t.MaxWidth = width; return t; }
    static T WithAlign<T>(T c, HorizontalAlignment a) where T : Control { c.HorizontalAlignment = a; return c; }

    // ---------- diagnostics window ----------

    void OpenDetails()
    {
        if (detailWindow != null) { detailWindow.Activate(); return; }
        var copy = Action("複製全部", () => Copy(detailText, "診斷內容"), Icons.Copy);
        var head = Columns("*,Auto", Column(2, Label("連線診斷", 18, FontWeight.SemiBold), Label("每秒更新 · 介面流量不代表線路頻寬上限", 12, key: "Muted")), copy);
        var diagnostics = Card(detailRows, new Thickness(4));
        var content = Column(16, InternetSection(), diagnostics, Gap(4));
        var scroll = new ScrollViewer { Content = content, HorizontalScrollBarVisibility = Avalonia.Controls.Primitives.ScrollBarVisibility.Disabled };
        var body = scroll;
        var layout = Rows("Auto,14,*", head, Gap(), body);
        layout.Margin = new Thickness(20);
        detailWindow = new Window
        {
            Title = "連線診斷 · USB Link", Width = 800, Height = 720, MinWidth = 520, MinHeight = 360,
            FontFamily = FontFamily, Content = layout,
        }.Res(BackgroundProperty, "Window");
        detailWindow.Closed += (_, _) =>
        {
            scroll.Content = null; diagnostics.Child = null;
            content.Children.Clear(); detailWindow = null;
        };
        RenderDetails();
        detailWindow.Show(this);
    }

    void RenderDetails()
    {
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
        chip.Res(Border.BackgroundProperty, color + "Soft");
        chipDot.Res(Border.BackgroundProperty, color);
        chipText.Res(TextBlock.ForegroundProperty, color == "Idle" ? "Muted" : color);
        chipText.Text = connected > 0 ? $"已連線 · {connected} 台裝置" : connecting > 0 ? $"正在連線 · {connecting} 台裝置" : error ? "連線異常" : "等候裝置";
    }

    void SeedPreview()
    {
        using var json = JsonDocument.Parse("""
        {"event":"status","windows_ipv4":"10.6.9.1","devices":[
          {"device":"Mac","title":"Mac USB 已連接","connected":true,"peer_ipv4":"10.6.9.2","peer_address_state":"已確認","tx":1027.2,"rx":25.6,"speed":"USB 協商速率：SuperSpeed","latency":"HTTP 往返 · 1.2 ms","benchmark_available":true,"benchmark_summary":"Mac 測速端已就緒"},
          {"device":"iPad","title":"iPad 的 USB IPv4 通信已驗證","connected":true,"peer_ipv4":"10.6.9.3","peer_address_state":"已確認","tx":512,"rx":12.8,"speed":"USB 協商速率：SuperSpeed","latency":"HTTP 往返 · 2.4 ms","benchmark_url":"http://10.6.9.1:58723/"}
        ],"detail":"Mac USB\n通信驗證：已驗證 IPv4 往返\n\niPad USB\n通信驗證：已驗證 IPv4 往返","share_ready":true}
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
        UpdateInternet(d);
        string S(string k) => d.TryGetProperty(k, out var v) && v.ValueKind == JsonValueKind.String ? v.GetString() ?? "" : "";
        bool B(string k) => d.TryGetProperty(k, out var v) && v.ValueKind == JsonValueKind.True;
        if (S("version") != "") versionText.Text = S("version");
        if (S("event") == "shutdown") { (Application.Current?.ApplicationLifetime as IClassicDesktopStyleApplicationLifetime)?.Shutdown(); return; }
        if (S("event") == "update-notice") { ShowUpdateNotice(d); return; }
        if (S("event") == "smb-account") { UpdateSMBAccount(d); return; }
        if (S("event") == "share-folders") { UpdateShareFolders(d); return; }
        if (S("event") == "gateway-request") { ShowGatewayRequest(d); return; }
        if (S("event") == "gateway") { UpdateGateway(d); return; }
        if (S("event") == "security") { UpdateSecurity(d); return; }
        // The custom caption remains usable while the core finishes stopping.
        bodyScroll.IsEnabled = footerControl.IsEnabled = !B("stopping");
        if (S("event") == "show") { Show(); WindowState = WindowState.Normal; Activate(); return; }

        if (S("windows_ipv4") != "") { WindowsHostIp = S("windows_ipv4"); ShareUrl = S("share_url") != "" ? S("share_url") : "smb://" + WindowsHostIp; addressValue.Text = WindowsHostIp; shareUrlValue.Text = ShareUrl; }
        JsonElement mac = default, ipad = default;
        var connected = 0; var connecting = 0; var connectionError = false;
        if (d.TryGetProperty("devices", out var devices) && devices.ValueKind == JsonValueKind.Array)
        {
            foreach (var slot in devices.EnumerateArray())
            {
                if (!slot.TryGetProperty("device", out var kind)) continue;
                var view = kind.GetString() switch { "Mac" => macStatus, "iPad" => ipadStatus, _ => null };
                if (view == null) continue;
                if (kind.GetString() == "Mac") mac = slot; else ipad = slot;
                var state = Text(slot,"connection_state");
                if(state=="connected"||state==""&&slot.TryGetProperty("connected",out var active)&&active.ValueKind==JsonValueKind.True)connected++;
                else if(state=="connecting")connecting++;
                else if(state=="error")connectionError=true;
            }
        }
        else // Older cores can still display their one available snapshot.
        {
            if (S("device") == "iPad") ipad = d; else mac = d;
            if (B("connected")) connected = 1;
        }
        macStatus.Update(mac); ipadStatus.Update(ipad);
        ApplyConnectionSummary(connected,connecting,connectionError);

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
