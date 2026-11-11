using Avalonia;
using Avalonia.Controls;
using Avalonia.Controls.Presenters;
using Avalonia.Controls.Templates;
using Avalonia.Controls.Shapes;
using Avalonia.Data;
using Avalonia.VisualTree;
using Avalonia.Layout;
using Avalonia.Media;

namespace Suhang.Desktop;

internal sealed class DeviceStatusView
{
    readonly string kind;
    readonly StatusPill pill = new("等候 USB 接線");
    TextBlock title => pill.Label;
    readonly TextBlock traffic = Label("—", Scale.Title1, FontWeight.Bold),
        peerAddress = Label("裝置地址 · 尚未分配", Scale.Secondary, key: "Muted"),
        peak = Label("", Scale.Caption, key: "Subtle"),
        speed = Label("USB 協商速率尚未取得", Scale.Caption, key: "Muted"), latency = Label("延遲 · 未測得", Scale.Caption, key: "Muted"),
        summary = Label("", Scale.Caption, key: "Muted"),
        idleHint = Label("連接 USB 線後顯示即時流量", Scale.Secondary, key: "Subtle");
    readonly SelectableTextBlock benchmarkAddress = new() { FontSize = Scale.Caption, TextWrapping = TextWrapping.Wrap };
    readonly Sparkline chart = new() { MinHeight = 48 };
    readonly ProgressBar progress = new() { Minimum = 0, Maximum = 100, Height = 3, IsVisible = false };
    readonly Button benchmark, reconnect;
    readonly TextBlock benchmarkLabel = Label("開始測速", Scale.Callout, FontWeight.Medium);
    readonly Control health;
    readonly Control deviceGlyph;
    readonly Border deviceTile;
    bool busy, connected;
    string url = "";
    public Control View { get; }
    readonly Border card;
    readonly Grid layout;
    readonly Grid plot, notes;
    readonly StackPanel extras;
    int density;

    /// The device's history, which the overview's shared chart draws; the row itself shows only the numbers.
    public Sparkline History => chart;

    public DeviceStatusView(string kind, Action<string> send, Action<string, string> copy, string seriesTone = "Accent")
    {
        this.kind = kind;
        chart.Res(Sparkline.TxBrushProperty, "Accent").Res(Sparkline.RxBrushProperty, "Cyan").Res(Sparkline.GridBrushProperty, "Stroke");
        pill.HorizontalAlignment = HorizontalAlignment.Left; pill.MinWidth = 0;
        idleHint.HorizontalAlignment = HorizontalAlignment.Center; idleHint.VerticalAlignment = VerticalAlignment.Center;
        summary.TextWrapping = TextWrapping.Wrap; summary.MaxLines = 2;
        health = Icons.Make(Icons.Info, 14, "Muted");
        benchmark = Action("", () =>
        {
            if (kind == "Mac" && busy) send("benchmark-cancel");
            else if (url != "") copy(url, kind + " 測速網址（請在 " + kind + " 瀏覽器開啟）");
        });
        benchmark.Content = benchmarkLabel; benchmark.Padding = new Thickness(Scale.Medium, 0); benchmark.Height = Scale.SmallControl; benchmark.CornerRadius = new CornerRadius(Scale.SmallControl / 2);
        reconnect = IconButton(Icons.Retry, "重新連線 " + kind, () => send(kind == "Mac" ? "retry-mac" : "retry-ipad"));
        reconnect.Content = Icons.Fixed(Icons.Retry, Scale.IconControl, "Muted");
        reconnect.Width = reconnect.Height = Scale.SmallControl; reconnect.Padding = new Thickness(0);
        reconnect.HorizontalContentAlignment = HorizontalAlignment.Center; reconnect.VerticalContentAlignment = VerticalAlignment.Center;
        reconnect.Template = new FuncControlTemplate<Button>((host, _) => {
            var content = new ContentPresenter { HorizontalContentAlignment = HorizontalAlignment.Center, VerticalContentAlignment = VerticalAlignment.Center, CornerRadius = new CornerRadius(Scale.SmallControl / 2) };
            content.Bind(ContentPresenter.ContentProperty, new Binding(nameof(Button.Content)) { Source = host });
            content.Bind(ContentPresenter.BackgroundProperty, new Binding(nameof(Button.Background)) { Source = host });
            return content;
        });
        void RetryAppearance() {
            reconnect.Opacity = reconnect.IsEnabled ? 1 : .35;
            if (reconnect.IsEnabled && (reconnect.IsPointerOver || reconnect.IsKeyboardFocusWithin)) reconnect.Res(Button.BackgroundProperty, reconnect.IsPressed ? "AccentSoft" : "IdleSoft");
            else reconnect.Background = Brushes.Transparent;
        }
        reconnect.PropertyChanged += (_,e) => { if(e.Property==Button.IsPressedProperty||e.Property==Control.IsPointerOverProperty||e.Property==Control.IsEnabledProperty||e.Property==Control.IsKeyboardFocusWithinProperty)RetryAppearance(); };
        deviceGlyph = Icons.Fixed(kind == "Mac" ? Icons.Laptop : Icons.Tablet, Scale.IconLead, "Idle");
        deviceTile = new Border { Width = 40, Height = 40, CornerRadius = new CornerRadius(12), Child = deviceGlyph, HorizontalAlignment = HorizontalAlignment.Center, VerticalAlignment = VerticalAlignment.Center }.Res(Border.BackgroundProperty,"IdleSoft");
        // A borderless row (the overview has no cards): identity on the left, the live numbers and actions on the right.
        var dot = new Border { Width = 8, Height = 8, CornerRadius = new CornerRadius(4), VerticalAlignment = VerticalAlignment.Center }.Res(Border.BackgroundProperty, seriesTone);
        ToolTip.SetTip(dot, "圖表中 " + kind + " 的線條顏色");
        var name = Row(8, dot, Label(kind, Scale.Title3, FontWeight.SemiBold), health, pill);
        var identity = Columns("Auto,12,*", deviceTile, Gap(), Column(2, name, peerAddress));
        ((Control)identity.Children[2]).VerticalAlignment = VerticalAlignment.Center;
        traffic.HorizontalAlignment = HorizontalAlignment.Right;
        peak.HorizontalAlignment = HorizontalAlignment.Right; peak.VerticalAlignment = VerticalAlignment.Top; peak.IsHitTestVisible = false;
        // The history is drawn by the overview's shared chart; this sparkline only keeps the samples.
        plot = new Grid { IsVisible = false };
        plot.Children.Add(chart); plot.Children.Add(peak);
        idleHint.HorizontalAlignment = HorizontalAlignment.Right;
        notes = new Grid(); notes.Children.Add(Row(12, idleHint, speed, latency)); notes.HorizontalAlignment = HorizontalAlignment.Right;
        var numbers = Column(2, traffic, notes); numbers.VerticalAlignment = VerticalAlignment.Center;
        var actions = Row(6, benchmark, reconnect); actions.VerticalAlignment = VerticalAlignment.Center;
        var line = Columns("*,24,Auto,20,Auto", identity, Gap(), numbers, Gap(), actions);
        line.Children.Add(plot);
        bool? compactRow = null;
        void FitRow()
        {
            var compact = line.Bounds.Width < 900;
            if (compactRow == compact) return;
            compactRow = compact;
            line.ColumnDefinitions = new ColumnDefinitions(compact ? "*" : "*,24,Auto,20,Auto");
            line.RowDefinitions = new RowDefinitions(compact ? "Auto,Auto,Auto" : "Auto");
            Grid.SetRow(numbers, compact ? 1 : 0); Grid.SetColumn(numbers, compact ? 0 : 2);
            Grid.SetRow(actions, compact ? 2 : 0); Grid.SetColumn(actions, compact ? 0 : 4);
            numbers.HorizontalAlignment = compact ? HorizontalAlignment.Left : HorizontalAlignment.Stretch;
            traffic.HorizontalAlignment = notes.HorizontalAlignment = compact ? HorizontalAlignment.Left : HorizontalAlignment.Right;
            numbers.Margin = new Thickness(0, compact ? Scale.Small : 0, 0, 0);
            actions.Margin = new Thickness(0, compact ? Scale.Small : 0, 0, 0);
            actions.HorizontalAlignment = compact ? HorizontalAlignment.Right : HorizontalAlignment.Stretch;
        }
        line.SizeChanged += (_, _) => FitRow();
        extras = Column(4, progress, summary, benchmarkAddress);
        layout = Rows("Auto,0,Auto", line, Gap(), extras);
        View = card = new Border { Child = layout, Padding = new Thickness(Scale.Tight, 14) };
        benchmarkAddress.Res(TextBlock.ForegroundProperty,"Muted");
        Update(DeviceStatus.Missing);
        SetDensity(0);
    }

    /// 0 roomy, 1 compact, 2 dense. Dense hides the speed/latency line;
    /// horizontal wrapping follows the row's available width independently.
    public void SetDensity(int level)
    {
        density = level;
        card.Padding = new Thickness(Scale.Tight, level switch { 0 => 14, 1 => 10, _ => 6 });
        notes.IsVisible = level < 2;
        deviceTile.Width = deviceTile.Height = level == 2 ? 32 : 40;
        RefreshExtras();
    }

    void RefreshExtras()
    {
        // The overview row has no room for the address; it lives in the benchmark button's tooltip.
        benchmarkAddress.IsVisible = false;
        extras.IsVisible = progress.IsVisible || summary.IsVisible || benchmarkAddress.IsVisible;
        extras.Margin = new Thickness(0, density == 2 ? 6 : 8, 0, 0);
    }

    public void Update(DeviceStatus data)
    {
        var active = data.Connected;
        if ((connected && !active) || !data.IsPresent) chart.Clear();
        connected = active;
        var address = data.PeerIPv4; var addressState = data.PeerAddressState;
        peerAddress.Text = address == "" ? "裝置地址 · 尚未分配" : address + (addressState == "待確認" ? " · 待確認" : "");
        ToolTip.SetTip(peerAddress, address == "" ? "連接並分配地址後顯示。" : kind + " 裝置地址：" + address + (addressState == "待確認" ? "\n已發送地址分配確認，等待裝置套用。" : ""));
        ToolTip.SetTip(reconnect, "重新連線 " + kind + (data.RetryAvailable ? "" : active ? " · 連線運行中" : " · 等候裝置或連線準備完成"));
        reconnect.IsEnabled = data.RetryAvailable;
        title.Text = data.Title is { Length: > 0 } text ? text : "等候 USB 接線";
        chart.IsVisible = speed.IsVisible = latency.IsVisible = active; idleHint.IsVisible = !active;
        idleHint.Text = data.ConnectionState switch { DeviceConnectionState.Connecting => "正在建立連線…", DeviceConnectionState.Error => "連線異常，可重新連線或檢查線材", _ => "連接 USB 線後顯示即時流量" };
        var state = data.ConnectionState;
        var tone = state switch { DeviceConnectionState.Connected => "Ok", DeviceConnectionState.Connecting => "Warn", DeviceConnectionState.Error => "Error", _ => "Idle" };
        var stateText = state switch { DeviceConnectionState.Connected => "已連線", DeviceConnectionState.Connecting => "正在連線", DeviceConnectionState.Error => "連線異常", _ => "離線" };
        pill.Set(tone);
        deviceTile.Res(Border.BackgroundProperty, tone + "Soft");
        foreach (var path in deviceGlyph.GetVisualDescendants().OfType<Shape>()) path.Res(Shape.StrokeProperty, tone);
        Avalonia.Automation.AutomationProperties.SetName(deviceTile, kind + " · " + stateText);
        ToolTip.SetTip(deviceTile, kind + " · " + stateText);
        ToolTip.SetTip(title, data.Subtitle); ToolTip.SetTip(health, data.Health);
        var tx = data.Tx / 8; var rx = data.Rx / 8;
        traffic.Text = active ? $"↑ {tx:0.0}    ↓ {rx:0.0}  MB/s" : "↑ —    ↓ —  MB/s";
        ToolTip.SetTip(traffic, "↑ 傳送至裝置 · ↓ 從裝置接收；即時介面流量，近 60 秒" + (active ? "\n" + (data.Speed is { Length: > 0 } ? data.Speed : "USB 協商速率尚未取得") + "\n" + (data.Latency is { Length: > 0 } ? data.Latency : "延遲 · 未測得") : ""));
        if (data.IsPresent) chart.Push(tx, rx);
        peak.Text = chart.Peak > 0 ? $"峰值 {chart.Peak:0.#} MB/s" : "";
        speed.Text = data.Speed is { Length: > 0 } sp ? sp : "USB 協商速率尚未取得";
        ToolTip.SetTip(speed, speed.Text);
        latency.Text = data.Latency is { Length: > 0 } lt ? lt : "延遲 · 未測得";
        ToolTip.SetTip(latency, "往返延遲包含協定與應用處理時間，不等於 Moonlight 畫面延遲。\n" + latency.Text);
        busy = data.MeasurementBusy; url = data.BenchmarkURL;
        benchmarkLabel.Text = kind == "Mac" ? busy ? "取消測速" : "瀏覽器測速" : "測速網址";
        Avalonia.Automation.AutomationProperties.SetName(benchmark, benchmarkLabel.Text + " " + kind);
        benchmark.IsEnabled = kind == "Mac" ? busy || url != "" : url != "";
        benchmark.IsVisible = kind == "Mac" || url != "";
        ToolTip.SetTip(benchmark, kind == "Mac" && busy ? "取消本次 Mac 瀏覽器測速。" : url + "\n點擊複製，在 " + kind + " 瀏覽器開啟；無需安裝測試程式。");
        progress.IsVisible = busy && kind == "Mac"; progress.Value = data.MeasurementProgress;
        // The standing "open this URL" instruction lives in the tooltip; live progress and results stay visible.
        summary.Text = data.BenchmarkSummary;
        summary.IsVisible = summary.Text != "" && (busy || !summary.Text.Contains("無需安裝程式"));
        benchmarkAddress.Text = url;
        Avalonia.Automation.AutomationProperties.SetName(benchmarkAddress,kind+" 瀏覽器測速網址");
        ToolTip.SetTip(summary, summary.Text);
        RefreshExtras();
    }

    public void SeedTraffic(double tx, double rx)
    {
        var random = new Random(kind == "Mac" ? 7 : 11);
        chart.Clear();
        for (var i = 0; i < Sparkline.Capacity; i++) chart.Push(tx * (.8 + .2 * Math.Sin(i / 6.0) + random.NextDouble() * .1), rx);
        peak.Text = $"峰值 {chart.Peak:0.#} MB/s";
    }
}
