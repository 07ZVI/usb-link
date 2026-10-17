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
    readonly TextBlock title = Label("等候 USB 接線", 13), traffic = Label("—", 16, FontWeight.SemiBold),
        peerAddress = Label("裝置地址 · 尚未分配", 12, key: "Muted"),
        peak = Label("", 11, key: "Subtle"),
        speed = Label("USB 協商速率尚未取得", 11, key: "Muted"), latency = Label("延遲 · 未測得", 11, key: "Muted"),
        summary = Label("", 11, key: "Muted");
    readonly SelectableTextBlock benchmarkAddress = new() { FontSize = 11, TextWrapping = TextWrapping.Wrap };
    readonly Sparkline chart = new() { MinHeight = 40 };
    readonly ProgressBar progress = new() { Minimum = 0, Maximum = 100, Height = 3, IsVisible = false };
    readonly Button benchmark, reconnect;
    readonly TextBlock benchmarkLabel = Label("開始測速", 12);
    readonly Control health;
    readonly Control deviceGlyph;
    readonly Border deviceTile;
    bool busy, connected;
    string url = "";
    public Control View { get; }

    public DeviceStatusView(string kind, Action<string> send, Action<string, string> copy)
    {
        this.kind = kind;
        chart.Res(Sparkline.TxBrushProperty, "Accent").Res(Sparkline.RxBrushProperty, "Cyan").Res(Sparkline.GridBrushProperty, "Stroke");
        title.TextWrapping = TextWrapping.Wrap; title.MaxLines = 2;
        summary.TextWrapping = TextWrapping.Wrap; summary.MaxLines = 2;
        health = Icons.Make(Icons.Info, 14, "Muted");
        benchmark = Action("", () =>
        {
            if (kind == "Mac" && busy) send("benchmark-cancel");
            else if (url != "") copy(url, kind + " 測速網址（請在 " + kind + " 瀏覽器開啟）");
        });
        benchmark.Content = benchmarkLabel; benchmark.Padding = new Thickness(8, 2); benchmark.MinHeight = 24;
        reconnect = IconButton(Icons.Retry, "重新連線 " + kind, () => send(kind == "Mac" ? "retry-mac" : "retry-ipad"));
        reconnect.Content = Icons.Fixed(Icons.Retry, 18, "Muted");
        reconnect.Width = reconnect.Height = 28; reconnect.Padding = new Thickness(0);
        reconnect.HorizontalContentAlignment = HorizontalAlignment.Center; reconnect.VerticalContentAlignment = VerticalAlignment.Center;
        reconnect.Template = new FuncControlTemplate<Button>((host, _) => {
            var content = new ContentPresenter { HorizontalContentAlignment = HorizontalAlignment.Center, VerticalContentAlignment = VerticalAlignment.Center, CornerRadius = new CornerRadius(4) };
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
        deviceGlyph = Icons.Fixed(kind == "Mac" ? Icons.Laptop : Icons.Tablet, 26, "Idle");
        deviceTile = new Border { Width = 38, Height = 38, CornerRadius = new CornerRadius(6), Child = deviceGlyph, HorizontalAlignment = HorizontalAlignment.Center, VerticalAlignment = VerticalAlignment.Center }.Res(Border.BackgroundProperty,"IdleSoft");
        var identity = Columns("Auto,10,*", deviceTile, Gap(),
            Column(2, Row(7, Label(kind, 16, FontWeight.SemiBold), health), peerAddress));
        var head = Columns("*,Auto", identity, WithMargin(Row(6, benchmark, reconnect), new Thickness(8, 0, 0, 0)));
        var notes = Columns("*,Auto", speed, latency);
        View = Card(Rows("Auto,6,Auto,6,Auto,4,*,4,Auto,4,Auto", head, Gap(), title, Gap(), Columns("*,Auto", traffic, peak), Gap(), chart, Gap(), notes, Gap(), Column(3, progress, summary, benchmarkAddress)), new Thickness(14, 12));
        benchmarkAddress.Res(TextBlock.ForegroundProperty,"Muted");
        Update(DeviceStatus.Missing);
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
        var state = data.ConnectionState;
        var tone = state switch { DeviceConnectionState.Connected => "Ok", DeviceConnectionState.Connecting => "Warn", DeviceConnectionState.Error => "Error", _ => "Idle" };
        var stateText = state switch { DeviceConnectionState.Connected => "已連線", DeviceConnectionState.Connecting => "正在連線", DeviceConnectionState.Error => "連線異常", _ => "離線" };
        title.Res(TextBlock.ForegroundProperty, tone);
        deviceTile.Res(Border.BackgroundProperty, tone + "Soft");
        foreach (var path in deviceGlyph.GetVisualDescendants().OfType<Shape>()) path.Res(Shape.StrokeProperty, tone);
        Avalonia.Automation.AutomationProperties.SetName(deviceTile, kind + " · " + stateText);
        ToolTip.SetTip(deviceTile, kind + " · " + stateText);
        ToolTip.SetTip(title, data.Subtitle); ToolTip.SetTip(health, data.Health);
        var tx = data.Tx / 8; var rx = data.Rx / 8;
        traffic.Text = data.IsPresent ? $"↑ {tx:0.0}    ↓ {rx:0.0}  MB/s" : "↑ —    ↓ —  MB/s";
        ToolTip.SetTip(traffic, "↑ 傳送至裝置 · ↓ 從裝置接收；即時介面流量，近 60 秒");
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
        summary.Text = data.BenchmarkSummary;
        benchmarkAddress.Text = url; benchmarkAddress.IsVisible = url != "";
        Avalonia.Automation.AutomationProperties.SetName(benchmarkAddress,kind+" 瀏覽器測速網址");
        ToolTip.SetTip(summary, summary.Text);
    }

    public void SeedTraffic(double tx, double rx)
    {
        var random = new Random(kind == "Mac" ? 7 : 11);
        chart.Clear();
        for (var i = 0; i < Sparkline.Capacity; i++) chart.Push(tx * (.8 + .2 * Math.Sin(i / 6.0) + random.NextDouble() * .1), rx);
        peak.Text = $"峰值 {chart.Peak:0.#} MB/s";
    }
}
