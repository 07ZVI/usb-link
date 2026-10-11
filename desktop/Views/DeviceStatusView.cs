using System.Text.Json;
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

public sealed partial class Dashboard
{
    sealed class DeviceStatusView
    {
        readonly string kind;
        readonly TextBlock title = Label("等候 USB 接線", 13), traffic = Label("—", 16, FontWeight.SemiBold),
            peerAddress = Label("裝置地址 · 尚未分配", 12, key: "Muted"),
            peak = Label("", 11, key: "Subtle"),
            speed = Label("USB 協商速率尚未取得", 11, key: "Muted"), latency = Label("延遲 · 未測得", 11, key: "Muted"),
            summary = Label("", 11, key: "Muted");
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

        public DeviceStatusView(Dashboard owner, string kind)
        {
            this.kind = kind;
            chart.Res(Sparkline.TxBrushProperty, "Accent").Res(Sparkline.RxBrushProperty, "Cyan").Res(Sparkline.GridBrushProperty, "Stroke");
            title.TextWrapping = TextWrapping.Wrap; title.MaxLines = 2;
            summary.TextWrapping = TextWrapping.Wrap; summary.MaxLines = 2;
            health = Icons.Make(Icons.Info, 14, "Muted");
            benchmark = owner.Action("", () =>
            {
                if (kind == "Mac") owner.Send(busy ? "benchmark-cancel" : "benchmark-start");
                else if (url != "") owner.Copy(url, "iPad 測速網址");
            });
            benchmark.Content = benchmarkLabel; benchmark.Padding = new Thickness(8, 2); benchmark.MinHeight = 24;
            reconnect = owner.IconButton(Icons.Retry, "重新連線 " + kind, () => owner.Send(kind == "Mac" ? "retry-mac" : "retry-ipad"));
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
            View = Card(Rows("Auto,6,Auto,6,Auto,4,*,4,Auto,4,Auto", head, Gap(), title, Gap(), Columns("*,Auto", traffic, peak), Gap(), chart, Gap(), notes, Gap(), Column(3, progress, summary)), new Thickness(14, 12));
            Update(default);
        }

        public void Update(JsonElement data)
        {
            string S(string key) => data.ValueKind == JsonValueKind.Object && data.TryGetProperty(key, out var v) && v.ValueKind == JsonValueKind.String ? v.GetString() ?? "" : "";
            bool B(string key) => data.ValueKind == JsonValueKind.Object && data.TryGetProperty(key, out var v) && v.ValueKind == JsonValueKind.True;
            double N(string key) => data.ValueKind == JsonValueKind.Object && data.TryGetProperty(key, out var v) && v.TryGetDouble(out var n) ? n : 0;
            var active = B("connected");
            if ((connected && !active) || data.ValueKind != JsonValueKind.Object) chart.Clear();
            connected = active;
            var address = S("peer_ipv4"); var addressState = S("peer_address_state");
            peerAddress.Text = address == "" ? "裝置地址 · 尚未分配" : address + (addressState == "待確認" ? " · 待確認" : "");
            ToolTip.SetTip(peerAddress, address == "" ? "連接並分配地址後顯示。" : kind + " 裝置地址：" + address + (addressState == "待確認" ? "\n已發送地址分配確認，等待裝置套用。" : ""));
            ToolTip.SetTip(reconnect, "重新連線 " + kind + (B("retry_available") ? "" : active ? " · 連線運行中" : " · 等候裝置或連線準備完成"));
            reconnect.IsEnabled = B("retry_available");
            title.Text = S("title") is { Length: > 0 } text ? text : "等候 USB 接線";
            var state = S("connection_state");
            if (state == "") state = active ? "connected" : "offline"; // Older core compatibility.
            var tone = state switch { "connected" => "Ok", "connecting" => "Warn", "error" => "Error", _ => "Idle" };
            var stateText = state switch { "connected" => "已連線", "connecting" => "正在連線", "error" => "連線異常", _ => "離線" };
            title.Res(TextBlock.ForegroundProperty, tone);
            deviceTile.Res(Border.BackgroundProperty, tone + "Soft");
            foreach (var path in deviceGlyph.GetVisualDescendants().OfType<Shape>()) path.Res(Shape.StrokeProperty, tone);
            Avalonia.Automation.AutomationProperties.SetName(deviceTile, kind + " · " + stateText);
            ToolTip.SetTip(deviceTile, kind + " · " + stateText);
            ToolTip.SetTip(title, S("subtitle")); ToolTip.SetTip(health, S("health"));
            var tx = N("tx") / 8; var rx = N("rx") / 8;
            traffic.Text = data.ValueKind == JsonValueKind.Object ? $"↑ {tx:0.0}    ↓ {rx:0.0}  MB/s" : "↑ —    ↓ —  MB/s";
            ToolTip.SetTip(traffic, "↑ 傳送至裝置 · ↓ 從裝置接收；即時介面流量，近 60 秒");
            if (data.ValueKind == JsonValueKind.Object) chart.Push(tx, rx);
            peak.Text = chart.Peak > 0 ? $"峰值 {chart.Peak:0.#} MB/s" : "";
            speed.Text = S("speed") is { Length: > 0 } sp ? sp : "USB 協商速率尚未取得";
            ToolTip.SetTip(speed, speed.Text);
            latency.Text = S("latency") is { Length: > 0 } lt ? lt : "延遲 · 未測得";
            ToolTip.SetTip(latency, "往返延遲包含協定與應用處理時間，不等於 Moonlight 畫面延遲。\n" + latency.Text);
            busy = B("measurement_busy"); url = S("benchmark_url");
            benchmarkLabel.Text = kind == "Mac" ? busy ? "取消測速" : "開始測速" : "測速網址";
            Avalonia.Automation.AutomationProperties.SetName(benchmark, benchmarkLabel.Text + " " + kind);
            benchmark.IsEnabled = kind == "Mac" ? busy || B("benchmark_available") : url != "";
            benchmark.IsVisible = kind == "Mac" || url != "";
            ToolTip.SetTip(benchmark, kind == "Mac" ? "需 Mac 測試程式配合；不影響 USB 連線或串流。" : url + "\n點擊複製，在 iPad Safari 開啟測速。");
            progress.IsVisible = busy && kind == "Mac"; progress.Value = N("measurement_progress");
            summary.Text = kind == "iPad" ? url != "" ? "在 iPad Safari 開啟測速網址。" : "連接後可在 iPad Safari 測速。" : S("benchmark_summary");
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
}
