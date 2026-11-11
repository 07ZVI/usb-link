using System.Globalization;
using Avalonia;
using Avalonia.Controls;
using Avalonia.Media;
using static Suhang.Desktop.TreemapView;

namespace Suhang.Desktop;

/// The overview's one chart: the last 60 seconds of total traffic (sent + received) for every device on one axis,
/// each a smooth line over a soft fade, with a quiet value axis and time axis. It reads the history the device
/// rows already keep, so it adds no polling of its own.
internal sealed class TrafficChart : Control
{
    readonly List<(Sparkline Source, string Tone)> series = new();
    const double AxisLeft = 40, AxisBottom = 22, TopPad = 8;
    bool firstDrawRecorded;

    public TrafficChart() { ActualThemeVariantChanged += (_, _) => InvalidateVisual(); ClipToBounds = false; }

    public void Add(Sparkline source, string tone) { series.Add((source, tone)); source.Changed += InvalidateVisual; }

    Color C(string key) => this.TryFindResource(key, ActualThemeVariant, out var v) && v is SolidColorBrush b ? b.Color : Colors.Gray;

    static double Total(Sparkline s, int i) => s.Tx[i] + s.Rx[i];

    FormattedText Text(string text, Color color, double size = Scale.Subheadline) =>
        new(text, CultureInfo.CurrentUICulture, FlowDirection.LeftToRight, new Typeface(Palette.FontStack), size, new SolidColorBrush(color));

    public override void Render(DrawingContext cx)
    {
        var w = Bounds.Width; var h = Bounds.Height;
        if (w < 80 || h < 60) return;
        var plot = new Rect(AxisLeft, TopPad, w - AxisLeft, h - TopPad - AxisBottom);
        var peak = 0.0;
        foreach (var (s, _) in series) for (var i = 0; i < s.Tx.Count; i++) peak = Math.Max(peak, Total(s, i));
        var top = Sparkline.NiceCeiling(Math.Max(peak * 1.1, 10));
        var ink = C("Subtle"); var grid = A(C("Ink"), ActualThemeVariant == Avalonia.Styling.ThemeVariant.Dark ? .07 : .06);
        var gridPen = new Pen(new SolidColorBrush(grid), 1);

        // Value axis: four steps, labels right-aligned to the plot's edge.
        for (var k = 0; k <= 4; k++)
        {
            var y = Math.Round(plot.Bottom - plot.Height * k / 4) + .5;
            cx.DrawLine(gridPen, new Point(plot.X, y), new Point(plot.Right, y));
            var label = Text((top * k / 4).ToString(top >= 20 ? "0" : "0.#", CultureInfo.InvariantCulture), ink);
            cx.DrawText(label, new Point(plot.X - 10 - label.Width, y - label.Height / 2));
        }
        // Time axis: 60 s ago on the left, now on the right.
        for (var k = 0; k <= 6; k++)
        {
            var x = plot.X + plot.Width * k / 6;
            var label = Text(k == 6 ? "現在" : $"{60 - k * 10} 秒", ink);
            var lx = k == 0 ? x : k == 6 ? x - label.Width : x - label.Width / 2;
            cx.DrawText(label, new Point(lx, plot.Bottom + 6));
        }

        var step = plot.Width / (Sparkline.Capacity - 1);
        foreach (var (s, tone) in series)
        {
            var n = s.Tx.Count; if (n < 2) continue;
            var c = C(tone);
            var x0 = plot.Right - step * (n - 1);
            Point At(int i) => new(x0 + step * i, plot.Bottom - plot.Height * Math.Min(1, Total(s, i) / top));
            // Catmull-Rom through the samples, so the line reads as a flow rather than a seismograph.
            void Curve(StreamGeometryContext g)
            {
                for (var i = 0; i < n - 1; i++)
                {
                    var p0 = At(Math.Max(0, i - 1)); var p1 = At(i); var p2 = At(i + 1); var p3 = At(Math.Min(n - 1, i + 2));
                    g.CubicBezierTo(new Point(p1.X + (p2.X - p0.X) / 6, Math.Clamp(p1.Y + (p2.Y - p0.Y) / 6, plot.Top, plot.Bottom)),
                        new Point(p2.X - (p3.X - p1.X) / 6, Math.Clamp(p2.Y - (p3.Y - p1.Y) / 6, plot.Top, plot.Bottom)), p2);
                }
            }
            var area = new StreamGeometry();
            using (var g = area.Open()) { g.BeginFigure(new Point(x0, plot.Bottom), true); g.LineTo(At(0)); Curve(g); g.LineTo(new Point(plot.Right, plot.Bottom)); g.EndFigure(true); }
            var line = new StreamGeometry();
            using (var g = line.Open()) { g.BeginFigure(At(0), false); Curve(g); g.EndFigure(false); }
            cx.DrawGeometry(new LinearGradientBrush
            {
                StartPoint = new RelativePoint(0, 0, RelativeUnit.Relative), EndPoint = new RelativePoint(0, 1, RelativeUnit.Relative),
                GradientStops = { new GradientStop(A(c, .26), 0), new GradientStop(A(c, 0), 1) },
            }, null, area);
            cx.DrawGeometry(null, new Pen(new SolidColorBrush(c), 2.25, lineCap: PenLineCap.Round, lineJoin: PenLineJoin.Round), line);
            // The latest value as a dot on the right edge.
            var last = At(n - 1);
            cx.DrawEllipse(new SolidColorBrush(A(c, .22)), null, last, 7, 7);
            cx.DrawEllipse(new SolidColorBrush(c), null, last, 3.5, 3.5);
        }
        if (series.All(x => x.Source.Tx.Count < 2))
        {
            var empty = Text("連接裝置後顯示近 60 秒的傳輸速率", C("Muted"), Scale.Body);
            cx.DrawText(empty, new Point(plot.X + (plot.Width - empty.Width) / 2, plot.Y + (plot.Height - empty.Height) / 2));
        }
        if (!firstDrawRecorded)
        {
            firstDrawRecorded = true;
            LaunchTelemetry.Mark("renderer-first-managed-draw");
        }
    }
}
