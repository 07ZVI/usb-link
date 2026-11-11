using System.Globalization;
using Avalonia;
using Avalonia.Controls;
using Avalonia.Media;
using static Suhang.Desktop.TreemapView;

namespace Suhang.Desktop;

/// A small ring of shares (category breakdown, used vs. free) with an optional two-line label in the hole.
/// Segment colors are palette keys so the ring follows the theme.
internal sealed class DonutChart : Control
{
    (string Brush, double Value, double Opacity)[] segments = [];
    string top = "", bottom = "";
    readonly double thickness;
    double sweep = 1;
    DateTime started;

    public DonutChart(double size, double thickness)
    {
        Width = Height = size; this.thickness = thickness;
        ActualThemeVariantChanged += (_, _) => InvalidateVisual();
        AttachedToVisualTree += (_, _) => Animate();
    }

    public DonutChart Set(IEnumerable<(string Brush, double Value, double Opacity)> parts, string label = "", string caption = "")
    {
        segments = parts.Where(p => p.Value > 0).ToArray(); top = label; bottom = caption; InvalidateVisual(); return this;
    }

    void Animate()
    {
        if (!Animated) return;
        started = DateTime.UtcNow; sweep = 0;
        void Tick(TimeSpan _)
        {
            var t = Math.Clamp((DateTime.UtcNow - started).TotalMilliseconds / 650, 0, 1); sweep = 1 - Math.Pow(1 - t, 3);
            InvalidateVisual();
            if (t < 1) TopLevel.GetTopLevel(this)?.RequestAnimationFrame(Tick);
        }
        TopLevel.GetTopLevel(this)?.RequestAnimationFrame(Tick);
    }

    Color C(string key) => this.TryFindResource(key, ActualThemeVariant, out var v) && v is SolidColorBrush b ? b.Color : Colors.Gray;

    public override void Render(DrawingContext cx)
    {
        var c = new Point(Bounds.Width / 2, Bounds.Height / 2); var r = Math.Min(Bounds.Width, Bounds.Height) / 2 - thickness / 2;
        if (r <= 0) return;
        cx.DrawEllipse(null, new Pen(new SolidColorBrush(C("IdleSoft")), thickness), c, r, r);
        var total = segments.Sum(s => s.Value);
        if (total > 0)
        {
            var at = 0d; var gap = segments.Length > 1 ? Math.Min(.006, .25 / segments.Length) : 0;
            foreach (var (brush, value, opacity) in segments)
            {
                var share = value / total * sweep; var from = at + gap / 2; var to = at + share - gap / 2; at += share;
                if (to - from < .0015) { if (share > 0) to = from + .0015; else continue; }
                var g = new StreamGeometry();
                using (var ctx = g.Open())
                {
                    Point P(double turn) => new(c.X + r * Math.Sin(turn * 2 * Math.PI), c.Y - r * Math.Cos(turn * 2 * Math.PI));
                    var mid = (from + Math.Min(to, from + .99995)) / 2;
                    ctx.BeginFigure(P(from), false);
                    ctx.ArcTo(P(mid), new Size(r, r), 0, false, SweepDirection.Clockwise);
                    ctx.ArcTo(P(Math.Min(to, from + .99995)), new Size(r, r), 0, false, SweepDirection.Clockwise);
                    ctx.EndFigure(false);
                }
                cx.DrawGeometry(null, new Pen(new SolidColorBrush(A(C(brush), opacity)), thickness, lineCap: segments.Length == 1 ? PenLineCap.Round : PenLineCap.Flat), g);
            }
        }
        var face = new Typeface(new FontFamily(Palette.FontStack), FontStyle.Normal, FontWeight.SemiBold);
        FormattedText T(string s, double size, Typeface f, string key) => new(s, CultureInfo.CurrentUICulture, FlowDirection.LeftToRight, f, size, new SolidColorBrush(C(key))) { MaxTextWidth = (r - thickness / 2) * 1.8, MaxLineCount = 1, Trimming = TextTrimming.CharacterEllipsis, TextAlignment = TextAlignment.Center };
        if (top == "") return;
        var a = T(top, Math.Clamp(r / 2.6, 11, 17), face, "Ink");
        var b = bottom == "" ? null : T(bottom, Math.Clamp(r / 4.2, 9.5, 11), new Typeface(new FontFamily(Palette.FontStack)), "Muted");
        var h = a.Height + (b?.Height ?? 0); var x = c.X - a.MaxTextWidth / 2;
        cx.DrawText(a, new Point(x, c.Y - h / 2));
        if (b != null) cx.DrawText(b, new Point(x, c.Y - h / 2 + a.Height));
    }
}
