using Avalonia;
using Avalonia.Controls;
using Avalonia.Media;
using Avalonia.VisualTree;
using static Suhang.Desktop.TreemapView;

namespace Suhang.Desktop;

/// A lit sphere with a soft halo: the overview's hero, standing in for Mole's planets. Its hue is a palette tone
/// (Ok, Busy, Warn, Error, Idle) so it reads the connection state at a glance; Busy breathes slowly.
internal sealed class Orb : Control
{
    string tone = "Idle";
    double phase;
    bool ticking;

    public Orb(double size) { Width = Height = size; ActualThemeVariantChanged += (_, _) => InvalidateVisual(); }

    public string Tone { get => tone; set { if (tone == value) return; tone = value; InvalidateVisual(); Tick(); } }

    void Tick()
    {
        if (ticking || tone != "Busy" || !Animated) return;
        ticking = true;
        void Step(TimeSpan t)
        {
            phase = t.TotalMilliseconds / 900;
            InvalidateVisual();
            if (tone == "Busy" && this.GetVisualRoot() != null) TopLevel.GetTopLevel(this)?.RequestAnimationFrame(Step); else ticking = false;
        }
        if (TopLevel.GetTopLevel(this) is { } top) top.RequestAnimationFrame(Step); else ticking = false;
    }

    protected override void OnAttachedToVisualTree(VisualTreeAttachmentEventArgs e) { base.OnAttachedToVisualTree(e); Tick(); }

    Color C(string key) => this.TryFindResource(key, ActualThemeVariant, out var v) && v is SolidColorBrush b ? b.Color : Colors.Gray;

    public override void Render(DrawingContext cx)
    {
        var c = new Point(Bounds.Width / 2, Bounds.Height / 2); var outer = Math.Min(Bounds.Width, Bounds.Height) / 2;
        // Connected reads as a warm planet; the state pill beside it names the state.
        var r = outer * .72; var hue = C(tone switch { "Idle" => "Subtle", "Ok" => "OrbWarm", _ => tone }); var dark = ActualThemeVariant == Avalonia.Styling.ThemeVariant.Dark;
        var breathe = tone == "Busy" ? .5 + .5 * Math.Sin(phase) : 1;
        // Halo.
        cx.DrawEllipse(new RadialGradientBrush { GradientStops = { new GradientStop(A(hue, (dark ? .34 : .24) * (.6 + .4 * breathe)), .55), new GradientStop(A(hue, 0), 1) } }, null, c, outer, outer);
        // Body: lit from the upper left, shadowed toward the lower right.
        var body = new RadialGradientBrush {
            Center = new RelativePoint(.36, .3, RelativeUnit.Relative), GradientOrigin = new RelativePoint(.32, .26, RelativeUnit.Relative),
            RadiusX = new RelativeScalar(.85, RelativeUnit.Relative), RadiusY = new RelativeScalar(.85, RelativeUnit.Relative),
            GradientStops = { new GradientStop(Over(Colors.White, hue, .55), 0), new GradientStop(hue, .45), new GradientStop(Over(Colors.Black, hue, .45), 1) } };
        cx.DrawEllipse(body, null, c, r, r);
        // A faint band, like a planet's atmosphere line.
        using (cx.PushClip(new RoundedRect(new Rect(c.X - r, c.Y - r, r * 2, r * 2), r)))
        {
            // Soft cloud bands, like a gas giant: lighter and darker streaks across the lit face.
            cx.DrawEllipse(null, new Pen(new SolidColorBrush(A(Colors.White, .12)), r * .1), new Point(c.X - r * .1, c.Y + r * .15), r * 1.25, r * .42);
            cx.DrawEllipse(null, new Pen(new SolidColorBrush(A(Over(Colors.Black, hue, .3), .14)), r * .08), new Point(c.X + r * .05, c.Y - r * .28), r * 1.1, r * .3);
            cx.DrawEllipse(null, new Pen(new SolidColorBrush(A(Colors.White, .07)), r * .05), new Point(c.X - r * .2, c.Y + r * .55), r * 1.0, r * .28);
        }
        cx.DrawEllipse(null, new Pen(new SolidColorBrush(A(Colors.White, dark ? .16 : .3)), 1), c, r - .5, r - .5);
    }
}
