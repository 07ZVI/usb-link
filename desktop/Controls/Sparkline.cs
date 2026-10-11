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

internal sealed class Sparkline : Control
{
    public static readonly StyledProperty<IBrush?> TxBrushProperty = AvaloniaProperty.Register<Sparkline, IBrush?>(nameof(TxBrush));
    public static readonly StyledProperty<IBrush?> RxBrushProperty = AvaloniaProperty.Register<Sparkline, IBrush?>(nameof(RxBrush));
    public static readonly StyledProperty<IBrush?> GridBrushProperty = AvaloniaProperty.Register<Sparkline, IBrush?>(nameof(GridBrush));
    static Sparkline() => AffectsRender<Sparkline>(TxBrushProperty, RxBrushProperty, GridBrushProperty);
    public IBrush? TxBrush { get => GetValue(TxBrushProperty); set => SetValue(TxBrushProperty, value); }
    public IBrush? RxBrush { get => GetValue(RxBrushProperty); set => SetValue(RxBrushProperty, value); }
    public IBrush? GridBrush { get => GetValue(GridBrushProperty); set => SetValue(GridBrushProperty, value); }

    public const int Capacity = 60;
    readonly List<double> tx = new(), rx = new();
    bool firstDrawRecorded;
    public double Peak { get; private set; }

    public void Clear() { tx.Clear(); rx.Clear(); Peak = 0; InvalidateVisual(); }

    public void Push(double t, double r)
    {
        tx.Add(Math.Max(0, t)); rx.Add(Math.Max(0, r));
        if (tx.Count > Capacity) { tx.RemoveAt(0); rx.RemoveAt(0); }
        Peak = Math.Max(tx.DefaultIfEmpty().Max(), rx.DefaultIfEmpty().Max());
        InvalidateVisual();
    }

    public override void Render(DrawingContext context)
    {
        var w = Bounds.Width; var h = Bounds.Height;
        if (w < 4 || h < 4) return;
        if (GridBrush is { } grid)
        {
            var pen = new Pen(grid, 1, new DashStyle(new double[] { 2, 3 }, 0));
            for (var i = 0; i <= 2; i++) { var y = Math.Round(h * i / 2) + .5; context.DrawLine(pen, new Point(0, y), new Point(w, y)); }
        }
        var top = Math.Max(1, NiceCeiling(Peak));
        Draw(context, rx, RxBrush, w, h, top);
        Draw(context, tx, TxBrush, w, h, top);
        if (!firstDrawRecorded) {
            firstDrawRecorded = true;
            // Actual visible-chart managed drawing; GPU presentation is separate.
            LaunchTelemetry.Mark("renderer-first-managed-draw");
        }
    }

    public static double NiceCeiling(double v)
    {
        if (v <= 0) return 1;
        var mag = Math.Pow(10, Math.Floor(Math.Log10(v)));
        foreach (var step in new[] { 1, 2, 2.5, 5, 10 }) if (v <= step * mag) return step * mag;
        return 10 * mag;
    }

    static void Draw(DrawingContext context, List<double> values, IBrush? brush, double w, double h, double top)
    {
        if (brush is not ISolidColorBrush solid || values.Count < 2) return;
        var step = w / (Capacity - 1);
        var x0 = w - step * (values.Count - 1);
        Point At(int i) => new(x0 + step * i, h - 1 - (h - 2) * Math.Min(1, values[i] / top));
        var line = new StreamGeometry();
        using (var g = line.Open())
        {
            g.BeginFigure(At(0), false);
            for (var i = 1; i < values.Count; i++) g.LineTo(At(i));
            g.EndFigure(false);
        }
        var area = new StreamGeometry();
        using (var g = area.Open())
        {
            g.BeginFigure(new Point(x0, h), true);
            for (var i = 0; i < values.Count; i++) g.LineTo(At(i));
            g.LineTo(new Point(w, h));
            g.EndFigure(true);
        }
        var c = solid.Color;
        var fill = new LinearGradientBrush
        {
            StartPoint = new RelativePoint(0, 0, RelativeUnit.Relative), EndPoint = new RelativePoint(0, 1, RelativeUnit.Relative),
            GradientStops = { new GradientStop(Color.FromArgb(56, c.R, c.G, c.B), 0), new GradientStop(Color.FromArgb(0, c.R, c.G, c.B), 1) },
        };
        context.DrawGeometry(fill, null, area);
        context.DrawGeometry(null, new Pen(brush, 1.75, lineCap: PenLineCap.Round, lineJoin: PenLineJoin.Round), line);
    }
}
