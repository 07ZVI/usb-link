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

internal static class Icons
{
    public const string Laptop = "M5 5h14a1 1 0 0 1 1 1v10H4V6a1 1 0 0 1 1-1z M2 17h20l-2 3H4z M10 17h4";
    public const string Tablet = "M7 2h10a2 2 0 0 1 2 2v16a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2z M10 19h4";
    public const string Plug = "M9.5 3v4 M14.5 3v4 M7 7h10v4a5 5 0 0 1-10 0z M12 16v5";
    public const string Close = "M6 6l12 12 M18 6L6 18";
    public const string Copy = "M9.5 8.5h9a1 1 0 0 1 1 1v10a1 1 0 0 1-1 1h-9a1 1 0 0 1-1-1v-10a1 1 0 0 1 1-1z M15.5 5.5v-1a1 1 0 0 0-1-1h-9a1 1 0 0 0-1 1v10a1 1 0 0 0 1 1h1";
    public const string Folder = "M3.5 6.5a1.5 1.5 0 0 1 1.5-1.5h4.5l2 2.5h7.5a1.5 1.5 0 0 1 1.5 1.5v8.5a1.5 1.5 0 0 1-1.5 1.5H5a1.5 1.5 0 0 1-1.5-1.5z";
    public const string Inbox = "M3.5 13.5l2.5-8h12l2.5 8v5a1 1 0 0 1-1 1h-15a1 1 0 0 1-1-1z M3.5 13.5h5l1.5 2.5h4l1.5-2.5h5";
    public const string Shield = "M12 3l7.5 3v5.5c0 4.5-3.2 8-7.5 9.5c-4.3-1.5-7.5-5-7.5-9.5V6z M9 12l2 2l4-4";
    public const string Pulse = "M3 12h4l2.5-6l5 12l2.5-6h4";
    public const string Retry = "M19.5 12a7.5 7.5 0 1 1-2.2-5.3 M19.5 4v4h-4";
    public const string Power = "M12 3.5v8 M7.2 6.3a7.5 7.5 0 1 0 9.6 0";
    public const string Clock = "M12 4a8 8 0 1 1 0 16a8 8 0 1 1 0-16z M12 7.5V12l3 2";
    public const string Chevron = "M9.5 6l6 6l-6 6";
    public const string Up = "M12 19V5 M6.5 10.5L12 5l5.5 5.5";
    public const string Down = "M12 5v14 M6.5 13.5L12 19l5.5-5.5";
    public const string Info = "M12 3.5a8.5 8.5 0 1 1 0 17a8.5 8.5 0 1 1 0-17z M12 11v5.5 M12 7.5v.5";
    public const string Globe = "M12 3.5a8.5 8.5 0 1 1 0 17a8.5 8.5 0 1 1 0-17z M3.5 12h17 M12 3.5c2.4 2.4 3.5 5.3 3.5 8.5s-1.1 6.1-3.5 8.5c-2.4-2.4-3.5-5.3-3.5-8.5s1.1-6.1 3.5-8.5z";
    public const string Play = "M12 3.5a8.5 8.5 0 1 1 0 17a8.5 8.5 0 1 1 0-17z M10.2 8.8l5 3.2l-5 3.2z";
    public const string Apps = "M5 4.5h5a.5.5 0 0 1 .5.5v5a.5.5 0 0 1-.5.5H5a.5.5 0 0 1-.5-.5V5a.5.5 0 0 1 .5-.5z M14 4.5h5a.5.5 0 0 1 .5.5v5a.5.5 0 0 1-.5.5h-5a.5.5 0 0 1-.5-.5V5a.5.5 0 0 1 .5-.5z M5 13.5h5a.5.5 0 0 1 .5.5v5a.5.5 0 0 1-.5.5H5a.5.5 0 0 1-.5-.5v-5a.5.5 0 0 1 .5-.5z M14 13.5h5a.5.5 0 0 1 .5.5v5a.5.5 0 0 1-.5.5h-5a.5.5 0 0 1-.5-.5v-5a.5.5 0 0 1 .5-.5z";
    public const string Check = "M5 12.5l4.5 4.5L19 7.5";
    public const string Warning = "M12 4l9 16H3z M12 10v4.5 M12 17.5v.5";
    public const string Search = "M10.5 4a6.5 6.5 0 1 1 0 13a6.5 6.5 0 1 1 0-13z M15.5 15.5L20 20";
    public const string Trash = "M4.5 7h15 M9.5 7V4.5h5V7 M6.5 7l1 12.5h9l1-12.5 M10.5 10.5v6 M13.5 10.5v6";
    public const string Plus = "M12 5v14 M5 12h14";
    public const string Usb = "M12 3v14 M12 17a2 2 0 1 0 0 4a2 2 0 1 0 0-4z M12 9l-4-2v3 M12 12l4-2 M8 5.5h-1.5v3H8z M15.5 8a1.3 1.3 0 1 0 0 2.6a1.3 1.3 0 1 0 0-2.6z";
    public const string Link = "M10 14a4 4 0 0 0 5.7 0l3-3a4 4 0 0 0-5.7-5.7l-1 1 M14 10a4 4 0 0 0-5.7 0l-3 3a4 4 0 0 0 5.7 5.7l1-1";

    // Path data stays immutable; views, strokes and theme bindings remain per icon.
    static readonly Dictionary<string, Geometry> geometry = new(StringComparer.Ordinal);
    internal static Geometry SharedGeometry(string data)
    {
        if (!geometry.TryGetValue(data, out var parsed)) geometry[data] = parsed = Geometry.Parse(data);
        return parsed;
    }
    // Fixed coordinates preserve margins and symmetry instead of stretching
    // different geometry bounds to the full icon square.
    public static Control Fixed(string data, double size, string brushKey)
    {
        var canvas = new Canvas { Width = 24, Height = 24 };
        canvas.Children.Add(new Path { Data = SharedGeometry(data), StrokeThickness = 1.7,
            StrokeLineCap = PenLineCap.Round, StrokeJoin = PenLineJoin.Round }.Res(Shape.StrokeProperty, brushKey));
        return new Viewbox { Width = size, Height = size, Child = canvas };
    }
    public static Control Make(string data, double size, string brushKey, double stroke = 1.6)
    {
        var path = new Path
        {
            Data = SharedGeometry(data), StrokeThickness = stroke,
            StrokeLineCap = PenLineCap.Round, StrokeJoin = PenLineJoin.Round, Stretch = Stretch.Uniform,
        }.Res(Shape.StrokeProperty, brushKey);
        return new Viewbox { Width = size, Height = size, Child = new Border { Width = 24, Height = 24, Child = path, Padding = new Thickness(0) } };
    }
}

/// Two-series throughput history. Each series is scaled to the shared maximum so
/// the ratio between directions stays visible.
