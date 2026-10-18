global using static Suhang.Desktop.ViewControls;
using Avalonia;
using Avalonia.Controls;
using Avalonia.Layout;
using Avalonia.Media;

namespace Suhang.Desktop;

internal static class ViewControls
{
    internal static TextBlock Label(string text, double size = 14, FontWeight? weight = null, string key = "Ink")
    {
        var t = new TextBlock { Text = text, FontSize = size, FontWeight = weight ?? FontWeight.Normal, TextWrapping = TextWrapping.NoWrap, TextTrimming = TextTrimming.CharacterEllipsis };
        return t.Res(TextBlock.ForegroundProperty, key);
    }
    internal static ToggleSwitch Switch() => new() { OnContent = "", OffContent = "", MinWidth = 0, Padding = new Thickness(0), VerticalAlignment = VerticalAlignment.Center };
    internal static Border Card(Control child, Thickness? padding = null) => new Border
    {
        Child = child, BorderThickness = new Thickness(1), CornerRadius = new CornerRadius(8), Padding = padding ?? new Thickness(20),
    }.Res(Border.BackgroundProperty, "Card").Res(Border.BorderBrushProperty, "Stroke");
    internal static Border Rule() => new Border { Height = 1 }.Res(Border.BackgroundProperty, "Stroke");
    internal static Grid Columns(string defs, params Control[] children)
    {
        var g = new Grid { ColumnDefinitions = new ColumnDefinitions(defs) };
        for (var i = 0; i < children.Length; i++) { Grid.SetColumn(children[i], i); g.Children.Add(children[i]); }
        return g;
    }
    internal static Grid Rows(string defs, params Control[] children)
    {
        var g = new Grid { RowDefinitions = new RowDefinitions(defs) };
        for (var i = 0; i < children.Length; i++) { Grid.SetRow(children[i], i); g.Children.Add(children[i]); }
        return g;
    }
    internal static Control Gap(double h = 0) => new Border { Height = h };
    internal static StackPanel Row(double spacing, params Control[] children)
    {
        var p = new StackPanel { Orientation = Orientation.Horizontal, Spacing = spacing };
        foreach (var c in children) { c.VerticalAlignment = VerticalAlignment.Center; p.Children.Add(c); }
        return p;
    }
    internal static StackPanel Column(double spacing, params Control[] children)
    {
        var p = new StackPanel { Spacing = spacing };
        foreach (var c in children) p.Children.Add(c);
        return p;
    }
    /// Secondary by default; `primary` fills with the accent and `danger` marks a destructive action
    /// (red text, or a red fill together with `primary` on a confirmation).
    internal static Button Action(string text, Action onClick, string? icon = null, bool primary = false, bool danger = false)
    {
        var fill = primary ? danger ? "Error" : "Accent" : null;
        var ink = primary ? "Window" : danger ? "Error" : "Ink";
        var label = Label(text, 13, primary ? FontWeight.SemiBold : FontWeight.Normal, ink);
        Control content = icon is null ? label : Row(8, Icons.Make(icon, 16, ink), label);
        var b = new Button { Content = content, Padding = new Thickness(14, 7), CornerRadius = new CornerRadius(4), MinHeight = 34 };
        if (icon != null && text != "") Avalonia.Automation.AutomationProperties.SetName(b, text);
        b.BorderThickness = new Thickness(1);
        if (fill != null) b.Res(Button.BackgroundProperty, fill).Res(Button.BorderBrushProperty, fill);
        else if (danger) b.Res(Button.BackgroundProperty, "Control").Res(Button.BorderBrushProperty, "Stroke");
        else b.Res(Button.BackgroundProperty, "Control").Res(Button.BorderBrushProperty, "Stroke");
        b.Click += (_, _) => onClick();
        // Fluent's disabled grey fill fights the palette; dim the whole button instead.
        b.PropertyChanged += (_, e) => { if (e.Property == Button.IsEnabledProperty) b.Opacity = b.IsEnabled ? 1 : .45; };
        return b;
    }
    internal static Button IconButton(string icon, string tip, Action onClick)
    {
        var b = new Button { Content = Icons.Make(icon, 16, "Muted"), Padding = new Thickness(8), CornerRadius = new CornerRadius(4), Background = Brushes.Transparent, BorderThickness = new Thickness(0) };
        ToolTip.SetTip(b, tip);
        Avalonia.Automation.AutomationProperties.SetName(b, tip);
        b.Click += (_, _) => onClick();
        return b;
    }
    /// Wrapped secondary text: the default for descriptions and hints.
    internal static TextBlock Hint(string text, string key = "Muted", double size = Scale.Secondary)
    {
        var label = Label(text, size, key: key); label.TextWrapping = TextWrapping.Wrap; label.TextTrimming = TextTrimming.None; return label;
    }
    /// A caption above a form field.
    internal static Control Field(string caption, Control input) => Column(5, Label(caption, Scale.Secondary, key: "Muted"), input);
    internal static T WithMargin<T>(T c, Thickness m) where T : Control { c.Margin = m; return c; }
}
