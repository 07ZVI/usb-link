using Avalonia;
using Avalonia.Controls;
using Avalonia.Layout;
using Avalonia.Media;

namespace Suhang.Desktop;

/// Spacing, radius and type scale shared by the dashboard's cards and rows.
internal static class Scale
{
    public const double Gutter = 16, Inset = 16, CardRadius = 8, ControlRadius = 4, TileRadius = 6;
    public const double Caption = 11, Secondary = 12, Body = 13, Section = 15, Title = 16, Hero = 30;
}

/// A rounded dot-and-label state indicator. Tone is a palette family
/// (Ok, Busy, Warn, Error, Idle): `<Tone>Soft` fills it and `<Tone>` colours the dot and text.
internal sealed class StatusPill : Border
{
    readonly Border dot = new() { Width = 8, Height = 8, CornerRadius = new CornerRadius(4) };
    public TextBlock Label { get; }

    public StatusPill(string text = "", double size = Scale.Secondary)
    {
        Label = ViewControls.Label(text, size, FontWeight.SemiBold);
        CornerRadius = new CornerRadius(12); Padding = new Thickness(10, 4, 12, 4);
        HorizontalAlignment = HorizontalAlignment.Left; VerticalAlignment = VerticalAlignment.Center;
        var content = new Grid { ColumnDefinitions = new ColumnDefinitions("Auto,*"), ColumnSpacing = 7 };
        dot.VerticalAlignment = VerticalAlignment.Center;
        Grid.SetColumn(Label, 1); content.Children.Add(dot); content.Children.Add(Label);
        Child = content;
        Set("Idle", text);
    }

    public void Set(string tone, string? text = null)
    {
        if (text != null) Label.Text = text;
        this.Res(BackgroundProperty, tone + "Soft");
        dot.Res(BackgroundProperty, tone);
        Label.Res(TextBlock.ForegroundProperty, tone == "Idle" ? "Muted" : tone);
    }
}

/// A rounded tile holding one line icon: the leading glyph of cards and rows.
internal static class IconTile
{
    public static Control Make(string icon, string brush, string background, double size = 32)
    {
        var glyph = Icons.Make(icon, size * .56, brush);
        glyph.HorizontalAlignment = HorizontalAlignment.Center; glyph.VerticalAlignment = VerticalAlignment.Center;
        return new Border { Width = size, Height = size, CornerRadius = new CornerRadius(Scale.TileRadius), Child = glyph }.Res(Border.BackgroundProperty, background);
    }
}

/// Settings rows: an icon tile, a title with an optional info tip, one short
/// description line and either a switch or a chevron. Long explanations belong in the tip.
internal static class SettingRow
{
    static Control Info(string tip)
    {
        var info = new Border { Background = Brushes.Transparent, Padding = new Thickness(2), Child = Icons.Make(Icons.Info, 13, "Subtle"), VerticalAlignment = VerticalAlignment.Center };
        ToolTip.SetTip(info, tip);
        Avalonia.Automation.AutomationProperties.SetName(info, tip);
        return info;
    }

    static Grid Layout(string icon, string title, string description, string? tip, Control end, Control? detail)
    {
        var heading = tip == null ? (Control)Label(title, Scale.Body) : Row(4, Label(title, Scale.Body), Info(tip));
        var lines = Column(1, heading, Label(description, Scale.Caption, key: "Subtle"));
        if (detail != null) lines.Children.Add(detail);
        lines.VerticalAlignment = VerticalAlignment.Center; lines.Margin = new Thickness(12, 0, 12, 0);
        end.VerticalAlignment = VerticalAlignment.Center;
        var grid = Columns("Auto,*,Auto", IconTile.Make(icon, "Muted", "IdleSoft", 32), lines, end);
        grid.VerticalAlignment = VerticalAlignment.Center;
        return grid;
    }

    /// A row whose trailing control is a switch; the row itself is not a button.
    public static Control Toggle(string icon, string title, string description, ToggleSwitch toggle, string? tip = null, Control? detail = null) =>
        new Border { Padding = new Thickness(8, 10), Child = Layout(icon, title, description, tip, toggle, detail), VerticalAlignment = VerticalAlignment.Stretch };

    /// A row that opens another window.
    public static Control Link(string icon, string title, string description, Action onClick)
    {
        var button = new Button
        {
            Content = Layout(icon, title, description, null, Icons.Make(Icons.Chevron, 14, "Subtle"), null),
            HorizontalAlignment = HorizontalAlignment.Stretch, HorizontalContentAlignment = HorizontalAlignment.Stretch,
            VerticalAlignment = VerticalAlignment.Stretch, VerticalContentAlignment = VerticalAlignment.Center, Padding = new Thickness(8, 10), Background = Brushes.Transparent, BorderThickness = new Thickness(0), CornerRadius = new CornerRadius(Scale.TileRadius),
        };
        button.Click += (_, _) => onClick();
        Avalonia.Automation.AutomationProperties.SetName(button, title);
        return button;
    }

    /// Rows share the available height equally, each closed by a hairline aligned with the text.
    public static Grid List(params Control[] rows)
    {
        var grid = new Grid { RowDefinitions = new RowDefinitions(string.Join(",", rows.Select(_ => "*"))) };
        for (var i = 0; i < rows.Length; i++)
        {
            Grid.SetRow(rows[i], i); grid.Children.Add(rows[i]);
            if (i == rows.Length - 1) continue;
            var line = WithMargin(Rule(), new Thickness(52, 0, 8, 0));
            line.VerticalAlignment = VerticalAlignment.Bottom;
            Grid.SetRow(line, i); grid.Children.Add(line);
        }
        return grid;
    }
}
