using Avalonia;
using Avalonia.Controls;
using Avalonia.Layout;
using Avalonia.Media;
using Avalonia.VisualTree;
using System.Text.RegularExpressions;

namespace Suhang.Desktop;

/// The design tokens (see docs/DESIGN.md). Type follows the macOS text styles; spacing sits on a 4-pt grid;
/// radii and control heights come in a few fixed steps. Views use these names, never ad-hoc numbers.
internal static class Scale
{
    // Type ramp (macOS HIG text styles, 1 pt = 1 DIP).
    public const double Footnote = 10, Subheadline = 11, Callout = 12, Body = 13, Title3 = 15, Title2 = 17, Title1 = 22, LargeTitle = 26, Display = 40;
    // Older names, kept as the same steps: Caption = Subheadline, Secondary = Callout, Section = Title3, Title = Title2, Page = Title1, Hero = Display.
    public const double Caption = Subheadline, Secondary = Callout, Section = Title3, Title = Title2, Page = Title1, Hero = Display;

    // Spacing: 2 4 6 8 12 16 20 24 32.
    public const double Hair = 2, Tight = 4, Snug = 6, Small = 8, Medium = 12, Regular = 16, Large = 20, XLarge = 24, XXLarge = 32;
    /// Window content margin, gap between cards, inner padding of a card.
    public const double Margin = Large, Gutter = Medium, Inset = Regular;

    // Corner radii: marks (dots, bars) 3, controls 8, tiles 8, cards 12, panels 16, capsules = height / 2.
    public const double MarkRadius = 3, ControlRadius = 8, TileRadius = 8, CardRadius = 16, PanelRadius = 20;
    // Control heights: regular controls 30 (capsule radius 15), large 36, list rows 44, leading row icons 28.
    public const double ControlHeight = 30, SmallControl = 26, LargeControl = 36, RowHeight = 44, RowIcon = 28, PillRadius = ControlHeight / 2;
    // Icon sizes: inline 14, in controls 16, leading in cards 20.
    public const double IconInline = 14, IconControl = 16, IconLead = 20;

    /// Card padding or gap for a density level: 0 roomy, 1 compact (about three quarters), 2 dense (half), snapped to the grid.
    public static double Pad(int density, double full) => density switch { 0 => full, 1 => Snap(full * .75), _ => Snap(full * .5) };
    static double Snap(double v) => v <= 2 ? 2 : v <= 4 ? 4 : v <= 6 ? 6 : v <= 9 ? 8 : v <= 13 ? 12 : v <= 17 ? 16 : v <= 21 ? 20 : v <= 27 ? 24 : 32;
}

/// A rounded dot-and-label state indicator. Tone is a palette family
/// (Ok, Busy, Warn, Error, Idle): `<Tone>Soft` fills it and `<Tone>` colours the dot and text.
internal sealed class StatusPill : Border
{
    readonly Border dot = new() { Width = 6, Height = 6, CornerRadius = new CornerRadius(3) };
    public TextBlock Label { get; }

    public StatusPill(string text = "", double size = Scale.Secondary)
    {
        Label = ViewControls.Label(text, size, FontWeight.SemiBold);
        // A 22-pt capsule: 3 above and below a 12-pt label line (16), dot and text 6 apart.
        CornerRadius = new CornerRadius(11); Padding = new Thickness(Scale.Small, 3, Scale.Medium - 2, 3);
        HorizontalAlignment = HorizontalAlignment.Left; VerticalAlignment = VerticalAlignment.Center;
        var content = new Grid { ColumnDefinitions = new ColumnDefinitions("Auto,*"), ColumnSpacing = Scale.Snug };
        dot.VerticalAlignment = VerticalAlignment.Center;
        Grid.SetColumn(Label, 1); content.Children.Add(dot); content.Children.Add(Label);
        Child = content;
        Set("Idle", text);
    }

    public string Tone { get; private set; } = "Idle";
    public event Action<string>? ToneChanged;

    public void Set(string tone, string? text = null)
    {
        if (text != null) Label.Text = text;
        if (Tone != tone) { Tone = tone; ToneChanged?.Invoke(tone); }
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
        return new Border { Width = size, Height = size, CornerRadius = new CornerRadius(size >= 36 ? Scale.CardRadius - 2 : Scale.TileRadius), Child = glyph }.Res(Border.BackgroundProperty, background);
    }

    /// The System Settings tile: a filled square in `tone` with a white glyph (28 pt, radius 7, glyph 16).
    public static Control Solid(string icon, string tone, double size = Scale.RowIcon)
    {
        var glyph = Icons.Make(icon, size * .58, "OnFill", 2);
        glyph.HorizontalAlignment = HorizontalAlignment.Center; glyph.VerticalAlignment = VerticalAlignment.Center;
        return new Border { Width = size, Height = size, CornerRadius = new CornerRadius(size / 4), Child = glyph }.Res(Border.BackgroundProperty, tone);
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

    // Row anatomy (System Settings): 12 | 28 tile | 12 | title + description | 12 | control | 12, at least 44 tall.
    static Grid Layout(string icon, string title, string description, string? tip, Control end, Control? detail, string tone)
    {
        var heading = tip == null ? (Control)Label(title, Scale.Body, FontWeight.Medium) : Row(Scale.Tight, Label(title, Scale.Body, FontWeight.Medium), Info(tip));
        var note = Label(description, Scale.Subheadline, key: "Muted"); note.Classes.Add("desc");
        var lines = Column(Scale.Hair, heading, note);
        if (detail != null) lines.Children.Add(detail);
        lines.VerticalAlignment = VerticalAlignment.Center; lines.Margin = new Thickness(Scale.Medium, 0, Scale.Medium, 0);
        end.VerticalAlignment = VerticalAlignment.Center;
        var grid = Columns("Auto,*,Auto", IconTile.Solid(icon, tone), lines, end);
        grid.MinHeight = Scale.RowHeight - 2 * Scale.Small;
        grid.VerticalAlignment = VerticalAlignment.Center;
        return grid;
    }

    /// A row whose trailing control is a switch; the row itself is not a button.
    public static Control Toggle(string icon, string title, string description, ToggleSwitch toggle, string? tip = null, Control? detail = null, string tone = "Accent") =>
        new Border { Padding = new Thickness(Scale.Medium, Scale.Small), Child = Layout(icon, title, description, tip, toggle, detail, tone), VerticalAlignment = VerticalAlignment.Stretch, Classes = { "row" } };

    /// A row that opens another window.
    public static Control Link(string icon, string title, string description, Action onClick, string tone = "Accent")
    {
        var button = new Button
        {
            Content = Layout(icon, title, description, null, Icons.Make(Icons.Chevron, Scale.IconInline, "Subtle"), null, tone),
            HorizontalAlignment = HorizontalAlignment.Stretch, HorizontalContentAlignment = HorizontalAlignment.Stretch,
            VerticalAlignment = VerticalAlignment.Stretch, VerticalContentAlignment = VerticalAlignment.Center, Padding = new Thickness(Scale.Medium, Scale.Small), Background = Brushes.Transparent, BorderThickness = new Thickness(0), CornerRadius = new CornerRadius(Scale.TileRadius),
        };
        button.Classes.Add("row");
        button.Click += (_, _) => onClick();
        Avalonia.Automation.AutomationProperties.SetName(button, title);
        return button;
    }

    /// Equal rows share the list's height; automatic rows take only what their text needs.
    public static void Distribute(Grid list, bool equal)
    {
        var rows = list.RowDefinitions.Count;
        list.RowDefinitions = new RowDefinitions(string.Join(",", Enumerable.Repeat(equal ? "*" : "Auto", rows)));
    }

    /// Dense rows (level 2) drop the description line into a tooltip and tighten their padding.
    public static void SetDensity(Control list, int level)
    {
        var padding = new Thickness(Scale.Medium, level switch { 0 => Scale.Small, 1 => Scale.Snug, _ => Scale.Hair });
        foreach (var visual in list.GetVisualDescendants().OfType<Control>().Where(c => c.Classes.Contains("row")).ToArray())
        {
            var description = visual.GetVisualDescendants().OfType<TextBlock>().FirstOrDefault(t => t.Classes.Contains("desc"));
            if (description != null) { description.IsVisible = level < 2; ToolTip.SetTip(visual, level == 2 ? description.Text : null); }
            if (visual is Border border) border.Padding = padding; else if (visual is Button button) button.Padding = padding;
        }
    }

    /// Rows share the available height equally, each closed by a hairline aligned with the text.
    public static Grid List(params Control[] rows)
    {
        var grid = new Grid { RowDefinitions = new RowDefinitions(string.Join(",", rows.Select(_ => "*"))) };
        for (var i = 0; i < rows.Length; i++)
        {
            Grid.SetRow(rows[i], i); grid.Children.Add(rows[i]);
            if (i == rows.Length - 1) continue;
            // Separators start under the text, as in grouped lists: 12 + 28 + 12.
            var line = WithMargin(Rule(), new Thickness(Scale.Medium + Scale.RowIcon + Scale.Medium, 0, 0, 0));
            line.VerticalAlignment = VerticalAlignment.Bottom;
            Grid.SetRow(line, i); grid.Children.Add(line);
        }
        return grid;
    }
}

/// Windows share one frame: palette background, font, centred over the owner and a
/// "USB Link · name" title, always inside the screen's work area (see WindowFit).
/// Dialogs size to their content and cannot be resized.
internal static class AppWindow
{
    public static Window Create(string name, double width, double height, double minWidth = 0, double minHeight = 0)
    {
        // Manual placement: WindowFit centres the window over its owner and keeps it inside the work area.
        var window = new Window { Title = "USB Link · " + name, Width = width, Height = height, FontFamily = new FontFamily(Palette.FontStack), WindowStartupLocation = WindowStartupLocation.Manual };
        if (minWidth > 0) window.MinWidth = minWidth;
        if (minHeight > 0) window.MinHeight = minHeight;
        WindowFit.Attach(window, minWidth, minHeight);
        return window.Res(Window.BackgroundProperty, "Window");
    }

    public static Window Dialog(string name, double width, Control content, bool topmost = false)
    {
        var window = Create(name, width, double.NaN);
        window.SizeToContent = SizeToContent.Height; window.CanResize = false; window.Topmost = topmost;
        window.WindowStartupLocation = WindowStartupLocation.CenterOwner;
        window.Content = new Border { Padding = new Thickness(Scale.Large), Child = content };
        return window;
    }

    /// Page frame: header, optional banner row, body (fills the height) and a quiet footer line.
    public static Control Page(Control header, Control body, Control? footer = null, Control? banner = null)
    {
        // Header, 20, optional banner, body, 12, optional footer: empty slots take no space at all.
        var grid = new Grid { Margin = new Thickness(0, Scale.Tight, 0, 0) };
        var parts = new List<(Control Part, string Size, double Gap)> { (header, "Auto", 0) };
        if (banner != null) parts.Add((banner, "Auto", Scale.Medium));
        parts.Add((body, "*", Scale.Large));
        if (footer != null) parts.Add((footer, "Auto", Scale.Medium));
        foreach (var (part, size, gap) in parts)
        {
            if (gap > 0) grid.RowDefinitions.Add(new RowDefinition(gap, GridUnitType.Pixel));
            grid.RowDefinitions.Add(new RowDefinition(GridLength.Parse(size)));
            Grid.SetRow(part, grid.RowDefinitions.Count - 1); grid.Children.Add(part);
        }
        return grid;
    }

    /// Title, one line of explanation and the window-level actions on the right.
    public static Control Header(string title, string? subtitle, params Control[] actions) => Header(title, string.IsNullOrEmpty(subtitle) ? null : Hint(subtitle), actions);

    /// A tool page's header: a large title and its live subtitle on the left, actions on the right. No illustration:
    /// the page gets its weight from the 26-pt title and the 24-pt air below it. (`orb` is kept for callers; unused.)
    public static Control Hero(string orb, string title, TextBlock? subtitle, params Control[] actions)
    {
        var text = Column(Scale.Tight, Label(title, Scale.LargeTitle, FontWeight.Bold));
        if (subtitle != null) { subtitle.TextWrapping = TextWrapping.Wrap; subtitle.TextTrimming = TextTrimming.None; subtitle.FontSize = Scale.Body; text.Children.Add(subtitle); }
        text.VerticalAlignment = VerticalAlignment.Bottom;
        var row = Row(Scale.Small, actions); row.VerticalAlignment = VerticalAlignment.Bottom;
        var bar = Columns("*,Auto", text, row);
        bar.ColumnSpacing = Scale.Regular; bar.Margin = new Thickness(Scale.Tight, Scale.Small, 0, Scale.Tight);
        return bar;
    }
    public static Control Hero(string orb, string title, string? subtitle, params Control[] actions) => Hero(orb, title, string.IsNullOrEmpty(subtitle) ? null : Hint(subtitle), actions);

    /// The subtitle may be a live label that the view updates.
    public static Control Header(string title, TextBlock? subtitle, params Control[] actions)
    {
        var text = Column(Scale.Hair, Label(title, Scale.Title1, FontWeight.Bold));
        if (subtitle != null) { subtitle.TextWrapping = TextWrapping.Wrap; subtitle.TextTrimming = TextTrimming.None; text.Children.Add(subtitle); }
        text.VerticalAlignment = VerticalAlignment.Center;
        var bar = Columns("*,Auto", text, Row(Scale.Small, actions));
        bar.ColumnSpacing = Scale.Regular; return bar;
    }

    /// Asks before something destructive or irreversible. The caller keeps only the follow-up action.
    public static void Confirm(Window? owner, string title, string text, string confirm, Action apply, bool danger = false, string? detail = null)
    {
        if (owner == null) return;
        Window? dialog = null;
        var body = Column(Scale.Medium, Label(title, Scale.Title2, FontWeight.SemiBold));
        if (!string.IsNullOrEmpty(detail)) body.Children.Add(Hint(detail, "Subtle"));
        body.Children.Add(Hint(text, "Ink", Scale.Body));
        var buttons = Row(8, Action("取消", () => dialog!.Close()), Action(confirm, () => { dialog!.Close(); apply(); }, primary: true, danger: danger));
        buttons.HorizontalAlignment = HorizontalAlignment.Right; buttons.Margin = new Thickness(0, Scale.Small, 0, 0);
        body.Children.Add(buttons);
        dialog = Dialog(title, 480, body);
        dialog.Closed += (_, _) => dialog.Content = null;
        _ = dialog.ShowDialog(owner);
    }
}

/// A titled card: heading, optional description, an action on the right and the body below.
internal static class Section
{
    public static Border Make(string title, string? description, Control body, Control? action = null, Control? status = null)
    {
        var heading = Column(2, Columns("Auto,*", Label(title, Scale.Section, FontWeight.SemiBold), status ?? Gap()));
        ((Grid)heading.Children[0]).ColumnSpacing = 12;
        if (!string.IsNullOrEmpty(description)) heading.Children.Add(Hint(description));
        var head = Columns("*,Auto", heading, action ?? Gap()); head.ColumnSpacing = 12;
        return Card(Column(Scale.Regular, head, body), new Thickness(Scale.Inset));
    }
}

/// One list item: optional icon tile, title, subtitle, a trailing control, then body rows.
internal static class ListItem
{
    public static Border Make(string title, string? subtitle, Control? trailing = null, string? icon = null, string tone = "Idle", params Control[] body)
    {
        var heading = Column(2, WrapLabel(title, Scale.Body, FontWeight.SemiBold));
        if (!string.IsNullOrEmpty(subtitle)) heading.Children.Add(Hint(subtitle, "Muted", Scale.Caption));
        var head = icon == null ? Columns("*,Auto", heading, trailing ?? Gap()) : Columns("Auto,*,Auto", IconTile.Make(icon, tone == "Idle" ? "Muted" : tone, tone + "Soft"), heading, trailing ?? Gap());
        head.ColumnSpacing = 12; foreach (var c in head.Children) c.VerticalAlignment = VerticalAlignment.Center;
        var content = Column(12, head);
        foreach (var c in body) content.Children.Add(c);
        return Card(content, new Thickness(16, 12));
    }
    /// A dense row for long inventories: title and kind share one line, one muted line of facts, then body rows.
    public static Border Compact(string title, string kind, string facts, Control? trailing = null, params Control[] body)
    {
        var name = Label(title, Scale.Body, FontWeight.SemiBold);
        var type = Label(kind, Scale.Caption, key: "Muted");
        var heading = Columns("Auto,*", name, type); heading.ColumnSpacing = 8;
        type.VerticalAlignment = VerticalAlignment.Center; name.VerticalAlignment = VerticalAlignment.Center;
        var head = Columns("*,Auto", heading, trailing ?? Gap()); head.ColumnSpacing = 8;
        var content = Column(4, head);
        if (!string.IsNullOrEmpty(facts)) content.Children.Add(Hint(facts, "Muted", Scale.Secondary));
        foreach (var c in body) content.Children.Add(c);
        return Card(content, new Thickness(16, 8));
    }
    static TextBlock WrapLabel(string text, double size, FontWeight weight) { var l = Label(text, size, weight); l.TextWrapping = TextWrapping.Wrap; l.TextTrimming = TextTrimming.None; return l; }
}

/// Placeholder for a list that is loading, empty or unavailable: what happened and what to do next.
internal static class EmptyState
{
    public static Control Make(string icon, string title, string? text = null, Control? action = null)
    {
        var column = Column(8, IconTile.Make(icon, "Subtle", "IdleSoft", 40), Label(title, Scale.Body, FontWeight.SemiBold));
        if (!string.IsNullOrEmpty(text)) { var hint = Hint(text); hint.TextAlignment = TextAlignment.Center; hint.MaxWidth = 380; column.Children.Add(hint); }
        if (action != null) column.Children.Add(action);
        foreach (var c in column.Children) c.HorizontalAlignment = HorizontalAlignment.Center;
        column.Margin = new Thickness(0, 32); return column;
    }
}

/// An inline banner. Tone is a palette family (Ok, Busy, Warn, Error); raw status codes are
/// translated by Friendly and kept as a small selectable line for support.
internal sealed class Notice : Border
{
    readonly Border icon = new() { Width = 20, Height = 20, VerticalAlignment = VerticalAlignment.Top };
    readonly TextBlock message = Hint("", "Ink", Scale.Body);
    readonly SelectableTextBlock code = new() { FontSize = Scale.Caption, TextWrapping = TextWrapping.Wrap, IsVisible = false };
    readonly ContentControl action = new() { VerticalAlignment = VerticalAlignment.Center };
    public Notice()
    {
        CornerRadius = new CornerRadius(Scale.TileRadius); Padding = new Thickness(12, 12); IsVisible = false;
        code.Res(TextBlock.ForegroundProperty, "Subtle");
        var text = Column(2, message, code); text.VerticalAlignment = VerticalAlignment.Center;
        var layout = Columns("Auto,*,Auto", icon, text, action); layout.ColumnSpacing = 12;
        Child = layout;
    }
    /// Message plus the technical code, as a view would read it back.
    public string Text => message.Text + (code.IsVisible ? " " + code.Text : "");
    public Notice WithAction(Control? button) { action.Content = button; return this; }
    public void Hide() => IsVisible = false;
    /// Shows `raw` as a readable sentence; an unknown tone keeps the previous colours.
    public void Show(string tone, string raw)
    {
        var (text, technical) = Friendly.Explain(raw);
        if (text == "") { Hide(); return; }
        message.Text = text; code.Text = technical == "" ? "" : "技術代碼：" + technical; code.IsVisible = technical != "";
        this.Res(BackgroundProperty, tone + "Soft");
        icon.Child = Icons.Make(tone switch { "Ok" => Icons.Check, "Busy" or "Idle" => Icons.Info, _ => Icons.Warning }, 16, tone);
        IsVisible = true;
    }
}

/// Raw codes (UPPER_SNAKE words and 0x HRESULT values) become short sentences. The original
/// codes are returned separately so a view can show them quietly and support can still ask for them.
internal static class Friendly
{
    static readonly Regex CodePattern = new(@"\b(?:[A-Z][A-Z0-9]*(?:_[A-Z0-9]+)+|0x[0-9A-Fa-f]{8})\b", RegexOptions.Compiled);
    static readonly (string Code, string Text)[] Known =
    {
        ("INTERNET_MOBILE_HOTSPOT_CONFLICT", "Windows 行動熱點已開啟，與網際網路共享衝突。請到「設定 › 網路和網際網路 › 行動熱點」關閉後，再按「重新檢查」；本程式不會更改它。"),
        ("INTERNET_EXISTING_NAT_CONFLICT", "Windows 已有 NAT 設定（常來自 Hyper-V、WSL 或其他虛擬化工具）。請先自行移除後按「重新檢查」；本程式不會更改它。"),
        ("INTERNET_EXISTING_ICS_CONFLICT", "Windows 已啟用內建的網際網路連線共用（ICS）。請在網路卡內容的「共用」頁籤關閉後按「重新檢查」；本程式不會更改它。"),
        ("INTERNET_WINNAT_UNAVAILABLE", "這台電腦不支援所需的 Windows NAT 功能，無法共享網際網路。"),
        ("INTERNET_USB_GATEWAY_REQUIRED", "請先接上 USB 裝置並完成連線，再開啟網際網路共享。"),
        ("FIREWALL_RULE_NOT_EFFECTIVE", "規則已寫入，但 Windows 尚未確認它生效。請重新整理核對。"),
        ("SMB_EXTERNAL_CHANGED_REFRESH_REQUIRED", "此共享已變更，請重新整理後再操作。"),
        ("NATIVE_SMB_RECEIPT_CHANGED", "已有共享的保存設定與目前設定不一致；不一定是新添加的磁碟有問題。請查看詳細錯誤。"),
        ("NATIVE_SMB_CHANGED_IN_WINDOWS", "這個共享已在 Windows 中被修改，請在 Windows 核對，或改由 Windows 管理。"),
        ("NATIVE_SMB_NAME_CONFLICT", "已有同名的共享，請改用其他資料夾或名稱。"),
        ("CORE_UI_ACTION_FAILED", "操作未能送達背景程式，尚未確認是否執行。可稍後重試。"),
        ("SECURITY_OPERATION_BUSY", "上一個安全操作仍在進行，請稍候再試。"),
        ("USB_TRACE_NO_SAFE_EVENT_SCHEMA", "未找到可安全記錄的 USB 事件格式。"),
    };
    static readonly (string Prefix, string Text)[] Families =
    {
        ("FIREWALL_", "防火牆規則未能確認生效。"), ("NATIVE_SMB_", "Windows 共享設定未完成。"), ("SMB_", "Windows 共享設定未完成。"),
        ("INTERNET_", "網際網路共享未完成。"), ("USB_", "USB 狀態未能確認。"), ("0x", "Windows 回報了錯誤。"),
    };

    public static (string Message, string Code) Explain(string raw)
    {
        raw = raw.Trim();
        var codes = CodePattern.Matches(raw).Select(m => m.Value).Distinct().ToArray();
        if (codes.Length == 0) return (raw, "");
        var rest = CodePattern.Replace(raw, "").Trim(' ', '\n', '\r', ':', '：', ';', '；', '·', '-');
        var known = Known.FirstOrDefault(k => codes.Contains(k.Code)).Text;
        var family = Families.FirstOrDefault(f => codes.Any(c => c.StartsWith(f.Prefix, StringComparison.Ordinal))).Text;
        var message = known ?? (rest.Length > 0 && rest.Any(c => c > 0x2E80) ? "" : family ?? "操作未完成，請重試。");
        if (rest.Length > 0 && rest.Length <= 160) message = message == "" ? rest : message + (known != null ? "（" + rest + "）" : " " + rest);
        return (message, string.Join("、", codes));
    }
}
