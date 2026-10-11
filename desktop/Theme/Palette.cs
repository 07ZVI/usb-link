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

internal static class Palette
{
    public const string FontStack = "Segoe UI Variable Text, Segoe UI, Microsoft JhengHei UI, Microsoft JhengHei, PingFang TC";

    static readonly (string Key, string Light, string Dark)[] Tokens =
    {
        ("Window", "#F3F3F3", "#202020"),
        ("Card", "#B3FFFFFF", "#0DFFFFFF"),
        ("CardHover", "#F9F9F9", "#15FFFFFF"),
        ("Field", "#80F9F9F9", "#08FFFFFF"),
        ("Control", "#FDFDFD", "#0FFFFFFF"),
        ("Stroke", "#14000000", "#17FFFFFF"),
        ("Ink", "#1B1B1B", "#FFFFFF"),
        ("Muted", "#5C5C5C", "#C8C8C8"),
        ("Subtle", "#8A8A8A", "#9A9A9A"),
        ("Accent", "#0F6CBD", "#4CC2FF"),
        ("AccentSoft", "#E6F0FA", "#1F3446"),
        ("Cyan", "#0B8A9E", "#5ED8D0"),
        ("Ok", "#107C10", "#6CCB5F"),
        ("OkSoft", "#DFF6DD", "#2A3A26"),
        ("Busy", "#0F6CBD", "#4CC2FF"),
        ("BusySoft", "#E6F0FA", "#1F3446"),
        ("Idle", "#8A8A8A", "#9A9A9A"),
        ("IdleSoft", "#0D000000", "#12FFFFFF"),
        ("Warn", "#9D5D00", "#FCE100"),
        ("WarnSoft", "#FFF4CE", "#433519"),
        ("Error", "#C42B1C", "#FF99A4"),
        ("ErrorSoft", "#FDE7E9", "#442726"),
    };

    public static void Install(IResourceDictionary resources)
    {
        var light = new ResourceDictionary();
        var dark = new ResourceDictionary();
        foreach (var (key, l, d) in Tokens)
        {
            light[key] = new SolidColorBrush(Color.Parse(l));
            dark[key] = new SolidColorBrush(Color.Parse(d));
        }
        resources.ThemeDictionaries[ThemeVariant.Light] = light;
        resources.ThemeDictionaries[ThemeVariant.Dark] = dark;
        // Fluent controls (toggle switches, focus rings) derive from these.
        foreach (var (key, value) in new[] {
            ("SystemAccentColor", "#0F6CBD"), ("SystemAccentColorDark1", "#115EA3"),
            ("SystemAccentColorDark2", "#0F548C"), ("SystemAccentColorDark3", "#0C3B5E"),
            ("SystemAccentColorLight1", "#2886DE"), ("SystemAccentColorLight2", "#4CC2FF"),
            ("SystemAccentColorLight3", "#62ABF5") })
            resources[key] = Color.Parse(value);
    }

    public static T Res<T>(this T control, AvaloniaProperty property, string key) where T : Control
    {
        control.Bind(property, control.GetResourceObservable(key));
        return control;
    }
}

/// Stroked 24×24 line icons, drawn rather than loaded so the renderer stays one file.
