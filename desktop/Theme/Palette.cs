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
        // Warm espresso and gold (Mole's status board): a soft gradient window, borderless translucent tiles, gold accents.
        ("Window", "#F8F0DF", "#221F1A"),
        ("BgFrom", "#FCF8EF", "#211E19"), ("BgTo", "#EFD9AA", "#3A2D1B"),
        ("Card", "#99FFFFFF", "#0FFFF3DC"),
        ("CardHover", "#CCFFFFFF", "#1AFFF3DC"),
        ("Field", "#B3FFFFFF", "#12FFF3DC"),
        ("Control", "#CCFFFFFF", "#17FFF3DC"),
        ("Stroke", "#0F2B2116", "#0FFFF3DC"),
        ("Ink", "#2B2116", "#F3EFE8"),
        ("Muted", "#6E604C", "#B3AA9C"),
        ("Subtle", "#9A8B74", "#8A8275"),
        ("Accent", "#A8711C", "#E8B556"),
        ("AccentSoft", "#F3E4C4", "#3D3220"),
        ("Cyan", "#5F7F8C", "#9DB7C2"),
        ("Ok", "#2F7D4F", "#8FD8A8"),
        ("OkSoft", "#D8EBD9", "#25352A"),
        ("Busy", "#A8711C", "#E8B556"),
        ("BusySoft", "#F3E4C4", "#3D3220"),
        ("Idle", "#9A8B74", "#8A8275"),
        ("IdleSoft", "#122B2116", "#12FFF3DC"),
        ("Warn", "#9A5B12", "#F2C46B"),
        ("WarnSoft", "#F6E2BF", "#41341C"),
        ("Error", "#C42B1C", "#FF99A4"),
        ("ErrorSoft", "#F8DDD5", "#45291F"),
        // One sky for every page now; the per-page keys stay so pages can still be tinted.
        ("PageHome", "#F8F0DF", "#221F1A"), ("PageShare", "#F8F0DF", "#221F1A"), ("PageSecurity", "#F8F0DF", "#221F1A"),
        ("PageDisk", "#F8F0DF", "#221F1A"), ("PageDetails", "#F8F0DF", "#221F1A"),
        ("OrbShare", "#3C8C86", "#5FC2B8"), ("OrbSecurity", "#7A63A8", "#A58BE0"), ("OrbDisk", "#B07A4C", "#D49A63"), ("OrbDetails", "#4C8A5E", "#78C48E"),
        ("OnFill", "#FFFFFF", "#FFFFFF"),
        // System Settings tile fills: the same saturated hue in both themes, always under a white glyph.
        ("TileBlue", "#3478F6", "#3478F6"), ("TileGreen", "#30B94D", "#30B94D"), ("TileOrange", "#F2930D", "#F2930D"),
        ("TilePurple", "#8E5BEA", "#8E5BEA"), ("TileTeal", "#24A79C", "#24A79C"), ("TileGray", "#8E8E93", "#8E8E93"),
        ("PrimaryFill", "#2B2116", "#F3EFE8"),
        ("PrimaryInk", "#FBF5E9", "#24211C"),
        // Disk space: the treemap ground, outlines and one hue per file category. Muted earth tones (Mole's disk map) keep white labels readable in both themes.
        ("Surface", "#FFFFFF", "#2E2A23"), ("MapBg", "#F1E6CF", "#1B1915"), ("StrokeStrong", "#222B2116", "#26FFF3DC"),
        ("AgeNew", "#A8711C", "#E8B556"), ("AgeOld", "#A39C8E", "#55504A"),
        // One family around the gold accent — amber, terracotta, olive, sage, plum, sand — distinct in hue but never
        // cold, so the map reads as part of the gradient window rather than a stock chart.
        ("CatApplication", "#D29B3C", "#D6A24A"), ("CatVideo", "#CC5A47", "#D66A56"), ("CatAudio", "#E08F6A", "#E39A78"),
        ("CatImage", "#93A04E", "#9DAA5C"), ("CatDocument", "#5F927F", "#6FA08E"), ("CatArchive", "#9A6B92", "#A87CA0"),
        ("CatCode", "#4F8C95", "#5F9AA2"), ("CatDiskImage", "#BC6276", "#C67284"), ("CatSystem", "#B5794A", "#BE8556"),
        ("CatOther", "#B7AA90", "#A89C84"),
    };

    // Fluent's own switch keys, restated from the palette: a filled neutral track
    // with a white knob when off and the accent when on, in both themes.
    static readonly (string Key, string Light, string Dark)[] SwitchTokens =
    {
        ("ButtonBackgroundDisabled", "#80FDFDFD", "#08FFFFFF"), ("ButtonBorderBrushDisabled", "#14000000", "#17FFFFFF"),
        ("ToggleSwitchFillOff", "#D9CDB6", "#4A443A"), ("ToggleSwitchFillOffPointerOver", "#CDBFA5", "#565046"),
        ("ToggleSwitchFillOffPressed", "#AEAEAE", "#767676"), ("ToggleSwitchFillOffDisabled", "#E6E6E6", "#383838"),
        ("ToggleSwitchStrokeOff", "#D9CDB6", "#4A443A"), ("ToggleSwitchStrokeOffPointerOver", "#CDBFA5", "#565046"),
        ("ToggleSwitchStrokeOffPressed", "#AEAEAE", "#767676"), ("ToggleSwitchStrokeOffDisabled", "#E6E6E6", "#383838"),
        ("ToggleSwitchKnobFillOff", "#FFFFFF", "#F2F2F2"), ("ToggleSwitchKnobFillOffPointerOver", "#FFFFFF", "#FFFFFF"),
        ("ToggleSwitchKnobFillOffPressed", "#F4F4F4", "#E4E4E4"), ("ToggleSwitchKnobFillOffDisabled", "#F7F7F7", "#8A8A8A"),
        ("ToggleSwitchFillOn", "#34A853", "#34C759"), ("ToggleSwitchFillOnPointerOver", "#2F9A4C", "#45D068"),
        ("ToggleSwitchFillOnPressed", "#2A8B44", "#2DB34F"), ("ToggleSwitchFillOnDisabled", "#B7D4C1", "#2D4A42"),
        ("ToggleSwitchStrokeOn", "#34A853", "#34C759"), ("ToggleSwitchStrokeOnPointerOver", "#2F9A4C", "#45D068"),
        ("ToggleSwitchStrokeOnPressed", "#2A8B44", "#2DB34F"), ("ToggleSwitchStrokeOnDisabled", "#B7D4C1", "#2D4A42"),
        ("ToggleSwitchKnobFillOn", "#FFFFFF", "#FFFFFF"), ("ToggleSwitchKnobFillOnPointerOver", "#FFFFFF", "#FFFFFF"),
        ("ToggleSwitchKnobFillOnPressed", "#F4F4F4", "#F4F4F4"), ("ToggleSwitchKnobFillOnDisabled", "#FFFFFF", "#6F8795"),
        // Disclosure rows are flat: no outline, a faint fill only under the pointer.
        ("ExpanderHeaderBackground", "#00000000", "#00000000"), ("ExpanderHeaderBackgroundPointerOver", "#0D000000", "#12FFFFFF"),
        ("ExpanderHeaderBackgroundPressed", "#14000000", "#17FFFFFF"), ("ExpanderHeaderBackgroundDisabled", "#00000000", "#00000000"),
        ("ExpanderHeaderBorderBrush", "#00000000", "#00000000"), ("ExpanderHeaderBorderBrushPointerOver", "#00000000", "#00000000"),
        ("ExpanderHeaderBorderBrushPressed", "#00000000", "#00000000"), ("ExpanderContentBackground", "#00000000", "#00000000"),
        ("ExpanderContentBorderBrush", "#00000000", "#00000000"),
        // Tabs are pills (see ThemeStyles): no selection underline.
        ("TabItemHeaderSelectedPipeFill", "#00000000", "#00000000"),
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
        foreach (var (key, l, d) in SwitchTokens)
        {
            light[key] = new SolidColorBrush(Color.Parse(l));
            dark[key] = new SolidColorBrush(Color.Parse(d));
        }
        resources.ThemeDictionaries[ThemeVariant.Light] = light;
        resources.ThemeDictionaries[ThemeVariant.Dark] = dark;
        // Fluent controls (toggle switches, focus rings) derive from these.
        foreach (var (key, value) in new[] {
            ("SystemAccentColor", "#C08A2E"), ("SystemAccentColorDark1", "#A8711C"),
            ("SystemAccentColorDark2", "#8A5C16"), ("SystemAccentColorDark3", "#6B4711"),
            ("SystemAccentColorLight1", "#D49E45"), ("SystemAccentColorLight2", "#E8B556"),
            ("SystemAccentColorLight3", "#F2CB80") })
            resources[key] = Color.Parse(value);
    }

    public static T Res<T>(this T control, AvaloniaProperty property, string key) where T : Control
    {
        control.Bind(property, control.GetResourceObservable(key));
        return control;
    }
}

/// Stroked 24×24 line icons, drawn rather than loaded so the renderer stays one file.
