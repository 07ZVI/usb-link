using Avalonia;
using Avalonia.Controls;
using Avalonia.Controls.Presenters;
using Avalonia.Controls.Primitives;
using Avalonia.Layout;
using Avalonia.Media;
using Avalonia.Markup.Xaml.MarkupExtensions;
using Avalonia.Styling;

namespace Suhang.Desktop;

/// App-wide control shapes on top of Fluent: open underline tabs, borderless bottom-line fields,
/// subtle flyouts and tooltips. Colors stay palette tokens so both themes follow.
internal static class ThemeStyles
{
    public static Styles Build()
    {
        var styles = new Styles();
        Style S(Func<Selector?, Selector> selector, params (AvaloniaProperty Property, object Value)[] setters)
        {
            var style = new Style(selector);
            foreach (var (p, v) in setters) style.Setters.Add(new Setter(p, v is string key ? new DynamicResourceExtension(key) : v));
            styles.Add(style); return style;
        }
        // Tabs: open typographic underline tabs (no capsule or box frames).
        S(x => x.OfType<TabItem>(), (TemplatedControl.CornerRadiusProperty, new CornerRadius(0)), (TemplatedControl.PaddingProperty, new Thickness(2, 0, 2, 4)),
            (Layoutable.MinHeightProperty, Scale.ControlHeight), (Layoutable.HeightProperty, Scale.ControlHeight), (Layoutable.MarginProperty, new Thickness(0, 0, Scale.Large, 0)),
            (TemplatedControl.ForegroundProperty, "Muted"), (TemplatedControl.FontSizeProperty, Scale.Body), (TemplatedControl.FontWeightProperty, FontWeight.Medium),
            (TemplatedControl.BackgroundProperty, "Transparent"), (TemplatedControl.BorderThicknessProperty, new Thickness(0)));
        S(x => x.OfType<TabItem>().Template().Is<Control>().Name("PART_SelectedPipe"), (Visual.IsVisibleProperty, false), (Visual.OpacityProperty, 0d));
        S(x => x.OfType<TabItem>().Class(":selected").Template().Is<Control>().Name("PART_SelectedPipe"), (Visual.IsVisibleProperty, false), (Visual.OpacityProperty, 0d));
        S(x => x.OfType<TabItem>().Template().OfType<Border>().Name("PART_LayoutRoot"),
            (Border.CornerRadiusProperty, new CornerRadius(0)), (Border.BackgroundProperty, "Transparent"),
            (Border.BorderThicknessProperty, new Thickness(0, 0, 0, 2)), (Border.BorderBrushProperty, "Transparent"));
        S(x => x.OfType<TabItem>().Class(":pointerover").Template().OfType<Border>().Name("PART_LayoutRoot"), (Border.BackgroundProperty, "HoverTint"));
        S(x => x.OfType<TabItem>().Class(":selected").Template().OfType<Border>().Name("PART_LayoutRoot"),
            (Border.BackgroundProperty, "Transparent"), (Border.BorderBrushProperty, "Accent"));
        S(x => x.OfType<TabItem>().Class(":selected"), (TemplatedControl.ForegroundProperty, "Ink"), (TemplatedControl.FontWeightProperty, FontWeight.SemiBold));
        S(x => x.OfType<TabItem>().Class(":selected").Template().OfType<ContentPresenter>().Name("PART_ContentPresenter"), (ContentPresenter.ForegroundProperty, "Ink"));
        S(x => x.OfType<TabItem>().Class(":selected").Class(":pointerover").Template().OfType<ContentPresenter>().Name("PART_ContentPresenter"), (ContentPresenter.ForegroundProperty, "Ink"));

        // Fields: clean underline inputs without enclosed rectangle boxes.
        S(x => x.OfType<TextBox>(), (TemplatedControl.CornerRadiusProperty, new CornerRadius(0)), (Layoutable.MinHeightProperty, Scale.ControlHeight),
            (TemplatedControl.PaddingProperty, new Thickness(2, 5)), (TemplatedControl.FontSizeProperty, Scale.Body),
            (TemplatedControl.BackgroundProperty, "Transparent"), (TemplatedControl.BorderThicknessProperty, new Thickness(0, 0, 0, 1)),
            (TemplatedControl.BorderBrushProperty, "LineStrong"));
        S(x => x.OfType<TextBox>().Class(":focus"), (TemplatedControl.BorderBrushProperty, "Accent"), (TemplatedControl.BorderThicknessProperty, new Thickness(0, 0, 0, 2)));
        S(x => x.OfType<ComboBox>(), (TemplatedControl.CornerRadiusProperty, new CornerRadius(0)), (Layoutable.MinHeightProperty, Scale.ControlHeight),
            (TemplatedControl.FontSizeProperty, Scale.Body), (TemplatedControl.BackgroundProperty, "Transparent"),
            (TemplatedControl.BorderThicknessProperty, new Thickness(0, 0, 0, 1)), (TemplatedControl.BorderBrushProperty, "LineStrong"));
        S(x => x.OfType<CheckBox>(), (TemplatedControl.FontSizeProperty, Scale.Body));
        S(x => x.OfType<Expander>(), (TemplatedControl.CornerRadiusProperty, new CornerRadius(Scale.CardRadius)), (TemplatedControl.FontSizeProperty, Scale.Body));
        S(x => x.OfType<ToolTip>(), (TemplatedControl.CornerRadiusProperty, new CornerRadius(Scale.ControlRadius)), (TemplatedControl.FontSizeProperty, Scale.Callout),
            (TemplatedControl.PaddingProperty, new Thickness(Scale.Small, Scale.Snug)));
        S(x => x.OfType<MenuFlyoutPresenter>(), (TemplatedControl.CornerRadiusProperty, new CornerRadius(Scale.ControlRadius + 2)));
        S(x => x.OfType<FlyoutPresenter>(), (TemplatedControl.CornerRadiusProperty, new CornerRadius(Scale.CardRadius)));
        S(x => x.OfType<MenuItem>(), (TemplatedControl.FontSizeProperty, Scale.Body), (Layoutable.MinHeightProperty, 26d));
        return styles;
    }
}
