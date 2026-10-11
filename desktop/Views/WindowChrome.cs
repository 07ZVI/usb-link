using Avalonia;
using Avalonia.Automation;
using Avalonia.Controls;
using Avalonia.Controls.Presenters;
using Avalonia.Controls.Shapes;
using Avalonia.Controls.Templates;
using Avalonia.Data;
using Avalonia.Input;
using Avalonia.Layout;
using Avalonia.Media;
using Avalonia.Platform;

namespace Suhang.Desktop;

public sealed partial class Dashboard
{
    Button? captionMinimize, captionMaximize, captionClose;
    bool UsesCustomTitleBar => OperatingSystem.IsWindows() || preview;

    void ConfigureWindowChrome()
    {
        if (!UsesCustomTitleBar) return;
        // Extend the client area while retaining the system resizing border.
        ExtendClientAreaToDecorationsHint = true;
        ExtendClientAreaChromeHints = ExtendClientAreaChromeHints.NoChrome;
        ExtendClientAreaTitleBarHeightHint = 44;
    }

    Control WithWindowChrome(Control heading)
    {
        if (!UsesCustomTitleBar) return heading;
        var drag = new Border { Background = Brushes.Transparent, Child = heading, MinHeight = 32 };
        drag.PointerPressed += (_, e) => {
            if (!e.GetCurrentPoint(drag).Properties.IsLeftButtonPressed) return;
            if (e.ClickCount == 2) ToggleWindowMaximized();
            else BeginMoveDrag(e);
            e.Handled = true;
        };

        Button Caption(string icon, string name, Action click, bool close = false)
        {
            var button = new Button {
                Width = 46, Height = 40, Padding = new Thickness(0), CornerRadius = new CornerRadius(0), BorderThickness = new Thickness(0),
                Background = Brushes.Transparent, Content = CaptionGlyph(icon), RenderTransform = new ScaleTransform(1,1),
                HorizontalContentAlignment = HorizontalAlignment.Center, VerticalContentAlignment = VerticalAlignment.Center,
            };
            // Caption controls use rectangular hover targets without the main
            // action buttons' border, rounded corners or press animation.
            button.Template = new FuncControlTemplate<Button>((host, _) => {
                var presenter = new ContentPresenter { Name = "CaptionPresenter", HorizontalContentAlignment = HorizontalAlignment.Center, VerticalContentAlignment = VerticalAlignment.Center };
                presenter.Bind(ContentPresenter.ContentProperty, new Binding(nameof(Button.Content)) { Source = host });
                presenter.Bind(ContentPresenter.BackgroundProperty, new Binding(nameof(Button.Background)) { Source = host });
                return presenter;
            });
            ToolTip.SetTip(button,name); AutomationProperties.SetName(button,name);
            button.Click += (_,_)=>click();
            button.PropertyChanged += (_,e)=> {
                if(e.Property==IsPointerOverProperty || e.Property==Button.IsPressedProperty) UpdateCaptionAppearance(button,close);
            };
            return button;
        }
        captionMinimize = Caption("M3 8h10", "最小化", () => WindowState = WindowState.Minimized);
        captionMaximize = Caption("M3 3h10v10H3z", "最大化", ToggleWindowMaximized);
        captionClose = Caption("M3 3l10 10 M13 3L3 13", "關閉視窗", Close, close:true);
        PropertyChanged += (_, e) => { if (e.Property == WindowStateProperty) UpdateWindowCaption(); };
        UpdateWindowCaption();
        var captions=Row(0, captionMinimize, captionMaximize, captionClose);
        // Align to the physical client edge while the brand keeps its inset.
        captions.Margin=new Thickness(0,-8,-24,0);
        return Columns("*,8,Auto", drag, Gap(), captions);
    }

    static Control CaptionGlyph(string data)
    {
        var canvas=new Canvas{Width=16,Height=16};
        canvas.Children.Add(new Avalonia.Controls.Shapes.Path { Data=Icons.SharedGeometry(data), StrokeThickness=1, StrokeLineCap=PenLineCap.Square, StrokeJoin=PenLineJoin.Miter }.Res(Shape.StrokeProperty,"Ink"));
        return canvas;
    }

    static void UpdateCaptionAppearance(Button button,bool close)
    {
        var hover=button.IsPointerOver;var pressed=button.IsPressed;
        if(close&&(hover||pressed))button.Background=Brush.Parse(pressed?"#A12316":"#C42B1C");
        else if(hover||pressed)button.Res(Button.BackgroundProperty,pressed?"Stroke":"IdleSoft");
        else button.Background=Brushes.Transparent;
        if(button.Content is Canvas glyph && glyph.Children[0] is Avalonia.Controls.Shapes.Path path) {
            if(close&&(hover||pressed))path.Stroke=Brushes.White;
            else path.Res(Shape.StrokeProperty,"Ink");
        }
    }

    void ToggleWindowMaximized() => WindowState = WindowState == WindowState.Maximized ? WindowState.Normal : WindowState.Maximized;

    void UpdateWindowCaption()
    {
        if (captionMaximize == null) return;
        var maximized = WindowState == WindowState.Maximized;
        captionMaximize.Content = CaptionGlyph(maximized ? "M5 2h9v9 M2 5h9v9H2z" : "M3 3h10v10H3z");
        UpdateCaptionAppearance(captionMaximize,false);
        var text = maximized ? "還原視窗" : "最大化";
        ToolTip.SetTip(captionMaximize, text);
        AutomationProperties.SetName(captionMaximize, text);
    }
}
