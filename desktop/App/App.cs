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

public sealed class App : Application
{
    public override void Initialize()
    {
        LaunchTelemetry.Mark("renderer-app-initialize");
        // Follow the Windows light/dark setting; every brush below is a theme resource.
        RequestedThemeVariant = Program.DarkPreview ? ThemeVariant.Dark : ThemeVariant.Default;
        Styles.Add(new FluentTheme());
        Palette.Install(Resources);
        LaunchTelemetry.Mark("renderer-theme-ready");
    }
    public override void OnFrameworkInitializationCompleted()
    {
        if (ApplicationLifetime is IClassicDesktopStyleApplicationLifetime desktop)
        {
            desktop.ShutdownMode = ShutdownMode.OnMainWindowClose;
            LaunchTelemetry.Mark("renderer-dashboard-create");
            desktop.MainWindow = new Dashboard();
            LaunchTelemetry.Mark("renderer-dashboard-ready");
        }
        base.OnFrameworkInitializationCompleted();
    }
}

/// Design tokens. Light/dark values follow the Windows 11 palette; the accent is
/// the blue of the Suhang icon, with cyan for the second traffic direction.
