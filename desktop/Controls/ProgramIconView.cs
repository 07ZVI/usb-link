using Avalonia;
using Avalonia.Controls;
using Avalonia.Media;
using Avalonia.Media.Imaging;
using Avalonia.Layout;
using Avalonia.Threading;

namespace Suhang.Desktop;

/// A program's icon at 16 DIPs. It shows the generic program icon at once and swaps in the shell icon when the
/// background lookup (see ProgramIcons) finds one, so building a row never waits for the shell.
internal sealed class ProgramIconView : Border
{
    readonly Control generic = Icons.Make(Icons.Executable, 16, "Subtle", 1.5);
    public const double Size = 18;

    public ProgramIconView(string path)
    {
        Width = Height = Size; VerticalAlignment = VerticalAlignment.Center;
        Child = generic;
        if (path.Length == 0) return;
        if (ProgramIcons.TryGet(path, out var cached)) Show(cached);
        else ProgramIcons.Request(path, Show);
    }

    /// True while the generic icon is shown (no shell icon was found or it has not arrived yet).
    public bool IsGeneric => ReferenceEquals(Child, generic);

    void Show(Bitmap? icon)
    {
        if (icon == null) return;
        var image = new Image { Source = icon, Width = 16, Height = 16, Stretch = Stretch.Uniform, HorizontalAlignment = HorizontalAlignment.Center, VerticalAlignment = VerticalAlignment.Center };
        RenderOptions.SetBitmapInterpolationMode(image, BitmapInterpolationMode.HighQuality);
        Child = image;
    }
}
