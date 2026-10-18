using Avalonia;
using Avalonia.Controls;
using Avalonia.Media;

namespace Suhang.Desktop;

public sealed partial class Dashboard
{
    sealed class DiagnosticLineView
    {
        readonly int kind;
        readonly TextBlock? key, value;
        string current;
        public Control View { get; }
        static int Kind(string line) => line == "" ? 0 : line == "尚無診斷資料；連接裝置後會自動更新。" ? 3 : line.IndexOf('：') is > 0 and <= 12 ? 1 : 2;

        public DiagnosticLineView(string line)
        {
            kind = Kind(line); current = "";
            if (kind == 0) View = Gap(10);
            else if (kind == 1)
            {
                key = Label("", Scale.Secondary, key: "Muted");
                value = Label("", Scale.Body);
                value.TextWrapping = TextWrapping.Wrap; value.TextTrimming = TextTrimming.None;
                View = Columns("150,*", key, value);
            }
            else
            {
                value = Label("", kind == 3 ? Scale.Body : Scale.Secondary, key: kind == 3 ? "Muted" : "Subtle");
                value.TextWrapping = TextWrapping.Wrap; value.TextTrimming = TextTrimming.None;
                View = value;
            }
            if (kind != 0) View.Margin = kind == 3 ? new Thickness(16) : new Thickness(16, 6);
            View.Tag = this;
            Update(line);
        }

        public bool Update(string line)
        {
            if (Kind(line) != kind) return false;
            if (line == current) return true;
            current = line;
            if (kind == 1)
            {
                var split = line.IndexOf('：');
                key!.Text = line[..split]; value!.Text = line[(split + 1)..];
            }
            else if (value != null) value.Text = line;
            return true;
        }
    }
}
