using Avalonia.Controls;
using Avalonia.Media;

namespace Suhang.Desktop;

public sealed partial class Dashboard
{
    bool backendUnavailable;
    string verifiedBackendVersion = "";
    readonly TextBlock backendFailure = new() { FontSize = 13, TextWrapping = TextWrapping.Wrap };
    Control backendFailureBanner = null!;

    void MarkBackendUnavailable(string code)
    {
        if (code.Length is 0 or > 80 || code.Any(c => !(c is >= 'A' and <= 'Z' or >= '0' and <= '9' or '_')))
            code = "CORE_STATUS_UNAVAILABLE";
        var initializing = verifiedBackendVersion == "" && code is "CORE_INITIALIZING" or "CORE_MONITOR_INITIALIZING";
        if (!backendUnavailable)
        {
            foreach (var window in OwnedWindows.ToArray()) window.Close();
            bodyScroll.Offset = default;
        }
        backendUnavailable = true;
        backendFailure.Text = initializing
            ? $"後台正在啟動 · {code}\n後台尚未就緒，操作暫不可用；正在繼續讀取狀態。"
            : $"後台狀態讀取失敗 · {code}\n下方資料已過期，操作已暫停；正在重試讀取。後台連線狀態尚未確認。";
        backendFailure.Res(TextBlock.ForegroundProperty, initializing ? "Muted" : "Warn");
        backendFailureBanner.IsVisible = true;
        versionText.Text = verifiedBackendVersion == "" ? "版本尚未核對" : verifiedBackendVersion + "（上次核對）";
        chipText.Text = initializing ? "後台啟動中" : "狀態已過期";
        chip.Res(Border.BackgroundProperty, initializing ? "IdleSoft" : "WarnSoft");
        chipDot.Res(Border.BackgroundProperty, initializing ? "Idle" : "Warn");
        chipText.Res(TextBlock.ForegroundProperty, initializing ? "Muted" : "Warn");
        body.IsEnabled = false;
        bodyScroll.IsEnabled = footerControl.IsEnabled = true;
        SetNotice("");
    }
}
