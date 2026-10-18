using System.Runtime.InteropServices;
using System.Text.Json;
using Avalonia;
using Avalonia.Controls;
using Avalonia.Media;
using Avalonia.Threading;

namespace Suhang.Desktop;

public sealed partial class Dashboard
{
    [DllImport("user32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    static extern bool MessageBeep(uint type);
    Window? updateNoticeWindow;

    void ShowUpdateNotice(JsonElement d)
    {
        string S(string k) => d.TryGetProperty(k, out var v) && v.ValueKind == JsonValueKind.String ? v.GetString() ?? "" : "";
        var id = S("id"); var version = S("update_version"); var phase = S("phase");
        if (id.Length != 32 || version.Length > 40 || (phase != "received" && phase != "installing")) return;
        var installing = phase == "installing";
        var title = installing ? "即將開始升級" : "已收到 USB 升級";
        var text = installing ? "USB 連線將短暫中斷。程式會正常結束並安裝新版。" : "新版已通過發布者簽章與檔案完整性驗證。";
        updateNoticeWindow?.Close();
        var noticeWindow = AppWindow.Dialog("升級通知", 470, Column(10, Label(title, Scale.Page, FontWeight.SemiBold),
            Label("USB Link " + version, Scale.Section), Hint(text, "Muted", Scale.Body)), topmost: true);
        noticeWindow.ShowInTaskbar = true; noticeWindow.WindowStartupLocation = WindowStartupLocation.CenterScreen;
        updateNoticeWindow = noticeWindow;
        noticeWindow.Opened += (_, _) => Dispatcher.UIThread.Post(() => {
            SetNotice(title + " · " + version);
            // Acknowledge only after the native window opens and Windows accepts
            // the system sound request. Muted system audio remains user's choice.
            if (OperatingSystem.IsWindows() && MessageBeep(0x40)) {
                DesktopClient.SendRaw(JsonSerializer.Serialize(new { action = "update-notice-shown", id }));
                
            }
        }, DispatcherPriority.Background);
        noticeWindow.Show();
        var timer = new DispatcherTimer { Interval = TimeSpan.FromSeconds(8) };
        timer.Tick += (_, _) => { timer.Stop(); noticeWindow.Close(); };
        noticeWindow.Closed += (_, _) => { timer.Stop(); if (updateNoticeWindow == noticeWindow) updateNoticeWindow = null; };
        timer.Start();
    }
}
