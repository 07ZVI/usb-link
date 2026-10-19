using Avalonia.Controls;
using Avalonia.Threading;

namespace Suhang.Desktop;

public sealed partial class Dashboard
{
    // Design tools only (--maximized, --open=name): reproduce window placement for screenshots.
    void PreviewWindowArgs()
    {
#if USBLINK_DESIGN_TOOLS
        if (Program.MaximizedPreview) WindowState = WindowState.Maximized;
        Action? open = Program.OpenPreview switch
        {
            "security" => () => OpenSecurity(GatewayTab),
            "tasks" => () => OpenSecurity(TasksTab),
            "smb" => OpenSMBManager,
            "details" => OpenDetails,
            "dialog" => () => AppWindow.Confirm(this, "取消共享？", "資料夾與檔案會保留，之後可以再次添加。", "取消共享", () => { }, danger: true),
            _ => null,
        };
        if (open != null) Dispatcher.UIThread.Post(open, DispatcherPriority.Background);
#endif
    }
}
