using System.Text.Json;
using Avalonia;
using Avalonia.Controls;
using Avalonia.Controls.ApplicationLifetimes;
using Avalonia.Media.Imaging;
using Avalonia.VisualTree;
using Avalonia.Automation;

namespace Suhang.Desktop;

public sealed partial class Dashboard
{
    // Synthetic fixtures verify simultaneous state and window reuse without system actions.
    void RunConnectionSmoke()
    {
        try
        {
            var labels = this.GetVisualDescendants().OfType<TextBlock>().Select(t => t.Text).ToArray();
            if (!labels.Contains("Mac") || !labels.Contains("iPad") || !labels.Contains("Windows 主機地址") || !labels.Contains("10.6.9.2") || !labels.Contains("10.6.9.3") ||
                labels.Contains("USB 連線") || labels.Contains("重新連線") || labels.Contains("複製 IP") || labels.Contains("Moonlight 電腦地址") || labels.Contains("撤銷這台電腦的信任") ||
                labels.Contains("共享與帳戶") || labels.Contains("Windows SMB 修復") || labels.Contains("訪客連線"))
                throw new InvalidOperationException("combined dashboard controls");
            var reconnects = this.GetVisualDescendants().OfType<Button>().Where(b => AutomationProperties.GetName(b)?.StartsWith("重新連線 ") == true).ToArray();
            if (reconnects.Length != 2 || !reconnects.Any(b => AutomationProperties.GetName(b) == "重新連線 Mac") || !reconnects.Any(b => AutomationProperties.GetName(b) == "重新連線 iPad") || reconnects.Any(b => b.Content is TextBlock))
                throw new InvalidOperationException("device reconnect icons");
            var speedLink = this.GetVisualDescendants().OfType<Button>().Single(b => b.Content is TextBlock t && t.Text == "測速網址");
            if (ToolTip.GetTip(speedLink) is not string tip || !tip.Contains("http://10.6.9.1:58723/")) throw new InvalidOperationException("benchmark tooltip URL");
            if (!ExtendClientAreaToDecorationsHint || ExtendClientAreaChromeHints != Avalonia.Platform.ExtendClientAreaChromeHints.NoChrome || root.Margin.Top != 8 || captionMinimize == null || captionMaximize == null || captionClose == null)
                throw new InvalidOperationException("custom titlebar configuration and controls");
            ToggleWindowMaximized();
            if (WindowState != WindowState.Maximized || AutomationProperties.GetName(captionMaximize) != "還原視窗") throw new InvalidOperationException("maximize caption state");
            ToggleWindowMaximized();
            if (WindowState != WindowState.Normal || AutomationProperties.GetName(captionMaximize) != "最大化") throw new InvalidOperationException("restore caption state");
            using(var stopping=JsonDocument.Parse("""{"stopping":true}"""))Update(stopping.RootElement);
            if(!root.IsEnabled||!captionMinimize.IsEffectivelyEnabled||!captionMaximize.IsEffectivelyEnabled||!captionClose.IsEffectivelyEnabled||bodyScroll.IsEnabled||footerControl.IsEnabled)
                throw new InvalidOperationException("stopping must preserve custom window controls");
            SeedPreview();
            if(reconnects.Any(b=>b.IsEnabled))throw new InvalidOperationException("running device retry must be disabled");
            using(var retry=JsonDocument.Parse("""{"devices":[{"device":"Mac","retry_available":true},{"device":"iPad","retry_available":false}]}"""))Update(retry.RootElement);
            if(!reconnects.Single(b=>AutomationProperties.GetName(b)=="重新連線 Mac").IsEnabled||reconnects.Single(b=>AutomationProperties.GetName(b)=="重新連線 iPad").IsEnabled)
                throw new InvalidOperationException("retry availability must be independent per device");
            using(var legacy=JsonDocument.Parse("""{"device":"Mac","connected":true}"""))Update(legacy.RootElement);
            if(chipText.Text!="已連線 · 1 台裝置")throw new InvalidOperationException("legacy core connection summary");
            SeedPreview();
            UpdateLayout(); UpdateResponsiveLayout(); UpdateLayout();
            CaptureConnectionPreview(this, "dashboard");
            using(var states=JsonDocument.Parse("""{"devices":[{"device":"Mac","title":"正在連線","connection_state":"connecting","retry_available":true},{"device":"iPad","title":"連線異常","connection_state":"error","retry_available":true}]}"""))Update(states.RootElement);
            var identities=this.GetVisualDescendants().OfType<Border>().Where(b=>AutomationProperties.GetName(b)?.Contains(" · ")==true).ToArray();
            if(!identities.Any(b=>AutomationProperties.GetName(b)=="Mac · 正在連線")||!identities.Any(b=>AutomationProperties.GetName(b)=="iPad · 連線異常"))throw new InvalidOperationException("connection states need accessible device labels");
            if(identities.Single(b=>AutomationProperties.GetName(b)=="Mac · 正在連線").Background?.ToString()==identities.Single(b=>AutomationProperties.GetName(b)=="iPad · 連線異常").Background?.ToString())throw new InvalidOperationException("connection and error colors must differ");
            if(chipText.Text!="正在連線 · 1 台裝置")throw new InvalidOperationException("host transport alone must not claim a connected peer");
            CaptureConnectionPreview(this,"connecting-error");
            SeedPreview();

            for (var attempt = 0; attempt < 3; attempt++)
            {
                OpenDetails();
                if (detailRows.GetVisualRoot() != detailWindow)
                    throw new InvalidOperationException("diagnostic controls must share the current window");
                if (attempt == 0) CaptureConnectionPreview(detailWindow!, "diagnostics");
                var originalRows = detailRows.Children.ToArray();
                RenderDetails();
                if (!originalRows.SequenceEqual(detailRows.Children)) throw new InvalidOperationException("unchanged diagnostic rows recreated");
                var originalText = detailText;
                detailText = detailText.Replace("已驗證 IPv4 往返", "診斷值已更新");
                RenderDetails();
                if (!originalRows.SequenceEqual(detailRows.Children) || !detailRows.GetVisualDescendants().OfType<TextBlock>().Any(t => t.Text!.Contains("診斷值已更新")))
                    throw new InvalidOperationException("diagnostic value update must preserve row identity");
                detailText = originalText; RenderDetails();
                detailWindow!.Close();
                if (detailWindow != null || detailRows.Parent != null)
                    throw new InvalidOperationException("diagnostics close must release reusable controls");
            }
            SeedPreview();
            OpenSMBManager();
            using(var account = JsonDocument.Parse("""{"account":{"exists":true,"local_name":"USBLink","username":"EXAMPLE\\USBLink"},"guest":false}""")) UpdateSMBAccount(account.RootElement);
            using(var folders = JsonDocument.Parse("""{"folders":[{"id":"aaaaaaaaaaaaaaaaaaaaaaaa","name":"Media","share_name":"USB-Media","path":"D:\\Media","smb_url":"smb://10.6.9.1/USB-Media","available":true,"native_shared":true,"account_access":"modify","guest_access":"none","guest_enabled":false}]}""")) UpdateShareFolders(folders.RootElement);
            smbAccountWindow!.Height = 1160;
            CaptureConnectionPreview(smbAccountWindow!, "smb");
            smbAccountWindow!.Close();
            using var detached = JsonDocument.Parse("""
            {"devices":[{"device":"Mac","title":"Mac USB 已連接","connected":true,"peer_ipv4":"10.6.9.2","tx":800,"rx":8,"benchmark_available":true},{"device":"iPad","title":"等候 USB 接線","connected":false,"tx":0,"rx":0}]}
            """);
            Update(detached.RootElement);
            labels = this.GetVisualDescendants().OfType<TextBlock>().Select(t => t.Text).ToArray();
            if (!labels.Contains("Mac USB 已連接") || !labels.Contains("等候 USB 接線") || chipText.Text != "已連線 · 1 台裝置")
                throw new InvalidOperationException("one device detach must preserve the other slot");
            CaptureConnectionPreview(this, "one-device");
            Width = 720; Height = 500; UpdateLayout(); UpdateResponsiveLayout(); UpdateLayout();
            if (compactLayout != true || this.GetVisualDescendants().OfType<LayoutTransformControl>().Any() || addressValue.FontSize != 34 || bodyScroll.Extent.Height <= bodyScroll.Viewport.Height)
                throw new InvalidOperationException("compact layout must scroll without reducing Windows DPI text size");
            CaptureConnectionPreview(this, "compact");
            Width = 520; Height = 420; UpdateLayout(); UpdateResponsiveLayout(); UpdateLayout();
            CaptureConnectionPreview(this, "small");
            bodyScroll.Offset = new Vector(0, bodyScroll.Extent.Height); UpdateLayout();
            CaptureConnectionPreview(this, "small-bottom");
            Console.Error.WriteLine("CONNECTION_SMOKE_PASS");
            (Application.Current?.ApplicationLifetime as IClassicDesktopStyleApplicationLifetime)?.Shutdown(0);
        }
        catch (Exception error)
        {
            Console.Error.WriteLine("CONNECTION_SMOKE_FAIL: " + error);
            (Application.Current?.ApplicationLifetime as IClassicDesktopStyleApplicationLifetime)?.Shutdown(1);
        }
    }

    static void CaptureConnectionPreview(Window window, string name)
    {
        window.UpdateLayout();
        using var bitmap = new RenderTargetBitmap(new PixelSize((int)window.Bounds.Width, (int)window.Bounds.Height), new Vector(96, 96));
        bitmap.Render(window);
        bitmap.Save(System.IO.Path.Combine("/private/tmp", "usb-link-unified-" + name + ".png"));
    }
}
