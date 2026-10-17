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
            var macSpeed = this.GetVisualDescendants().OfType<Button>().Single(b => AutomationProperties.GetName(b) == "瀏覽器測速 Mac");
            if(!macSpeed.IsEnabled || ToolTip.GetTip(macSpeed) is not string macTip || !macTip.Contains("http://10.6.9.1:10690/speed/") || !labels.Contains("http://10.6.9.1:10690/speed/"))throw new InvalidOperationException("Mac browser measurement URL must be visible and enabled without a native peer");
            var speedLink = this.GetVisualDescendants().OfType<Button>().Single(b => b.Content is TextBlock t && t.Text == "測速網址");
            if (ToolTip.GetTip(speedLink) is not string tip || !tip.Contains("http://10.6.9.1:58723/speed/")) throw new InvalidOperationException("benchmark tooltip URL");
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
            using (var missing = JsonDocument.Parse("""{"devices":[{"device":"Mac","connected":true,"peer_ipv4":"10.6.9.2"}]}""")) Update(missing.RootElement);
            var ipadLabels = ipadStatus.View.GetVisualDescendants().OfType<TextBlock>().Select(t => t.Text).ToArray();
            if (!ipadLabels.Contains("裝置地址 · 尚未分配") || !ipadLabels.Contains("↑ —    ↓ —  MB/s") || ipadLabels.Contains("10.6.9.3") ||
                ipadStatus.View.GetVisualDescendants().OfType<Sparkline>().Single().Peak != 0 ||
                reconnects.Single(b => AutomationProperties.GetName(b) == "重新連線 iPad").IsEnabled ||
                ipadStatus.View.GetVisualDescendants().OfType<SelectableTextBlock>().Any(t => t.IsVisible))
                throw new InvalidOperationException("missing device must clear its address, traffic history, retry and benchmark URL");
            using(var noBrowser=JsonDocument.Parse("""{"devices":[{"device":"Mac","connected":true,"benchmark_available":true}]}"""))Update(noBrowser.RootElement);
            if(macSpeed.IsEnabled)throw new InvalidOperationException("USB connection alone must not enable browser measurement without a URL");
            using(var browserBusy=JsonDocument.Parse("""{"devices":[{"device":"Mac","connected":true,"benchmark_url":"http://10.6.9.1:10690/speed/","measurement_busy":true,"measurement_progress":50}]}"""))Update(browserBusy.RootElement);
            if(!macSpeed.IsEnabled || AutomationProperties.GetName(macSpeed)!="取消測速 Mac")throw new InvalidOperationException("running browser measurement needs cancellation");
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

            var retainedAddress = addressValue.Text;
            var retainedPeak = ipadStatus.View.GetVisualDescendants().OfType<Sparkline>().Single().Peak;
            OpenDetails();
            void CheckInitialStartup(string code)
            {
                using var startup = JsonDocument.Parse(JsonSerializer.Serialize(new { @event = "backend-unavailable", code, version = "unverified" }));
                Update(startup.RootElement);
                if (!backendUnavailable || !backendFailureBanner.IsVisible || !backendFailure.Text!.Contains("後台正在啟動") ||
                    !backendFailure.Text.Contains(code) || backendFailure.Text.Contains("讀取失敗") || backendFailure.Text.Contains("已過期") ||
                    verifiedBackendVersion != "" || versionText.Text != "版本尚未核對" || chipText.Text != "後台啟動中" ||
                    body.IsEnabled || !bodyScroll.IsEnabled || !footerControl.IsEnabled || !captionClose!.IsEffectivelyEnabled ||
                    detailWindow != null || addressValue.Text != retainedAddress ||
                    ipadStatus.View.GetVisualDescendants().OfType<Sparkline>().Single().Peak != retainedPeak)
                    throw new InvalidOperationException("initial startup must stay unverified and disable actions with a neutral pending message");
            }
            CheckInitialStartup("CORE_INITIALIZING");
            CaptureConnectionPreview(this, "backend-initializing");
            using (var unavailable = JsonDocument.Parse("""{"event":"backend-unavailable","code":"CORE_DESKTOP_STATUS_TOO_LARGE","version":"unverified","devices":[]}""")) Update(unavailable.RootElement);
            if (!backendUnavailable || !backendFailureBanner.IsVisible || !backendFailure.Text!.Contains("CORE_DESKTOP_STATUS_TOO_LARGE") ||
                versionText.Text != "版本尚未核對" || chipText.Text != "狀態已過期" || body.IsEnabled || !bodyScroll.IsEnabled || !footerControl.IsEnabled ||
                !captionClose!.IsEffectivelyEnabled || detailWindow != null || addressValue.Text != retainedAddress ||
                ipadStatus.View.GetVisualDescendants().OfType<Sparkline>().Single().Peak != retainedPeak ||
                !ipadStatus.View.GetVisualDescendants().OfType<TextBlock>().Any(t => t.Text == "10.6.9.3"))
                throw new InvalidOperationException("backend failure must preserve stale data, disclose failure and keep exit usable");
            using (var partial = JsonDocument.Parse("""{"event":"status","devices":[]}""")) Update(partial.RootElement);
            if (!backendUnavailable || body.IsEnabled) throw new InvalidOperationException("unverified partial status must not clear backend failure");
            CaptureConnectionPreview(this, "backend-unavailable");
            CheckInitialStartup("CORE_MONITOR_INITIALIZING");
            using (var restored = JsonDocument.Parse("""{"event":"status","version":"test-version"}""")) Update(restored.RootElement);
            if (backendUnavailable || backendFailureBanner.IsVisible || !body.IsEnabled || !footerControl.IsEnabled || versionText.Text != "test-version")
                throw new InvalidOperationException("verified backend status must restore normal controls");
            foreach (var code in new[] { "CORE_INITIALIZING", "CORE_MONITOR_INITIALIZING" })
            {
                using var startup = JsonDocument.Parse(JsonSerializer.Serialize(new { @event = "backend-unavailable", code }));
                Update(startup.RootElement);
                if (!backendUnavailable || !backendFailureBanner.IsVisible || !backendFailure.Text!.Contains("後台狀態讀取失敗") ||
                    !backendFailure.Text.Contains(code) || chipText.Text != "狀態已過期" || body.IsEnabled ||
                    versionText.Text != "test-version（上次核對）" || verifiedBackendVersion != "test-version")
                    throw new InvalidOperationException("startup after a verified status must remain a connection failure");
            }
            using (var restored = JsonDocument.Parse("""{"event":"status","version":"test-version"}""")) Update(restored.RootElement);
            SeedPreview();
            using (var unavailable = JsonDocument.Parse("""{"event":"backend-unavailable","code":"arbitrary text"}""")) Update(unavailable.RootElement);
            if (versionText.Text != "test-version（上次核對）" || !backendFailure.Text!.Contains("CORE_STATUS_UNAVAILABLE") || backendFailure.Text.Contains("arbitrary text"))
                throw new InvalidOperationException("failure must label last verified version and constrain the displayed code");
            using (var restored = JsonDocument.Parse("""{"event":"status","version":"test-version"}""")) Update(restored.RootElement);
            SeedPreview();

            for (var attempt = 0; attempt < 3; attempt++)
            {
                OpenDetails();
                if (detailRows.GetVisualRoot() != detailWindow)
                    throw new InvalidOperationException("diagnostic controls must share the current window");
#if USBLINK_LOCAL_DIAGNOSTICS
                var localToggle = detailWindow!.GetVisualDescendants().OfType<ToggleSwitch>().Single(t => AutomationProperties.GetName(t) == "開發者調試");
                localToggle.IsChecked = true;
                localToggle.RaiseEvent(new Avalonia.Interactivity.RoutedEventArgs(Button.ClickEvent));
                if (!localDiagnosticsEnabled || localDiagnosticsRefresh == null ||
                    !detailWindow!.GetVisualDescendants().OfType<TextBox>().Any(t => AutomationProperties.GetName(t) == "完整診斷文字" && t.Text == detailText && t.IsEffectivelyVisible))
                    throw new InvalidOperationException("local diagnostics must show the current text when enabled");
                if (detailWindow!.GetVisualDescendants().OfType<Button>().Any(b => AutomationProperties.GetName(b) is "開啟本次 USB 推送安裝" or "關閉 USB 推送安裝"))
                    throw new InvalidOperationException("developer debug must have one master switch and no separate USB push buttons");
                using (var backendOff = JsonDocument.Parse("""{"developer_debug":{"available":true,"enabled":false,"busy":false}}""")) UpdateLocalDiagnostics(backendOff.RootElement);
                if (localDiagnosticsEnabled || localToggle.IsChecked == true) throw new InvalidOperationException("master switch must use confirmed backend state");
                localDiagnosticsPendingID = new string('a', 32); localDiagnosticsRequested = true;
                using (var stale = JsonDocument.Parse("""{"developer_debug":{"available":true,"enabled":false,"busy":false,"request_id":"old"}}""")) UpdateLocalDiagnostics(stale.RootElement);
                if (localDiagnosticsPendingID == "" || localToggle.IsChecked != true) throw new InvalidOperationException("stale status must not finish a pending debug request");
                using (var failed = JsonDocument.Parse("""{"developer_debug":{"available":true,"enabled":false,"busy":false,"request_id":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","error":"USB_LOCAL_PUSH_TEST_FAILURE"}}""")) UpdateLocalDiagnostics(failed.RootElement);
                if (localDiagnosticsPendingID != "" || localDiagnosticsEnabled || localToggle.IsChecked == true || !localToggle.IsEnabled || !localDiagnosticsMessage.Contains("USB_LOCAL_PUSH_TEST_FAILURE"))
                    throw new InvalidOperationException("failed debug enable must revert switch and disclose failure");
                using (var backendOn = JsonDocument.Parse("""{"developer_debug":{"available":true,"enabled":true,"busy":false}}""")) UpdateLocalDiagnostics(backendOn.RootElement);
                if (!localDiagnosticsEnabled || localToggle.IsChecked != true) throw new InvalidOperationException("reopened debug view must show background owner state");
                using (var preparing = JsonDocument.Parse("""{"developer_debug":{"available":true,"enabled":true,"busy":true,"persistence":"saved","saved_enabled":true,"usb_phase":"preparing","usb_ready":false}}""")) UpdateLocalDiagnostics(preparing.RootElement);
                if (!localDiagnosticsEnabled || !localToggle.IsEnabled || !localDiagnosticsMessage.Contains("準備中") || !detailWindow!.GetVisualDescendants().OfType<TextBox>().Any(t => AutomationProperties.GetName(t) == "完整診斷文字" && t.IsEffectivelyVisible))
                    throw new InvalidOperationException("USB preparation must not block diagnostics or closing debug");
                using (var usbFailed = JsonDocument.Parse("""{"developer_debug":{"available":true,"enabled":true,"busy":false,"persistence":"saved","usb_phase":"failed","usb_ready":false,"error":"USB_LOCAL_PUSH_TEST_FAILURE"}}""")) UpdateLocalDiagnostics(usbFailed.RootElement);
                if (!localDiagnosticsEnabled || localToggle.IsChecked != true || !localDiagnosticsMessage.Contains("未就緒"))
                    throw new InvalidOperationException("USB failure must preserve diagnostics and disclose transport failure");
                using (var revoking = JsonDocument.Parse("""{"developer_debug":{"available":true,"enabled":false,"busy":true,"persistence":"saved","usb_phase":"revoking","usb_ready":false}}""")) UpdateLocalDiagnostics(revoking.RootElement);
                if (localDiagnosticsEnabled || !localDiagnosticsMessage.Contains("正在完成"))
                    throw new InvalidOperationException("closing cannot claim cleanup complete while revoking");
                using (var savedOn = JsonDocument.Parse("""{"developer_debug":{"available":true,"enabled":true,"busy":false,"persistence":"saved","saved_enabled":true,"usb_phase":"ready","usb_ready":true}}""")) UpdateLocalDiagnostics(savedOn.RootElement);
                if (!localDiagnosticsEnabled || !localDiagnosticsMessage.Contains("設定已保存")) throw new InvalidOperationException("saved ready state must be explicit");
                var photoToggle = detailWindow!.GetVisualDescendants().OfType<ToggleSwitch>().Single(t => AutomationProperties.GetName(t) == "照片介面隔離");
                using (var photoOff = JsonDocument.Parse("""{"photo_isolation":{"available":true,"requested":false,"effective":false,"busy":false,"persistence":"saved","saved_enabled":false,"phase":"off"}}""")) UpdateLocalDiagnostics(photoOff.RootElement);
                if (photoToggle.IsChecked == true || !photoToggle.IsEnabled) throw new InvalidOperationException("photo toggle must use confirmed preference state");
                photoIsolationPendingID = new string('b', 32); photoIsolationPendingEnabled = true;
                using (var stalePhoto = JsonDocument.Parse("""{"photo_isolation":{"available":true,"requested":false,"request_id":"old","persistence":"saved"}}""")) UpdateLocalDiagnostics(stalePhoto.RootElement);
                if (photoIsolationPendingID == "" || photoToggle.IsChecked != true) throw new InvalidOperationException("old photo response must not finish current request");
                using (var photoFailed = JsonDocument.Parse("""{"photo_isolation":{"available":true,"requested":false,"effective":false,"busy":false,"request_id":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","persistence":"failed","error":"PHOTO_SAVE_FAILED"}}""")) UpdateLocalDiagnostics(photoFailed.RootElement);
                if (photoIsolationPendingID != "" || photoToggle.IsChecked == true || !photoIsolationMessage.Contains("PHOTO_SAVE_FAILED")) throw new InvalidOperationException("failed photo preference must not claim enabled");
                photoIsolationPendingID = new string('c', 32); photoIsolationPendingEnabled = true;
                using (var photoRejected = JsonDocument.Parse("""{"photo_isolation":{"available":true,"requested":false,"effective":false,"busy":false,"request_id":"old","rejected_id":"cccccccccccccccccccccccccccccccc","rejected_error":"PHOTO_DEBUG_REQUIRED","persistence":"saved","saved_enabled":false,"phase":"off"}}""")) UpdateLocalDiagnostics(photoRejected.RootElement);
                if (photoIsolationPendingID != "" || photoToggle.IsChecked == true || !photoToggle.IsEnabled || !photoIsolationMessage.Contains("PHOTO_DEBUG_REQUIRED")) throw new InvalidOperationException("rejected photo request must release the pending toggle without claiming enablement");
                // The action pipe can fail independently while normal snapshots keep arriving.
                localDiagnosticsPendingID = new string('d', 32); localDiagnosticsRequested = false;
                photoIsolationPendingID = new string('e', 32); photoIsolationPendingEnabled = true;
                const string unchangedControls = """{"event":"status","version":"test-version","developer_debug":{"available":true,"enabled":true,"busy":false,"request_id":"old","persistence":"saved"},"photo_isolation":{"available":true,"requested":false,"effective":false,"busy":false,"request_id":"old","persistence":"saved"}}""";
                using (var unchanged = JsonDocument.Parse(unchangedControls)) Update(unchanged.RootElement);
                using (var staleFailure = JsonDocument.Parse("""{"event":"local-control-result","action":"photo-isolation-on","request_id":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","code":"CORE_UI_ACTION_FAILED"}""")) Update(staleFailure.RootElement);
                if (localDiagnosticsPendingID == "" || photoIsolationPendingID == "" || photoToggle.IsEnabled) throw new InvalidOperationException("unrelated snapshots or failure IDs must not acknowledge current requests");
                var chipBeforeFailure = chipText.Text;
                using (var masterDeliveryFailed = JsonDocument.Parse("""{"event":"local-control-result","action":"local-usb-update-off","request_id":"dddddddddddddddddddddddddddddddd","code":"CORE_UI_ACTION_FAILED"}""")) Update(masterDeliveryFailed.RootElement);
                using (var photoDeliveryFailed = JsonDocument.Parse("""{"event":"local-control-result","action":"photo-isolation-on","request_id":"eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee","code":"CORE_UI_ACTION_FAILED"}""")) Update(photoDeliveryFailed.RootElement);
                if (localDiagnosticsPendingID != "" || photoIsolationPendingID != "" || localToggle.IsChecked != true || photoToggle.IsChecked == true || !photoToggle.IsEnabled || !localToggle.IsEnabled || chipText.Text != chipBeforeFailure)
                    throw new InvalidOperationException("action failures must release waits, retain verified state, and preserve connection display");
                using (var unchanged = JsonDocument.Parse(unchangedControls)) Update(unchanged.RootElement);
                if (localDiagnosticsPendingID != "" || photoIsolationPendingID != "" || localToggle.IsChecked != true || photoToggle.IsChecked == true || !photoToggle.IsEnabled ||
                    detailWindow!.GetVisualDescendants().OfType<TextBlock>().Count(t => t.Text?.Contains(LocalControlDeliveryFailure) == true && t.IsEffectivelyVisible) != 2)
                    throw new InvalidOperationException("normal snapshots must preserve delivery uncertainty without trapping either toggle");
                localDiagnosticsPendingID = new string('f', 32); localDiagnosticsRequested = false;
                photoIsolationPendingID = new string('f', 32); photoIsolationPendingEnabled = true;
                using (var lateMasterFailure = JsonDocument.Parse("""{"event":"local-control-result","action":"local-usb-update-off","request_id":"dddddddddddddddddddddddddddddddd","code":"CORE_UI_ACTION_FAILED"}""")) Update(lateMasterFailure.RootElement);
                using (var latePhotoFailure = JsonDocument.Parse("""{"event":"local-control-result","action":"photo-isolation-on","request_id":"eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee","code":"CORE_UI_ACTION_FAILED"}""")) Update(latePhotoFailure.RootElement);
                if (localDiagnosticsPendingID != new string('f', 32) || photoIsolationPendingID != new string('f', 32)) throw new InvalidOperationException("old delivery failures must not cancel retries");
                localDiagnosticsPendingID = photoIsolationPendingID = "";
                using (var lateSuccess = JsonDocument.Parse("""{"event":"status","version":"test-version","developer_debug":{"available":true,"enabled":false,"busy":false,"request_id":"dddddddddddddddddddddddddddddddd","persistence":"saved"},"photo_isolation":{"available":true,"requested":true,"effective":false,"busy":false,"request_id":"eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee","persistence":"saved"}}""")) Update(lateSuccess.RootElement);
                if (localDiagnosticsEnabled || !photoIsolationRequested || localDiagnosticsDeliveryFailureID != "" || photoIsolationDeliveryFailureID != "") throw new InvalidOperationException("late authoritative completion must replace uncertain delivery outcome");
                SeedPreview();
                using (var photoInactive = JsonDocument.Parse("""{"developer_debug":{"available":true,"enabled":false,"busy":false},"photo_isolation":{"available":true,"requested":true,"effective":false,"busy":false,"persistence":"saved","saved_enabled":true}}""")) UpdateLocalDiagnostics(photoInactive.RootElement);
                if (photoToggle.IsEnabled || photoToggle.IsChecked != true || photoIsolationEffective || !photoIsolationMessage.Contains("目前未生效")) throw new InvalidOperationException("saved photo intent must stay inactive while debug master is off");
                using (var photoRecoveryFailed = JsonDocument.Parse("""{"photo_isolation":{"available":true,"requested":true,"effective":false,"busy":false,"phase":"recovery_pending","persistence":"saved","saved_enabled":true,"error":"PHOTO_RECOVERY_PENDING"}}""")) UpdateLocalDiagnostics(photoRecoveryFailed.RootElement);
                if (!detailWindow!.GetVisualDescendants().OfType<TextBlock>().Any(t => AutomationProperties.GetName(t) == "照片介面恢復狀態" && t.IsEffectivelyVisible && t.Text!.Contains("PHOTO_RECOVERY_PENDING"))) throw new InvalidOperationException("photo recovery failure must remain visible after master closes tools");
                using (var photoRestoring = JsonDocument.Parse("""{"developer_debug":{"available":true,"enabled":true,"busy":false},"photo_isolation":{"available":true,"requested":false,"effective":false,"busy":true,"phase":"recovering","persistence":"saved","saved_enabled":false}}""")) UpdateLocalDiagnostics(photoRestoring.RootElement);
                if (photoToggle.IsChecked == true || !photoIsolationMessage.Contains("尚未確認完成")) throw new InvalidOperationException("photo off must disclose restoration still pending");
                using (var photoWaiting = JsonDocument.Parse("""{"photo_isolation":{"available":true,"requested":true,"effective":false,"busy":false,"phase":"waiting_photo_interface","persistence":"saved","saved_enabled":true,"owned_nodes":0,"observed_nodes":0}}""")) UpdateLocalDiagnostics(photoWaiting.RootElement);
                if (photoIsolationEffective || !photoIsolationMessage.Contains("目前尚未確認隔離")) throw new InvalidOperationException("zero photo nodes must not claim isolation");
                using (var photoActive = JsonDocument.Parse("""{"photo_isolation":{"available":true,"requested":true,"effective":true,"busy":false,"phase":"active","persistence":"saved","saved_enabled":true,"owned_nodes":1,"observed_nodes":1}}""")) UpdateLocalDiagnostics(photoActive.RootElement);
                if (photoToggle.IsChecked != true || !photoIsolationEffective || !photoIsolationMessage.Contains("1 個由本程式接管恢復")) throw new InvalidOperationException("photo activation must reflect confirmed native status");
                using (var timing = JsonDocument.Parse("""{"connection_timing":{"available":true,"mode":"fast","phase":"active","persistence":"saved"}}""")) UpdateConnectionTiming(timing.RootElement);
                localDiagnosticsRefresh?.Invoke();
                if (!connectionTimingAvailable || !connectionTimingMessage.Contains("持續使用") || connectionTimingMode != "fast") throw new InvalidOperationException("timing switch must remain active until disabled");
                using (var delayedState = JsonDocument.Parse("""{"connection_timing":{"available":true,"mode":"delayed","phase":"active","persistence":"saved"}}""")) UpdateConnectionTiming(delayedState.RootElement);
                localDiagnosticsRefresh?.Invoke();
                if (connectionTimingMode != "delayed" || !connectionTimingMessage.Contains("設定已保存")) throw new InvalidOperationException("persistent delay switch state missing");
                var markers = detailWindow!.GetVisualDescendants().OfType<Button>().Where(b => AutomationProperties.GetName(b)?.StartsWith("標記第 ") == true).ToArray();
                if (markers.Length != 2 || markers.Any(b => !b.IsEffectivelyVisible))
                    throw new InvalidOperationException("two manual trust markers must be available in local diagnostics");
                var originalOutput = Console.Out;
                using (var markerOutput = new StringWriter())
                {
                    try
                    {
                        Console.SetOut(markerOutput);
                        SendDeveloperDebug(true, new string('a', 32)); SendDeveloperDebug(false, new string('b', 32));
                        var debugRequests = markerOutput.ToString().Split('\n', StringSplitOptions.RemoveEmptyEntries);
                        if (debugRequests.Length != 2) throw new InvalidOperationException("developer debug request count");
                        for (var i = 0; i < debugRequests.Length; i++)
                        {
                            using var request = JsonDocument.Parse(debugRequests[i]);
                            if (request.RootElement.GetProperty("action").GetString() != (i == 0 ? "local-usb-update-on" : "local-usb-update-off") || request.RootElement.GetProperty("id").GetString() != new string(i == 0 ? 'a' : 'b', 32))
                                throw new InvalidOperationException("master switch must transmit USB authorization and matching request identity");
                        }
                        markerOutput.GetStringBuilder().Clear();
                        foreach (var marker in markers) marker.RaiseEvent(new Avalonia.Interactivity.RoutedEventArgs(Button.ClickEvent));
                        if (markerOutput.ToString() != "" || !detailWindow!.GetVisualDescendants().OfType<TextBlock>().Any(t => t.Text == "介面預覽，未傳送人工標記。"))
                            throw new InvalidOperationException("preview marker clicks must not send live events");
                        SendManualTrustPrompt(1); SendManualTrustPrompt(2);
                        var requests = markerOutput.ToString().Split('\n', StringSplitOptions.RemoveEmptyEntries);
                        if (requests.Length != 2) throw new InvalidOperationException("manual marker request count");
                        for (var i = 0; i < requests.Length; i++)
                        {
                            using var request = JsonDocument.Parse(requests[i]);
                            if (request.RootElement.EnumerateObject().Count() != 1 || request.RootElement.GetProperty("action").GetString() != (i == 0 ? "trust-prompt-first" : "trust-prompt-second"))
                                throw new InvalidOperationException("manual marker must send only its fixed action");
                        }
                        try { SendManualTrustPrompt(3); throw new InvalidOperationException("invalid marker accepted"); }
                        catch (ArgumentOutOfRangeException) { }
                        if (markerOutput.ToString().Split('\n', StringSplitOptions.RemoveEmptyEntries).Length != 2)
                            throw new InvalidOperationException("invalid marker emitted a request");
                        markerOutput.GetStringBuilder().Clear();
                        var serviceTrials = detailWindow!.GetVisualDescendants().OfType<Button>().Where(b => AutomationProperties.GetName(b) is "開始 Apple 服務臨時對照" or "取消並恢復 Apple 服務").ToArray();
                        if (serviceTrials.Length != 2 || serviceTrials.Any(b => !b.IsEffectivelyVisible))
                            throw new InvalidOperationException("two service trial controls must be available in local diagnostics");
                        foreach (var trial in serviceTrials) trial.RaiseEvent(new Avalonia.Interactivity.RoutedEventArgs(Button.ClickEvent));
                        if (markerOutput.ToString() != "" || !detailWindow!.GetVisualDescendants().OfType<TextBlock>().Any(t => t.Text == "介面預覽，未傳送服務對照請求。"))
                            throw new InvalidOperationException("preview service trial clicks must not send live requests");
                        SendTrustServiceTrial(false); SendTrustServiceTrial(true);
                        var trialRequests = markerOutput.ToString().Split('\n', StringSplitOptions.RemoveEmptyEntries);
                        if (trialRequests.Length != 2) throw new InvalidOperationException("service trial request count");
                        for (var i = 0; i < trialRequests.Length; i++)
                        {
                            using var request = JsonDocument.Parse(trialRequests[i]);
                            if (request.RootElement.EnumerateObject().Count() != 1 || request.RootElement.GetProperty("action").GetString() != (i == 0 ? "trust-service-trial-start" : "trust-service-trial-cancel"))
                                throw new InvalidOperationException("service trial must send only its fixed action");
                        }
                        markerOutput.GetStringBuilder().Clear();
                        var timingSwitches = detailWindow!.GetVisualDescendants().OfType<ToggleSwitch>().Where(b => AutomationProperties.GetName(b) is "快速偵測" or "延遲切換對照（12 秒）").ToArray();
                        if (timingSwitches.Length != 2 || timingSwitches.Any(b => !b.IsEffectivelyVisible || b.IsChecked != true)) throw new InvalidOperationException("timing diagnostics must use two switches with confirmed state");
                        var fastSwitch = timingSwitches.Single(b => AutomationProperties.GetName(b) == "快速偵測");
                        var delaySwitch = timingSwitches.Single(b => AutomationProperties.GetName(b) == "延遲切換對照（12 秒）");
                        fastSwitch.IsChecked = false;
                        fastSwitch.RaiseEvent(new Avalonia.Interactivity.RoutedEventArgs(Button.ClickEvent));
                        if (delaySwitch.IsEnabled || delaySwitch.IsChecked == true) throw new InvalidOperationException("delay requires fast detection and must clear with its master switch");
                        if (markerOutput.ToString() != "" || !detailWindow!.GetVisualDescendants().OfType<TextBlock>().Any(t => t.Text == "介面預覽，未傳送時序對照請求。"))
                            throw new InvalidOperationException("preview timing clicks must not send live requests");
                        foreach (var mode in new[] { "fast", "delayed", "normal" }) SendConnectionTimingTrial(mode);
                        var timingRequests = markerOutput.ToString().Split('\n', StringSplitOptions.RemoveEmptyEntries);
                        var timingActions = new[] { "trust-timing-fast", "trust-timing-delayed", "trust-timing-reset" };
                        if (timingRequests.Length != 3) throw new InvalidOperationException("timing request count");
                        for (var i = 0; i < timingRequests.Length; i++)
                        {
                            using var request = JsonDocument.Parse(timingRequests[i]);
                            if (request.RootElement.EnumerateObject().Count() != 1 || request.RootElement.GetProperty("action").GetString() != timingActions[i])
                                throw new InvalidOperationException("timing trial must send only its fixed action");
                        }
                        try { SendConnectionTimingTrial("arbitrary"); throw new InvalidOperationException("unknown timing mode accepted"); }
                        catch (ArgumentOutOfRangeException) { }
                        if (markerOutput.ToString().Split('\n', StringSplitOptions.RemoveEmptyEntries).Length != 3) throw new InvalidOperationException("unknown timing mode emitted request");
                        markerOutput.GetStringBuilder().Clear();
                        photoToggle.IsChecked = false;
                        photoToggle.RaiseEvent(new Avalonia.Interactivity.RoutedEventArgs(Button.ClickEvent));
                        if (markerOutput.ToString() != "" || photoIsolationMessage != "介面預覽，未傳送照片介面隔離請求。") throw new InvalidOperationException("photo preview must not mutate a real device");
                        var photoID = Guid.NewGuid().ToString("N");
                        SendPhotoIsolation(true, photoID); SendPhotoIsolation(false, photoID);
                        var photoRequests = markerOutput.ToString().Split('\n', StringSplitOptions.RemoveEmptyEntries);
                        if (photoRequests.Length != 2) throw new InvalidOperationException("photo request count");
                        for (var i = 0; i < photoRequests.Length; i++)
                        {
                            using var request = JsonDocument.Parse(photoRequests[i]);
                            if (request.RootElement.EnumerateObject().Count() != 2 || request.RootElement.GetProperty("id").GetString() != photoID || request.RootElement.GetProperty("action").GetString() != (i == 0 ? "photo-isolation-on" : "photo-isolation-off")) throw new InvalidOperationException("photo request must carry only fixed action and request identity");
                        }
                        try { SendPhotoIsolation(true, "old"); throw new InvalidOperationException("invalid photo request id accepted"); }
                        catch (ArgumentException) { }
                        if (markerOutput.ToString().Split('\n', StringSplitOptions.RemoveEmptyEntries).Length != 2) throw new InvalidOperationException("invalid photo request emitted");
                    }
                    finally { Console.SetOut(originalOutput); }
                }
#else
                if (typeof(Dashboard).GetMethod("LocalDiagnosticsSection", System.Reflection.BindingFlags.Instance | System.Reflection.BindingFlags.NonPublic) != null)
                    throw new InvalidOperationException("public build must exclude local developer diagnostics");
#endif
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
#if USBLINK_LOCAL_DIAGNOSTICS
                if (localDiagnosticsRefresh != null) throw new InvalidOperationException("local diagnostics close must release window controls");
#endif
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
            OpenDetails(); OpenTaskManager(); OpenSMBManager();
            HideToTray();
            if (IsVisible || detailWindow != null || taskWindow != null || smbAccountWindow != null || smbPassword.Text != "")
                throw new InvalidOperationException("tray hide must close child windows and clear credentials");
            using (var show = JsonDocument.Parse("""{"event":"show"}""")) Update(show.RootElement);
            if (!IsVisible || WindowState != WindowState.Normal)
                throw new InvalidOperationException("tray show must reuse dashboard");
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
