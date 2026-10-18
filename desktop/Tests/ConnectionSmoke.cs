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
                var diagnosticsFold = detailWindow!.GetVisualDescendants().OfType<Expander>().Single(e => e.Header?.ToString() == "詳細診斷 / 調試資訊");
                if (diagnosticsFold.IsExpanded) throw new InvalidOperationException("debug stream must start collapsed");
                diagnosticsFold.IsExpanded = true;
                detailWindow!.UpdateLayout();
                foreach (var state in new[]{"off","preparing","waiting_client","ready","recovery_required"}) {
                    using var snapshot = JsonDocument.Parse(JsonSerializer.Serialize(new { internet_sharing = new { state } }));
                    UpdateInternet(snapshot.RootElement);
                    if (internetToggle.IsChecked != (state is "preparing" or "waiting_client" or "ready") || internetToggle.IsEnabled != (state != "preparing"))
                        throw new InvalidOperationException("internet switch must reflect confirmed state: " + state);
                }
                if (detailRows.GetVisualRoot() != detailWindow)
                    throw new InvalidOperationException("diagnostic controls must share the current window");
#if USBLINK_LOCAL_DIAGNOSTICS
                var localToggle = detailWindow!.GetVisualDescendants().OfType<ToggleSwitch>().Single(t => AutomationProperties.GetName(t) == "開發者調試");
                localToggle.IsChecked = true;
                localToggle.RaiseEvent(new Avalonia.Interactivity.RoutedEventArgs(Button.ClickEvent));
                detailWindow!.UpdateLayout();
                var experimentFold = detailWindow!.GetVisualDescendants().OfType<Expander>().Single(e => e.Header?.ToString() == "連線實驗");
                if (experimentFold.IsExpanded) throw new InvalidOperationException("connection experiments must start collapsed on each open");
                experimentFold.IsExpanded = true;
                detailWindow!.UpdateLayout();
                var experimentSwitches = ((Control)experimentFold.Content!).GetVisualDescendants().OfType<ToggleSwitch>().ToArray();
                if (experimentSwitches.Length != 1 || experimentSwitches.Any(t => !t.IsEffectivelyVisible)) throw new InvalidOperationException("expanded experiments must contain only the explicit NCM Direct control");
                if (detailWindow!.GetVisualDescendants().OfType<ToggleSwitch>().Any(t => AutomationProperties.GetName(t) is "快速偵測" or "延遲切換對照（12 秒）" or "WPD 請求跟蹤" or "照片介面隔離" or "照片介面前置阻斷" or "Apple 服務屏蔽對照")) throw new InvalidOperationException("automatic diagnostics and legacy timing must have no separate switch");
                var textFold = detailWindow!.GetVisualDescendants().OfType<Expander>().Single(e => e.Header?.ToString() == "完整診斷文字");
                if (textFold.IsExpanded) throw new InvalidOperationException("full diagnostic text must start collapsed");
                textFold.IsExpanded = true;
                detailWindow!.UpdateLayout();
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
                using (var photoRecoveryFailed = JsonDocument.Parse("""{"photo_isolation":{"available":true,"requested":false,"effective":false,"busy":false,"phase":"recovery_pending","error":"PHOTO_RECOVERY_PENDING"}}""")) UpdateLocalDiagnostics(photoRecoveryFailed.RootElement);
                if (!detailWindow!.GetVisualDescendants().OfType<TextBlock>().Any(t => AutomationProperties.GetName(t) == "照片介面恢復狀態" && t.IsEffectivelyVisible && t.Text!.Contains("PHOTO_RECOVERY_PENDING"))) throw new InvalidOperationException("automatic photo recovery failure must remain visible");
                localDiagnosticsPendingID = new string('d', 32); localDiagnosticsRequested = false;
                using (var deliveryFailed = JsonDocument.Parse("""{"event":"local-control-result","action":"local-usb-update-off","request_id":"dddddddddddddddddddddddddddddddd","code":"CORE_UI_ACTION_FAILED"}""")) Update(deliveryFailed.RootElement);
                if (localDiagnosticsPendingID != "" || !localToggle.IsEnabled || !localDiagnosticsEnabled) throw new InvalidOperationException("master delivery failure must release pending without changing backend state");
                using (var healthyAfterFailure = JsonDocument.Parse("""{"developer_debug":{"available":true,"enabled":true,"busy":false}}""")) UpdateLocalDiagnostics(healthyAfterFailure.RootElement);
                if (!localDiagnosticsMessage.Contains("未能確認") && localDiagnosticsDeliveryFailureID == "") throw new InvalidOperationException("healthy snapshot must not invent acknowledgement of a failed master request");
                using (var timing = JsonDocument.Parse("""{"connection_timing":{"available":true,"mode":"fast","phase":"active","persistence":"saved"}}""")) UpdateConnectionTiming(timing.RootElement);
                localDiagnosticsRefresh?.Invoke();
                if (!connectionTimingAvailable || !connectionTimingMessage.Contains("持續使用") || connectionTimingMode != "fast") throw new InvalidOperationException("legacy timing status must remain readable without a control");
                using (var delayedState = JsonDocument.Parse("""{"connection_timing":{"available":true,"mode":"delayed","phase":"active","persistence":"saved"}}""")) UpdateConnectionTiming(delayedState.RootElement);
                localDiagnosticsRefresh?.Invoke();
                if (connectionTimingMode != "delayed" || !connectionTimingMessage.Contains("設定已保存")) throw new InvalidOperationException("legacy persisted delay status must remain readable");
                using (var automaticTiming = JsonDocument.Parse("""{"connection_timing":{"available":true,"mode":"fast","phase":"active","persistence":"automatic"}}""")) UpdateConnectionTiming(automaticTiming.RootElement);
                if (connectionTimingMode != "fast" || !connectionTimingMessage.Contains("自動執行") || connectionTimingMessage.Contains("保存")) throw new InvalidOperationException("automatic detection must not imply a saved manual choice");
                var obsoleteButtons = detailWindow!.GetVisualDescendants().OfType<Button>().Where(b => AutomationProperties.GetName(b)?.StartsWith("標記第 ") == true || AutomationProperties.GetName(b) is "開始 Apple 服務臨時對照" or "取消並恢復 Apple 服務").ToArray();
                if (obsoleteButtons.Length != 0) throw new InvalidOperationException("manual markers and paired Apple service buttons must be absent");
                foreach (var experiment in trustExperiments.Where(e => e.Key == "ncm_direct"))
                {
                    using var state = JsonDocument.Parse(JsonSerializer.Serialize(new Dictionary<string, object> { [experiment.Key] = new { available = true, requested = true, effective = false, busy = false, persistence = "saved", saved_enabled = true, phase = "waiting" } }));
                    UpdateLocalDiagnostics(state.RootElement);
                    var control = detailWindow!.GetVisualDescendants().OfType<ToggleSwitch>().Single(t => AutomationProperties.GetName(t) == experiment.Title);
                    if (control.IsChecked != true || experiment.Effective || !control.IsEnabled) throw new InvalidOperationException("saved experiment selection must not fabricate effective state");
                    experiment.PendingID = new string('f', 32); experiment.PendingEnabled = false;
                    UpdateLocalDiagnostics(state.RootElement);
                    if (experiment.PendingID == "" || control.IsChecked == true) throw new InvalidOperationException("stale experiment snapshot finished a current off request");
                    using var failure = JsonDocument.Parse(JsonSerializer.Serialize(new { @event = "local-control-result", action = experiment.Action + "-off", request_id = experiment.PendingID, code = "CORE_UI_ACTION_FAILED" }));
                    Update(failure.RootElement);
                    if (experiment.PendingID != "" || experiment.DeliveryFailureID == "" || control.IsChecked != true) throw new InvalidOperationException("failed experiment delivery must release wait and preserve last authority");
                    UpdateLocalDiagnostics(state.RootElement);
                    if (experiment.DeliveryFailureID == "") throw new InvalidOperationException("old snapshots must preserve uncertain delivery warning");
                    using var ack = JsonDocument.Parse(JsonSerializer.Serialize(new Dictionary<string, object> { [experiment.Key] = new { available = true, requested = false, effective = false, busy = false, persistence = "saved", saved_enabled = false, request_id = experiment.DeliveryFailureID, phase = "off" } }));
                    UpdateLocalDiagnostics(ack.RootElement);
                    if (experiment.DeliveryFailureID != "" || control.IsChecked == true) throw new InvalidOperationException("matching authoritative experiment ack must replace delivery warning");
                }
                using (var armed = JsonDocument.Parse("""{"photo_policy":{"available":true,"requested":true,"effective":false,"busy":false,"persistence":"saved","saved_enabled":true,"policy_armed":true,"phase":"policy_armed_waiting_reenumeration"}}""")) UpdateLocalDiagnostics(armed.RootElement);
                if (!trustExperiments.Single(e => e.Key == "photo_policy").Message.Contains("尚未確認前置阻斷")) throw new InvalidOperationException("armed policy must not imply blocked photo traffic");
                using (var unsupported = JsonDocument.Parse("""{"photo_policy":{"available":false,"requested":true,"effective":false,"busy":false,"persistence":"saved","saved_enabled":true,"phase":"unsupported","error":"PHOTO_POLICY_WINDOWS_EDITION_OR_BUILD_UNSUPPORTED"}}""")) UpdateLocalDiagnostics(unsupported.RootElement);
                if (detailWindow!.GetVisualDescendants().OfType<ToggleSwitch>().Any(t => AutomationProperties.GetName(t) == "照片介面前置阻斷")) throw new InvalidOperationException("retired photo policy must have no control");
                using (var recovered = JsonDocument.Parse("""{"ncm_direct":{"available":true,"requested":false,"effective":false,"busy":false,"persistence":"saved","saved_enabled":false,"recovery_required":false,"phase":"recovery_verified"}}""")) UpdateLocalDiagnostics(recovered.RootElement);
                if (trustExperiments.Single(e => e.Key == "ncm_direct") is var recoveredDirect && (recoveredDirect.NeedsAttention || recoveredDirect.Message.Contains("尚未確認"))) throw new InvalidOperationException("verified direct recovery must clear recovery warning");
                foreach (var wpdError in new[] { "OPERATION_FAILED", "WPD_TRACE_OPERATION_FAILED" })
                {
                    using var wpdNotCovered = JsonDocument.Parse(JsonSerializer.Serialize(new { wpd_trace = new { available = true, requested = true, effective = false, busy = false, persistence = "automatic", phase = "failed", error = wpdError, cause_code = "WPD_TRACE_SAFE_METADATA_NOT_COVERED" } }));
                    UpdateLocalDiagnostics(wpdNotCovered.RootElement);
                    if (automaticWpd.NeedsAttention || !automaticWpd.Message.Contains("未覆蓋：本機格式未通過隱私檢查") || !automaticWpd.Message.Contains("未記錄不代表請求未發生") || automaticWpd.Message.Contains(wpdError)) throw new InvalidOperationException("WPD privacy coverage limit must not imply an actionable operation failure");
                }
                foreach (var wpdState in new[] {
                    new { effective = false, phase = "recovery_pending", error = "WPD_TRACE_OPERATION_FAILED" },
                    new { effective = false, phase = "stopping", error = "WPD_TRACE_OPERATION_FAILED" },
                    new { effective = true, phase = "error", error = "OPERATION_FAILED" },
                    new { effective = false, phase = "error", error = "WPD_TRACE_STOP_FAILED" } })
                {
                    using var wpdFailure = JsonDocument.Parse(JsonSerializer.Serialize(new { wpd_trace = new { available = true, requested = false, wpdState.effective, busy = false, persistence = "automatic", wpdState.phase, wpdState.error, cause_code = "WPD_TRACE_SAFE_METADATA_NOT_COVERED" } }));
                    UpdateLocalDiagnostics(wpdFailure.RootElement);
                    if (!automaticWpd.NeedsAttention || !automaticWpd.Message.Contains(wpdState.error) || automaticWpd.Message.Contains("該通道未啟用")) throw new InvalidOperationException("WPD live/recovery/stop failure must not be hidden by a coverage cause");
                }
                using (var partialTrace = JsonDocument.Parse("""{"wpd_trace":{"available":true,"requested":true,"effective":true,"busy":false,"persistence":"saved","saved_enabled":true,"phase":"active","provider_coverage":"partial","enabled_provider_count":1}}""")) UpdateLocalDiagnostics(partialTrace.RootElement);
                if (!automaticWpd.Message.Contains("部分跟蹤")) throw new InvalidOperationException("partial WPD coverage must be explicit");
                using (var directUnverified = JsonDocument.Parse("""{"ncm_direct":{"available":true,"requested":true,"effective":false,"busy":false,"persistence":"saved","saved_enabled":true,"phase":"direct_descriptors_verified_network_pending","ordinary_ipv4_network_ready":false,"mode_requested":5,"observed_configuration":1,"observed_target_matched":true,"recovery_required":true}}""")) UpdateLocalDiagnostics(directUnverified.RootElement);
                if (trustExperiments.Single(e => e.Key == "ncm_direct") is var incompleteDirect && (incompleteDirect.Message.Contains("已通過") || !incompleteDirect.Message.Contains("模式 5 切換已確認") || incompleteDirect.NeedsAttention)) throw new InvalidOperationException("a direct descriptor candidate must distinguish mode success from incomplete networking without a false recovery failure");
                foreach (var directPhase in new[] { "intent_saved", "mode_request_submitting" })
                {
                    using var preparing = JsonDocument.Parse(JsonSerializer.Serialize(new { ncm_direct = new { available = true, requested = true, effective = false, busy = true, persistence = "saved", saved_enabled = true, phase = directPhase, recovery_required = true } }));
                    UpdateLocalDiagnostics(preparing.RootElement);
                    if (trustExperiments.Single(e => e.Key == "ncm_direct") is var preparingDirect && (preparingDirect.NeedsAttention || !preparingDirect.Message.Contains("正在核對本輪設備"))) throw new InvalidOperationException("normal direct mode switching must not demand recovery or an immediate replug");
                }
                using (var directVerified = JsonDocument.Parse("""{"ncm_direct":{"available":true,"requested":true,"effective":true,"busy":false,"persistence":"saved","saved_enabled":true,"phase":"direct_ipv4_peer_verified","ordinary_ipv4_network_ready":true,"recovery_required":true}}""")) UpdateLocalDiagnostics(directVerified.RootElement);
                if (trustExperiments.Single(e => e.Key == "ncm_direct") is var activeDirect && (!activeDirect.Message.Contains("已通過 IPv4") || activeDirect.NeedsAttention)) throw new InvalidOperationException("active verified direct networking must not look like a failed recovery obligation");
                using (var directStopping = JsonDocument.Parse("""{"ncm_direct":{"available":true,"requested":false,"effective":true,"busy":true,"persistence":"saved","saved_enabled":false,"phase":"direct_network_stopping","ordinary_ipv4_network_ready":true,"recovery_required":true}}""")) UpdateLocalDiagnostics(directStopping.RootElement);
                if (trustExperiments.Single(e => e.Key == "ncm_direct") is var stoppingDirect && (stoppingDirect.Message.Contains("已通過") || !stoppingDirect.NeedsAttention)) throw new InvalidOperationException("stopping direct networking must never revive an earlier ready status");
                experimentFold.IsExpanded = false;
                detailWindow!.UpdateLayout();
                TextBlock VisibleSummary(string name) => detailWindow!.GetVisualDescendants().OfType<TextBlock>().Single(t => AutomationProperties.GetName(t) == name && t.IsEffectivelyVisible);
                if (!VisibleSummary("本地實驗恢復狀態").Text!.Contains("NCM Direct")) throw new InvalidOperationException("direct stop must remain visible outside collapsed experiments");
                using (var recoveryBusy = JsonDocument.Parse("""{"photo_isolation":{"available":true,"requested":false,"effective":false,"busy":true,"phase":"recovering","persistence":"saved","saved_enabled":false},"amds_hold":{"available":true,"requested":false,"effective":false,"busy":true,"phase":"recovering","persistence":"saved","saved_enabled":false}}""")) UpdateLocalDiagnostics(recoveryBusy.RootElement);
                if (!VisibleSummary("照片介面恢復狀態").Text!.Contains("尚未確認完成") || !VisibleSummary("本地實驗恢復狀態").Text!.Contains("Apple 服務")) throw new InvalidOperationException("busy restoration must remain outside collapsed experiments");
                using (var autoTrace = JsonDocument.Parse("""{"wpd_trace":{"available":true,"requested":true,"effective":true,"busy":false,"persistence":"automatic","saved_enabled":false,"phase":"active","provider_coverage":"partial"}}""")) UpdateLocalDiagnostics(autoTrace.RootElement);
                if (!VisibleSummary("WPD 自動診斷狀態").Text!.Contains("部分跟蹤")) throw new InvalidOperationException("automatic WPD readback must not depend on its old preference");
                using (var closedRecovery = JsonDocument.Parse("""{"developer_debug":{"available":true,"enabled":false,"busy":false},"photo_isolation":{"available":true,"requested":false,"effective":false,"busy":false,"phase":"recovery_pending","error":"PHOTO_RESTORE_FAILED","persistence":"saved","saved_enabled":false},"amds_hold":{"available":true,"requested":false,"effective":false,"busy":false,"phase":"recovery_failed","error":"AMDS_RESTORE_FAILED","persistence":"saved","saved_enabled":false},"wpd_trace":{"available":true,"requested":false,"effective":false,"busy":false,"phase":"recovery_failed","error":"WPD_STOP_FAILED","persistence":"automatic","saved_enabled":false}}""")) UpdateLocalDiagnostics(closedRecovery.RootElement);
                if (!VisibleSummary("照片介面恢復狀態").Text!.Contains("PHOTO_RESTORE_FAILED") || !VisibleSummary("本地實驗恢復狀態").Text!.Contains("AMDS_RESTORE_FAILED") || !VisibleSummary("WPD 自動診斷狀態").Text!.Contains("WPD_STOP_FAILED")) throw new InvalidOperationException("master off must retain photo, service and automatic trace recovery failures");
                using (var recoveredControls = JsonDocument.Parse("""{"developer_debug":{"available":true,"enabled":true,"busy":false},"photo_isolation":{"available":true,"requested":false,"effective":false,"busy":false,"phase":"off","persistence":"saved","saved_enabled":false},"photo_policy":{"available":true,"requested":false,"effective":false,"busy":false,"phase":"off","persistence":"saved","saved_enabled":false},"ncm_direct":{"available":true,"requested":false,"effective":false,"busy":false,"phase":"recovery_verified","persistence":"saved","saved_enabled":false},"amds_hold":{"available":true,"requested":false,"effective":false,"busy":false,"phase":"off","persistence":"saved","saved_enabled":false},"wpd_trace":{"available":true,"requested":true,"effective":true,"busy":false,"phase":"active","persistence":"saved","saved_enabled":false}}""")) UpdateLocalDiagnostics(recoveredControls.RootElement);
                if (detailWindow!.GetVisualDescendants().OfType<TextBlock>().Any(t => (AutomationProperties.GetName(t) is "本地實驗恢復狀態" or "照片介面恢復狀態") && t.IsEffectivelyVisible)) throw new InvalidOperationException("confirmed recovery must clear outside warnings");
                using (var archiveRecording = JsonDocument.Parse("""{"connection_archive":{"available":true,"phase":"recording","current_id":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","queue_dropped":0,"size_dropped":0,"write_failures":0}}""")) UpdateLocalDiagnostics(archiveRecording.RootElement);
                if (!VisibleSummary("連線檔案採集狀態").Text!.Contains("本輪檔案記錄中") || VisibleSummary("連線檔案採集狀態").Text!.Contains("全部採集完成")) throw new InvalidOperationException("active archive must not imply complete collection");
                using (var archiveFailed = JsonDocument.Parse("""{"developer_debug":{"available":true,"enabled":false,"busy":false},"connection_archive":{"available":true,"phase":"write_failed","error":"ARCHIVE_WRITE_FAILED","queue_dropped":2,"size_dropped":1,"write_failures":1,"redacted":3}}""")) UpdateLocalDiagnostics(archiveFailed.RootElement);
                if (!VisibleSummary("連線檔案採集狀態").Text!.Contains("ARCHIVE_WRITE_FAILED") || !VisibleSummary("連線檔案採集狀態").Text!.Contains("佇列漏記 2") || !VisibleSummary("連線檔案採集狀態").Text!.Contains("採集可能不完整")) throw new InvalidOperationException("archive failures must remain visible with debug closed");
                using (var archiveRecovered = JsonDocument.Parse("""{"developer_debug":{"available":true,"enabled":true,"busy":false},"connection_archive":{"available":true,"phase":"recording","queue_dropped":0,"size_dropped":0,"write_failures":0}}""")) UpdateLocalDiagnostics(archiveRecovered.RootElement);
                using (var usbStarting = JsonDocument.Parse("""{"local_usb_trace":{"available":true,"active":true,"phase":"metadata_only","coverage":"metadata_only","accepted":0,"received":0,"target_scope":"unknown"}}""")) UpdateLocalDiagnostics(usbStarting.RootElement);
                if (!VisibleSummary("USB 事件採集狀態").Text!.Contains("未覆蓋有效事件") || VisibleSummary("USB 事件採集狀態").Text!.Contains("已就緒")) throw new InvalidOperationException("USB session/schema discovery must not imply event coverage");
                using (var usbMetadata = JsonDocument.Parse("""{"local_usb_trace":{"available":true,"active":true,"phase":"metadata_only","coverage":"metadata_only","accepted":2,"received":2,"target_scope":"unknown","started_utc":"2026-10-17T10:00:00Z","last_event_utc":"2026-10-17T10:01:00Z"}}""")) UpdateLocalDiagnostics(usbMetadata.RootElement);
                if (!VisibleSummary("USB 事件採集狀態").Text!.Contains("事件元資料可用") || !VisibleSummary("USB 事件採集狀態").Text!.Contains("尚不能歸因") || !VisibleSummary("USB 事件採集狀態").Text!.Contains("觀察時段")) throw new InvalidOperationException("USB metadata scope/window must stay explicit");
                using (var usbLost = JsonDocument.Parse("""{"developer_debug":{"available":true,"enabled":false},"local_usb_trace":{"available":true,"active":false,"phase":"recovery_pending","coverage":"incomplete","accepted":2,"received":9,"events_lost":7,"schema_rejected":1,"error":"USB_TRACE_STOP_FAILED"}}""")) UpdateLocalDiagnostics(usbLost.RootElement);
                if (!VisibleSummary("USB 事件採集狀態").Text!.Contains("證據不完整") || !VisibleSummary("USB 事件採集狀態").Text!.Contains("事件遺失 7") || !VisibleSummary("USB 事件採集狀態").Text!.Contains("USB_TRACE_STOP_FAILED")) throw new InvalidOperationException("USB loss/stop failure must remain visible with master off");
                using (var usbUncovered = JsonDocument.Parse("""{"local_usb_trace":{"available":true,"phase":"no_safe_event_schema","coverage":"not_covered"}}""")) UpdateLocalDiagnostics(usbUncovered.RootElement);
                if (!VisibleSummary("USB 事件採集狀態").Text!.Contains("未找到可通過格式及隱私檢查")) throw new InvalidOperationException("USB untrusted schema must show uncovered reason");
                using (var usbNoSchemaError = JsonDocument.Parse("""{"local_usb_trace":{"available":true,"phase":"error","coverage":"not_covered","accepted":0,"error":"USB_TRACE_NO_SAFE_EVENT_SCHEMA"}}""")) UpdateLocalDiagnostics(usbNoSchemaError.RootElement);
                if (!VisibleSummary("USB 事件採集狀態").Text!.Contains("未覆蓋：") || VisibleSummary("USB 事件採集狀態").Text!.Contains("證據不完整") || !VisibleSummary("USB 事件採集狀態").Text!.Contains("USB_TRACE_NO_SAFE_EVENT_SCHEMA")) throw new InvalidOperationException("unavailable safe schema must not be described as lost capture evidence");
                using (var usbArchiveLoss = JsonDocument.Parse("""{"local_usb_trace":{"available":true,"phase":"error","coverage":"not_covered","accepted":0,"archive_rejected":2,"late_events":3,"timestamp_unknown":4,"error":"USB_TRACE_NO_SAFE_EVENT_SCHEMA"}}""")) UpdateLocalDiagnostics(usbArchiveLoss.RootElement);
                if (!VisibleSummary("USB 事件採集狀態").Text!.Contains("證據不完整") || !VisibleSummary("USB 事件採集狀態").Text!.Contains("未收錄到檔案 2") || !VisibleSummary("USB 事件採集狀態").Text!.Contains("觀察結束後到達 3") || !VisibleSummary("USB 事件採集狀態").Text!.Contains("事件時間無法確認 4")) throw new InvalidOperationException("USB archive/timing evidence loss must override uncovered capability status");
                using (var legacyUSB = JsonDocument.Parse("""{"developer_debug":{"available":true,"enabled":true}}""")) UpdateLocalDiagnostics(legacyUSB.RootElement);
                if (localUSBTracePresent || localUSBTraceMessage != "") throw new InvalidOperationException("missing USB summary must clear stale new-backend evidence");
                experimentFold.IsExpanded = true;
                detailWindow!.UpdateLayout();
                var originalOutput = Console.Out;
                using (var metadataOnly = JsonDocument.Parse("""{"local_usb_trace":{"available":true,"active":true,"coverage":"not_covered","callbacks_received":6,"session_metadata_callbacks":6,"session_header_callbacks":1,"received":0,"accepted":0,"schema_rejected":0}}""")) UpdateLocalDiagnostics(metadataOnly.RootElement);
                if (!localUSBTraceMessage.Contains("僅收到會話元資料") || localUSBTraceMessage.Contains("格式或隱私檢查未通過") || localUSBTraceNeedsAttention) throw new InvalidOperationException("session metadata is neither USB evidence nor schema loss");
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
                        foreach (var experiment in trustExperiments.Where(e => e.Key == "ncm_direct"))
                        {
                            var control = detailWindow!.GetVisualDescendants().OfType<ToggleSwitch>().Single(t => AutomationProperties.GetName(t) == experiment.Title);
                            control.IsChecked = true;
                            control.RaiseEvent(new Avalonia.Interactivity.RoutedEventArgs(Button.ClickEvent));
                            if (markerOutput.ToString() != "" || experiment.Message != "介面預覽，未傳送實驗設定。") throw new InvalidOperationException("preview experiment must not emit live RPC");
                            SendTrustExperiment(experiment.Action, true, new string('a', 32));
                            SendTrustExperiment(experiment.Action, false, new string('b', 32));
                            var requests = markerOutput.ToString().Split('\n', StringSplitOptions.RemoveEmptyEntries);
                            if (requests.Length != 2) throw new InvalidOperationException("experiment request count");
                            for (var i = 0; i < requests.Length; i++)
                            {
                                using var request = JsonDocument.Parse(requests[i]);
                                if (request.RootElement.EnumerateObject().Count() != 2 || request.RootElement.GetProperty("action").GetString() != experiment.Action + (i == 0 ? "-on" : "-off") || request.RootElement.GetProperty("id").GetString() != new string(i == 0 ? 'a' : 'b', 32)) throw new InvalidOperationException("experiment must emit only fixed action and correlation identity");
                            }
                            markerOutput.GetStringBuilder().Clear();
                        }
                        foreach (var invalid in new[] { ("shell", new string('a', 32)), ("wpd-trace", new string('a', 32)), ("amds-hold", "old") })
                        {
                            try { SendTrustExperiment(invalid.Item1, true, invalid.Item2); throw new InvalidOperationException("invalid experiment request accepted"); }
                            catch (ArgumentException) { }
                        }
                        if (markerOutput.ToString() != "") throw new InvalidOperationException("invalid experiment request emitted");
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
                if (localDiagnosticsRefresh != null || localTrustExperimentRefresh != null) throw new InvalidOperationException("local diagnostics close must release window controls");
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
            ResizeAndSettle(720, 500); UpdateLayout(); UpdateResponsiveLayout(); UpdateLayout();
            if (compactLayout != true || this.GetVisualDescendants().OfType<LayoutTransformControl>().Any() || addressValue.FontSize != 34 || bodyScroll.Extent.Height <= bodyScroll.Viewport.Height)
                throw new InvalidOperationException($"compact layout must scroll without reducing Windows DPI text size (compact={compactLayout}, client={ClientSize}, font={addressValue.FontSize}, extent={bodyScroll.Extent.Height}, viewport={bodyScroll.Viewport.Height})");
            CaptureConnectionPreview(this, "compact");
            ResizeAndSettle(520, 420); UpdateLayout(); UpdateResponsiveLayout(); UpdateLayout();
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
            using (var automatic = JsonDocument.Parse("""{"event":"status","default_network_isolation":{"phase":"running","photo_effective":true,"amds_effective":true}}""")) Update(automatic.RootElement);
            if (!automaticIsolationStatus.IsVisible || !automaticIsolationStatus.Text!.Contains("已隔離") || !automaticIsolationStatus.Text.Contains("已暫停")) throw new InvalidOperationException("automatic policies need a readonly public summary");
            using (var networkRestoring = JsonDocument.Parse("""{"event":"status","network_only":{"enabled":false,"busy":false,"restoring":true,"phase":"recovering"}}""")) Update(networkRestoring.RootElement);
            if (networkOnly.IsChecked == true || !networkOnly.IsEnabled || !networkOnlyStatus.IsVisible || !networkOnlyStatus.Text!.Contains("正在還原")) throw new InvalidOperationException("network-only off must show restoration in progress");
            using (var networkPending = JsonDocument.Parse("""{"event":"status","network_only":{"enabled":false,"busy":false,"restore_pending":true,"phase":"recovery_pending","error":"PHOTO_RESTORE_FAILED"}}""")) Update(networkPending.RootElement);
            if (!networkOnlyStatus.Text!.Contains("PHOTO_RESTORE_FAILED") || !networkOnlyStatus.Text.Contains("尚未確認還原")) throw new InvalidOperationException("network-only restore failure must stay visible");
            using (var networkOn = JsonDocument.Parse("""{"event":"status","network_only":{"enabled":true,"busy":false,"effective":true,"known_nodes":2,"known_applied":2,"phase":"known_applied"}}""")) Update(networkOn.RootElement);
            if (networkOnly.IsChecked != true || !networkOnlyStatus.Text!.Contains("已封鎖")) throw new InvalidOperationException("network-only on must show the read-back state");
            if (this.GetVisualDescendants().OfType<TextBlock>().Any(t => t.Text == "退出介面") || !this.GetVisualDescendants().OfType<TextBlock>().Any(t => t.Text == "退出程序")) throw new InvalidOperationException("exit must describe the whole program");
            using (var trayExit = JsonDocument.Parse("""{"event":"program-exit-request"}""")) Update(trayExit.RootElement);
            if (programExitID != "" || programExitAwaiting || !notice.Text!.Contains("介面預覽")) throw new InvalidOperationException("tray exit must share the preview-safe program exit path");
            VerifyExitButtonWire();
            programExitID = "11111111111111111111111111111111"; programExitAwaiting = true;
            SendProgramExitRequest("exit-program");
            var requestGeneration = programExitConfirmationGeneration;
            using (var idleExit = JsonDocument.Parse("""{"event":"status","program_exit":{"phase":"idle"}}""")) Update(idleExit.RootElement);
            if (bodyScroll.IsEnabled || !programExitAwaiting) throw new InvalidOperationException("queued idle snapshot cannot enable actions while exit confirmation is pending");
            ExpireProgramExitConfirmation("22222222222222222222222222222222", requestGeneration);
            if (!programExitAwaiting) throw new InvalidOperationException("foreign confirmation timeout cannot cancel exit");
            exitHidden = true;
            ExpireProgramExitConfirmation(programExitID, requestGeneration);
            if (programExitAwaiting || programExitCommitSent || !programExitButton.IsEnabled || !programExitStatus.Text!.Contains("不代表恢復已完成") || programExitID != "11111111111111111111111111111111") throw new InvalidOperationException("missing confirmation must allow same-request retry without claiming restoration");
            if (exitHidden || !IsVisible) throw new InvalidOperationException("a lost exit acknowledgement must bring the hidden window back");
            programExitAwaiting = true;
            SendProgramExitRequest("exit-program");
            ExpireProgramExitConfirmation(programExitID, requestGeneration);
            if (!programExitAwaiting) throw new InvalidOperationException("previous retry timer cannot cancel current confirmation");
            using (var wrongExit = JsonDocument.Parse("""{"event":"program-exit-result","request_id":"22222222222222222222222222222222"}""")) Update(wrongExit.RootElement);
            if (!programExitAwaiting) throw new InvalidOperationException("unrelated exit result cleared current request");
            using (var stoppingExit = JsonDocument.Parse("""{"event":"status","program_exit":{"phase":"stopping_connections","request_id":"11111111111111111111111111111111","busy":true}}""")) Update(stoppingExit.RootElement);
            if (bodyScroll.IsEnabled || !footerControl.IsEnabled || programExitButton.IsEnabled || !captionClose!.IsEffectivelyEnabled) throw new InvalidOperationException("exit must block mutations but retain window controls");
            if (programExitConfirmationTimer != null) throw new InvalidOperationException("acknowledged native stopping must not have an arbitrary restore deadline");
            exitHidden = true;
            using (var failedExit = JsonDocument.Parse("""{"event":"status","program_exit":{"phase":"failed","request_id":"11111111111111111111111111111111","error":"CORE_EXIT_RECOVERY_PENDING"},"default_network_isolation":{"phase":"recovery_pending","photo_restored":false,"amds_restored":true,"policy_restored":true}}""")) Update(failedExit.RootElement);
            if (!programExitButton.IsEnabled || programExitAwaiting || bodyScroll.IsEnabled || !programExitStatus.Text!.Contains("重試") || !automaticIsolationStatus.Text!.Contains("待確認")) throw new InvalidOperationException("restore failure must retain retry and disclose unresolved state");
            if (exitHidden || !IsVisible) throw new InvalidOperationException("a failed restore must bring the hidden window back");
            programExitAwaiting = true;
            using (var readyExit = JsonDocument.Parse("""{"event":"status","program_exit":{"phase":"ready","request_id":"22222222222222222222222222222222"}}""")) Update(readyExit.RootElement);
            if (programExitCommitSent) throw new InvalidOperationException("foreign exit request must not commit");
            using (var readyExit = JsonDocument.Parse("""{"event":"status","program_exit":{"phase":"ready","request_id":"11111111111111111111111111111111"},"default_network_isolation":{"phase":"restored","restored":true}}""")) Update(readyExit.RootElement);
            if (!programExitCommitSent || !automaticIsolationStatus.Text!.Contains("均已恢復")) throw new InvalidOperationException("ready exit must commit only matching request");
            var commitGeneration = programExitConfirmationGeneration;
            using (var readyRepeated = JsonDocument.Parse("""{"event":"status","program_exit":{"phase":"ready","request_id":"11111111111111111111111111111111"}}""")) Update(readyRepeated.RootElement);
            if (programExitConfirmationTimer == null || commitGeneration != programExitConfirmationGeneration) throw new InvalidOperationException("repeated ready snapshots must not extend or erase the missing commit acknowledgement deadline");
            ExpireProgramExitConfirmation(programExitID, commitGeneration);
            if (programExitAwaiting || programExitCommitSent || !programExitButton.IsEnabled || bodyScroll.IsEnabled) throw new InvalidOperationException("lost commit acknowledgement must permit retry while keeping stopped actions disabled");
            programExitAwaiting = programExitCommitSent = true;
            using (var failedCommit = JsonDocument.Parse("""{"event":"program-exit-result","request_id":"11111111111111111111111111111111","code":"CORE_EXIT_REQUEST_FAILED"}""")) Update(failedCommit.RootElement);
            if (programExitAwaiting || programExitCommitSent || !programExitButton.IsEnabled) throw new InvalidOperationException("failed commit must remain retryable");
            using (var readyAgain = JsonDocument.Parse("""{"event":"status","program_exit":{"phase":"ready","request_id":"11111111111111111111111111111111"}}""")) Update(readyAgain.RootElement);
            if (programExitCommitSent || programExitAwaiting || !programExitStatus.Text!.Contains("重試")) throw new InvalidOperationException("normal snapshots must not hide a failed commit or retry silently");
            programExitID = "33333333333333333333333333333333"; programExitAwaiting = true;
            using (var staleFailed = JsonDocument.Parse("""{"event":"status","program_exit":{"phase":"failed","request_id":"11111111111111111111111111111111"}}""")) Update(staleFailed.RootElement);
            if (!programExitAwaiting) throw new InvalidOperationException("old failed snapshot must not cancel a new exit request");
            Console.Error.WriteLine("CONNECTION_SMOKE_PASS");
            (Application.Current?.ApplicationLifetime as IClassicDesktopStyleApplicationLifetime)?.Shutdown(0);
        }
        catch (Exception error)
        {
            Console.Error.WriteLine("CONNECTION_SMOKE_FAIL: " + error);
            (Application.Current?.ApplicationLifetime as IClassicDesktopStyleApplicationLifetime)?.Shutdown(1);
        }
    }

    // Some platforms apply window resizes asynchronously; pump a nested loop until the client area follows.
    void ResizeAndSettle(double width, double height)
    {
        Width = width; Height = height;
        for (var i = 0; i < 40 && (Math.Abs(ClientSize.Width - width) > 1 || Math.Abs(ClientSize.Height - height) > 1); i++)
        {
            var frame = new Avalonia.Threading.DispatcherFrame();
            Avalonia.Threading.DispatcherTimer.RunOnce(() => frame.Continue = false, TimeSpan.FromMilliseconds(25));
            Avalonia.Threading.Dispatcher.UIThread.PushFrame(frame);
        }
    }

    static void VerifyExitButtonWire()
    {
        var originalPreview = Program.Preview;
        var originalStandalone = Program.StandaloneTasks;
        var originalOutput = Console.Out;
        Dashboard? fixture = null;
        using var wire = new System.IO.StringWriter();
        try
        {
            // Standalone construction skips the backend reader. Never show this
            // fixture: its button writes only to the captured synthetic pipe.
            Program.Preview = false; Program.StandaloneTasks = true;
            Console.SetOut(wire);
            fixture = new Dashboard();
            fixture.programExitButton.RaiseEvent(new Avalonia.Interactivity.RoutedEventArgs(Button.ClickEvent));
            var requests = wire.ToString().Split('\n', StringSplitOptions.RemoveEmptyEntries);
            if (requests.Length != 1 || fixture.programExitButton.Flyout != null || !fixture.programExitAwaiting || fixture.bodyScroll.IsEnabled || fixture.programExitButton.IsEnabled)
                throw new InvalidOperationException("first footer click must directly request exit once and disable mutations");
            using var request = JsonDocument.Parse(requests[0]);
            var id = request.RootElement.GetProperty("id").GetString();
            if (request.RootElement.GetProperty("action").GetString() != "exit-program" || !Guid.TryParseExact(id, "N", out _) || id != fixture.programExitID)
                throw new InvalidOperationException("footer exit must use the authenticated exit request protocol");
            fixture.programExitButton.RaiseEvent(new Avalonia.Interactivity.RoutedEventArgs(Button.ClickEvent));
            if (wire.ToString().Split('\n', StringSplitOptions.RemoveEmptyEntries).Length != 1)
                throw new InvalidOperationException("repeat click while awaiting cannot dispatch another exit");
            using var ready = JsonDocument.Parse(JsonSerializer.Serialize(new { @event = "status", program_exit = new { phase = "ready", request_id = id } }));
            fixture.Update(ready.RootElement);
            requests = wire.ToString().Split('\n', StringSplitOptions.RemoveEmptyEntries);
            if (requests.Length != 2) throw new InvalidOperationException("ready must send exactly one separate commit");
            using var commit = JsonDocument.Parse(requests[1]);
            if (commit.RootElement.GetProperty("action").GetString() != "exit-program-commit" || commit.RootElement.GetProperty("id").GetString() != id)
                throw new InvalidOperationException("direct footer click must preserve the restore-then-commit protocol");
        }
        finally
        {
            if (fixture != null) { fixture.backendEnded = true; fixture.CancelProgramExitConfirmation(); fixture.Close(); }
            Console.SetOut(originalOutput);
            Program.Preview = originalPreview; Program.StandaloneTasks = originalStandalone;
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
