#if USBLINK_LOCAL_DIAGNOSTICS
using System.Text;
using System.Text.Json;
using Avalonia;
using Avalonia.Controls;
using Avalonia.Media;
using Avalonia.Platform.Storage;

namespace Suhang.Desktop;

public sealed partial class Dashboard
{
    bool localDiagnosticsEnabled, localDiagnosticsBusy, localDiagnosticsAvailable = true;
    bool localDiagnosticsRequested;
    string localDiagnosticsPendingID = "", localDiagnosticsMessage = "";
    string localDiagnosticsDeliveryFailureID = "", photoIsolationDeliveryFailureID = "";
    const string LocalControlDeliveryFailure = "操作回報未能取得（CORE_UI_ACTION_FAILED）；尚未確認是否執行，開關依後台狀態顯示，可重試。";
    bool connectionTimingAvailable;
    string connectionTimingMode = "normal";
    string connectionTimingMessage = "目前未啟用時序對照。";
    bool photoIsolationAvailable, photoIsolationRequested, photoIsolationEffective, photoIsolationBusy, photoIsolationNeedsAttention;
    bool photoIsolationPendingEnabled;
    string photoIsolationPendingID = "", photoIsolationMessage = "照片介面隔離尚未就緒。";
    System.Action? localDiagnosticsRefresh;

    Control LocalDiagnosticsSection()
    {
        var toggle = Switch();
        toggle.IsChecked = localDiagnosticsEnabled;
        Avalonia.Automation.AutomationProperties.SetName(toggle, "開發者調試");
        var status = Label("", 12, key: "Muted");
        status.TextWrapping = TextWrapping.Wrap;
        var text = new TextBox { IsReadOnly = true, AcceptsReturn = true, TextWrapping = TextWrapping.Wrap, MinHeight = 120, MaxHeight = 300 };
        Avalonia.Automation.AutomationProperties.SetName(text, "完整診斷文字");
        var copy = Action("複製診斷", async () =>
        {
            var snapshot = LocalDiagnosticsText();
            try
            {
                var clipboard = (detailWindow ?? this).Clipboard;
                if (clipboard == null) { status.Text = "目前無法使用剪貼簿。"; return; }
                await clipboard.SetTextAsync(snapshot);
                status.Text = "已複製目前診斷內容。";
            }
            catch { status.Text = "複製失敗，請重試或匯出檔案。"; }
        }, Icons.Copy);
        var export = Action("匯出診斷文字…", async () =>
        {
            var snapshot = LocalDiagnosticsText();
            try
            {
                var storage = (detailWindow ?? this).StorageProvider;
                if (!storage.CanSave) { status.Text = "目前無法開啟儲存視窗。"; return; }
                var file = await storage.SaveFilePickerAsync(new FilePickerSaveOptions
                {
                    Title = "匯出本地診斷", SuggestedFileName = $"USB-Link-diagnostics-{DateTime.Now:yyyyMMdd-HHmmss}.txt",
                    DefaultExtension = "txt", ShowOverwritePrompt = true,
                    FileTypeChoices = new[] { new FilePickerFileType("文字檔案") { Patterns = new[] { "*.txt" } } },
                });
                if (file == null) return;
                using (file)
                await using (var stream = await file.OpenWriteAsync())
                {
                    stream.SetLength(0);
                    await using var writer = new StreamWriter(stream, new UTF8Encoding(false));
                    await writer.WriteAsync(snapshot);
                }
                status.Text = "已匯出目前診斷內容。";
            }
            catch { status.Text = "匯出失敗，請確認目的資料夾可寫入後重試。"; }
        });
        var markerStatus = Label("", 12, key: "Muted");
        markerStatus.TextWrapping = TextWrapping.Wrap;
        Avalonia.Automation.AutomationProperties.SetName(markerStatus, "信任提示人工標記狀態");
        Button Marker(int ordinal)
        {
            var title = $"標記第 {ordinal} 次信任提示";
            var button = Action(title, () =>
            {
                if (preview) { markerStatus.Text = "介面預覽，未傳送人工標記。"; return; }
                try
                {
                    SendManualTrustPrompt(ordinal);
                    markerStatus.Text = $"已傳送第 {ordinal} 次提示的人工標記（點擊時間 {DateTimeOffset.Now:HH:mm:ss.fff zzz}）。";
                }
                catch { markerStatus.Text = "人工標記未能傳送，請重試。"; }
            });
            Avalonia.Automation.AutomationProperties.SetName(button, title);
            return button;
        }
        var trialStatus = Label("", 12, key: "Muted");
        trialStatus.TextWrapping = TextWrapping.Wrap;
        Avalonia.Automation.AutomationProperties.SetName(trialStatus, "Apple 服務臨時對照請求狀態");
        Button ServiceTrial(bool cancel)
        {
            var title = cancel ? "取消並恢復 Apple 服務" : "開始 Apple 服務臨時對照";
            var button = Action(title, () =>
            {
                if (preview) { trialStatus.Text = "介面預覽，未傳送服務對照請求。"; return; }
                try
                {
                    SendTrustServiceTrial(cancel);
                    trialStatus.Text = cancel
                        ? "已傳送取消並恢復請求；實際恢復結果請查看診斷提示。"
                        : "已傳送開始請求；請等待診斷提示，再依提示先拔下、再插入 iPad。";
                }
                catch { trialStatus.Text = "服務對照請求未能傳送，請重試。"; }
            });
            Avalonia.Automation.AutomationProperties.SetName(button, title);
            return button;
        }
        var timingStatus = Label("", 12, key: "Muted");
        timingStatus.TextWrapping = TextWrapping.Wrap;
        Avalonia.Automation.AutomationProperties.SetName(timingStatus, "信任提示時序對照狀態");
        var fastTiming = Switch();
        var delayedTiming = Switch();
        Avalonia.Automation.AutomationProperties.SetName(fastTiming, "快速偵測");
        Avalonia.Automation.AutomationProperties.SetName(delayedTiming, "延遲切換對照（12 秒）");
        void SetTiming(string mode)
        {
            if (preview)
            {
                connectionTimingMode = mode;
                connectionTimingMessage = "介面預覽，未傳送時序對照請求。";
                localDiagnosticsRefresh?.Invoke();
                return;
            }
            try
            {
                SendConnectionTimingTrial(mode);
                timingStatus.Text = "正在儲存時序對照設定，等待背景回報。";
            }
            catch { timingStatus.Text = "時序對照設定未能傳送，請重試。"; }
        }
        fastTiming.Click += (_, _) => SetTiming(fastTiming.IsChecked == true ? "fast" : "normal");
        delayedTiming.Click += (_, _) => SetTiming(delayedTiming.IsChecked == true ? "delayed" : "fast");
        var photoIsolation = Switch();
        Avalonia.Automation.AutomationProperties.SetName(photoIsolation, "照片介面隔離");
        var photoStatus = Label("", 12, key: "Muted");
        photoStatus.TextWrapping = TextWrapping.Wrap;
        Avalonia.Automation.AutomationProperties.SetName(photoStatus, "照片介面隔離狀態");
        var photoRecoveryStatus = Label("", 12, key: "Muted");
        photoRecoveryStatus.TextWrapping = TextWrapping.Wrap;
        Avalonia.Automation.AutomationProperties.SetName(photoRecoveryStatus, "照片介面恢復狀態");
        photoIsolation.Click += (_, _) =>
        {
            var enabled = photoIsolation.IsChecked == true;
            if (preview) { photoIsolationRequested = enabled; photoIsolationMessage = "介面預覽，未傳送照片介面隔離請求。"; localDiagnosticsRefresh?.Invoke(); return; }
            var id = Guid.NewGuid().ToString("N");
            photoIsolationPendingID = id;
            photoIsolationDeliveryFailureID = "";
            photoIsolationPendingEnabled = enabled;
            photoIsolationMessage = enabled ? "正在儲存照片介面隔離設定…" : "正在關閉照片介面隔離，等待恢復結果…";
            localDiagnosticsRefresh?.Invoke();
            try { SendPhotoIsolation(enabled, id); }
            catch { photoIsolationPendingID = ""; photoIsolationMessage = "照片介面隔離設定未能傳送，請重試。"; localDiagnosticsRefresh?.Invoke(); }
        };
        var tools = Column(10,
            WithWrap(Label("看到 iPad「信任此電腦」提示時，點擊對應按鈕，用於粗略對齊時序。這是人工標記；反應與傳送有延遲，點擊時間不等於系統彈窗時間。", 12, key: "Muted"), 680),
            Row(8, Marker(1), Marker(2)), markerStatus,
            WithWrap(Label("信任提示時序對照不更改 Apple 服務。快速偵測開啟後使用 1 秒兜底檢查；再開啟延遲對照，每次接入會額外等待 12 秒。設定會保存並持續生效，直到手動關閉。關閉開發者調試會停用對照，重新開啟時恢復已保存的選擇。", 12, key: "Muted"), 680),
            Columns("*,Auto", Label("快速偵測", 13), fastTiming),
            Columns("*,Auto", Label("延遲切換對照（12 秒）", 13), delayedTiming), timingStatus,
            Columns("*,Auto", Label("照片介面隔離", 13), photoIsolation),
            WithWrap(Label("開啟後暫停這台 iPad 的 Windows USB 照片匯入，設定會保存；只在開發者調試開啟時生效。關閉此開關或開發者調試會恢復照片介面。不能保證消除所有信任提示。", 12, key: "Muted"), 680), photoStatus,
            WithWrap(Label("臨時停止 Apple Mobile Device Service，會暫停或中斷 iTunes／Apple Devices 的同步與備份，不更改啟動類型；請先結束同步與備份。對照及恢復預算共 120 秒；若恢復失敗，將保留恢復記錄並暫停 iPad 連線，以診斷結果為準。開始後等待診斷提示，再先拔下、後插入 iPad。", 12, key: "Muted"), 680),
            Row(8, ServiceTrial(false), ServiceTrial(true)), trialStatus,
            text, Row(8, copy, export));
        void Refresh()
        {
            tools.IsVisible = localDiagnosticsPendingID != "" ? localDiagnosticsRequested : localDiagnosticsEnabled;
            toggle.IsChecked = localDiagnosticsPendingID != "" ? localDiagnosticsRequested : localDiagnosticsEnabled;
            toggle.IsEnabled = localDiagnosticsAvailable;
            if (localDiagnosticsMessage != "") status.Text = (localDiagnosticsDeliveryFailureID != "" ? LocalControlDeliveryFailure + "\n" : "") + localDiagnosticsMessage;
            if (tools.IsVisible && text.Text != detailText) text.Text = detailText;
            copy.IsEnabled = export.IsEnabled = tools.IsVisible && !string.IsNullOrWhiteSpace(detailText);
            fastTiming.IsChecked = connectionTimingMode is "fast" or "delayed";
            delayedTiming.IsChecked = connectionTimingMode == "delayed";
            fastTiming.IsEnabled = preview || connectionTimingAvailable;
            delayedTiming.IsEnabled = (preview || connectionTimingAvailable) && fastTiming.IsChecked == true;
            timingStatus.Text = connectionTimingMessage;
            photoIsolation.IsChecked = photoIsolationPendingID != "" ? photoIsolationPendingEnabled : photoIsolationRequested;
            photoIsolation.IsEnabled = localDiagnosticsEnabled && (preview || photoIsolationAvailable) && photoIsolationPendingID == "" && (!photoIsolationBusy || photoIsolationRequested);
            photoStatus.Text = photoRecoveryStatus.Text = (photoIsolationDeliveryFailureID != "" ? LocalControlDeliveryFailure + "\n" : "") + photoIsolationMessage;
            photoRecoveryStatus.IsVisible = !tools.IsVisible && (photoIsolationBusy || photoIsolationEffective || photoIsolationNeedsAttention);
        }
        toggle.Click += (_, _) =>
        {
            var enabled = toggle.IsChecked == true;
            if (preview) { localDiagnosticsEnabled = enabled; Refresh(); return; }
            var id = Guid.NewGuid().ToString("N");
            localDiagnosticsPendingID = id;
            localDiagnosticsDeliveryFailureID = "";
            localDiagnosticsRequested = enabled;
            localDiagnosticsMessage = "正在儲存開發者調試設定…";
            Refresh();
            try { SendDeveloperDebug(enabled, id); }
            catch { localDiagnosticsPendingID = ""; localDiagnosticsMessage = "設定未能傳送，請重試。"; Refresh(); }
        };
        localDiagnosticsRefresh = Refresh;
        Refresh();
        return Card(Column(12,
            Columns("*,Auto", Label("開發者調試", 15, FontWeight.SemiBold), toggle),
            WithWrap(Label("開啟後可查看完整診斷，並允許 Mac 經 USB 推送已簽名的新版完整安裝包；關閉會撤銷推送授權。安裝時會中斷連線，Windows 仍保留管理員確認。開關狀態會保存，背景程式重啟後會恢復；USB 安裝通道會在背景準備。", 12, key: "Muted"), 680),
            status, photoRecoveryStatus, tools));
    }

    void UpdateLocalDiagnostics(JsonElement d)
    {
        UpdateConnectionTiming(d);
        UpdatePhotoIsolation(d);
        if (!d.TryGetProperty("developer_debug", out var debug) || debug.ValueKind != JsonValueKind.Object) { localDiagnosticsRefresh?.Invoke(); return; }
        bool Flag(string name) => debug.TryGetProperty(name, out var v) && v.ValueKind == JsonValueKind.True;
        string Text(string name) => debug.TryGetProperty(name, out var v) && v.ValueKind == JsonValueKind.String ? v.GetString() ?? "" : "";
        localDiagnosticsAvailable = Flag("available");
        localDiagnosticsBusy = Flag("busy");
        var persistence = Text("persistence");
        var phase = Text("usb_phase");
        if (localDiagnosticsDeliveryFailureID != "" && Text("request_id") == localDiagnosticsDeliveryFailureID &&
            (persistence is "saved" or "failed" || (persistence == "" && !localDiagnosticsBusy)))
            localDiagnosticsDeliveryFailureID = "";
        if (localDiagnosticsPendingID != "" && Text("request_id") == localDiagnosticsPendingID &&
            (persistence is "saved" or "failed" || (persistence == "" && !localDiagnosticsBusy)))
            localDiagnosticsPendingID = "";
        if (localDiagnosticsPendingID == "") localDiagnosticsEnabled = Flag("enabled");
        localDiagnosticsMessage = !localDiagnosticsAvailable ? "開發者調試尚未就緒。"
            : persistence == "failed" ? "開關狀態保存失敗，下次可能恢復先前設定。" + Text("error")
            : persistence == "loading" ? "正在讀取已保存的開發者調試設定…"
            : localDiagnosticsPendingID != "" || persistence == "saving" ? "正在儲存開發者調試設定，診斷內容可先使用。"
            : phase == "revoking" ? "開發者調試已關閉，正在完成 USB 推送授權清理…"
            : phase == "preparing" ? "開發者調試已開啟，USB 安裝通道準備中；診斷內容可先使用。"
            : phase == "waiting_usb" ? "開發者調試已開啟，等待 Mac USB 連線以啟用安裝通道。"
            : phase == "failed" || Text("error") != "" ? "診斷內容可使用，USB 安裝通道未就緒：" + Text("error")
            : phase == "ready" && Flag("usb_ready") ? "開發者調試已開啟，USB 推送安裝已就緒；設定已保存。"
            : localDiagnosticsEnabled ? "開發者調試已開啟，USB 安裝通道正在確認。" : "開發者調試已關閉，USB 推送安裝已撤銷。";
        localDiagnosticsRefresh?.Invoke();
    }

    void UpdatePhotoIsolation(JsonElement d)
    {
        if (!d.TryGetProperty("photo_isolation", out var state) || state.ValueKind != JsonValueKind.Object) return;
        bool Flag(string key) => state.TryGetProperty(key, out var v) && v.ValueKind == JsonValueKind.True;
        string Text(string key) => state.TryGetProperty(key, out var v) && v.ValueKind == JsonValueKind.String ? v.GetString() ?? "" : "";
        int Count(string key) => state.TryGetProperty(key, out var v) && v.ValueKind == JsonValueKind.Number && v.TryGetInt32(out var n) ? Math.Max(0, n) : 0;
        photoIsolationAvailable = Flag("available");
        if (photoIsolationPendingID != "" && Text("rejected_id") == photoIsolationPendingID) photoIsolationPendingID = "";
        if (photoIsolationPendingID != "" && Text("request_id") != photoIsolationPendingID) return;
        photoIsolationBusy = Flag("busy");
        photoIsolationEffective = Flag("effective");
        var persistence = Text("persistence");
        if (photoIsolationDeliveryFailureID != "" &&
            (Text("rejected_id") == photoIsolationDeliveryFailureID || Text("request_id") == photoIsolationDeliveryFailureID &&
            (persistence is "saved" or "failed" || (persistence == "" && !photoIsolationBusy))))
            photoIsolationDeliveryFailureID = "";
        if (photoIsolationPendingID != "" && (persistence is "saved" or "failed" || (persistence == "" && !photoIsolationBusy))) photoIsolationPendingID = "";
        if (photoIsolationPendingID == "") photoIsolationRequested = Flag("requested");
        var phase = Text("phase");
        var error = Text("error");
        photoIsolationNeedsAttention = error != "" || persistence == "failed" || phase == "recovery_pending";
        photoIsolationMessage = !photoIsolationAvailable ? "照片介面隔離尚未就緒。"
            : persistence == "failed" ? "照片介面隔離設定保存或讀取失敗，下次可能恢復先前設定：" + error
            : error != "" ? "照片介面隔離尚未完成：" + error
            : Text("rejected_error") != "" ? "照片介面隔離設定未變更：" + Text("rejected_error")
            : persistence is "loading" or "saving" || photoIsolationPendingID != "" ? "正在讀取或儲存照片介面隔離設定…"
            : phase is "recovering" or "recovery_pending" ? "正在恢復照片介面，尚未確認完成。"
            : photoIsolationBusy ? "正在核對照片介面狀態…"
            : photoIsolationEffective ? $"照片介面隔離已確認。目前觀察到 {Count("observed_nodes")} 個介面，其中 {Count("owned_nodes")} 個由本程式接管恢復。"
            : phase == "waiting_photo_interface" ? "隔離選擇已保存，正在等候可核對的照片介面；目前尚未確認隔離。"
            : Flag("saved_enabled") ? "照片介面隔離選擇已保存，目前未生效；等待開發者調試或 iPad 就緒。"
            : "照片介面隔離已關閉。";
    }

    void UpdateConnectionTiming(JsonElement d)
    {
        connectionTimingAvailable = d.TryGetProperty("connection_timing", out var timing) &&
            timing.ValueKind == JsonValueKind.Object && timing.TryGetProperty("available", out var available) && available.ValueKind == JsonValueKind.True;
        if (!connectionTimingAvailable) { connectionTimingMode = "normal"; connectionTimingMessage = "此版本的背景程式尚未提供時序對照。"; return; }
        var mode = timing.TryGetProperty("mode", out var selected) && selected.ValueKind == JsonValueKind.String ? selected.GetString() : "normal";
        connectionTimingMode = mode is "fast" or "delayed" ? mode : "normal";
        var phase = timing.TryGetProperty("phase", out var state) && state.ValueKind == JsonValueKind.String ? state.GetString() : "";
        var persistence = timing.TryGetProperty("persistence", out var saved) && saved.ValueKind == JsonValueKind.String ? saved.GetString() : "";
        var error = timing.TryGetProperty("persistence_error", out var problem) && problem.ValueKind == JsonValueKind.String ? problem.GetString() : "";
        connectionTimingMessage = persistence == "failed" ? "時序對照設定未能保存或恢復，下次可能使用先前選擇：" + error
            : persistence is "loading" or "saving" ? "正在讀取或儲存時序對照設定…"
            : mode is not ("fast" or "delayed") ? "目前使用一般流程，未啟用時序對照。"
            : phase == "delaying" ? "延遲對照進行中，模式切換前額外等待 12 秒。"
            : mode == "fast" ? "快速偵測已開啟，後續接入持續使用；設定已保存。"
            : "快速偵測及延遲 12 秒對照已開啟，後續接入持續使用；設定已保存。";
    }

    void UpdateLocalControlResult(JsonElement d)
    {
        string Text(string key) => d.TryGetProperty(key, out var v) && v.ValueKind == JsonValueKind.String ? v.GetString() ?? "" : "";
        var id = Text("request_id");
        if (Text("code") != "CORE_UI_ACTION_FAILED" || !Guid.TryParseExact(id, "N", out _)) return;
        switch (Text("action"))
        {
            case "local-usb-update-on" or "local-usb-update-off" when id == localDiagnosticsPendingID:
                localDiagnosticsPendingID = "";
                localDiagnosticsDeliveryFailureID = id;
                break;
            case "photo-isolation-on" or "photo-isolation-off" when id == photoIsolationPendingID:
                photoIsolationPendingID = "";
                photoIsolationDeliveryFailureID = id;
                break;
            default: return;
        }
        localDiagnosticsRefresh?.Invoke();
    }

    string LocalDiagnosticsText() => $"USB Link · {versionText.Text}\n本地診斷快照 · {DateTimeOffset.Now:O}\n\n{detailText}";

    static void SendDeveloperDebug(bool enabled, string id) => DesktopClient.Send(new
    {
        action = enabled ? "local-usb-update-on" : "local-usb-update-off", id,
    });

    static void SendPhotoIsolation(bool enabled, string id)
    {
        if (!Guid.TryParseExact(id, "N", out _)) throw new ArgumentException("invalid photo isolation request id", nameof(id));
        DesktopClient.Send(new { action = enabled ? "photo-isolation-on" : "photo-isolation-off", id });
    }

    static void SendManualTrustPrompt(int ordinal)
    {
        var action = ordinal switch
        {
            1 => "trust-prompt-first",
            2 => "trust-prompt-second",
            _ => throw new ArgumentOutOfRangeException(nameof(ordinal)),
        };
        DesktopClient.Send(new { action });
    }

    static void SendTrustServiceTrial(bool cancel) => DesktopClient.Send(new
    {
        action = cancel ? "trust-service-trial-cancel" : "trust-service-trial-start",
    });

    static void SendConnectionTimingTrial(string mode) => DesktopClient.Send(new
    {
        action = mode switch
        {
            "fast" => "trust-timing-fast",
            "delayed" => "trust-timing-delayed",
            "normal" => "trust-timing-reset",
            _ => throw new ArgumentOutOfRangeException(nameof(mode)),
        },
    });
}
#endif
