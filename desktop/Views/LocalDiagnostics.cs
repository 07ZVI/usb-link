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
    string photoIsolationPendingID = "", photoIsolationMessage = "照片介面隔離尚未就緒。";
    bool connectionArchiveActive, connectionArchiveNeedsAttention;
    string connectionArchiveMessage = "等待本輪檔案狀態。";
    bool localUSBTracePresent, localUSBTraceNeedsAttention;
    string localUSBTraceMessage = "";
    System.Action? localDiagnosticsRefresh;

    Control LocalDiagnosticsSection()
    {
        var toggle = Switch();
        toggle.IsChecked = localDiagnosticsEnabled;
        Avalonia.Automation.AutomationProperties.SetName(toggle, "開發者調試");
        var status = Label("", 12, key: "Muted");
        status.TextWrapping = TextWrapping.Wrap;
        Avalonia.Automation.AutomationProperties.SetName(status, "開發者調試狀態");
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
        var photoRecoveryStatus = Label("", 12, key: "Muted");
        photoRecoveryStatus.TextWrapping = TextWrapping.Wrap;
        Avalonia.Automation.AutomationProperties.SetName(photoRecoveryStatus, "照片介面恢復狀態");
        var experiments = new Expander
        {
            Header = "連線實驗", IsExpanded = false, HorizontalAlignment = Avalonia.Layout.HorizontalAlignment.Stretch,
            Content = Column(10,
                WithWrap(Label("NCM Direct 為進階對照功能，預設不啟用。日常網路所需的 Apple 服務與照片介面策略由程式自動管理。", 12, key: "Muted"), 680),
                TrustExperimentControls()),
        };
        var tools = Column(10, experiments,
            new Expander { Header = "完整診斷文字", IsExpanded = false, HorizontalAlignment = Avalonia.Layout.HorizontalAlignment.Stretch, Content = Column(8, text, Row(8, copy, export)) });
        var experimentRecoveryStatus = TrustExperimentRecoveryStatus();
        var wpdStatus = Label("", 12, key: "Muted");
        wpdStatus.TextWrapping = TextWrapping.Wrap;
        Avalonia.Automation.AutomationProperties.SetName(wpdStatus, "WPD 自動診斷狀態");
        var archiveStatus = Label("", 12, key: "Muted");
        archiveStatus.TextWrapping = TextWrapping.Wrap;
        Avalonia.Automation.AutomationProperties.SetName(archiveStatus, "連線檔案採集狀態");
        var usbStatus = Label("", 12, key: "Muted");
        usbStatus.TextWrapping = TextWrapping.Wrap;
        Avalonia.Automation.AutomationProperties.SetName(usbStatus, "USB 事件採集狀態");
        void Refresh()
        {
            tools.IsVisible = localDiagnosticsPendingID != "" ? localDiagnosticsRequested : localDiagnosticsEnabled;
            toggle.IsChecked = localDiagnosticsPendingID != "" ? localDiagnosticsRequested : localDiagnosticsEnabled;
            toggle.IsEnabled = localDiagnosticsAvailable;
            if (localDiagnosticsMessage != "") status.Text = (localDiagnosticsDeliveryFailureID != "" ? LocalControlDeliveryFailure + "\n" : "") + localDiagnosticsMessage;
            if (tools.IsVisible && text.Text != detailText) text.Text = detailText;
            copy.IsEnabled = export.IsEnabled = tools.IsVisible && !string.IsNullOrWhiteSpace(detailText);
            wpdStatus.Text = "WPD 自動診斷：" + automaticWpd.Message
                + (!localDiagnosticsEnabled && automaticWpd.Effective ? " 總開關已關閉，等待停止確認。" : "");
            wpdStatus.IsVisible = localDiagnosticsEnabled || automaticWpd.Busy || automaticWpd.Effective || automaticWpd.NeedsAttention;
            usbStatus.Text = "USB 事件：" + localUSBTraceMessage;
            usbStatus.IsVisible = localUSBTracePresent;
            usbStatus.Res(TextBlock.ForegroundProperty, localUSBTraceNeedsAttention ? "Warn" : "Muted");
            archiveStatus.Text = "連線檔案：" + connectionArchiveMessage;
            archiveStatus.IsVisible = localDiagnosticsEnabled || connectionArchiveActive || connectionArchiveNeedsAttention;
            archiveStatus.Res(TextBlock.ForegroundProperty, connectionArchiveNeedsAttention ? "Warn" : "Muted");
            photoRecoveryStatus.Text = "照片介面恢復：" + photoIsolationMessage;
            photoRecoveryStatus.IsVisible = photoIsolationBusy || photoIsolationPendingID != "" || photoIsolationNeedsAttention || photoIsolationDeliveryFailureID != "" || (!localDiagnosticsEnabled && photoIsolationEffective);
            localTrustExperimentRefresh?.Invoke();
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
            WithWrap(Label("WPD 照片服務與 USB 事件診斷隨總開關自動啟停。新採集只保存經隱私檢查的摘要，舊原始記錄保留在本機。", 12, key: "Muted"), 680),
            status, wpdStatus, usbStatus, archiveStatus, photoRecoveryStatus, experimentRecoveryStatus, tools));
    }

    void UpdateLocalDiagnostics(JsonElement d)
    {
        UpdateConnectionTiming(d);
        UpdatePhotoIsolation(d);
        UpdateLocalTrustExperiments(d);
        UpdateConnectionArchive(d);
        UpdateLocalUSBTrace(d);
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
        photoIsolationNeedsAttention = error != "" || persistence == "failed" || phase is "recovering" or "recovery_pending" or "recovery_required" or "recovery_failed" or "stopping";
        photoIsolationMessage = persistence == "failed" ? "照片介面隔離設定保存或讀取失敗，下次可能恢復先前設定：" + error
            : error != "" ? "照片介面隔離尚未完成：" + error
            : !photoIsolationAvailable ? "照片介面隔離尚未就緒。"
            : Text("rejected_error") != "" ? "照片介面隔離設定未變更：" + Text("rejected_error")
            : persistence is "loading" or "saving" || photoIsolationPendingID != "" ? "正在讀取或儲存照片介面隔離設定…"
            : phase is "recovering" or "recovery_pending" or "recovery_required" or "recovery_failed" or "stopping" ? "正在恢復照片介面，尚未確認完成。"
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
            : persistence == "automatic" && mode == "fast" ? "快速偵測由背景程式自動執行。"
            : mode is not ("fast" or "delayed") ? "目前使用一般流程，未啟用時序對照。"
            : phase == "delaying" ? "延遲對照進行中，模式切換前額外等待 12 秒。"
            : mode == "fast" ? "快速偵測已開啟，後續接入持續使用；設定已保存。"
            : "快速偵測及延遲 12 秒對照已開啟，後續接入持續使用；設定已保存。";
    }

    void UpdateLocalUSBTrace(JsonElement d)
    {
        localUSBTracePresent = d.TryGetProperty("local_usb_trace", out var state) && state.ValueKind == JsonValueKind.Object;
        localUSBTraceNeedsAttention = false;
        localUSBTraceMessage = "";
        if (!localUSBTracePresent) return;
        bool Flag(string key) => state.TryGetProperty(key, out var v) && v.ValueKind == JsonValueKind.True;
        string Text(string key) => state.TryGetProperty(key, out var v) && v.ValueKind == JsonValueKind.String ? v.GetString() ?? "" : "";
        ulong Count(string key) => state.TryGetProperty(key, out var v) && v.ValueKind == JsonValueKind.Number && v.TryGetUInt64(out var n) ? n : 0;
        var phase = Text("phase");
        var failures = new List<string>();
        foreach (var (key, label) in new[] { ("queue_overflow", "佇列漏記"), ("schema_rejected", "格式或隱私檢查未通過"), ("events_lost", "事件遺失"), ("realtime_buffers_lost", "緩衝記錄遺失"), ("archive_rejected", "未收錄到檔案"), ("late_events", "觀察結束後到達"), ("timestamp_unknown", "事件時間無法確認"), ("invalid_header_callbacks", "事件標頭無效"), ("known_provider_shape_rejected", "USB 事件結構未通過"), ("known_provider_template_rejected", "USB 事件格式未通過"), ("known_provider_scalar_rejected", "USB 事件欄位未通過") })
            if (Count(key) is var n && n != 0) failures.Add($"{label} {n}");
        localUSBTraceNeedsAttention = Text("coverage") == "incomplete" || Text("error") != "" || failures.Count != 0 || phase is "error" or "recovery_pending";
        var uncovered = Count("accepted") == 0 && failures.Count == 0 && (Text("coverage") == "not_covered" || phase == "no_safe_event_schema");
        localUSBTraceMessage = uncovered && Count("session_metadata_callbacks") > 0 && Count("received") == 0 ? "未覆蓋：僅收到會話元資料，尚無 USB 事件。"
            : uncovered && (phase == "no_safe_event_schema" || Text("error") == "USB_TRACE_NO_SAFE_EVENT_SCHEMA") ? "未覆蓋：未找到可通過格式及隱私檢查的事件。"
            : uncovered && (phase != "disabled" || Text("error") != "") ? "未覆蓋：尚未取得可用的事件證據。"
            : localUSBTraceNeedsAttention ? "證據不完整。"
            : !Flag("available") ? "未覆蓋：此環境尚未提供採集能力。"
            : phase == "disabled" ? "採集已關閉。"
            : phase == "discovering" ? "正在核對可安全記錄的事件，尚未確認覆蓋。"
            : phase == "no_safe_event_schema" ? "未覆蓋：未找到可通過格式及隱私檢查的事件。"
            : Text("coverage") == "metadata_only" && Count("accepted") > 0 ? "事件元資料可用，僅包含通過隱私檢查的摘要。"
            : "未覆蓋有效事件；採集啟動不代表已取得證據。";
        if (Text("error") is var error && error != "") localUSBTraceMessage += " 原因：" + error + "。";
        if (phase == "recovery_pending") localUSBTraceMessage += " 停止結果尚未確認。";
        if (failures.Count != 0) localUSBTraceMessage += " " + string.Join("、", failures) + "。";
        localUSBTraceMessage += $" 已接收 USB 事件 {Count("received")}、已收錄 {Count("accepted")}。";
        if (Count("callbacks_received") > 0) localUSBTraceMessage += $" 回呼 {Count("callbacks_received")}；會話元資料 {Count("session_metadata_callbacks")}（標頭 {Count("session_header_callbacks")}）；未知來源 {Count("unknown_provider_callbacks")}。";
        string TimeText(string key) => DateTimeOffset.TryParse(Text(key), System.Globalization.CultureInfo.InvariantCulture, System.Globalization.DateTimeStyles.RoundtripKind, out var t) ? t.ToLocalTime().ToString("MM-dd HH:mm:ss") : "";
        var started = TimeText("started_utc");
        var stopped = TimeText("stopped_utc");
        if (started != "") localUSBTraceMessage += " 觀察時段：" + started + " 至 " + (stopped != "" ? stopped : Flag("active") ? "目前" : "結束時間待確認") + "。";
        if (TimeText("last_event_utc") is var last && last != "") localUSBTraceMessage += " 最近事件：" + last + "。";
        localUSBTraceMessage += " 未覆蓋配對或實際信任提示；系統事件尚不能歸因到這台 iPad，也不能據此判定是哪個應用觸發。";
    }

    void UpdateConnectionArchive(JsonElement d)
    {
        if (!d.TryGetProperty("connection_archive", out var state) || state.ValueKind != JsonValueKind.Object) return;
        string Text(string key) => state.TryGetProperty(key, out var v) && v.ValueKind == JsonValueKind.String ? v.GetString() ?? "" : "";
        ulong Count(string key) => state.TryGetProperty(key, out var v) && v.ValueKind == JsonValueKind.Number && v.TryGetUInt64(out var count) ? count : 0;
        var available = state.TryGetProperty("available", out var ready) && ready.ValueKind == JsonValueKind.True;
        var phase = Text("phase");
        var error = Text("error");
        connectionArchiveActive = phase == "recording" && Text("current_id") != "";
        var failures = new List<string>();
        foreach (var (key, label) in new[] { ("queue_dropped", "佇列漏記"), ("size_dropped", "容量限制漏記"), ("write_failures", "寫入失敗"), ("rejected", "記錄拒絕"), ("cancelled_events", "停止後未收錄"), ("retention_failures", "舊檔清理失敗"), ("partial_tails", "未完整寫入的檔案") })
            if (Count(key) is var count && count != 0) failures.Add($"{label} {count}");
        connectionArchiveNeedsAttention = error != "" || phase == "write_failed" || failures.Count != 0;
        connectionArchiveMessage = error != "" ? "記錄尚未完成：" + error
            : phase == "write_failed" ? "檔案寫入失敗，採集結果尚未確認。"
            : !available ? "檔案記錄尚未就緒。"
            : connectionArchiveActive ? "本輪檔案記錄中，會隨 Mac 診斷自動收取。"
            : phase == "recording" ? "等待新一輪連線記錄，檔案會隨 Mac 診斷自動收取。"
            : phase == "stopped" ? "檔案記錄已停止，封存結果以每輪檔案為準。"
            : "檔案狀態待確認。";
        if (failures.Count != 0) connectionArchiveMessage += " 累計：" + string.Join("、", failures) + "；採集可能不完整。";
        if (Count("redacted") is var redacted && redacted != 0) connectionArchiveMessage += $" 已隱去 {redacted} 項敏感內容。";
        connectionArchiveMessage += " 檔案封存不代表 USB 或照片服務事件已完整覆蓋。";
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
            default:
                if (!UpdateTrustExperimentDeliveryFailure(Text("action"), id)) return;
                break;
        }
        localDiagnosticsRefresh?.Invoke();
    }

    string LocalDiagnosticsText() => $"USB Link · {versionText.Text}\n本地診斷快照 · {DateTimeOffset.Now:O}\n\n{detailText}";

    static void SendDeveloperDebug(bool enabled, string id) => DesktopClient.Send(new
    {
        action = enabled ? "local-usb-update-on" : "local-usb-update-off", id,
    });




}
#endif
