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
    bool photoIsolationAvailable, photoIsolationRequested, photoIsolationEffective, photoIsolationBusy, photoIsolationNeedsAttention;
    string photoIsolationPendingID = "", photoIsolationMessage = "照片介面隔離尚未就緒。";
    System.Action? localDiagnosticsRefresh;

    Control LocalDiagnosticsSection()
    {
        var toggle = Switch();
        toggle.IsChecked = localDiagnosticsEnabled;
        Avalonia.Automation.AutomationProperties.SetName(toggle, "開發者調試");
        var status = Hint("");
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
        var photoRecoveryStatus = Hint("");
        Avalonia.Automation.AutomationProperties.SetName(photoRecoveryStatus, "照片介面恢復狀態");
        var experiments = new Expander
        {
            Header = "連線實驗", IsExpanded = false, HorizontalAlignment = Avalonia.Layout.HorizontalAlignment.Stretch,
            Content = Column(10,
                Hint("NCM Direct 為進階對照功能，預設不啟用。日常網路所需的 Apple 服務與照片介面策略由程式自動管理。"),
                TrustExperimentControls()),
        };
        var tools = Column(10, experiments,
            new Expander { Header = "完整診斷文字", IsExpanded = false, HorizontalAlignment = Avalonia.Layout.HorizontalAlignment.Stretch, Content = Column(8, text, Row(8, copy, export)) });
        var experimentRecoveryStatus = TrustExperimentRecoveryStatus();
        void Refresh()
        {
            tools.IsVisible = localDiagnosticsPendingID != "" ? localDiagnosticsRequested : localDiagnosticsEnabled;
            toggle.IsChecked = localDiagnosticsPendingID != "" ? localDiagnosticsRequested : localDiagnosticsEnabled;
            toggle.IsEnabled = localDiagnosticsAvailable;
            if (localDiagnosticsMessage != "") status.Text = (localDiagnosticsDeliveryFailureID != "" ? LocalControlDeliveryFailure + "\n" : "") + localDiagnosticsMessage;
            if (tools.IsVisible && text.Text != detailText) text.Text = detailText;
            copy.IsEnabled = export.IsEnabled = tools.IsVisible && !string.IsNullOrWhiteSpace(detailText);
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
        return Section.Make("開發者調試", "開啟後可查看完整診斷，並允許 Mac 經 USB 推送已簽名的新版完整安裝包；關閉會撤銷推送授權。安裝時會中斷連線，Windows 仍保留管理員確認。開關狀態會保存，背景程式重啟後會恢復。",
            Column(10, status, photoRecoveryStatus, experimentRecoveryStatus, tools), toggle);
    }

    void UpdateLocalDiagnostics(JsonElement d)
    {
        UpdatePhotoIsolation(d);
        UpdateLocalTrustExperiments(d);
        UpdateMacMtuCap(d);
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
                if (!UpdateTrustExperimentDeliveryFailure(Text("action"), id) && !UpdateMacMtuCapDeliveryFailure(Text("action"), id)) return;
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
