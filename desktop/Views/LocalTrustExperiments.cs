#if USBLINK_LOCAL_DIAGNOSTICS
using System.Text.Json;
using Avalonia;
using Avalonia.Controls;
using Avalonia.Controls.Primitives;
using Avalonia.Media;

namespace Suhang.Desktop;

public sealed partial class Dashboard
{
    sealed class TrustExperiment(string key, string action, string title, string help)
    {
        public readonly string Key = key, Action = action, Title = title, Help = help;
        public bool Available = Program.Preview;
        public bool Requested, Saved, Effective, Busy, PendingEnabled, NeedsAttention;
        public string PendingID = "", DeliveryFailureID = "", Message = "等待後台狀態。";
    }

    readonly TrustExperiment[] trustExperiments =
    [
        new("photo_policy", "photo-policy", "照片介面前置阻斷",
            "對已核對的這台 iPad 照片介面預先設定安裝限制，影響 Windows 照片匯入。需系統支援並可能要重新插入才生效；策略已就位不代表已阻斷。與「照片介面隔離」互斥；選中時退出背景程式仍保留策略，關閉此開關或開發者調試才恢復，可能需重新插入。"),
        new("ncm_direct", "ncm-direct", "NCM Direct（模式 5）",
            "下一輪接入嘗試只保留 NCM 網路介面，避開照片與配對介面；獨立核對設備、驅動及網路對端後才配置連線。仍是實驗功能，不能保證每次都零信任提示；失敗或關閉後可能需拔下再插入 iPad 恢復。模式 5 與 USB 配置 5 不同。"),
        new("amds_hold", "amds-hold", "Apple 服務屏蔽對照",
            "開啟時持續暫停 Apple Mobile Device Service，沒有自動到期；會中斷這台電腦上 iTunes／Apple Devices 的同步與備份，不改啟動類型。關閉此開關、開發者調試或退出背景程式時恢復原狀態；恢復完成以背景讀回為準。請先結束同步與備份。"),
    ];
    readonly TrustExperiment automaticWpd = new("wpd_trace", "", "WPD 自動診斷", "");
    System.Action? localTrustExperimentRefresh;

    Control TrustExperimentControls()
    {
        var controls = new List<Control>();
        var bindings = new List<(TrustExperiment state, ToggleSwitch toggle, TextBlock status)>();
        foreach (var experiment in trustExperiments.Where(e => e.Key == "ncm_direct"))
        {
            var toggle = Switch();
            Avalonia.Automation.AutomationProperties.SetName(toggle, experiment.Title);
            var status = Label("", 12, key: "Muted");
            status.TextWrapping = TextWrapping.Wrap;
            Avalonia.Automation.AutomationProperties.SetName(status, experiment.Title + "狀態");
            toggle.Click += (_, _) =>
            {
                var enabled = toggle.IsChecked == true;
                if (preview)
                {
                    experiment.Saved = experiment.Requested = enabled;
                    experiment.Message = "介面預覽，未傳送實驗設定。";
                }
                else
                {
                    experiment.PendingID = Guid.NewGuid().ToString("N");
                    experiment.PendingEnabled = enabled;
                    experiment.DeliveryFailureID = "";
                    experiment.Message = "正在儲存設定，等待背景回報…";
                    try { SendTrustExperiment(experiment.Action, enabled, experiment.PendingID); }
                    catch { experiment.PendingID = ""; experiment.Message = "設定未能傳送，請重試。"; }
                }
                localDiagnosticsRefresh?.Invoke();
            };
            bindings.Add((experiment, toggle, status));
            controls.Add(Columns("*,Auto", Label(experiment.Title, 13), toggle));
            controls.Add(WithWrap(Label(experiment.Help, 12, key: "Muted"), 680));
            controls.Add(status);
        }
        controls.Add(WithWrap(Label("此進階選擇會保存；只在開發者調試開啟時使用。關閉後可能需重新接入恢復普通模式。", 12, key: "Muted"), 680));
        localTrustExperimentRefresh = () =>
        {
            foreach (var (state, toggle, status) in bindings)
            {
                var selected = state.PendingID != "" ? state.PendingEnabled : state.Saved;
                toggle.IsChecked = selected;
                toggle.IsEnabled = localDiagnosticsEnabled && (state.Available || selected) && state.PendingID == "" && (!state.Busy || selected);
                status.Text = (state.DeliveryFailureID != "" ? LocalControlDeliveryFailure + "\n" : "") + state.Message;
            }
        };
        return Column(10, controls.ToArray());
    }

    Control TrustExperimentRecoveryStatus()
    {
        var status = Label("", 12, key: "Warn");
        status.TextWrapping = TextWrapping.Wrap;
        Avalonia.Automation.AutomationProperties.SetName(status, "本地實驗恢復狀態");
        var refresh = localTrustExperimentRefresh;
        localTrustExperimentRefresh = () =>
        {
            refresh?.Invoke();
            status.Text = string.Join("\n", trustExperiments.Where(e => e.NeedsAttention || e.Busy || e.PendingID != "" || e.DeliveryFailureID != "" || (!localDiagnosticsEnabled && e.Effective)).Select(e => e.Title + "：" + (e.DeliveryFailureID != "" ? LocalControlDeliveryFailure + " " : "") + e.Message));
            status.IsVisible = status.Text != "";
        };
        return status;
    }

    void UpdateLocalTrustExperiments(JsonElement d)
    {
        foreach (var experiment in trustExperiments.Append(automaticWpd))
        {
            if (!d.TryGetProperty(experiment.Key, out var state) || state.ValueKind != JsonValueKind.Object) continue;
            bool Flag(string key) => state.TryGetProperty(key, out var value) && value.ValueKind == JsonValueKind.True;
            string Text(string key) => state.TryGetProperty(key, out var value) && value.ValueKind == JsonValueKind.String ? value.GetString() ?? "" : "";
            int Number(string key) => state.TryGetProperty(key, out var value) && value.ValueKind == JsonValueKind.Number && value.TryGetInt32(out var number) ? number : -1;
            var requestID = Text("request_id");
            var rejectedID = Text("rejected_id");
            var persistence = Text("persistence");
            var completed = persistence is "saved" or "failed" || (persistence == "" && !Flag("busy"));
            if (experiment.DeliveryFailureID != "" && (rejectedID == experiment.DeliveryFailureID || requestID == experiment.DeliveryFailureID && completed)) experiment.DeliveryFailureID = "";
            if (experiment.PendingID != "" && rejectedID == experiment.PendingID) experiment.PendingID = "";
            if (experiment.PendingID != "" && requestID != experiment.PendingID) continue;
            experiment.Available = Flag("available");
            experiment.Busy = Flag("busy");
            experiment.Effective = Flag("effective");
            experiment.Requested = Flag("requested");
            if (experiment.PendingID != "" && completed) experiment.PendingID = "";
            if (experiment.PendingID == "") experiment.Saved = Flag("saved_enabled");
            var phase = Text("phase");
            var error = Text("error");
            var directSwitched = experiment.Key == "ncm_direct" && Number("mode_requested") == 5 && Number("observed_configuration") == 1 && Flag("observed_target_matched");
            var directActive = experiment.Key == "ncm_direct" && experiment.Requested && (phase is "preparing" or "intent_saved" or "mode_request_submitting" or "direct_descriptors_verified_network_pending" or "direct_native_nic_verifying" or "direct_network_session_starting" or "direct_network_waiting_for_ipv4_peer" or "direct_ipv4_peer_verified");
            var recoveryPending = (phase is "recovering" or "recovery_pending" or "recovery_required" or "recovery_failed" or "restore_waiting_reenumeration" or "stopping" or "direct_network_stopping") || Flag("restore_requires_reenumeration") || (Flag("recovery_required") && !directActive);
            var cause = Text("cause_code");
            var wpdNotCovered = experiment.Key == "wpd_trace" && cause == "WPD_TRACE_SAFE_METADATA_NOT_COVERED"
                && !experiment.Effective && !recoveryPending && persistence != "failed"
                && error is "" or "OPERATION_FAILED" or "WPD_TRACE_OPERATION_FAILED" or "WPD_TRACE_SAFE_METADATA_NOT_COVERED";
            experiment.NeedsAttention = !wpdNotCovered && (error != "" || persistence == "failed" || recoveryPending);
            experiment.Message = wpdNotCovered ? "未覆蓋：本機格式未通過隱私檢查，該通道未啟用；未記錄不代表請求未發生。"
                : error != "" ? (directSwitched ? "模式 5 切換已確認，後續連線尚未完成：" : "尚未完成：") + error + (cause != "" ? " / " + cause : "") + (experiment.Key == "ncm_direct" && Flag("recovery_required") ? "。恢復普通連線時，請關閉此開關後拔下再插入 iPad。" : "")
                : Text("rejected_error") != "" ? "設定未變更：" + Text("rejected_error")
                : !experiment.Available ? "此環境尚未提供這項實驗。"
                : persistence is "loading" or "saving" || experiment.PendingID != "" ? "正在讀取或儲存設定…"
                : persistence == "failed" ? "設定未能保存或讀回。"
                : recoveryPending ? experiment.Key is "photo_policy" or "ncm_direct" ? "恢復尚未確認；可能需拔下再插入 iPad。" : "正在恢復原狀態，尚未確認完成。"
                : experiment.Key == "photo_policy" && Flag("policy_armed") ? "精確照片介面舊策略已就位，尚未確認前置阻斷；退出程序時核對恢復。"
                : experiment.Key == "ncm_direct" && experiment.Requested && phase == "direct_ipv4_peer_verified" && experiment.Effective && Flag("ordinary_ipv4_network_ready") ? "NCM Direct 已通過 IPv4 對端驗證，串流與 LocalSend 仍需實際測試。"
                : directSwitched && experiment.Saved ? "模式 5 切換已確認，正在核對網卡、地址分配及 IPv4 通信，尚未確認連通。"
                : directActive ? "正在核對本輪設備並切換模式 5，尚未確認網路連通。"
                : experiment.Key == "ncm_direct" && experiment.Saved ? "NCM Direct 已選擇，下一輪接入將使用獨立網路驗證；尚未確認連通。"
                : experiment.Key == "wpd_trace" && phase == "waiting_provider_registration" ? "等待 Windows 提供者註冊；接入 iPad 後會自動重新核對。"
                : experiment.Key == "wpd_trace" && experiment.Effective ? (Text("provider_coverage") == "partial" ? "WPD 已開始部分跟蹤；未覆蓋的提供者及原因見診斷。" : "WPD 採集已啟動，事件覆蓋仍待確認。") + "僅保存通過隱私檢查的摘要；尚未歸因到這台 iPad，未覆蓋原因見診斷。"
                : experiment.Key == "amds_hold" && experiment.Effective ? "Apple 服務已確認由連線策略暫停；退出程序時恢復原狀態。"
                : experiment.Busy ? "正在核對實驗狀態…"
                : experiment.Key == "wpd_trace" && experiment.Requested ? "自動診斷正在準備，尚未確認開始記錄。"
                : experiment.Key != "wpd_trace" && experiment.Saved ? "選擇已保存，目前未確認生效；等待開發者調試或可核對的設備。"
                : "已關閉。";
        }
    }

    bool UpdateTrustExperimentDeliveryFailure(string action, string id)
    {
        var experiment = trustExperiments.SingleOrDefault(e => action == e.Action + "-on" || action == e.Action + "-off");
        if (experiment == null || experiment.PendingID != id) return false;
        experiment.PendingID = "";
        experiment.DeliveryFailureID = id;
        return true;
    }

    void ResetTrustExperimentWaits()
    {
        foreach (var experiment in trustExperiments) experiment.PendingID = "";
    }

    static void SendTrustExperiment(string action, bool enabled, string id)
    {
        if (action != "ncm-direct" || !Guid.TryParseExact(id, "N", out _)) throw new ArgumentException("invalid local experiment request");
        DesktopClient.Send(new { action = action + (enabled ? "-on" : "-off"), id });
    }
}
#endif
