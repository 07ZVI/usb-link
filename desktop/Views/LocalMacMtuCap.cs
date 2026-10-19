#if USBLINK_LOCAL_DIAGNOSTICS
using System.Text.Json;
using Avalonia.Controls;

namespace Suhang.Desktop;

// Developer experiment: cap the Mac USB link MTU for the next Mac connection.
public sealed partial class Dashboard
{
    static readonly string[] macMtuCapValues = ["auto", "9000", "1500"];
    static readonly string[] macMtuCapLabels = ["自動", "9000", "1500"];
    string macMtuCapSaved = "auto", macMtuCapPendingID = "", macMtuCapDeliveryFailureID = "", macMtuCapMessage = "等待後台狀態。";
    string macMtuCapPendingValue = "auto";
    bool macMtuCapAvailable = Program.Preview, macMtuCapBusy;
    System.Action? macMtuCapRefresh;

    Control MacMtuCapControls()
    {
        var combo = new ComboBox { ItemsSource = macMtuCapLabels, SelectedIndex = 0, MinWidth = 120 };
        Avalonia.Automation.AutomationProperties.SetName(combo, "Mac 連線 MTU 上限（實驗）");
        var status = Hint("");
        Avalonia.Automation.AutomationProperties.SetName(status, "Mac 連線 MTU 上限狀態");
        var syncing = false;
        combo.SelectionChanged += (_, _) =>
        {
            if (syncing || combo.SelectedIndex < 0 || combo.SelectedIndex >= macMtuCapValues.Length) return;
            var value = macMtuCapValues[combo.SelectedIndex];
            if (value == (macMtuCapPendingID != "" ? macMtuCapPendingValue : macMtuCapSaved)) return;
            if (preview)
            {
                macMtuCapSaved = value;
                macMtuCapMessage = "介面預覽，未傳送實驗設定。";
            }
            else
            {
                macMtuCapPendingID = Guid.NewGuid().ToString("N");
                macMtuCapPendingValue = value;
                macMtuCapDeliveryFailureID = "";
                macMtuCapMessage = "正在儲存設定，等待背景回報…";
                try { SendMacMtuCap(value, macMtuCapPendingID); }
                catch { macMtuCapPendingID = ""; macMtuCapMessage = "設定未能傳送，請重試。"; }
            }
            localDiagnosticsRefresh?.Invoke();
        };
        macMtuCapRefresh = () =>
        {
            var selected = macMtuCapPendingID != "" ? macMtuCapPendingValue : macMtuCapSaved;
            var index = Array.IndexOf(macMtuCapValues, selected);
            syncing = true;
            combo.SelectedIndex = index < 0 ? 0 : index;
            syncing = false;
            combo.IsEnabled = localDiagnosticsEnabled && macMtuCapAvailable && macMtuCapPendingID == "";
            status.Text = (macMtuCapDeliveryFailureID != "" ? LocalControlDeliveryFailure + "\n" : "") + macMtuCapMessage;
        };
        return Column(10,
            Columns("*,Auto", Label("Mac 連線 MTU 上限（實驗）", Scale.Body), combo),
            Hint("下次 Mac 連線生效；用於測試大封包是否造成上傳變慢或斷線。"),
            status);
    }

    void UpdateMacMtuCap(JsonElement d)
    {
        if (!d.TryGetProperty("mac_mtu_cap", out var state) || state.ValueKind != JsonValueKind.Object) return;
        string Text(string key) => state.TryGetProperty(key, out var value) && value.ValueKind == JsonValueKind.String ? value.GetString() ?? "" : "";
        var requestID = Text("request_id");
        var rejectedID = Text("rejected_id");
        var persistence = Text("persistence");
        var completed = persistence is "saved" or "failed";
        if (macMtuCapDeliveryFailureID != "" && (rejectedID == macMtuCapDeliveryFailureID || requestID == macMtuCapDeliveryFailureID && completed)) macMtuCapDeliveryFailureID = "";
        if (macMtuCapPendingID != "" && rejectedID == macMtuCapPendingID) macMtuCapPendingID = "";
        if (macMtuCapPendingID != "" && requestID != macMtuCapPendingID) return;
        macMtuCapAvailable = state.TryGetProperty("available", out var available) && available.ValueKind == JsonValueKind.True;
        macMtuCapBusy = state.TryGetProperty("busy", out var busy) && busy.ValueKind == JsonValueKind.True;
        if (macMtuCapPendingID != "" && completed) macMtuCapPendingID = "";
        if (macMtuCapPendingID == "" && Array.IndexOf(macMtuCapValues, Text("saved_cap")) >= 0) macMtuCapSaved = Text("saved_cap");
        var effective = Text("effective_cap");
        macMtuCapMessage = Text("rejected_error") != "" ? "設定未變更：" + Text("rejected_error")
            : !macMtuCapAvailable ? "此環境尚未提供這項實驗。"
            : persistence is "loading" or "saving" || macMtuCapPendingID != "" ? "正在讀取或儲存設定…"
            : persistence == "failed" ? "設定未能保存或讀回。"
            : !localDiagnosticsEnabled ? "開發者調試關閉時一律使用自動。"
            : $"已選擇：{macMtuCapLabels[Math.Max(0, Array.IndexOf(macMtuCapValues, macMtuCapSaved))]}；下次 Mac 連線使用{(effective == "" ? "" : "：" + (effective == "auto" ? "自動" : effective))}。";
    }

    bool UpdateMacMtuCapDeliveryFailure(string action, string id)
    {
        if (!action.StartsWith("mac-mtu-cap-") || macMtuCapPendingID != id) return false;
        macMtuCapPendingID = "";
        macMtuCapDeliveryFailureID = id;
        return true;
    }

    static void SendMacMtuCap(string value, string id)
    {
        if (Array.IndexOf(macMtuCapValues, value) < 0 || !Guid.TryParseExact(id, "N", out _)) throw new ArgumentException("invalid MTU cap request");
        DesktopClient.Send(new { action = "mac-mtu-cap-" + value, id });
    }
}
#endif
