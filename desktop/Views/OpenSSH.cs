using System.Text;
using System.Text.Json;
using Avalonia;
using Avalonia.Controls;
using Avalonia.Layout;
using Avalonia.Media;
using Avalonia.Platform.Storage;
using Avalonia.Threading;

namespace Suhang.Desktop;

public sealed partial class Dashboard
{
    const string SSHInstaller = "OpenSSH-Win64-v10.4.0.0.msi";
    sealed record SSHAccount(string SID, string Name) { public override string ToString() => Name; }
    StackPanel sshKeys = null!, sshServiceActions = null!, sshInstallOptions = null!;
    TextBlock sshState = null!, sshScope = null!, sshActivity = null!;
    TextBox sshInput = null!;
    ComboBox sshAccounts = null!;
    Notice sshProblem = null!;
    Button sshImport = null!, sshFile = null!, sshRefresh = null!;
    DispatcherTimer? sshTimer;
    string sshPendingID = "", sshPendingAction = "";
    bool sshBusy, sshRendering, sshLoaded, sshInstalled;
    string SSHSID => (sshAccounts.SelectedItem as SSHAccount)?.SID ?? "";

    Control OpenSSHPanel()
    {
        sshBusy = sshRendering = sshLoaded = sshInstalled = false;
        sshPendingID = sshPendingAction = "";
        sshKeys = new() { Spacing = Scale.Small };
        sshServiceActions = new() { Orientation = Orientation.Horizontal, Spacing = Scale.Small };
        sshState = Label("尚未讀取 OpenSSH 狀態", Scale.Title2, FontWeight.SemiBold);
        sshActivity = Hint("");
        sshScope = Hint("選擇 Windows 本機帳戶後，查看它實際使用的授權公鑰。");
        sshProblem = new();
        sshAccounts = new() { MinWidth = 200, HorizontalAlignment = HorizontalAlignment.Stretch };
        sshAccounts.SelectionChanged += (_, _) => { if (!sshRendering && !sshBusy) SSHRequest("openssh-refresh"); };
        sshInput = new() { AcceptsReturn = true, MaxLength = 16 << 10, Height = 100, Watermark = "貼上 .pub 公鑰內容，例如 ssh-ed25519 AAAA… name@device", TextWrapping = TextWrapping.Wrap };
        sshInput.TextChanged += (_, _) => SSHControls();
        sshImport = Action("匯入公鑰", () => SSHRequest("openssh-import", publicKey: sshInput.Text ?? ""), Icons.Plus, primary: true);
        sshFile = Action("選擇 .pub 檔案", PickSSHPublicKey);
        sshRefresh = Action("重新整理", () => SSHRequest("openssh-refresh"), Icons.Retry);
        var installOnline = Action("線上安裝", () => SSHConfirmInstall("openssh-install-online"));
        var installOffline = Action("離線安裝…", PickSSHInstaller);
        var downloadInstall = Action("下載官方安裝包並安裝", () => SSHConfirmInstall("openssh-install-download"));
        var installers = new WrapPanel { Orientation = Orientation.Horizontal };
        foreach (var button in new[] { installOnline, installOffline, downloadInstall }) { button.Margin = new Thickness(0, 0, Scale.Small, Scale.Small); installers.Children.Add(button); }
        var help = Hint("線上安裝使用 Windows Update。離線安裝支援官方 OpenSSH 10.4.0.0p1-Preview（x64）MSI；會核對 SHA-256 與 Microsoft 簽章。已有 SSH 服務時不會混裝。");
        sshInstallOptions = Column(Scale.Small, installers, help);
        var content = Column(Scale.Regular,
            Columns("*,Auto", sshState, sshRefresh), sshActivity, sshServiceActions,
            sshInstallOptions, Rule(),
            Label("Windows 帳戶與授權公鑰", Scale.Title3, FontWeight.SemiBold),
            sshAccounts, sshScope,
            Hint("公鑰位置依目前 OpenSSH 設定判斷（Mac USB 來源 10.6.9.2）。自訂位置請手動管理；匯入成功不代表已通過登入測試。"),
            sshKeys, Rule(), sshInput, Row(Scale.Small, sshFile, sshImport),
            Hint("只匯入公鑰；私鑰留在連線的裝置上。服務與網路存取沿用 OpenSSH 及 Windows 的設定。"), sshProblem);
        SSHControls();
        return new ScrollViewer { Content = content, HorizontalScrollBarVisibility = Avalonia.Controls.Primitives.ScrollBarVisibility.Disabled };
    }

    void SSHConfirmInstall(string action, string path = "")
    {
        if (securityWindow == null || sshBusy) return;
        var message = action == "openssh-install-online"
            ? "透過 Windows Update 下載並安裝 OpenSSH Server，需要網際網路。Windows 可能建立 SSH 防火牆規則。"
            : "安裝 Microsoft 官方 OpenSSH 10.4.0.0p1-Preview（x64）。安裝程式可能啟動 SSH 並設定防火牆；SSH 的可連線範圍取決於 Windows 現有設定。";
        AppWindow.Confirm(securityWindow.Owner, "安裝 OpenSSH Server？", message, "安裝", () => SSHRequest(action, path: path));
    }

    async void PickSSHInstaller()
    {
        if (securityWindow == null || sshBusy) return;
        var owner = securityWindow;
        try {
            var files = await owner.StorageProvider.OpenFilePickerAsync(new FilePickerOpenOptions { Title = "選擇 " + SSHInstaller, AllowMultiple = false,
                FileTypeFilter = new[] { new FilePickerFileType("OpenSSH 官方安裝包") { Patterns = new[] { "*.msi" } } } });
            var path = files.FirstOrDefault()?.TryGetLocalPath();
            if (!string.IsNullOrEmpty(path) && securityWindow == owner) SSHConfirmInstall("openssh-install-offline", path);
        } catch { if (securityWindow == owner) sshProblem.Show("Warn", "無法開啟安裝包選擇器。"); }
    }

    async void PickSSHPublicKey()
    {
        if (securityWindow == null || sshBusy || !sshLoaded) return;
        var owner = securityWindow;
        try {
            var files = await owner.StorageProvider.OpenFilePickerAsync(new FilePickerOpenOptions { Title = "選擇 SSH 公鑰", AllowMultiple = false,
                FileTypeFilter = new[] { new FilePickerFileType("SSH 公鑰") { Patterns = new[] { "*.pub" } } } });
            if (files.FirstOrDefault() is not { } file || securityWindow != owner) return;
            await using var stream = await file.OpenReadAsync();
            var bytes = new byte[(16 << 10) + 1]; var length = 0;
            while (length < bytes.Length) { var n = await stream.ReadAsync(bytes.AsMemory(length)); if (n == 0) break; length += n; }
            if (length > 16 << 10) throw new InvalidOperationException("公鑰檔案超過 16 KB。");
            var text = new UTF8Encoding(false, true).GetString(bytes, 0, length);
            if (text.Contains("PRIVATE KEY", StringComparison.Ordinal)) throw new InvalidOperationException("這是私鑰。請選擇 .pub 公鑰檔案。");
            if (securityWindow == owner) sshInput.Text = text;
        } catch (Exception e) { if (securityWindow == owner) sshProblem.Show("Warn", "無法讀取公鑰：" + e.Message); }
    }

    void SSHRequest(string action, string publicKey = "", string id = "", string path = "")
    {
        if (securityWindow == null || sshBusy) return;
        if (preview) { sshProblem.Show("Busy", "介面預覽，不會執行系統操作。"); return; }
        if (action == "openssh-import" && Encoding.UTF8.GetByteCount(publicKey) > 16 << 10) { sshProblem.Show("Warn", "一次最多匯入 16 KB 公鑰，請分批匯入。"); return; }
        var requestID = Guid.NewGuid().ToString("N");
        var body = JsonSerializer.Serialize(new { action, request_id = requestID, username = SSHSID, public_key = publicKey, id, path });
        if (Encoding.UTF8.GetByteCount(body) >= 32768) { sshProblem.Show("Warn", "公鑰內容過長，請縮短注釋或分批匯入。"); return; }
        sshBusy = true; sshProblem.Hide();
        sshPendingID = requestID; sshPendingAction = action;
        sshTimer?.Stop(); sshTimer = new() { Interval = TimeSpan.FromMinutes(11) };
        sshTimer.Tick += (_, _) => { if (sshPendingID == requestID) {
            sshTimer?.Stop(); sshPendingID = sshPendingAction = ""; sshBusy = false; sshLoaded = false;
            sshProblem.Show("Warn", "OpenSSH 回覆逾時，操作結果尚未確認。請重新整理後再操作。"); SSHControls();
        }};
        sshTimer.Start(); SSHControls();
        DesktopClient.SendRaw(body);
    }

    void SSHControls()
    {
        if (sshAccounts == null || sshImport == null) return;
        sshAccounts.IsEnabled = !sshBusy;
        sshInput.IsEnabled = sshFile.IsEnabled = !sshBusy && sshLoaded;
        sshImport.IsEnabled = !sshBusy && sshLoaded && !string.IsNullOrWhiteSpace(sshInput.Text);
        sshRefresh.IsEnabled = !sshBusy;
        sshServiceActions.IsEnabled = sshKeys.IsEnabled = !sshBusy;
        sshInstallOptions.IsVisible = !sshInstalled;
        sshInstallOptions.IsEnabled = !sshBusy;
        sshActivity.IsVisible = sshBusy;
        sshActivity.Text = sshPendingAction.Contains("install", StringComparison.Ordinal) ? "正在下載或安裝 OpenSSH，可能需要幾分鐘…" : "正在讀取或更新 OpenSSH…";
    }

    void UpdateOpenSSH(JsonElement d)
    {
        if (securityWindow == null || sshState == null) return;
        var id = Text(d, "request_id"); var action = Text(d, "action");
        if (id != "" && (id != sshPendingID || action != sshPendingAction) || id == "" && !preview) return;
        sshTimer?.Stop(); sshPendingID = sshPendingAction = ""; sshBusy = false;
        if (id != "") ShareRequest(new { action = "ui-result-ack", id, decision = "openssh" });
        var problem = Text(d, "problem");
        if (problem.Length > 0) sshProblem.Show("Warn", problem); else sshProblem.Hide();
        if (!d.TryGetProperty("status", out var s) || s.ValueKind != JsonValueKind.Object) { sshLoaded = false; SSHControls(); return; }
        sshInstalled = s.TryGetProperty("installed", out var installed) && installed.ValueKind == JsonValueKind.True;
        var state = Text(s, "state");
        sshState.Text = !sshInstalled ? "OpenSSH Server · 尚未安裝" : state == "Running" ? "OpenSSH Server · 執行中" : state == "Stopped" ? "OpenSSH Server · 已停止" : "OpenSSH Server · " + state;
        sshServiceActions.Children.Clear();
        if (sshInstalled) {
            sshServiceActions.Children.Add(Action(state == "Running" ? "停止服務" : "啟動服務", () => {
                if (state == "Running") AppWindow.Confirm(securityWindow!.Owner, "停止 SSH 服務？", "新的 SSH 登入將無法建立，現有連線也可能中斷。", "停止服務", () => SSHRequest("openssh-stop"));
                else SSHRequest("openssh-start");
            }));
            var auto = Text(s, "start_mode") == "Auto";
            sshServiceActions.Children.Add(Action(auto ? "改為手動啟動" : "設為開機啟動", () => SSHRequest(auto ? "openssh-manual" : "openssh-automatic")));
        }
        var selected = SSHSID;
        sshRendering = true;
        var accounts = Entries(s, "accounts").Select(a => new SSHAccount(Text(a, "sid"), Text(a, "name"))).ToArray();
        sshAccounts.ItemsSource = accounts;
        sshAccounts.SelectedItem = accounts.FirstOrDefault(a => a.SID == Text(s, "sid")) ?? accounts.FirstOrDefault(a => a.SID == selected) ?? accounts.FirstOrDefault();
        sshRendering = false;
        sshLoaded = sshInstalled && Text(s, "sid") != "" && Text(s, "sid") == SSHSID && Text(s, "path") != "";
        var shared = s.TryGetProperty("shared", out var sharedValue) && sharedValue.ValueKind == JsonValueKind.True;
        sshScope.Text = sshLoaded ? (shared ? "管理員共用公鑰 · 變更會影響使用此檔案的所有管理員帳戶\n" : "此 Windows 帳戶的公鑰\n") + Text(s, "path") : "選擇 Windows 本機帳戶，讀取它的公鑰。";
        sshKeys.Children.Clear();
        if (sshLoaded) foreach (var key in Entries(s, "keys")) {
            var keyID = Text(key, "id"); var fingerprint = Text(key, "fingerprint");
            var restricted = key.TryGetProperty("restricted", out var value) && value.ValueKind == JsonValueKind.True;
            var remove = Action("刪除", () => AppWindow.Confirm(securityWindow!.Owner, "刪除這項公鑰？",
                (shared ? "這是管理員共用公鑰，刪除會影響使用它的所有管理員帳戶。\n" : "刪除後，這把公鑰將不能建立新的登入；既有 SSH 工作階段不會因此撤銷。\n") + fingerprint,
                "刪除公鑰", () => SSHRequest("openssh-delete", id: keyID), danger: true), danger: true);
            var details = Column(Scale.Tight, Label(Text(key, "comment") is { Length: > 0 } comment ? comment : Text(key, "type"), Scale.Body, FontWeight.SemiBold),
                new SelectableTextBlock { Text = fingerprint, FontSize = Scale.Callout, TextWrapping = TextWrapping.Wrap }, Hint(Text(key, "type") + (restricted ? " · 含存取限制" : "")));
            sshKeys.Children.Add(Columns("*,Auto", details, remove)); sshKeys.Children.Add(Rule());
        }
        if (sshKeys.Children.Count == 0) sshKeys.Children.Add(Hint(sshLoaded ? "尚無授權公鑰。可以貼上或選擇 .pub 檔案匯入。" : "尚未讀取公鑰。"));
        if (problem.Length == 0 && action == "openssh-import") sshInput.Text = "";
        SSHControls();
        if (!preview && problem.Length == 0 && sshInstalled && !sshLoaded && SSHSID != "") SSHRequest("openssh-refresh");
    }

    void CloseOpenSSH()
    {
        sshTimer?.Stop(); sshPendingID = sshPendingAction = ""; sshBusy = sshLoaded = false;
        if (sshInput != null) sshInput.Text = "";
    }
}
