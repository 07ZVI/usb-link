using System.Security.Cryptography;
using System.Text.Json;
using System.Text;
using Avalonia;
using Avalonia.Controls;
using Avalonia.Media;
using Avalonia.Threading;
namespace Suhang.Desktop;
public sealed partial class Dashboard
{
    const string SMBServerAddress = "smb://10.6.9.1/";
    Window? smbAccountWindow;
    TextBox smbAccountName = null!, smbPassword = null!, smbNewPassword = null!, smbConfirmPassword = null!;
    TextBlock smbAccountProblem = null!, smbAccountStatus = null!, smbPasswordHint = null!;
    CheckBox smbShowNewPassword = null!;
    Button smbCreate = null!, smbRefresh = null!;
    DispatcherTimer? smbAccountTimer;
    Control smbPasswordEditor = null!, smbConfirmationRow = null!;
    readonly List<Control> smbAccountActions = new();
    bool smbAccountExists, smbAccountLoaded, smbAccountBusy, smbNameEdited, smbSettingPassword;
    string smbSavedAccountName = "", smbSavedPassword = "", smbLoginUsername = "", smbPendingID = "", smbPendingAction = "", smbPasswordPurpose = "";
    bool SMBPasswordChanged => smbPassword.Text is { Length: > 0 } text && text != smbSavedPassword;
    void OpenSMBAccount() => OpenSMBManager();
    void OpenSMBManager()
    {
        if (smbAccountWindow != null) { smbAccountWindow.Activate(); return; }
        smbAccountWindow = new Window { Title = "USB Link · SMB 共享", Width = 940, Height = 790, MinWidth = 560, MinHeight = 420, FontFamily = new FontFamily(Palette.FontStack), WindowStartupLocation = WindowStartupLocation.CenterOwner };
        shareFoldersWindow = smbAccountWindow;
        smbAccountWindow.Res(BackgroundProperty, "Window");
        var account = BuildSMBAccountPanel(); var guest = BuildSMBGuestPanel(); var folders = BuildShareFoldersPanel(); var repair = BuildSMBRepairPanel();
        smbAccountWindow.Content = new Border { Padding = new Thickness(24), Child = Rows("Auto,*",
            Column(5, Label("SMB 共享", 24, FontWeight.SemiBold), SMBHint("管理共享資料夾、帳戶、訪客連線與 Windows SMB 修復。"), Gap(16)),
            new ScrollViewer { Content = Column(20, account, guest, folders, repair), HorizontalScrollBarVisibility = Avalonia.Controls.Primitives.ScrollBarVisibility.Disabled }) };
        smbAccountWindow.Closed += (_, _) => {
            smbAccountTimer?.Stop(); smbAccountTimer = null; smbPendingID = smbPendingAction = smbPasswordPurpose = ""; smbAccountBusy = false;
            ClearNewSMBPassword(); smbAccountWindow!.Content = null; smbAccountWindow = null; smbAccountActions.Clear();
            shareFolderTimer?.Stop(); sharePendingID = ""; shareBusy = false; shareFoldersWindow = null;
            shareRefreshQueued = false; shareAccessDrafts.Clear(); shareAddDrafts.Clear();
            CloseSMBMaintenance(smbGuestState); CloseSMBMaintenance(smbRepairState);
        };
        smbAccountWindow.Show(this); UpdateSMBControls(); RequestSMBAccount("native-smb-account-read"); RequestShareFolders("share-folders-refresh");
    }
    Control BuildSMBAccountPanel()
    {
        smbAccountExists = smbAccountLoaded = smbAccountBusy = smbNameEdited = false;
        smbSavedAccountName = smbSavedPassword = smbLoginUsername = smbPendingID = smbPendingAction = smbPasswordPurpose = ""; smbAccountActions.Clear();
        smbAccountName = new TextBox { Text = "USBLink", MaxLength = 20, Watermark = "使用者名稱" };
        smbPassword = new TextBox { PasswordChar = '●', MaxLength = 256 }; smbNewPassword = smbPassword;
        smbConfirmPassword = new TextBox { PasswordChar = '●', MaxLength = 256, Watermark = "再次輸入密碼" };
        TextCopyMenu(smbAccountName); TextCopyMenu(smbPassword); TextCopyMenu(smbConfirmPassword);
        smbShowNewPassword = new CheckBox { Content = "顯示密碼" };
        smbAccountStatus = Label("正在讀取帳戶狀態…", 12, key: "Muted"); smbAccountProblem = SMBHint(""); smbPasswordHint = SMBHint("");
        smbAccountName.TextChanged += (_, _) => { if (smbAccountLoaded) smbNameEdited = smbAccountName.Text != smbSavedAccountName; UpdateSMBControls(); };
        smbPassword.TextChanged += (_, _) => { if (!smbSettingPassword) UpdateSMBControls(); };
        smbConfirmPassword.TextChanged += (_, _) => UpdateSMBControls();
        smbShowNewPassword.IsCheckedChanged += (_, _) => {
            var show = smbShowNewPassword.IsChecked == true;
            smbPassword.PasswordChar = smbConfirmPassword.PasswordChar = show ? '\0' : '●';
            if (show && smbAccountExists && smbPassword.Text == "" && !smbAccountBusy) RequestSMBAccount("native-smb-account-read", purpose: "view");
        };
        Button AccountAction(string text, Action click, bool primary = false) { var b = Action(text, click, primary: primary); smbAccountActions.Add(b); return b; }
        smbRefresh = AccountAction("重新整理", () => RequestSMBAccount("native-smb-account-read"));
        var generate = AccountAction("生成密碼", () => { var password = "Usb!" + Convert.ToHexString(RandomNumberGenerator.GetBytes(12)).ToLowerInvariant(); smbPassword.Text = smbConfirmPassword.Text = password; });
        smbCreate = AccountAction("保存帳戶", SaveSMBAccountForm, primary: true);
        smbConfirmationRow = Column(5, Label("確認新密碼", 12, key: "Muted"), smbConfirmPassword);
        smbPasswordEditor = Column(10,
            Columns("*,16,*", Column(5, Label("使用者名稱", 12, key: "Muted"), smbAccountName), Gap(), Column(5, Label("密碼", 12, key: "Muted"), smbPassword)),
            smbConfirmationRow, Row(12, smbShowNewPassword, generate), smbPasswordHint);
        smbAccountActions.AddRange(new Control[] { smbAccountName, smbPassword, smbConfirmPassword, smbShowNewPassword });
        return Card(Column(12, Columns("*,Auto", Column(3, Label("帳戶與密碼", 18, FontWeight.SemiBold), smbAccountStatus), smbRefresh),
            smbPasswordEditor, Columns("*,Auto", smbAccountProblem, smbCreate)), new Thickness(18));
    }
    static void TextCopyMenu(TextBox box)
    {
        var copy = new MenuItem { Header = "複製" }; var select = new MenuItem { Header = "全選" };
        copy.Click += (_, _) => box.Copy(); select.Click += (_, _) => box.SelectAll();
        var menu = new ContextMenu { ItemsSource = new[] { copy, select } };
        menu.Opened += (_, _) => copy.IsEnabled = box.CanCopy;
        box.ContextMenu = menu;
    }
    static TextBlock SMBHint(string text) { var label = Label(text, 12, key: "Muted"); label.TextWrapping = TextWrapping.Wrap; return label; }
    static bool ValidSMBName(string text) => text.Length is > 0 and <= 20 && text.Trim() == text && !text.EndsWith('.') && text.IndexOfAny("\"/\\[]:;|=,+*?<>@".ToCharArray()) < 0 && !text.Any(char.IsControl);
    static bool ValidSMBPassword(string text) => text.Length <= 256 && text.EnumerateRunes().Count() >= 8 && !text.Contains('\0');
    void UpdateSMBControls()
    {
        if (smbAccountName == null) return;
        foreach (var c in smbAccountActions) c.IsEnabled = smbAccountLoaded && !smbAccountBusy;
        smbRefresh.IsEnabled = !smbAccountBusy;
        smbPasswordEditor.IsVisible = smbAccountLoaded;
        smbConfirmationRow.IsVisible = !smbAccountExists || SMBPasswordChanged;
        smbPassword.Watermark = smbAccountExists ? "已保存 · 留空保留，勾選顯示可查看" : "至少 8 個字元";
        smbCreate.Content = Label(smbAccountExists ? "保存帳戶" : "建立並保存", 13, FontWeight.SemiBold, "Window");
        var password = smbPassword.Text ?? ""; var confirmation = smbConfirmPassword.Text ?? "";
        var passwordValid = smbAccountExists && !SMBPasswordChanged || ValidSMBPassword(password) && password == confirmation;
        smbCreate.IsEnabled = smbAccountLoaded && !smbAccountBusy && ValidSMBName(smbAccountName.Text ?? "") && passwordValid && (!smbAccountExists || smbAccountName.Text != smbSavedAccountName || SMBPasswordChanged);
        smbPasswordHint.Text = !ValidSMBName(smbAccountName.Text ?? "") ? "名稱需為 1–20 個字元，不能包含網域、路徑或 Windows 禁用符號。" : SMBPasswordChanged && confirmation != "" && password != confirmation ? "兩次密碼不一致。" : SMBPasswordChanged && password != "" && !ValidSMBPassword(password) ? "密碼至少 8 個字元。" : "名稱與密碼一起保存。顯示後可選取文字複製；修改後請更新裝置的登入資訊；iPad 切換帳戶前請先彈出此伺服器的所有共享。";
    }
    void HideSMBPassword() { smbShowNewPassword.IsChecked = false; smbPassword.PasswordChar = smbConfirmPassword.PasswordChar = '●'; }
    void ClearNewSMBPassword() { smbSavedPassword = ""; smbSettingPassword = true; smbPassword.Text = ""; smbSettingPassword = false; smbConfirmPassword.Text = ""; HideSMBPassword(); }
    void RequestSMBAccount(string action, string? password = null, string? username = null, string purpose = "")
    {
        if (smbAccountWindow == null || smbAccountBusy || preview) return;
        smbPendingID = Guid.NewGuid().ToString("N"); smbPendingAction = action; smbPasswordPurpose = purpose; smbAccountBusy = true;
        if (purpose == "") HideSMBPassword();
        smbAccountProblem.Text = action == "native-smb-account-read" ? "正在讀取帳戶…" : "正在保存 Windows 設定…"; UpdateSMBControls();
        smbAccountTimer?.Stop(); var id = smbPendingID; var timer = new DispatcherTimer { Interval = TimeSpan.FromSeconds(30) }; smbAccountTimer = timer;
        timer.Tick += (_, _) => { timer.Stop(); if (smbPendingID == id) FailSMBAccountRequest("等待 Windows 回覆逾時。請重新整理核對狀態；不要重複保存。", action); }; timer.Start();
        ShareRequest(new { action, id, password, username, remember = purpose != "" });
    }
    void FailSMBAccountRequest(string problem, string action)
    {
        smbAccountTimer?.Stop(); smbPendingID = smbPendingAction = smbPasswordPurpose = ""; smbAccountBusy = false; smbAccountLoaded = false; HideSMBPassword();
        smbAccountStatus.Text = action == "native-smb-account-read" ? "帳戶狀態無法讀取" : "保存結果尚未確認";
        smbAccountProblem.Text = problem + (action == "native-smb-account-read" ? "" : "\n輸入內容已保留。"); smbAccountProblem.Res(TextBlock.ForegroundProperty, "Warn"); UpdateSMBControls();
        SynchronizeSMBGuest(false, smbGuestEnabled);
    }
    void SaveSMBAccountForm() { if (smbCreate.IsEnabled) RequestSMBAccount("native-smb-account-save", SMBPasswordChanged ? smbPassword.Text ?? "" : "", smbAccountName.Text); }
    void UpdateSMBAccount(JsonElement value)
    {
        if (TryUpdateSMBMaintenance(value) || smbAccountWindow == null) return;
        var id = Text(value, "request_id"); if (!preview && id == "") return; var action = Text(value, "action"); var matched = id != "" && id == smbPendingID && action == smbPendingAction;
        if (smbPendingID != "" && !matched || id != "" && !matched) return;
        if (!value.TryGetProperty("account", out var account)) { if (matched) FailSMBAccountRequest(Text(value, "problem") is { Length: > 0 } error ? error : "Windows 回覆不完整。", action); return; }
        smbAccountTimer?.Stop(); var purpose = matched && action == "native-smb-account-read" ? smbPasswordPurpose : "";
        var preserveName = smbSavedAccountName != "" && smbAccountName.Text != smbSavedAccountName || smbNameEdited && !smbAccountLoaded;
        var preservePassword = SMBPasswordChanged;
        smbPendingID = smbPendingAction = smbPasswordPurpose = ""; smbAccountBusy = false;
        var problem = Text(value, "problem"); if (Text(account, "problem") != "") problem += (problem == "" ? "" : "\n") + Text(account, "problem");
        smbAccountExists = account.TryGetProperty("exists", out var exists) && exists.ValueKind == JsonValueKind.True; smbAccountLoaded = smbAccountExists || problem == "";
        var nameSaved = matched && value.TryGetProperty("name_saved", out var ns) && ns.ValueKind == JsonValueKind.True;
        var passwordSaved = matched && value.TryGetProperty("password_saved", out var ps) && ps.ValueKind == JsonValueKind.True;
        smbSavedAccountName = smbAccountExists ? Text(account, "local_name") : ""; smbLoginUsername = Text(account, "username");
        if (smbAccountExists && (!preserveName || nameSaved)) smbAccountName.Text = smbSavedAccountName;
        else if (!smbAccountExists && !smbNameEdited && Text(account, "local_name") != "") smbAccountName.Text = Text(account, "local_name");
        var guestKnown = value.TryGetProperty("guest", out var guest) && guest.ValueKind is JsonValueKind.True or JsonValueKind.False;
        smbGuestEnabled = guestKnown && guest.ValueKind == JsonValueKind.True;
        SynchronizeSMBGuest(guestKnown, smbGuestEnabled);
        var password = Text(account, "password");
        if (purpose == "view" && !preservePassword) {
            if (password == "" && problem == "") problem = "已保存的密碼無法讀取，請設定新密碼。";
            smbSavedPassword = password; smbSettingPassword = true; smbPassword.Text = password; smbSettingPassword = false;
            smbShowNewPassword.IsChecked = password != ""; smbPassword.PasswordChar = password != "" ? '\0' : '●';
        }
        if (passwordSaved) ClearNewSMBPassword();
        smbAccountStatus.Text = problem != "" ? (smbAccountExists ? "帳戶已建立 · 需要處理" : "帳戶狀態無法確認") : smbAccountExists ? "專用帳戶已建立" : "尚未建立專用帳戶";
        smbAccountStatus.Res(TextBlock.ForegroundProperty, problem != "" ? "Warn" : smbAccountExists ? "Ok" : "Muted");
        smbAccountProblem.Text = problem != "" ? problem : nameSaved || passwordSaved ? "帳戶已保存。" : ""; smbAccountProblem.Res(TextBlock.ForegroundProperty, problem == "" ? "Muted" : "Warn"); UpdateSMBControls();
        if (matched) ShareRequest(new { action = "smb-ui-result-ack", id, decision = "smb-account" });
        if (Program.SMBWireSmoke && matched) ContinueSMBWireSmoke();
    }
}
