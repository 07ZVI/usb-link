using System.Text.Json;
using Avalonia;
using Avalonia.Controls;
using Avalonia.VisualTree;
namespace Suhang.Desktop;
public sealed partial class Dashboard
{
    // Synthetic fixtures only. The separate wire test exercises stdin/stdout.
    void RunSMBAccountSmoke()
    {
        OpenSMBManager(); var window = smbAccountWindow!;
        OpenShareFolders(); if (!ReferenceEquals(window,shareFoldersWindow)) throw new InvalidOperationException("SMB windows not combined");
        OpenSMBGuest(); OpenSMBRepair();
        if (!ReferenceEquals(window,smbGuestState.Window) || !ReferenceEquals(window,smbRepairState.Window) || window.Title != "USB Link · SMB 共享")
            throw new InvalidOperationException("guest and repair must share the SMB window");
        window.UpdateLayout();
        using var missing = JsonDocument.Parse("""{"account":{"exists":false,"local_name":"USBLink"},"guest":false}"""); UpdateSMBAccount(missing.RootElement);
        smbPassword.Text = "😀😀😀😀"; smbConfirmPassword.Text = smbPassword.Text; UpdateSMBControls();
        if (smbCreate.IsEnabled) throw new InvalidOperationException("UTF16 counted as characters");
        smbPassword.Text = "Example!123"; smbConfirmPassword.Text = "Different!123"; UpdateSMBControls();
        if (smbCreate.IsEnabled) throw new InvalidOperationException("password confirmation");
        smbConfirmPassword.Text = smbPassword.Text; UpdateSMBControls(); if (!smbCreate.IsEnabled) throw new InvalidOperationException("create form disabled");
        ClearNewSMBPassword();
        using var existing = JsonDocument.Parse("""{"account":{"exists":true,"local_name":"USBLink","username":"EXAMPLE\\USBLink","password":"UnrequestedExample!123"},"guest":false}""");
        smbAccountLoaded=false;smbNameEdited=false;UpdateSMBAccount(existing.RootElement);
        if(smbAccountName.Text!="USBLink" || smbAccountName.IsReadOnly || smbPassword.Text!="" || !smbPasswordEditor.IsVisible || smbConfirmationRow.IsVisible)throw new InvalidOperationException("combined editable form");
        if(window.GetVisualDescendants().OfType<TextBox>().Any(t=>t.Text==SMBServerAddress))throw new InvalidOperationException("duplicate server address");
        if(window.GetVisualDescendants().OfType<Button>().Any(t=>t.Content is TextBlock label && new[]{"複製登入使用者名稱","複製密碼","查看密碼"}.Contains(label.Text)))throw new InvalidOperationException("credential copy buttons retained");
        if(smbAccountName.ContextMenu==null||smbPassword.ContextMenu==null)throw new InvalidOperationException("text copy unavailable");
        if(smbCreate.IsEnabled)throw new InvalidOperationException("unchanged account form");
        smbAccountName.Text="Simple";UpdateSMBControls();if(!smbCreate.IsEnabled)throw new InvalidOperationException("name-only save disabled");
        smbPendingID="bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";smbPendingAction="native-smb-account-read";smbPasswordPurpose="view";smbAccountBusy=true;
        using var stale=JsonDocument.Parse("""{"action":"native-smb-account-read","request_id":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","account":{"exists":true,"local_name":"Old","password":"Stale!123"}}""");UpdateSMBAccount(stale.RootElement);
        if(!smbAccountBusy||smbPassword.Text!="")throw new InvalidOperationException("stale reveal");
        using var reveal=JsonDocument.Parse("""{"action":"native-smb-account-read","request_id":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","account":{"exists":true,"local_name":"USBLink","password":"VisibleExample!123"}}""");UpdateSMBAccount(reveal.RootElement);
        if(smbAccountBusy||smbPassword.Text!="VisibleExample!123"||smbAccountName.Text!="Simple"||SMBPasswordChanged||smbConfirmationRow.IsVisible||smbPassword.PasswordChar!='\0')throw new InvalidOperationException("read must preserve name and saved password baseline");
        HideSMBPassword();if(smbPassword.PasswordChar=='\0')throw new InvalidOperationException("password not masked");
        smbPassword.Text=smbConfirmPassword.Text="NewExample!123";UpdateSMBControls();if(!smbCreate.IsEnabled||!smbConfirmationRow.IsVisible)throw new InvalidOperationException("combined save disabled");
        smbPendingID="cccccccccccccccccccccccccccccccc";smbPendingAction="native-smb-account-save";
        using var failed=JsonDocument.Parse("""{"action":"native-smb-account-save","request_id":"cccccccccccccccccccccccccccccccc","problem":"Example save error","account":{"exists":true,"local_name":"USBLink"}}""");UpdateSMBAccount(failed.RootElement);
        if(smbPassword.Text!="NewExample!123"||smbAccountName.Text!="Simple")throw new InvalidOperationException("failed save clears edits");
        FailSMBAccountRequest("Example timeout","native-smb-account-save");if(smbAccountBusy||!smbRefresh.IsEnabled||smbCreate.IsEnabled||smbPassword.Text!="NewExample!123")throw new InvalidOperationException("unconfirmed save state");
        ClearNewSMBPassword();smbAccountName.Text="USBLink";smbNameEdited=false;UpdateSMBAccount(existing.RootElement);UpdateSMBControls();
        using var shares=JsonDocument.Parse("""{"folders":[{"id":"aaaaaaaaaaaaaaaaaaaaaaaa","name":"Media","share_name":"USB-Media","path":"D:\\Media","smb_url":"smb://10.6.9.1/USB-Media","available":true,"native_shared":true,"account_access":"modify","guest_access":"read","guest_enabled":true},{"name":"Archive","share_name":"Archive","path":"E:\\Archive","available":true,"native_shared":true,"external_share":true}]}""");UpdateShareFolders(shares.RootElement);
        if(shareFolderRows.Children.Count!=2)throw new InvalidOperationException("existing published shares");
        if(shareFolderRows.GetVisualDescendants().OfType<Button>().Count(b=>Avalonia.Automation.AutomationProperties.GetName(b)?.StartsWith("取消共享「")==true)!=1)
            throw new InvalidOperationException("owned shares need a cancel icon; external shares remain Windows managed");
        var checks=shareFolderRows.GetVisualDescendants().OfType<CheckBox>().ToArray();
        if(checks.Length!=4||checks[0].IsChecked!=true||checks[1].IsChecked!=true||checks[2].IsChecked!=true||checks[3].IsChecked!=false)throw new InvalidOperationException("inline per-principal access");
        checks[0].IsChecked=false;if(checks[1].IsEnabled)throw new InvalidOperationException("modify enabled without access");checks[0].IsChecked=true;
        checks[1].IsChecked=false;checks[3].IsChecked=true;
        shareBusy=true;RequestShareFolders("share-folders-refresh");
        if(!shareRefreshQueued)throw new InvalidOperationException("maintenance refresh dropped during share request");
        UpdateShareFolders(shares.RootElement);
        checks=shareFolderRows.Children.OfType<Border>().Last(c=>c.GetVisualDescendants().OfType<CheckBox>().Any()).GetVisualDescendants().OfType<CheckBox>().ToArray();
        if(checks[1].IsChecked!=false||checks[3].IsChecked!=true||shareAccessDrafts.Count!=1||shareRefreshQueued)
            throw new InvalidOperationException("shared refresh must preserve unsaved folder access");
        using var confirmed=JsonDocument.Parse("""{"folders":[{"id":"aaaaaaaaaaaaaaaaaaaaaaaa","path":"D:\\Media","account_access":"read","guest_access":"modify"}]}""");UpdateShareFolders(confirmed.RootElement);
        if(shareAccessDrafts.Count!=0)throw new InvalidOperationException("confirmed access must consume saved draft");
        UpdateShareFolders(shares.RootElement);
        checks=shareFolderRows.GetVisualDescendants().OfType<CheckBox>().ToArray();checks[1].IsChecked=false;
        using var failure=JsonDocument.Parse("""{"problem":"Example read error"}""");UpdateShareFolders(failure.RootElement);
        if(shareAccessDrafts.Count!=1||checks[1].IsChecked!=false)throw new InvalidOperationException("failed read must preserve draft");
        UpdateShareFolders(shares.RootElement);
        var revert=shareFolderRows.GetVisualDescendants().OfType<Button>().Single(b=>b.Content is TextBlock t&&t.Text=="還原");
        revert.RaiseEvent(new Avalonia.Interactivity.RoutedEventArgs(Button.ClickEvent));
        if(shareAccessDrafts.Count!=0)throw new InvalidOperationException("revert must clear draft");
        var smbScroll=window.GetVisualDescendants().OfType<ScrollViewer>().First(s=>s.Content is StackPanel);
        smbScroll.Offset=new Vector(0,0);window.UpdateLayout();
        SaveSecurityPreview(window,"usb-link-smb-unified-0.8.135.png");
        window.Width=760;window.Height=540;window.UpdateLayout();SaveSecurityPreview(window,"usb-link-smb-unified-small-0.8.135.png");
        window.Width=560;window.Height=540;window.UpdateLayout();SaveSecurityPreview(window,"usb-link-smb-unified-dpi-small.png");
        smbScroll.Offset=new Vector(0,smbScroll.Extent.Height);window.UpdateLayout();SaveSecurityPreview(window,"usb-link-smb-unified-repair.png");
        using var unpublished=JsonDocument.Parse("""{"folders":[{"id":"bbbbbbbbbbbbbbbbbbbbbbbb","name":"Media","share_name":"USB-New","path":"D:\\Media","available":true,"native_shared":false,"account_access":"modify","guest_access":"none"}]}""");UpdateShareFolders(unpublished.RootElement);
        if(!shareFolderRows.GetVisualDescendants().OfType<Button>().Any(b=>b.Content is TextBlock t&&t.Text=="重試共享"))throw new InvalidOperationException("unpublished share has no recovery action");
        using var migrating=JsonDocument.Parse("""{"folders":[{"id":"bbbbbbbbbbbbbbbbbbbbbbbb","name":"Media","share_name":"USB-New","path":"D:\\Media","available":true,"native_shared":true,"migration_pending":true,"account_access":"modify","guest_access":"none","folder_problem":"共享名稱更新待完成"}]}""");UpdateShareFolders(migrating.RootElement);
        if(!shareFolderRows.GetVisualDescendants().OfType<Button>().Any(b=>b.Content is TextBlock t&&t.Text=="重試共享") ||
           !shareFolderRows.GetVisualDescendants().OfType<TextBlock>().Any(t=>t.Text?.Contains("名稱更新待完成")==true) ||
           shareFolderRows.GetVisualDescendants().OfType<CheckBox>().Any(c=>c.IsEffectivelyEnabled) ||
           !shareFolderRows.GetVisualDescendants().OfType<Button>().Any(b=>Avalonia.Automation.AutomationProperties.GetName(b)?.StartsWith("取消共享「")==true&&b.IsEffectivelyEnabled))
            throw new InvalidOperationException("pending rename must allow retry or cancel while access edits stay disabled");
        window.Close();if(smbPassword.Text!=""||smbConfirmPassword.Text!=""||shareFoldersWindow!=null||smbGuestState.Window!=null||smbRepairState.Window!=null)throw new InvalidOperationException("close credential and shared-window cleanup");
        OpenSMBGuest();smbGuestState.ID="dddddddddddddddddddddddddddddddd";smbGuestState.Action="native-smb-account-read";
        using var guest=JsonDocument.Parse("""{"action":"native-smb-account-read","request_id":"dddddddddddddddddddddddddddddddd","account":{"exists":true},"guest":false}""");UpdateSMBAccount(guest.RootElement);
        if(smbGuest.IsChecked==true||!smbGuest.IsEnabled||smbGuestState.ID!=""||smbAccountLoaded)throw new InvalidOperationException("merged guest panel reply must not overwrite the account request");
        SaveSecurityPreview(smbGuestState.Window!,"usb-link-smb-guest-0.8.135.png");
        var reopened=smbAccountWindow;OpenSMBRepair();if(!ReferenceEquals(reopened,smbRepairState.Window))throw new InvalidOperationException("repair reopened another window");
        SaveSecurityPreview(smbRepairState.Window!,"usb-link-smb-repair-0.8.135.png");smbRepairState.Window!.Close();
        Console.WriteLine("SMB_ACCOUNT_UI_SMOKE_OK");
    }
    int smbWireStage;
    void ContinueSMBWireSmoke(){
        if(!smbAccountLoaded || smbAccountBusy || smbAccountName.Text!="FixtureUser")throw new InvalidOperationException("stdin account reply did not render");
        if(!shareBusy && shareFolderRows.Children.Count==1) CompleteSMBWireSmoke();
    }
    void CompleteSMBWireSmoke(){
        if(!smbAccountLoaded) return;
        if(shareBusy || shareFolderRows.Children.Count!=1)throw new InvalidOperationException("stdin share reply did not render");
        if(smbWireStage==0){
            var checks=shareFolderRows.GetVisualDescendants().OfType<CheckBox>().ToArray();
            if(checks.Length!=4||checks[0].IsChecked!=true||checks[1].IsChecked!=false||checks[2].IsChecked!=false)throw new InvalidOperationException("stdin checkbox rights did not render");
            if(Program.SMBRetryWireSmoke){
                var retry=shareFolderRows.GetVisualDescendants().OfType<Button>().Single(b=>b.Content is TextBlock t&&t.Text=="重試共享");
                smbWireStage=1;retry.RaiseEvent(new Avalonia.Interactivity.RoutedEventArgs(Button.ClickEvent));return;
            }
            smbWireStage=1;checks[1].IsChecked=true;
            var save=shareFolderRows.GetVisualDescendants().OfType<Button>().Single(b=>b.Content is TextBlock t&&t.Text=="保存權限");
            save.RaiseEvent(new Avalonia.Interactivity.RoutedEventArgs(Button.ClickEvent));return;
        }
        if(Program.SMBRetryWireSmoke && shareFolderRows.GetVisualDescendants().OfType<Button>().Any(b=>b.Content is TextBlock t&&t.Text=="重試共享"))throw new InvalidOperationException("retry response did not publish share");
        Console.WriteLine("SMB_STDIN_STDOUT_WIRE_SMOKE_OK");
        (Application.Current?.ApplicationLifetime as Avalonia.Controls.ApplicationLifetimes.IClassicDesktopStyleApplicationLifetime)?.Shutdown(0);
    }
}
