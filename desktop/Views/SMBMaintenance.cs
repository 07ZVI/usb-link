using System.Text.Json;
using Avalonia;
using Avalonia.Controls;
using Avalonia.Media;
using Avalonia.Threading;
namespace Suhang.Desktop;
public sealed partial class Dashboard
{
    ToggleSwitch smbGuest = null!;
    bool smbGuestEnabled;
    sealed class SMBMaintenanceState
    {
        public Window? Window;
        public TextBlock Status = Hint("");
        public readonly List<Control> Actions = new();
        public string ID = "", Action = "";
        public DispatcherTimer? Timer;
        public Button? Refresh;
        public bool Loaded;
        public Control? View;
    }
    readonly SMBMaintenanceState smbGuestState = new(), smbRepairState = new();
    void OpenSMBGuest()
    {
        OpenSMBManager(); smbGuestState.View?.BringIntoView();
    }
    Control BuildSMBGuestPanel()
    {
        var s = smbGuestState; s.Window = smbAccountWindow;
        smbGuest = Switch(); smbGuest.IsEnabled = false;
        Avalonia.Automation.AutomationProperties.SetName(smbGuest, "允許訪客免密碼連線");
        s.Status = Hint("正在讀取訪客設定…"); s.Loaded = false; s.Actions.Clear(); s.Actions.Add(smbGuest); s.Refresh = null;
        var row = Columns("*,Auto", Column(2, Label("允許訪客免密碼連線", Scale.Body), Hint("訪客只能存取已在資料夾中允許訪客的共享。", "Muted", Scale.Caption)), smbGuest);
        s.View = Section.Make("訪客連線", null, Column(12, row,
            Hint("開啟後會啟用 Windows 全機訪客，其他允許訪客的 Windows 共享也可能受影響。iPad 切換訪客與專用帳戶前，請先在「檔案」彈出此伺服器的所有共享。", "Subtle", Scale.Caption), s.Status));
        smbGuest.Click += (_,_)=>{
            if(smbGuest.IsChecked==true){smbGuest.IsChecked=false;ConfirmSMBMaintenance(s,"允許訪客連線？","這會啟用 Windows Guest 網路身份，並可能調整全機 SMB 簽名要求。其他網路上允許訪客的共享也可能受影響。",()=>RequestSMBMaintenance(s,"native-smb-guest-on"),"允許訪客");}
            else RequestSMBMaintenance(s,"native-smb-guest-off");
        };
        return s.View;
    }
    void OpenSMBRepair()
    {
        OpenSMBManager();
        if (smbRepairState.View is Expander fold) fold.IsExpanded = true;
        smbRepairState.View?.BringIntoView();
    }
    Control BuildSMBRepairPanel()
    {
        var s=smbRepairState;s.Window=smbAccountWindow;
        s.Status=Hint("");s.Loaded=true;s.Actions.Clear();
        var retry=Action("重試共享",()=>RequestSMBMaintenance(s,"native-smb-retry"));
        var repair=Action("修復 Windows 元件",()=>ConfirmSMBMaintenance(s,"修復 Windows SMB 元件？","缺少元件時使用 Windows 官方修復，可能連線 Windows Update，耗時較長。不會自動重啟或安裝 SMB1。",()=>RequestSMBMaintenance(s,"native-smb-repair"),"開始修復"));
        s.Actions.AddRange(new Control[]{retry,repair});s.Refresh=null;
        s.View=new Expander{Header="進階：Windows SMB 修復",IsExpanded=false,HorizontalAlignment=Avalonia.Layout.HorizontalAlignment.Stretch,
            Content=Column(10,Hint("共享不可用時可先重試。僅在 Windows SMB 元件缺失時使用元件修復。"),Row(10,retry,repair),s.Status)};
        return s.View;
    }
    void CloseSMBMaintenance(SMBMaintenanceState s)
    {
        s.Timer?.Stop();s.Timer=null;s.ID=s.Action="";s.Window=null;s.View=null;s.Refresh=null;s.Loaded=false;s.Actions.Clear();
    }
    void SynchronizeSMBGuest(bool loaded, bool enabled, string problem = "")
    {
        var s=smbGuestState;if(s.Window==null||s.ID!="")return;
        s.Loaded=loaded;smbGuest.IsEnabled=loaded;smbGuest.IsChecked=enabled;
        s.Status.Text=!loaded?"訪客設定尚未確認，請重新整理。":enabled?"訪客連線已啟用。":"訪客連線未啟用。";
        if(problem!="")s.Status.Text+="\n"+problem;
        s.Status.Res(TextBlock.ForegroundProperty,!loaded||problem!=""?"Warn":"Muted");
    }
    void ConfirmSMBMaintenance(SMBMaintenanceState s,string title,string text,Action apply,string confirm="確認")
    {
        var owner=s.Window;if(owner==null||s.ID!="")return;
        AppWindow.Confirm(owner,title,text,confirm,()=>{if(s.Window==owner)apply();});
    }
    void RequestSMBMaintenance(SMBMaintenanceState s,string action)
    {
        if(s.Window==null||s.ID!=""||preview)return;
        s.ID=Guid.NewGuid().ToString("N");s.Action=action;foreach(var c in s.Actions)c.IsEnabled=false;if(s.Refresh!=null)s.Refresh.IsEnabled=false;
        s.Status.Text=action=="native-smb-account-read"?"正在讀取訪客設定…":"正在處理 Windows 設定…";
        s.Timer?.Stop();var id=s.ID;var timer=new DispatcherTimer{Interval=TimeSpan.FromSeconds(30)};s.Timer=timer;
        timer.Tick+=(_,_)=>{timer.Stop();if(s.ID==id){s.ID=s.Action="";s.Status.Text="等待 Windows 回覆逾時，請核對後再操作。";if(s.Refresh!=null)s.Refresh.IsEnabled=true;foreach(var c in s.Actions)c.IsEnabled=s!=smbGuestState;}};timer.Start();
        ShareRequest(new{action,id});
    }
    bool TryUpdateSMBMaintenance(JsonElement value)
    {
        var id=Text(value,"request_id");if(id=="")return false;
        var s=new[]{smbGuestState,smbRepairState}.FirstOrDefault(s=>s.Window!=null&&s.ID==id&&s.Action==Text(value,"action"));if(s==null)return false;
        var completedAction=s.Action;s.Timer?.Stop();s.ID=s.Action="";var problem=Text(value,"problem");
        var hasAccount=value.TryGetProperty("account",out var account);
        if(hasAccount&&Text(account,"problem")!="")problem+=(problem==""?"":"\n")+Text(account,"problem");
        var guestKnown=value.TryGetProperty("guest",out var guest)&&guest.ValueKind is JsonValueKind.True or JsonValueKind.False;
        s.Loaded=hasAccount&&(s!=smbGuestState||guestKnown);
        if(s==smbGuestState&&s.Loaded){smbGuestEnabled=guest.ValueKind==JsonValueKind.True;smbGuest.IsChecked=smbGuestEnabled;}
        foreach(var c in s.Actions)c.IsEnabled=s.Loaded||s==smbRepairState;if(s.Refresh!=null)s.Refresh.IsEnabled=true;
        s.Status.Text=problem!=""?problem:!s.Loaded?"Windows 回覆不完整。":s==smbGuestState?(smbGuestEnabled?"訪客連線已啟用。":"訪客連線未啟用。"):"Windows 處理已完成。";
        s.Status.Res(TextBlock.ForegroundProperty,problem!=""||!s.Loaded?"Warn":"Muted");
        ShareRequest(new{action="smb-ui-result-ack",id,decision="smb-account"});
        if(hasAccount&&completedAction!="native-smb-account-read")RequestShareFolders("share-folders-refresh");
        return true;
    }
}
