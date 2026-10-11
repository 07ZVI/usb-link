using System.Text.Json;
using Avalonia;
using Avalonia.Controls;
using Avalonia.Media;
using Avalonia.Platform.Storage;
using Avalonia.Threading;
namespace Suhang.Desktop;
public sealed partial class Dashboard
{
 Window? shareFoldersWindow;
 StackPanel shareFolderRows = new() { Spacing = 10 };
 TextBlock shareFolderProblem = Label("",12,key:"Warn");
 Button shareRefresh = null!, shareAdd = null!;
 DispatcherTimer? shareFolderTimer;
 string sharePendingID = "";
 bool shareBusy;
 bool shareRefreshQueued;
 sealed record ShareAccessDraft(string Path,string Account,string Guest);
 readonly Dictionary<string,ShareAccessDraft> shareAccessDrafts = new();
 readonly Dictionary<string,Control> shareAddDrafts = new(StringComparer.OrdinalIgnoreCase);
 void ShareRequest(object value) { if (preview) return; DesktopClient.SendRaw(JsonSerializer.Serialize(value));  }
 void OpenShareFolders() => OpenSMBManager();
 Control BuildShareFoldersPanel() {
  shareFolderRows = new() { Spacing = 10 }; shareFolderProblem = SMBHint(""); shareFolderProblem.Res(TextBlock.ForegroundProperty,"Warn");
  shareBusy = false; sharePendingID = ""; shareRefreshQueued = false;
  shareAccessDrafts.Clear(); shareAddDrafts.Clear();
  shareRefresh = Action("重新整理",()=>RequestShareFolders("share-folders-refresh")); shareAdd = Action("添加共享",PickShareFolders,Icons.Folder);
  shareFolderRows.Children.Add(SMBHint("正在讀取 Windows 已共享的資料夾…"));
  return Column(12, Columns("*,Auto",Label("共享資料夾",18,FontWeight.SemiBold),Row(8,shareRefresh,shareAdd)),
    SMBHint("在各資料夾下勾選並保存權限。只啟用存取為只讀，允許修改包含新增、編輯、重新命名與刪除。"),shareFolderRows,shareFolderProblem);
 }
 void RequestShareFolders(string action,string? id=null,string? path=null,string? accountAccess=null,string? guestAccess=null,bool remember=false) {
  if(shareFoldersWindow==null)return;
  if(shareBusy){if(action=="share-folders-refresh")shareRefreshQueued=true;return;}
  if(preview)return;
  sharePendingID=Guid.NewGuid().ToString("N");shareBusy=true;shareRefresh.IsEnabled=shareAdd.IsEnabled=false;shareFolderRows.IsEnabled=false;
  shareFolderProblem.Text=action=="share-folders-refresh"?"正在讀取 Windows 共享…":"正在保存並核對 Windows 共享…";
  shareFolderTimer?.Stop();var requestID=sharePendingID;var timer=new DispatcherTimer{Interval=TimeSpan.FromSeconds(30)};shareFolderTimer=timer;
  timer.Tick+=(_,_)=>{timer.Stop();if(sharePendingID==requestID){sharePendingID="";shareBusy=false;shareRefresh.IsEnabled=shareAdd.IsEnabled=true;shareFolderRows.IsEnabled=true;shareFolderProblem.Text="等待 Windows 回覆逾時，保存結果尚未確認。請重新整理後再操作。";DrainShareRefresh();}};timer.Start();
  ShareRequest(new{action,id,path,request_id=sharePendingID,account_access=accountAccess,guest_access=guestAccess,remember});
 }
 void DrainShareRefresh(){if(!shareRefreshQueued)return;shareRefreshQueued=false;RequestShareFolders("share-folders-refresh");}
 async void PickShareFolders() {
  var owner=shareFoldersWindow;if(owner==null||shareBusy)return;
  try { var folders=await owner.StorageProvider.OpenFolderPickerAsync(new FolderPickerOpenOptions{Title="選擇共享資料夾",AllowMultiple=false});
   var path=folders.FirstOrDefault()?.TryGetLocalPath();if(path!=null&&shareFoldersWindow==owner) AddShareDraft(path);
  } catch(Exception) { shareFolderProblem.Text="無法開啟資料夾選擇器。"; }
 }
 void AddShareDraft(string path) {
  if(shareAddDrafts.TryGetValue(path,out var existing)){existing.BringIntoView();return;}
  var name=System.IO.Path.GetFileName(path.TrimEnd('\\','/'));if(name=="")name=path;
  var card=Card(new StackPanel(),new Thickness(16));
  var cancel=Action("取消",()=>{shareAddDrafts.Remove(path);shareFolderRows.Children.Remove(card);});
  card.Child=Column(10,Columns("*,Auto",Label(name+" · 新增共享",15,FontWeight.SemiBold),cancel),SMBHint(path),
   InlineShareAccess("",path,"modify","none",smbGuestEnabled,true));
  shareAddDrafts[path]=card;shareFolderRows.Children.Insert(0,card);card.BringIntoView();
 }
 static string ShareAccessLabel(string value)=>value=="read"?"只讀":value=="modify"?"可修改":"禁止存取";
 Control InlineShareAccess(string id,string path,string account,string guest,bool guestEnabled,bool adding=false) {
  var selectedAccount=account;var selectedGuest=guest;
  if(!adding&&shareAccessDrafts.TryGetValue(id,out var draft)&&draft.Path==path){selectedAccount=draft.Account;selectedGuest=draft.Guest;}
  var accountOn=new CheckBox{Content="啟用帳戶存取",IsChecked=selectedAccount!="none"};
  var accountWrite=new CheckBox{Content="允許修改",IsChecked=selectedAccount=="modify"};
  var guestOn=new CheckBox{Content="啟用訪客存取",IsChecked=selectedGuest!="none"};
  var guestWrite=new CheckBox{Content="允許修改",IsChecked=selectedGuest=="modify"};
  string Value(CheckBox enabled,CheckBox write)=>enabled.IsChecked==true?(write.IsChecked==true?"modify":"read"):"none";
  var state=SMBHint("");
  var save=Action(adding?"建立共享":"保存權限",()=>RequestShareFolders(adding?"share-folder-add":"native-smb-access-save",id:adding?null:id,path:adding?path:null,accountAccess:Value(accountOn,accountWrite),guestAccess:Value(guestOn,guestWrite)),primary:true);
  var revert=Action("還原",()=>{accountOn.IsChecked=account!="none";accountWrite.IsChecked=account=="modify";guestOn.IsChecked=guest!="none";guestWrite.IsChecked=guest=="modify";});
  var choices=Row(8,revert,save);
  void Changed() {
   accountWrite.IsEnabled=accountOn.IsChecked==true;guestWrite.IsEnabled=guestOn.IsChecked==true;
   var a=Value(accountOn,accountWrite);var g=Value(guestOn,guestWrite);var dirty=adding||a!=account||g!=guest;
   if(!adding){if(dirty)shareAccessDrafts[id]=new(path,a,g);else shareAccessDrafts.Remove(id);}
   choices.IsVisible=dirty;save.IsEnabled=dirty;
   state.Text="帳戶："+ShareAccessLabel(a)+"    訪客："+ShareAccessLabel(g)+(g!="none"&&!guestEnabled?"（全機訪客尚未啟用）":"")+(dirty?" · 尚未保存":"");
  }
  foreach(var box in new[]{accountOn,accountWrite,guestOn,guestWrite}) box.IsCheckedChanged+=(_,_)=>Changed();
  Changed();
  return Column(10,Columns("*,16,*",Column(7,Label("專用帳戶權限",12,key:"Muted"),Row(14,accountOn,accountWrite)),Gap(),Column(7,Label("訪客權限",12,key:"Muted"),Row(14,guestOn,guestWrite))),Columns("*,Auto",state,choices));
 }
 void UpdateShareFolders(JsonElement value) {
  if(shareFoldersWindow==null)return;
  var requestID=Text(value,"request_id");if(!preview&&requestID=="")return;
  if(sharePendingID!=""&&requestID!=sharePendingID||requestID!=""&&requestID!=sharePendingID)return;
  var matched=requestID!="";
  shareFolderTimer?.Stop();sharePendingID="";shareBusy=false;shareRefresh.IsEnabled=shareAdd.IsEnabled=true;shareFolderRows.IsEnabled=true;
  shareFolderProblem.Text=Text(value,"problem");
  if(!value.TryGetProperty("folders",out var list)||list.ValueKind!=JsonValueKind.Array){if(shareFolderProblem.Text=="")shareFolderProblem.Text="Windows 共享回覆不完整。";DrainShareRefresh();return;}
  shareFolderRows.Children.Clear();
  var folders=Entries(value,"folders").ToArray();
  foreach(var folder in folders) {
   var id=Text(folder,"id");var name=Text(folder,"share_name");if(name=="")name=Text(folder,"name");var path=Text(folder,"path");var url=Text(folder,"smb_url");if(url=="")url=Text(folder,"url");
   var available=folder.TryGetProperty("available",out var ready)&&ready.ValueKind==JsonValueKind.True;
   var pathLabel=Label(path+(available?"":" · 目前不可存取"),12,key:available?"Muted":"Warn");pathLabel.TextWrapping=TextWrapping.Wrap;
   var external=folder.TryGetProperty("external_share",out var ext)&&ext.ValueKind==JsonValueKind.True;
   var changed=folder.TryGetProperty("managed_conflict",out var altered)&&altered.ValueKind==JsonValueKind.True;
   var account=Text(folder,"account_access");var guest=Text(folder,"guest_access");
   if(account=="")account="modify";if(guest=="")guest="none";
   var guestEnabled=folder.TryGetProperty("guest_enabled",out var ge)&&ge.ValueKind==JsonValueKind.True;
   var published=folder.TryGetProperty("native_shared",out var shared)&&shared.ValueKind==JsonValueKind.True;
   // Only a matching identity and confirmed readback can consume an edit.
   if(shareAccessDrafts.TryGetValue(id,out var draft)&&
      (external||changed||draft.Path!=path||draft.Account==account&&draft.Guest==guest))shareAccessDrafts.Remove(id);
   if(!external&&!changed&&shareFolderProblem.Text==""&&Text(folder,"folder_problem")=="")shareAddDrafts.Remove(path);
   var actions=Row(8,Action("複製地址",()=>Copy(url,"共享地址")));
   if(external)actions.Children.Add(Action("在 Windows 管理",()=>ShareRequest(new{action="windows-smb-manage"})));
   else {
    if(!published&&available&&!changed)actions.Children.Add(Action("重試共享",()=>RequestShareFolders("native-smb-retry")));
    actions.Children.Add(Action(published?"停止共享":"移除",()=>RemoveShareFolder(id,name)));
   }
   var recovery=folder.TryGetProperty("permission_recovery",out var pending)&&pending.ValueKind==JsonValueKind.True;
   if(changed)actions.Children.Add(Action("交由 Windows 管理",()=>ReleaseShareOwnership(id,name)));
   if(recovery)actions.Children.Add(Action("保留目前權限",()=>KeepSharePermissions(id,name,path)));
   var nameLabel=Label(name+(external?" · Windows 管理":published?" · 已共享":" · 未共享"),15,FontWeight.SemiBold);nameLabel.TextTrimming=TextTrimming.CharacterEllipsis;
   var details=Column(10,Columns("*,Auto",nameLabel,actions),pathLabel);
   if(external||changed)details.Children.Add(SMBHint(changed?"權限已由 Windows 修改，請在 Windows 核對。":"此共享的帳戶與訪客權限由 Windows 管理。"));
   else details.Children.Add(InlineShareAccess(id,path,account,guest,guestEnabled));
   if(folder.TryGetProperty("access_recovery",out var accessPending)&&accessPending.ValueKind==JsonValueKind.True)details.Children.Add(SMBHint("上次權限保存尚未完成，請重新核對並保存。"));
   var folderProblem=Text(folder,"folder_problem");if(folderProblem!=""){var warning=Label(folderProblem,12,key:"Warn");warning.TextWrapping=TextWrapping.Wrap;details.Children.Add(warning);}
   if(recovery)details.Children.Add(SMBHint("權限恢復尚未完成。可先重試關閉共享；若已自行管理權限，可選擇保留目前權限。"));
   shareFolderRows.Children.Add(Card(details,new Thickness(16)));
  }
  if(shareFolderProblem.Text==""){
   var ids=folders.Where(f=>Text(f,"id")!="").Select(f=>Text(f,"id")).ToHashSet();
   foreach(var id in shareAccessDrafts.Keys.Where(id=>!ids.Contains(id)).ToArray())shareAccessDrafts.Remove(id);
  }
  foreach(var card in shareAddDrafts.Values)shareFolderRows.Children.Insert(0,card);
  if(folders.Length==0&&shareAddDrafts.Count==0)shareFolderRows.Children.Add(SMBHint(Text(value,"problem")==""?"Windows 目前沒有可管理的共享資料夾。":"未取得共享列表，請重新整理。"));
  if(matched)ShareRequest(new{action="smb-ui-result-ack",id=requestID,decision="share-folders"});
  if(Program.SMBWireSmoke&&matched)CompleteSMBWireSmoke();
  DrainShareRefresh();
 }
 void KeepSharePermissions(string id,string name,string path){
  if(shareFoldersWindow==null)return;
  var dialog=new Window{Title="保留目前資料夾權限",Width=500,SizeToContent=SizeToContent.Height,CanResize=false,WindowStartupLocation=WindowStartupLocation.CenterOwner};dialog.Res(BackgroundProperty,"Window");
  var explanation=Label("此操作只清除「"+name+"」的權限恢復記錄，不會更改目前權限。先前給專用帳戶或 Guest 的讀寫權限可能仍然保留；如不需要，請自行在 Windows 檢查並移除。資料夾的共享必須已關閉，之後可以重新設定共享或移除資料夾。",12,key:"Warn");explanation.TextWrapping=TextWrapping.Wrap;
  var location=Label(path,12,key:"Muted");location.TextWrapping=TextWrapping.Wrap;
  dialog.Content=new Border{Padding=new Thickness(24),Child=Column(16,Label("保留目前權限？",18,FontWeight.SemiBold),location,explanation,Row(8,Action("取消",()=>dialog.Close()),Action("保留並清除恢復記錄",()=>{dialog.Close();RequestShareFolders("native-smb-acl-forget",id:id,remember:true);},primary:true)))};
  _=dialog.ShowDialog(shareFoldersWindow);
 }

 void ReleaseShareOwnership(string id,string name){
  if(shareFoldersWindow==null)return;
  var dialog=new Window{Title="交由 Windows 管理",Width=500,SizeToContent=SizeToContent.Height,CanResize=false,WindowStartupLocation=WindowStartupLocation.CenterOwner};dialog.Res(BackgroundProperty,"Window");
  var text=Label("「"+name+"」已在 Windows 中修改。此操作從 USB Link 移除管理記錄，保留 Windows 共享和目前資料夾權限；檔案不會刪除，共享也不會關閉。之後請在 Windows 管理這個共享，Guest 的全機設定仍可能影響它。",12,key:"Warn");text.TextWrapping=TextWrapping.Wrap;
  dialog.Content=new Border{Padding=new Thickness(24),Child=Column(16,Label("交由 Windows 管理？",18,FontWeight.SemiBold),text,Row(8,Action("取消",()=>dialog.Close()),Action("保留並交由 Windows 管理",()=>{dialog.Close();RequestShareFolders("native-smb-release",id:id,remember:true);},primary:true)))};
  _=dialog.ShowDialog(shareFoldersWindow);
 }

 void RemoveShareFolder(string id,string name){
  if(shareFoldersWindow==null)return;
  var dialog=new Window{Title="移除共享",Width=420,SizeToContent=SizeToContent.Height,CanResize=false,WindowStartupLocation=WindowStartupLocation.CenterOwner};dialog.Res(BackgroundProperty,"Window");
  dialog.Content=new Border{Padding=new Thickness(24),Child=Column(16,Label("移除「"+name+"」的共享？",18,FontWeight.SemiBold),Label("檔案會保留在原資料夾。",12,key:"Muted"),Row(8,Action("取消",()=>dialog.Close()),Action("移除",()=>{dialog.Close();RequestShareFolders("share-folder-remove",id:id);},primary:true)))};
  _=dialog.ShowDialog(shareFoldersWindow);
 }
}
