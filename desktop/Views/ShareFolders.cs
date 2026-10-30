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
 Notice shareNotice = new();
 string shareFolderIssue = "";
 Button shareAdd = null!;
 DispatcherTimer? shareFolderTimer;
 string sharePendingID = "";
 bool shareBusy;
 bool shareRefreshQueued;
 sealed record ShareAccessDraft(string Path,string Account,string Guest);
 readonly Dictionary<string,ShareAccessDraft> shareAccessDrafts = new();
 void ShareRequest(object value) { if (preview) return; DesktopClient.SendRaw(JsonSerializer.Serialize(value));  }
 Control BuildShareFoldersPanel() {
  shareFolderRows = new() { Spacing = 10 }; shareNotice = new(); shareFolderIssue = "";
  shareBusy = false; sharePendingID = ""; shareRefreshQueued = false;
  shareAccessDrafts.Clear();
  shareAdd = Action("添加共享",PickShareFolders,Icons.Plus,primary:true);
  shareFolderRows.Children.Add(Hint("正在讀取 Windows 已共享的資料夾…"));
  return Section.Make("共享資料夾","先添加資料夾，再為專用帳戶與訪客選擇權限。添加後立即共享，預設允許專用帳戶修改、禁止訪客。",Column(12,shareNotice,shareFolderRows),shareAdd);
 }
 void RequestShareFolders(string action,string? id=null,string? path=null,string? accountAccess=null,string? guestAccess=null,bool remember=false) {
  if(shareFoldersWindow==null)return;
  if(shareBusy){if(action=="share-folders-refresh")shareRefreshQueued=true;return;}
  if(preview)return;
  sharePendingID=Guid.NewGuid().ToString("N");shareBusy=true;shareAdd.IsEnabled=false;shareFolderRows.IsEnabled=false;
  shareNotice.Show("Busy",action=="share-folders-refresh"?"正在讀取 Windows 共享…":"正在保存並核對 Windows 共享…");
  shareFolderTimer?.Stop();var requestID=sharePendingID;var timer=new DispatcherTimer{Interval=TimeSpan.FromSeconds(30)};shareFolderTimer=timer;
  timer.Tick+=(_,_)=>{timer.Stop();if(sharePendingID==requestID){sharePendingID="";shareBusy=false;shareAdd.IsEnabled=true;shareFolderRows.IsEnabled=true;shareNotice.Show("Warn","等待 Windows 回覆逾時，保存結果尚未確認。請重新整理後再操作。");DrainShareRefresh();}};timer.Start();
  ShareRequest(new{action,id,path,request_id=sharePendingID,account_access=accountAccess,guest_access=guestAccess,remember});
 }
 void DrainShareRefresh(){if(!shareRefreshQueued)return;shareRefreshQueued=false;RequestShareFolders("share-folders-refresh");}
 async void PickShareFolders() {
  var owner=shareFoldersWindow;if(owner==null||shareBusy)return;
  try { var folders=await owner.StorageProvider.OpenFolderPickerAsync(new FolderPickerOpenOptions{Title="選擇共享資料夾",AllowMultiple=false});
   var path=folders.FirstOrDefault()?.TryGetLocalPath();if(path!=null&&shareFoldersWindow==owner) RequestShareFolders("share-folder-add",path:path,accountAccess:"modify",guestAccess:"none");
  } catch(Exception) { shareNotice.Show("Warn","無法開啟資料夾選擇器。"); }
 }
 static string ShareAccessLabel(string value)=>value=="read"?"只讀":value=="modify"?"可修改":"禁止存取";
 Control InlineShareAccess(string id,string path,string account,string guest,bool guestEnabled) {
  var selectedAccount=account;var selectedGuest=guest;
  if(shareAccessDrafts.TryGetValue(id,out var draft)&&draft.Path==path){selectedAccount=draft.Account;selectedGuest=draft.Guest;}
  var accountOn=new CheckBox{Content="啟用帳戶存取",IsChecked=selectedAccount!="none"};
  var accountWrite=new CheckBox{Content="允許修改",IsChecked=selectedAccount=="modify"};
  var guestOn=new CheckBox{Content="啟用訪客存取",IsChecked=selectedGuest!="none"};
  var guestWrite=new CheckBox{Content="允許修改",IsChecked=selectedGuest=="modify"};
  string Value(CheckBox enabled,CheckBox write)=>enabled.IsChecked==true?(write.IsChecked==true?"modify":"read"):"none";
  var state=Hint("");
  var save=Action("保存權限",()=>RequestShareFolders("native-smb-access-save",id:id,accountAccess:Value(accountOn,accountWrite),guestAccess:Value(guestOn,guestWrite)),primary:true);
  var revert=Action("還原",()=>{accountOn.IsChecked=account!="none";accountWrite.IsChecked=account=="modify";guestOn.IsChecked=guest!="none";guestWrite.IsChecked=guest=="modify";});
  var choices=Row(8,revert,save);
  void Changed() {
   accountWrite.IsEnabled=accountOn.IsChecked==true;guestWrite.IsEnabled=guestOn.IsChecked==true;
   var a=Value(accountOn,accountWrite);var g=Value(guestOn,guestWrite);var dirty=a!=account||g!=guest;
   if(dirty)shareAccessDrafts[id]=new(path,a,g);else shareAccessDrafts.Remove(id);
   choices.IsVisible=dirty;save.IsEnabled=dirty;
   state.Text="帳戶："+ShareAccessLabel(a)+"    訪客："+ShareAccessLabel(g)+(g!="none"&&!guestEnabled?"（全機訪客尚未啟用）":"")+(dirty?" · 尚未保存":"");
  }
  foreach(var box in new[]{accountOn,accountWrite,guestOn,guestWrite}) box.IsCheckedChanged+=(_,_)=>Changed();
  Changed();
  var grid=Columns("*,*",Field("專用帳戶",Row(14,accountOn,accountWrite)),Field("訪客",Row(14,guestOn,guestWrite)));grid.ColumnSpacing=16;
  return Column(10,grid,Columns("*,Auto",state,choices));
 }
 void UpdateShareFolders(JsonElement value) {
  if(shareFoldersWindow==null)return;
  var requestID=Text(value,"request_id");if(!preview&&requestID=="")return;
  if(sharePendingID!=""&&requestID!=sharePendingID||requestID!=""&&requestID!=sharePendingID)return;
  var matched=requestID!="";
  shareFolderTimer?.Stop();sharePendingID="";shareBusy=false;shareAdd.IsEnabled=true;shareFolderRows.IsEnabled=true;
  shareFolderIssue=Text(value,"problem");if(shareFolderIssue=="")shareNotice.Hide();else shareNotice.Show("Warn",shareFolderIssue);
  if(!value.TryGetProperty("folders",out var list)||list.ValueKind!=JsonValueKind.Array){if(shareFolderIssue=="")shareNotice.Show("Warn","Windows 共享回覆不完整。");DrainShareRefresh();return;}
  shareFolderRows.Children.Clear();
  var folders=Entries(value,"folders").ToArray();
  foreach(var folder in folders) shareFolderRows.Children.Add(ShareFolderCard(folder));
  if(shareFolderIssue==""){
   var ids=folders.Where(f=>Text(f,"id")!="").Select(f=>Text(f,"id")).ToHashSet();
   foreach(var id in shareAccessDrafts.Keys.Where(id=>!ids.Contains(id)).ToArray())shareAccessDrafts.Remove(id);
  }
  if(folders.Length==0)shareFolderRows.Children.Add(shareFolderIssue==""?EmptyState.Make(Icons.Folder,"尚未共享任何資料夾","按「添加共享」選擇要讓 Mac 或 iPad 讀取的資料夾。",Action("添加共享",PickShareFolders,Icons.Plus,primary:true)):EmptyState.Make(Icons.Warning,"未取得共享列表","請按右上角的「重新整理」重試。"));
  if(matched)ShareRequest(new{action="smb-ui-result-ack",id=requestID,decision="share-folders"});
  if(Program.SMBWireSmoke&&matched)CompleteSMBWireSmoke();
  DrainShareRefresh();
 }

 static bool Flag(JsonElement e,string key)=>e.TryGetProperty(key,out var v)&&v.ValueKind==JsonValueKind.True;
 Border ShareFolderCard(JsonElement folder) {
  var id=Text(folder,"id");var name=Text(folder,"share_name");if(name=="")name=Text(folder,"name");var path=Text(folder,"path");var url=Text(folder,"smb_url");if(url=="")url=Text(folder,"url");
  var available=Flag(folder,"available");var external=Flag(folder,"external_share");var changed=Flag(folder,"managed_conflict");
  var account=Text(folder,"account_access");var guest=Text(folder,"guest_access");
  if(account=="")account="modify";if(guest=="")guest="none";
  var guestEnabled=Flag(folder,"guest_enabled");var published=Flag(folder,"native_shared");var migrationPending=Flag(folder,"migration_pending");var recovery=Flag(folder,"permission_recovery");
  // Only a matching identity and confirmed readback can consume an edit.
  if(shareAccessDrafts.TryGetValue(id,out var draft)&&
     (external||changed||draft.Path!=path||draft.Account==account&&draft.Guest==guest))shareAccessDrafts.Remove(id);
  var (tone,state)=external?("Idle","由 Windows 管理"):!available?("Warn","目前不可存取"):migrationPending?("Warn","名稱更新待完成"):published?("Ok","已共享"):("Warn","未共享");
  var trailing=Row(8,new StatusPill(state,Scale.Caption),Action("複製地址",()=>Copy(url,"共享地址")));
  ((StatusPill)trailing.Children[0]).Set(tone);
  if(!external)trailing.Children.Add(IconButton(Icons.Trash,"取消共享「"+name+"」（保留檔案）",()=>AppWindow.Confirm(shareFoldersWindow,"取消共享？","「"+name+"」將不再提供給 Mac 與 iPad。資料夾與檔案會保留，之後可以再次添加。","取消共享",()=>RequestShareFolders("share-folder-remove",id:id),danger:true,detail:path)));
  var body=new List<Control>();
  var recover=Row(8);
  if(external)recover.Children.Add(Action("在 Windows 管理",()=>ShareRequest(new{action="windows-smb-manage"})));
  else if((!published||migrationPending)&&available&&!changed)recover.Children.Add(Action("重試共享",()=>RequestShareFolders("native-smb-retry")));
  if(changed)recover.Children.Add(Action("交由 Windows 管理",()=>ReleaseShareOwnership(id,name)));
  if(recovery)recover.Children.Add(Action("保留目前權限",()=>KeepSharePermissions(id,name,path)));
  if(external||changed)body.Add(Banner(changed?"權限已由 Windows 修改，請在 Windows 核對。":"此共享的帳戶與訪客權限由 Windows 管理。",changed?"Warn":"Idle"));
  else { var permissions=InlineShareAccess(id,path,account,guest,guestEnabled); permissions.IsEnabled=!migrationPending; body.Add(permissions); }
  if(Flag(folder,"access_recovery"))body.Add(Banner("上次權限保存尚未完成，請重新核對並保存。","Warn"));
  if(Text(folder,"folder_problem") is {Length:>0} problem)body.Add(Banner(problem,"Warn"));
  if(recovery)body.Add(Banner("權限恢復尚未完成。可先重試關閉共享；若已自行管理權限，可選擇保留目前權限。","Warn"));
  if(recover.Children.Count>0)body.Add(recover);
  var displayPath=Text(folder,"display_path");if(displayPath=="")displayPath=path;
  return ListItem.Make(name,displayPath,trailing,Icons.Folder,tone=="Idle"?"Idle":tone,body.ToArray());
 }
 static Control Banner(string text,string tone){var n=new Notice();n.Show(tone,text);return n;}
 void KeepSharePermissions(string id,string name,string path)=>AppWindow.Confirm(shareFoldersWindow,"保留目前權限？","此操作只清除「"+name+"」的權限恢復記錄，不會更改目前權限。先前給專用帳戶或 Guest 的讀寫權限可能仍然保留；如不需要，請自行在 Windows 檢查並移除。資料夾的共享必須已關閉，之後可以重新設定共享或移除資料夾。","保留並清除恢復記錄",()=>RequestShareFolders("native-smb-acl-forget",id:id,remember:true),detail:path);
 void ReleaseShareOwnership(string id,string name)=>AppWindow.Confirm(shareFoldersWindow,"交由 Windows 管理？","「"+name+"」已在 Windows 中修改。此操作從 USB Link 移除管理記錄，保留 Windows 共享和目前資料夾權限；檔案不會刪除，共享也不會關閉。之後請在 Windows 管理這個共享，Guest 的全機設定仍可能影響它。","保留並交由 Windows 管理",()=>RequestShareFolders("native-smb-release",id:id,remember:true));
}
