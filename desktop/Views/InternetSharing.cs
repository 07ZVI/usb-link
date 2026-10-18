using System.Text.Json;
using Avalonia;
using Avalonia.Controls;
using Avalonia.Layout;
namespace Suhang.Desktop;
public sealed partial class Dashboard
{
 readonly TextBlock internetState=Hint("共享關閉。僅支援目前已授權的 Mac。");
 readonly Notice internetNotice=new();
 readonly StackPanel dependencyRows=new(){Spacing=6};
 readonly ComboBox internetUpstream=new(){MinWidth=240};
 readonly ToggleSwitch internetToggle = Switch();
 Button? internetRetry;
 bool internetActive, internetRecovery;
 List<uint> internetIndices=new(){0};
 Border? internetSection;
 Control InternetSection()
 {
  if(internetSection != null)return internetSection;
  internetUpstream.ItemsSource=new[]{"目前的非 USB 網際網路出口"};internetUpstream.SelectedIndex=0;
  internetToggle.IsEnabled = preview;
  Avalonia.Automation.AutomationProperties.SetName(internetToggle,"共享網際網路");
  internetToggle.Click += (_,_) => {
   internetToggle.IsChecked = internetActive;
   if(preview)return;
   internetToggle.IsEnabled=false;
   SendInternet(internetActive||internetRecovery?"internet-disable":"internet-enable");
  };
  internetRetry=Action("重試關閉共享",()=>{if(!preview)SendInternet("internet-disable");},primary:true);
  internetNotice.WithAction(Row(8,Action("重新檢查",()=>SendInternet("internet-refresh")),internetRetry));
  var main=Columns("*,Auto",Column(2,Label("共享網際網路",Scale.Body),internetState),internetToggle);main.ColumnSpacing=16;
  var dependencies=new Expander{Header="所需元件",IsExpanded=false,HorizontalAlignment=HorizontalAlignment.Stretch,Content=Column(10,dependencyRows,Action("檢查 / 安裝全部所需元件",()=>{if(!preview)DesktopClient.Send(new{action="dependency-install",id="all"});}))};
  return internetSection = Section.Make("共享網際網路給 Mac","讓 Mac 透過 USB 使用這台電腦的網路。預設關閉；開啟後請在 Mac 更新 USB 網路的 DHCP 租約，確認有往返流量才會顯示可用。",
   Column(12,main,internetNotice,Field("網路出口",internetUpstream),Row(8,Action("重新檢查出口",()=>SendInternet("internet-refresh"),Icons.Retry)),dependencies));
 }
 void SendInternet(string action)
 {
  if(preview)return;
  var n=internetUpstream.SelectedIndex;
  var index=n>=0&&n<internetIndices.Count?internetIndices[n]:0;
  DesktopClient.Send(new{action,upstream=index});
 }
 static string DependencyStateText(string state)=>state switch{"ready"=>"已就緒","missing"=>"缺少","not_checked"=>"尚未檢查","downloading"=>"下載中","verifying"=>"驗證中","installing"=>"安裝中","failed" or "error"=>"失敗",_=>"狀態：" + state};
 static string DependencyTone(string state)=>state switch{"ready"=>"Ok","missing" or "failed" or "error"=>"Warn","downloading" or "verifying" or "installing"=>"Busy",_=>"Idle"};
 void UpdateInternet(JsonElement d)
 {
  if(InternetSharingState.Read(d) is { } state) {
   internetActive=state.State is "ready" or "waiting_client" or "preparing";
   internetRecovery=state.State=="recovery_required";
   internetToggle.IsChecked=internetActive;
   internetToggle.IsEnabled=state.State!="preparing";
   internetState.Text=state.State switch {"ready"=>"共享可用","waiting_client"=>"已準備好，等待 Mac 更新 DHCP 租約並開始上網","preparing"=>"正在準備共享…","off"=>"共享關閉","recovery_required"=>"清理尚未完成，請重試關閉共享",_=>"共享狀態：" + state.State};
   ToolTip.SetTip(internetState,state.State=="ready"?"已觀察到本次 DHCP 配置及網際網路雙向流量。":null);
   if(state.Problem!="")internetNotice.Show("Warn",state.Problem);
   else if(internetRecovery)internetNotice.Show("Warn","上次關閉共享時有項目尚未清理。重試後才能再次開啟。");
   else internetNotice.Hide();
   internetRetry!.IsVisible=internetRecovery;
   var indices=new List<uint>{0};var names=new List<string>{"目前的非 USB 網際網路出口"};
   foreach(var up in state.Upstreams){indices.Add(up.Index);names.Add(up.Name);}
   if(!indices.SequenceEqual(internetIndices)){internetIndices=indices;internetUpstream.ItemsSource=names;internetUpstream.SelectedIndex=0;}
  }
  if(DependencyState.Read(d) is { } dependencies){
   dependencyRows.Children.Clear();
   foreach(var x in dependencies){
    var pill=new StatusPill(DependencyStateText(x.State),Scale.Caption);pill.Set(DependencyTone(x.State));
    var line=Columns("*,Auto",Column(1,Label(x.ID,Scale.Body),Hint(x.Features.Count>0?"影響：" + string.Join("、",x.Features):"","Muted",Scale.Caption)),pill);
    dependencyRows.Children.Add(line);
    if(x.Problem!=""){var n=new Notice();n.Show("Warn",x.Problem);dependencyRows.Children.Add(n);}
   }
  }
 }
}
