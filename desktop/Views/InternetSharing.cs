using System.Text.Json;
using Avalonia;
using Avalonia.Controls;
namespace Suhang.Desktop;
public sealed partial class Dashboard
{
 readonly TextBlock internetState=Label("共享關閉。僅支援目前已授權的 Mac。",12,key:"Muted");
 readonly TextBlock dependencyState=Label("正在檢查外部元件…",12,key:"Muted");
 readonly ComboBox internetUpstream=new(){MinWidth=200};
 readonly ToggleSwitch internetToggle = Switch();
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
  return internetSection = Card(Column(10,Label("Windows → Mac 共享網際網路",16),internetState,
   Label("預設關閉。啟用後請在 Mac 更新 USB 網路的 DHCP 租約；取得新網關及往返流量後才顯示可用。",12,key:"Muted"),
   internetUpstream,Row(8,Action("檢查出口",()=>SendInternet("internet-refresh")),Label("共享網際網路",13),internetToggle),
   new Expander{Header="元件狀態",IsExpanded=false,HorizontalAlignment=Avalonia.Layout.HorizontalAlignment.Stretch,Content=dependencyState},Action("檢查 / 安裝全部所需元件",()=>{if(!preview)DesktopClient.Send(new{action="dependency-install",id="all"});})),new Thickness(14));
 }
 void SendInternet(string action)
 {
  if(preview)return;
  var n=internetUpstream.SelectedIndex;
  var index=n>=0&&n<internetIndices.Count?internetIndices[n]:0;
  DesktopClient.Send(new{action,upstream=index});
 }
 void UpdateInternet(JsonElement d)
 {
  if(InternetSharingState.Read(d) is { } state) {
   internetActive=state.State is "ready" or "waiting_client" or "preparing";
   internetRecovery=state.State=="recovery_required";
   internetToggle.IsChecked=internetActive;
   internetToggle.IsEnabled=state.State!="preparing";
   internetToggle.OnContent=internetToggle.OffContent=internetRecovery?"重試關閉":"";
   var message=state.State switch {"ready"=>"共享可用：已觀察到本次 DHCP 配置及網際網路雙向流量。","waiting_client"=>"已準備，等待 Mac 更新 DHCP 租約及產生網際網路流量。","off"=>"共享關閉。","recovery_required"=>"清理待恢復，請重試關閉共享。",_=>"共享狀態："+state.State};
   if(state.Problem!="")message+="\n"+state.Problem;internetState.Text=message;
   var indices=new List<uint>{0};var names=new List<string>{"目前的非 USB 網際網路出口"};
   foreach(var up in state.Upstreams){indices.Add(up.Index);names.Add(up.Name);}
   if(!indices.SequenceEqual(internetIndices)){internetIndices=indices;internetUpstream.ItemsSource=names;internetUpstream.SelectedIndex=0;}
  }
  if(DependencyState.Read(d) is { } dependencies)
   dependencyState.Text=string.Join("\n",dependencies.Select(x=>x.ID+"："+x.State+" · 影響 "+string.Join(", ",x.Features)+(x.Problem!=""?" · "+x.Problem:"")));
 }
}
