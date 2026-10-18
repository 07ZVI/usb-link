using System.Text.Json;
using Avalonia;
using Avalonia.Controls;
using Avalonia.Media;
using Avalonia.Threading;
namespace Suhang.Desktop;
public sealed partial class Dashboard
{
 StackPanel gatewayRows=new(){Spacing=8};
 TextBlock gatewayState=Hint("USB 連線前將啟用應用程式授權。");
 HashSet<string> seenGatewayRequests=new();
 Queue<JsonElement> gatewayRequests=new();Window? gatewayPrompt;
 string gatewayPendingID="",gatewayPendingAction="";
 DispatcherTimer? gatewayTimer;
 CancellationTokenSource? gatewaySignatureCancellation;
 readonly SemaphoreSlim signatureWorkers = new(2);
 int gatewaySignatureGeneration;
 void CancelGatewaySignatures(){gatewaySignatureGeneration++;gatewaySignatureCancellation?.Cancel();gatewaySignatureCancellation?.Dispose();gatewaySignatureCancellation=null;}
 void CloseGatewayPanel(){gatewayTimer?.Stop();gatewayPendingID=gatewayPendingAction="";CancelGatewaySignatures();}
 async Task CheckGrantSignature(TextBlock label,string path,string hash,int generation,CancellationToken token){
  try {
   await signatureWorkers.WaitAsync(token);
   ExecutableSignature signature;
   try { signature=await Task.Run(()=>ExecutableSignature.InspectAsync(path,hash,token),token); }
   finally {signatureWorkers.Release();}
   if(token.IsCancellationRequested||generation!=gatewaySignatureGeneration||securityWindow==null)return;
   ShowSignature(label,signature);
  } catch(OperationCanceledException) { }
 }

 static void ShowSignature(TextBlock label,ExecutableSignature signature){label.Text=signature.Display;label.Res(TextBlock.ForegroundProperty,signature.Tone);}
 void GatewayRequest(object value){
  if(preview)return;
  var body=JsonSerializer.SerializeToElement(value).EnumerateObject().ToDictionary(p=>p.Name,p=>(object?)p.Value.Clone());
  var action=((JsonElement)body["action"]!).GetString()??"";
  if(action!="gateway-decide"){
   if(securityWindow==null||gatewayPendingID!="")return;
   gatewayPendingID=Guid.NewGuid().ToString("N");gatewayPendingAction=action;body["request_id"]=gatewayPendingID;
   gatewayState.Text="正在讀取或更新 USB 授權…";var id=gatewayPendingID;
   gatewayTimer?.Stop();var timer=new DispatcherTimer{Interval=TimeSpan.FromSeconds(60)};gatewayTimer=timer;
   timer.Tick+=(_,_)=>{timer.Stop();if(gatewayPendingID==id){gatewayPendingID=gatewayPendingAction="";gatewayState.Text="等待 Windows USB 授權回覆逾時，請重新整理核對。";if(securityTabs?.SelectedIndex==0)securityCount.Text="USB 授權尚未確認";}};timer.Start();
  }
  DesktopClient.SendRaw(JsonSerializer.Serialize(body));
 }
 void ShowGatewayRequest(JsonElement d){
  if(!d.TryGetProperty("request",out var request)||gatewayRequests.Count>=32)return;
  var id=Text(request,"id");if(id.Length!=24||!seenGatewayRequests.Add(id))return;
  gatewayRequests.Enqueue(request.Clone());NextGatewayRequest();
 }
 void NextGatewayRequest(){
  if(gatewayPrompt!=null||gatewayRequests.Count==0)return;
  var r=gatewayRequests.Dequeue();var path=Text(r,"path");var id=Text(r,"id");var remember=new CheckBox{Content="記住此程式的選擇",IsChecked=false};
  var direction=(Text(r,"direction")=="inbound"?"接收入站連線":"發起出站連線")+" · "+Text(r,"protocol")+" · "+Text(r,"remote");
  var signature=Hint("數位簽章：正在驗證…");
  var signatureCancellation=new CancellationTokenSource();var signatureToken=signatureCancellation.Token;
  Window? dialog=null;
  async Task CheckSignature(){
   try {
    var result=await Task.Run(()=>ExecutableSignature.InspectAsync(path,Text(r,"sha256"),signatureToken),signatureToken);
    if(signatureToken.IsCancellationRequested||gatewayPrompt!=dialog)return;
    ShowSignature(signature,result);
   } catch(OperationCanceledException) { }
  }
  bool answered=false;
  void Decide(string decision){answered=true;GatewayRequest(new{action="gateway-decide",id,decision,remember=remember.IsChecked==true});dialog!.Close();}
  var heading=Label(System.IO.Path.GetFileName(path)+" 想使用 USB 網路",Scale.Title+2,FontWeight.SemiBold);heading.TextWrapping=TextWrapping.Wrap;
  var buttons=Row(8,Action("阻止",()=>Decide("block")),Action("允許",()=>Decide("allow"),primary:true));buttons.HorizontalAlignment=Avalonia.Layout.HorizontalAlignment.Right;
  dialog=AppWindow.Dialog("USB 網路連線請求",530,Column(14,heading,Column(4,Hint(path,"Ink"),Hint(direction)),signature,
   Hint("連線已被阻止。允許後，程式需要重試連線。授權只作用於 USB 通道，Windows 其他防火牆規則仍會生效；簽章有效也不會自動授權。"),remember,buttons),topmost:true);
  gatewayPrompt=dialog;
  dialog.Closed+=(_,_)=>{signatureCancellation.Cancel();signatureCancellation.Dispose();if(!answered)GatewayRequest(new{action="gateway-decide",id,decision="block",remember=false});gatewayPrompt=null;NextGatewayRequest();};
  _=dialog.ShowDialog(this);if(!preview)_=CheckSignature();else signature.Text="數位簽章：未簽署（介面預覽）";
 }
 Control GatewayPanel(){gatewayRows=new(){Spacing=10};gatewayState=Hint("正在讀取 USB 授權…");
  var head=Column(6,Hint("尚未授權的程式預設被阻止，有連線請求時由你決定。授權只作用於 USB 網路（TCP、UDP、IPv4、IPv6）；本程式自己的通信會自動放行。"),gatewayState);head.Margin=new Thickness(0,12,0,12);
  return Rows("Auto,*",head,new ScrollViewer{Content=gatewayRows,HorizontalScrollBarVisibility=Avalonia.Controls.Primitives.ScrollBarVisibility.Disabled});}
 void UpdateGateway(JsonElement d){
  var id=Text(d,"request_id");
  if(id!=""&&(id!=gatewayPendingID||Text(d,"action")!=gatewayPendingAction)||id==""&&!preview&&gatewayPendingID!="")return;
  if(id!=""){gatewayTimer?.Stop();gatewayPendingID=gatewayPendingAction="";ShareRequest(new{action="ui-result-ack",id,decision="gateway"});}
  var problem=Text(d,"problem");var active=d.TryGetProperty("active_links",out var n)?n.GetInt32():0;
  if(!d.TryGetProperty("grants",out _)&&problem!=""){gatewayState.Text=Friendly.Explain("未完成："+problem).Message;if(securityTabs?.SelectedIndex==0)securityCount.Text="USB 授權尚未確認 · 可重新整理";return;}
  gatewayState.Text=problem.Length>0?Friendly.Explain("未完成："+problem).Message:active>0?"USB 網關已啟用 · 未授權程式預設阻止":"未連接 USB 裝置 · 授權已保留";
  gatewayState.TextWrapping=TextWrapping.Wrap;CancelGatewaySignatures();gatewayRows.Children.Clear();
  gatewaySignatureCancellation=new CancellationTokenSource();var token=gatewaySignatureCancellation.Token;var generation=gatewaySignatureGeneration;
  foreach(var grant in Entries(d,"grants")){var path=Text(grant,"path");var allow=Text(grant,"decision")=="allow";
   var signature=Hint(preview?"數位簽章：需由 Windows 驗證（介面預覽）":"數位簽章：正在驗證…");
   var decision=new StatusPill(allow?"允許":"阻止",Scale.Caption);decision.Set(allow?"Ok":"Error");
   gatewayRows.Children.Add(ListItem.Make(System.IO.Path.GetFileName(path),path,Row(8,decision,Action("撤銷授權",()=>GatewayRequest(new{action="gateway-forget",path}),danger:true)),body:signature));
   if(!preview&&securityWindow!=null)_=CheckGrantSignature(signature,path,Text(grant,"sha256"),generation,token);
  }
  if(gatewayRows.Children.Count==0)gatewayRows.Children.Add(EmptyState.Make(Icons.Shield,"尚無程式授權","程式第一次要求使用 USB 網路時，會在這裡詢問你。"));
  if(securityTabs?.SelectedIndex==0)securityCount.Text=$"{Entries(d,"grants").Count()} 項 USB 授權 · {DateTime.Now:HH:mm:ss}";
 }
}
