using System.Text.Json;
using Avalonia;
using Avalonia.Controls;
using Avalonia.Media;
using Avalonia.Threading;
namespace Suhang.Desktop;
public sealed partial class Dashboard
{
 StackPanel gatewayRows=new(){Spacing=8};
 TextBlock gatewayState=Label("USB 連線前將啟用應用程式授權。",12,key:"Muted");
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
  var info=new TextBlock{Text=path+"\n\n"+(Text(r,"direction")=="inbound"?"接收入站連線":"發起出站連線")+" · "+Text(r,"protocol")+" · "+Text(r,"remote"),TextWrapping=TextWrapping.Wrap,FontSize=12};
  var dialog=new Window{Title="USB 網路連線請求",Width=530,SizeToContent=SizeToContent.Height,CanResize=false,Topmost=true,WindowStartupLocation=WindowStartupLocation.CenterOwner,FontFamily=new FontFamily(Palette.FontStack)};gatewayPrompt=dialog;dialog.Res(BackgroundProperty,"Window");
  var signature=new TextBlock{Text="數位簽章：正在驗證…",TextWrapping=TextWrapping.Wrap,FontSize=12}.Res(TextBlock.ForegroundProperty,"Muted");
  var signatureCancellation=new CancellationTokenSource();var signatureToken=signatureCancellation.Token;
  async Task CheckSignature(){
   try {
    var result=await Task.Run(()=>ExecutableSignature.InspectAsync(path,Text(r,"sha256"),signatureToken),signatureToken);
    if(signatureToken.IsCancellationRequested||gatewayPrompt!=dialog)return;
    ShowSignature(signature,result);
   } catch(OperationCanceledException) { }
  }
  bool answered=false;
  void Decide(string decision){answered=true;GatewayRequest(new{action="gateway-decide",id,decision,remember=remember.IsChecked==true});dialog.Close();}
  var heading=Label(System.IO.Path.GetFileName(path)+" 想使用 USB 網路",20,FontWeight.SemiBold);heading.TextWrapping=TextWrapping.Wrap;
  dialog.Content=new Border{Padding=new Thickness(24),Child=Column(16,heading,info,signature,new TextBlock{Text="連線已被阻止。允許後，程式需要重試連線。授權只作用於 USB 通道，Windows 其他防火牆規則仍會生效。簽章有效也不會自動授權。",TextWrapping=TextWrapping.Wrap,FontSize=12}.Res(TextBlock.ForegroundProperty,"Muted"),remember,Row(10,Action("阻止",()=>Decide("block")),Action("允許",()=>Decide("allow"),primary:true)))};
  dialog.Closed+=(_,_)=>{signatureCancellation.Cancel();signatureCancellation.Dispose();if(!answered)GatewayRequest(new{action="gateway-decide",id,decision="block",remember=false});gatewayPrompt=null;NextGatewayRequest();};
  _=dialog.ShowDialog(this);if(!preview)_=CheckSignature();else signature.Text="數位簽章：未簽署（介面預覽）";
 }
 Control GatewayPanel(){gatewayRows=new(){Spacing=8};gatewayState=Label("正在讀取 USB 授權…",12,key:"Muted");return Rows("Auto,Auto,*",new Border{Padding=new Thickness(0,12,0,12),Child=new TextBlock{Text="未知程式先被阻止，收到連線請求後由你允許。TCP、UDP、IPv4 與 IPv6 均限制在 USB 網卡；本程式的通信自動放行。",TextWrapping=TextWrapping.Wrap,FontSize=12}.Res(TextBlock.ForegroundProperty,"Muted")},gatewayState,new ScrollViewer{Content=gatewayRows,HorizontalScrollBarVisibility=Avalonia.Controls.Primitives.ScrollBarVisibility.Disabled});}
 void UpdateGateway(JsonElement d){
  var id=Text(d,"request_id");
  if(id!=""&&(id!=gatewayPendingID||Text(d,"action")!=gatewayPendingAction)||id==""&&!preview&&gatewayPendingID!="")return;
  if(id!=""){gatewayTimer?.Stop();gatewayPendingID=gatewayPendingAction="";ShareRequest(new{action="ui-result-ack",id,decision="gateway"});}
  var problem=Text(d,"problem");var active=d.TryGetProperty("active_links",out var n)?n.GetInt32():0;
  if(!d.TryGetProperty("grants",out _)&&problem!=""){gatewayState.Text="未完成："+problem;if(securityTabs?.SelectedIndex==0)securityCount.Text="USB 授權尚未確認 · 可重新整理";return;}
  gatewayState.Text=problem.Length>0?"未完成："+problem:active>0?"USB 網關已啟用 · 未授權程式預設阻止":"未連接 USB 裝置 · 授權已保留";
  gatewayState.TextWrapping=TextWrapping.Wrap;CancelGatewaySignatures();gatewayRows.Children.Clear();
  gatewaySignatureCancellation=new CancellationTokenSource();var token=gatewaySignatureCancellation.Token;var generation=gatewaySignatureGeneration;
  foreach(var grant in Entries(d,"grants")){var path=Text(grant,"path");var decision=Text(grant,"decision");var title=(decision=="allow"?"允許":"阻止")+" · "+System.IO.Path.GetFileName(path);
   var signature=new TextBlock{Text=preview?"數位簽章：需由 Windows 驗證（介面預覽）":"數位簽章：正在驗證…",TextWrapping=TextWrapping.Wrap,FontSize=12}.Res(TextBlock.ForegroundProperty,"Muted");
   var heading=Label(title,15,FontWeight.SemiBold);heading.TextWrapping=TextWrapping.Wrap;
   gatewayRows.Children.Add(Card(Column(7,Columns("*,Auto",heading,Action("撤銷",()=>GatewayRequest(new{action="gateway-forget",path}))),new TextBlock{Text=path,TextWrapping=TextWrapping.Wrap,FontSize=12}.Res(TextBlock.ForegroundProperty,"Muted"),signature),new Thickness(12)));
   if(!preview&&securityWindow!=null)_=CheckGrantSignature(signature,path,Text(grant,"sha256"),generation,token);
  }
  if(gatewayRows.Children.Count==0)gatewayRows.Children.Add(Label("尚無其他程式的 USB 授權。",13,key:"Muted"));
  if(securityTabs?.SelectedIndex==0)securityCount.Text=$"{Entries(d,"grants").Count()} 項 USB 授權 · {DateTime.Now:HH:mm:ss}";
 }
}
