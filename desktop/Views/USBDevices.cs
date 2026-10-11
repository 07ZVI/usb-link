using System.Text.Json;
using Avalonia;
using Avalonia.Automation;
using Avalonia.Controls;
using Avalonia.Layout;
using Avalonia.Media;

namespace Suhang.Desktop;

public sealed partial class Dashboard
{
    static readonly string[] usbGroupTitles = { "輸入裝置", "儲存裝置", "音訊與影像", "網路裝置", "集線器", "控制裝置", "其他與未知裝置" };
    static int USBGroup(JsonElement device)
    {
        if(Text(device,"display_kind")=="lighting")return 5;
        if(Text(device,"display_kind") is "link" or "network")return 3;
        var types = Entries(device,"types").Select(t=>t.GetString()??"").ToHashSet();
        string[][] groups = { new[]{"keyboard","mouse","hid"}, new[]{"storage"}, new[]{"audio","camera","imaging","media"}, new[]{"network"}, new[]{"hub"} };
        for(var i=0;i<groups.Length;i++)if(groups[i].Any(types.Contains))return i;
        return 6;
    }
    static string USBDisplayKind(JsonElement device)
    {
        var hint=Text(device,"display_kind");
        if(hint=="lighting")return "主板燈光控制器";
        if(hint=="link")return "USB Link 網路連線";
        if(hint is "keyboard" or "mouse" or "network")return USBKind(hint);
        var types=Entries(device,"types").Select(t=>t.GetString()??"unknown").Where(t=>t!="composite").Distinct().ToList();
        if(types.Count>1)types.Remove("hid");
        return types.Count==0?"USB 裝置":string.Join("、",types.Select(t=>t=="hid"?"HID 控制／輸入裝置":USBKind(t)));
    }
    static string USBSize(ulong bytes)
    {
        string[] units={"B","KB","MB","GB","TB","PB"};var value=(double)bytes;var unit=0;
        while(value>=1000&&unit<units.Length-1){value/=1000;unit++;}
        return value.ToString(value>=100?"0":value>=10?"0.#":"0.##")+" "+units[unit];
    }
    static ulong USBNumber(JsonElement d,string key)=>d.TryGetProperty(key,out var n)&&n.TryGetUInt64(out var v)?v:0;
    static string USBText(JsonElement element,string key)=>element.ValueKind==JsonValueKind.Object?Text(element,key):"";
    internal static double? USBUsedPercent(ulong total,ulong free,bool known) => known&&total>0&&free<=total?100.0*(total-free)/total:null;
    void RenderUSBDevices(JsonElement[] devices)
    {
        var duplicates = devices.GroupBy(d=>Text(d,"name"),StringComparer.OrdinalIgnoreCase).ToDictionary(g=>g.Key,g=>g.Count(),StringComparer.OrdinalIgnoreCase);
        foreach(var group in devices.OrderBy(USBGroup).ThenBy(d=>Text(d,"name"),StringComparer.CurrentCultureIgnoreCase).GroupBy(USBGroup)){
            usbRows.Children.Add(new Border{Padding=new Thickness(2,8,2,2),Child=Label(usbGroupTitles[group.Key]+" · "+group.Count(),13,FontWeight.SemiBold,key:"Muted")});
            foreach(var device in group){
                var name=Label(Text(device,"name"),15,FontWeight.SemiBold);name.TextWrapping=TextWrapping.Wrap;
                var functions=Label(USBDisplayKind(device),12,key:"Muted");functions.TextWrapping=TextWrapping.Wrap;
                var location=Text(device,"location");
                var metadata=$"VID {Text(device,"vid")} · PID {Text(device,"pid")} · Windows 已偵測";
                if(device.TryGetProperty("node_count",out var count)&&count.TryGetInt32(out var nodes))metadata+=$"\n包含 {nodes} 個 Windows 裝置節點";
                if(device.TryGetProperty("merged_roots",out var roots)&&roots.TryGetInt32(out var merged)&&merged>1)metadata+=$" · 已合併 {merged} 個 USB 節點";
                metadata+=location==""?"\n接口位置：Windows 尚未提供":"\n接口位置："+location;
                metadata+="\nWindows 功能："+string.Join("、",Entries(device,"types").Select(t=>USBKind(t.GetString()??"unknown")));
                if(Text(device,"description") is {Length:>0} description)metadata+="\n\n"+description;
                if(duplicates[Text(device,"name")]>1)metadata+="\n同名裝置保留分列：未確認屬於同一個實體裝置。";
                var usb=device.TryGetProperty("usb",out var connection)?connection:default;
                var specification=USBText(usb,"specification");var speed=USBText(usb,"speed");var protocols=USBText(usb,"port_protocols");
                var usbSummary=specification!=""?"裝置 "+specification:"USB 版本尚未取得";
                if(speed!="")usbSummary+=" · "+speed;
                metadata+="\n裝置規格："+(specification!=""?specification:"Windows 尚未提供")+"\n目前協商速率："+(speed!=""?speed:"Windows 尚未提供")+"\n接口支援："+(protocols!=""?protocols:"Windows 尚未提供");
                metadata+="\nUSB 3.x 接口的 3.1／3.2 版本及通道數，Windows 快取資料未提供；協商速率不代表實際傳輸速度。";
                var info=new SelectableTextBlock{Text=metadata,FontSize=12,TextWrapping=TextWrapping.Wrap,MaxWidth=380};info.Res(TextBlock.ForegroundProperty,"Muted");
                var details=IconButton(Icons.Info,"裝置資訊",()=>{});details.Padding=new Thickness(6);details.Width=32;details.Height=32;
                details.Content=Icons.Fixed(Icons.Info,18,"Muted");details.VerticalAlignment=VerticalAlignment.Top;
                details.Flyout=new Flyout{Content=Column(8,Label("裝置資訊",14,FontWeight.SemiBold),info)};
                var content=Column(5,Columns("*,Auto",Column(4,name,functions),details));
                var usbLabel=Label(usbSummary,12,key:"Muted");usbLabel.TextWrapping=TextWrapping.Wrap;content.Children.Add(usbLabel);
                foreach(var disk in Entries(device,"storage")){
                    var model=Text(disk,"model");var size=USBNumber(disk,"bytes");
                    var diskTitle=(model!=""&&model!=Text(device,"name")?model+" · ":"")+(size>0?"磁碟容量 "+USBSize(size):"磁碟容量尚未提供");
                    var diskLabel=Label(diskTitle,12,key:"Muted");diskLabel.TextWrapping=TextWrapping.Wrap;content.Children.Add(diskLabel);
                    var volumes=Entries(disk,"volumes").ToArray();
                    foreach(var volume in volumes){
                        var title=Text(volume,"name");if(title=="")title="未命名磁碟區";
                        var known=volume.TryGetProperty("space_known",out var k)&&k.ValueKind==JsonValueKind.True;
                        var total=USBNumber(volume,"bytes");var free=USBNumber(volume,"free_bytes");var percentage=USBUsedPercent(total,free,known);
                        var space=percentage.HasValue?$"可用 {USBSize(USBNumber(volume,"free_bytes"))} / {USBSize(USBNumber(volume,"bytes"))}":"容量與可用空間尚未提供";
                        var line=Label($"{Text(volume,"mount")} · {title}\n{space}",13);line.TextWrapping=TextWrapping.Wrap;content.Children.Add(line);
                        if(percentage is double used){
                            var usedLabel=Label($"已用 {USBSize(total-free)} · {used:0.#}%",12,key:used>=95?"Warn":"Muted");content.Children.Add(usedLabel);
                            var bar=new ProgressBar{Minimum=0,Maximum=100,Value=used,Height=6,HorizontalAlignment=HorizontalAlignment.Stretch,Margin=new Thickness(0,2,0,6)};
                            bar.Res(ProgressBar.ForegroundProperty,used>=95?"Warn":"Accent");
                            AutomationProperties.SetName(bar,$"{Text(volume,"mount")} {title} 已用 {used:0.#}%，可用 {USBSize(free)}");
                            ToolTip.SetTip(bar,$"已用 {USBSize(total-free)} / {USBSize(total)} · 可用 {USBSize(free)}");content.Children.Add(bar);
                        }
                    }
                    if(Text(disk,"problem") is {Length:>0} diskProblem)content.Children.Add(Label(diskProblem,12,key:"Warn"));
                    else if(volumes.Length==0)content.Children.Add(Label("沒有已指派磁碟代號的磁碟區（可能未掛載或尚未格式化）。",12,key:"Muted"));
                }
                if(Text(device,"storage_problem") is {Length:>0} storageProblem){var warning=Label(storageProblem,12,key:"Warn");warning.TextWrapping=TextWrapping.Wrap;content.Children.Add(warning);}
                usbRows.Children.Add(Card(content,new Thickness(12)));
            }
        }
    }
}
