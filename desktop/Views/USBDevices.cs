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
            usbRows.Children.Add(new Border{Padding=new Thickness(2,10,2,0),Child=Label(usbGroupTitles[group.Key]+" · "+group.Count(),Scale.Secondary,FontWeight.SemiBold,key:"Muted")});
            foreach(var device in group){
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
                metadata+="\n裝置規格："+(specification!=""?specification:"Windows 尚未提供")+"\n目前協商速率："+(speed!=""?speed:"Windows 尚未提供")+"\n接口支援："+(protocols!=""?protocols:"Windows 尚未提供");
                metadata+="\nUSB 3.x 接口的 3.1／3.2 版本及通道數，Windows 快取資料未提供；協商速率不代表實際傳輸速度。";
                var info=new SelectableTextBlock{Text=metadata,FontSize=Scale.Secondary,TextWrapping=TextWrapping.Wrap,MaxWidth=380};info.Res(TextBlock.ForegroundProperty,"Muted");
                var details=IconButton(Icons.Info,"裝置資訊",()=>{});details.Padding=new Thickness(5);details.Width=28;details.Height=28;
                details.Content=Icons.Fixed(Icons.Info,16,"Muted");
                details.Flyout=new Flyout{Content=Column(8,Label("裝置資訊",14,FontWeight.SemiBold),info)};
                // Key facts share one line; unknown values are left out ("尚未取得" only when nothing else is known).
                var facts=new List<string>();
                if(specification!="")facts.Add(specification);
                if(speed!="")facts.Add(speed);
                var content=new List<Control>();
                var diskBodies=new List<Control>();
                foreach(var disk in Entries(device,"storage")){
                    var model=Text(disk,"model");var size=USBNumber(disk,"bytes");
                    if(model!=""&&model!=Text(device,"name"))facts.Add(model);
                    if(size>0)facts.Add("磁碟容量 "+USBSize(size));
                    var volumes=Entries(disk,"volumes").ToArray();
                    foreach(var volume in volumes)diskBodies.Add(USBVolumeRow(volume));
                    if(Text(disk,"problem") is {Length:>0} diskProblem)diskBodies.Add(Hint(diskProblem,"Warn",Scale.Caption));
                    else if(volumes.Length==0)diskBodies.Add(Hint("沒有已指派磁碟代號的磁碟區（可能未掛載或尚未格式化）。","Muted",Scale.Caption));
                }
                if(diskBodies.Count>0){content.Add(WithMargin(Rule(),new Thickness(0,4,0,2)));content.AddRange(diskBodies);}
                if(Text(device,"storage_problem") is {Length:>0} storageProblem)content.Add(Hint(storageProblem,"Warn",Scale.Caption));
                usbRows.Children.Add(ListItem.Compact(Text(device,"name"),USBDisplayKind(device),facts.Count>0?string.Join(" · ",facts):"USB 版本尚未取得",details,content.ToArray()));
            }
        }
    }
    /// Mount and name on the left, free space and used share on the right, a thin usage bar below.
    static Control USBVolumeRow(JsonElement volume)
    {
        var title=Text(volume,"name");if(title=="")title="未命名磁碟區";
        var known=volume.TryGetProperty("space_known",out var k)&&k.ValueKind==JsonValueKind.True;
        var total=USBNumber(volume,"bytes");var free=USBNumber(volume,"free_bytes");var percentage=USBUsedPercent(total,free,known);
        var mount=Text(volume,"mount");
        var space=percentage is double share?$"可用 {USBSize(free)} / {USBSize(total)} · 已用 {share:0.#}%":"容量與可用空間尚未提供";
        var name=Label($"{mount} · {title}",Scale.Secondary,FontWeight.SemiBold);
        var amount=Label(space,Scale.Secondary,key:percentage>=95?"Warn":"Muted");
        var line=Columns("*,Auto",name,amount);line.ColumnSpacing=12;
        var row=Column(4,line);
        if(percentage is double used){
            var bar=new ProgressBar{Minimum=0,Maximum=100,Value=used,Height=4,HorizontalAlignment=HorizontalAlignment.Stretch};
            bar.Res(ProgressBar.ForegroundProperty,used>=95?"Warn":"Accent");
            AutomationProperties.SetName(bar,$"{mount} {title} 已用 {used:0.#}%，可用 {USBSize(free)}");
            ToolTip.SetTip(bar,$"已用 {USBSize(total-free)} / {USBSize(total)} · 可用 {USBSize(free)}");row.Children.Add(bar);
        }
        return WithMargin(row,new Thickness(0,2,0,2));
    }
}
