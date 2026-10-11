using System.Text.Json;
namespace Suhang.Desktop;
internal sealed record UpstreamChoice(uint Index, string Name);
internal sealed record InternetSharingState(string State,string Problem,IReadOnlyList<UpstreamChoice> Upstreams)
{
    internal static InternetSharingState? Read(JsonElement display)
    {
        if(!display.TryGetProperty("internet_sharing",out var value)||value.ValueKind!=JsonValueKind.Object)return null;
        var choices=new List<UpstreamChoice>();
        if(value.TryGetProperty("upstreams",out var upstreams)&&upstreams.ValueKind==JsonValueKind.Array)
            foreach(var u in upstreams.EnumerateArray())
                if(u.TryGetProperty("index",out var i)&&i.TryGetUInt32(out var index)&&u.TryGetProperty("name",out var n)&&n.ValueKind==JsonValueKind.String)
                    choices.Add(new(index,n.GetString()??""));
        return new(Text(value,"state"),Text(value,"problem"),choices);
    }
    internal static string Text(JsonElement value,string key)=>value.TryGetProperty(key,out var p)&&p.ValueKind==JsonValueKind.String?p.GetString()??"":"";
}
internal sealed record DependencyState(string ID,string State,string Problem,IReadOnlyList<string> Features)
{
    internal static IReadOnlyList<DependencyState>? Read(JsonElement display)
    {
        if(!display.TryGetProperty("dependencies",out var value)||value.ValueKind!=JsonValueKind.Array)return null;
        var result=new List<DependencyState>();
        foreach(var d in value.EnumerateArray()){
            if(d.ValueKind!=JsonValueKind.Object)continue;
            var features=new List<string>();
            if(d.TryGetProperty("features",out var list)&&list.ValueKind==JsonValueKind.Array)
                foreach(var f in list.EnumerateArray())if(f.ValueKind==JsonValueKind.String)features.Add(f.GetString()??"");
            result.Add(new(InternetSharingState.Text(d,"id"),InternetSharingState.Text(d,"state"),InternetSharingState.Text(d,"problem"),features));
        }
        return result;
    }
}
