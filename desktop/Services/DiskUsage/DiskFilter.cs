using System.Globalization;
using System.IO.Enumeration;
using System.Runtime.CompilerServices;

namespace Suhang.Desktop.DiskUsage;

internal sealed class DiskFilter
{
    readonly (Func<DiskNode,bool> Match,bool Aggregate)[] terms;
    readonly ConditionalWeakTable<DiskNode,DiskFilterCache> cache=new();
    DiskFilter((Func<DiskNode,bool>,bool)[] terms) => this.terms=terms;

    internal static bool TryParse(string text,out DiskFilter? filter,out string? error) {
        filter=null;error=null;
        if(string.IsNullOrWhiteSpace(text))return true;
        var terms=new List<(Func<DiskNode,bool>,bool)>();
        var now=DateTime.UtcNow;
        foreach(var raw in text.Split((char[]?)null,StringSplitOptions.RemoveEmptyEntries).SelectMany(s=>s.Split(';',StringSplitOptions.RemoveEmptyEntries))) {
            var negate=raw.StartsWith('!');var body=negate?raw[1..]:raw;
            if(body.Length==0||body.StartsWith('!')) { error="無法解讀條件："+raw;return false; }
            var arms=body.Split('|');
            var predicates=new List<Func<DiskNode,bool>>();var aggregate=true;
            var categoryGroup=body.StartsWith("type:",StringComparison.OrdinalIgnoreCase);
            for(var i=0;i<arms.Length;i++) {
                var arm=arms[i];
                if(categoryGroup&&i>0&&!arm.Contains(':'))arm="type:"+arm;
                if(!ParseTerm(arm,now,out var predicate,out var supported,out error))return false;
                predicates.Add(predicate!);aggregate&=supported;
            }
            terms.Add((file=>negate?!predicates.Any(p=>p(file)):predicates.Any(p=>p(file)),aggregate));
        }
        if(terms.Count>0)filter=new(terms.ToArray());
        return true;
    }
    static bool ParseTerm(string text,DateTime now,out Func<DiskNode,bool>? predicate,out bool aggregate,out string? error) {
        predicate=null;aggregate=false;error=null;
        if(text.Length==0) { error="條件不可為空白";return false; }
        if(text[0] is '>' or '<' or '=') {
            var count=text.Length>1&&text[1]=='='?2:1;
            var op=text[..count];
            if(op is not (">" or ">=" or "<" or "<=" or "=" )||!Quantity(text[count..],false,out var size)) {
                error="無法解讀大小："+text;return false;
            }
            aggregate=true;
            predicate=n=>op switch { ">"=>n.Size>size,">="=>n.Size>=size,"<"=>n.Size<size,"<="=>n.Size<=size,_=>n.Size==size };
            return true;
        }
        if(text.StartsWith("older:",StringComparison.OrdinalIgnoreCase)||text.StartsWith("newer:",StringComparison.OrdinalIgnoreCase)) {
            var older=text.StartsWith("older:",StringComparison.OrdinalIgnoreCase);
            if(!Quantity(text[6..],true,out var seconds)||seconds>(now-DateTime.MinValue).TotalSeconds) {
                error="無法解讀時間："+text;return false;
            }
            var cutoff=now.AddSeconds(-seconds);predicate=n=>older?n.LastWriteUtc<cutoff:n.LastWriteUtc>=cutoff;return true;
        }
        if(text.StartsWith("type:",StringComparison.OrdinalIgnoreCase)) {
            if(!Enum.TryParse<FileCategory>(text[5..],true,out var category)||!Enum.IsDefined(category)||text[5..].Any(char.IsDigit)) {
                error="未知檔案類型："+text[5..];return false;
            }
            predicate=n=>n.Category==category;return true;
        }
        if(text.Contains(':')) { error="無法解讀條件："+text;return false; }
        predicate=text.IndexOfAny(['*','?'])>=0?n=>FileSystemName.MatchesSimpleExpression(text,n.Name,true):
            n=>n.Name.Contains(text,StringComparison.OrdinalIgnoreCase);
        return true;
    }
    static bool Quantity(string text,bool age,out double value) {
        value=0;var i=0;
        while(i<text.Length&&(char.IsAsciiDigit(text[i])||text[i]=='.'))i++;
        if(i==0||!double.TryParse(text[..i],NumberStyles.AllowDecimalPoint,CultureInfo.InvariantCulture,out var amount)||!double.IsFinite(amount)||amount<0)return false;
        var unit=text[i..].ToLowerInvariant();
        var scale=age?unit switch { "h"=>3600d,"d"=>86400d,"w"=>604800d,"m"=>2592000d,"y"=>31536000d,_=>-1 }:
            unit switch { "" or "b"=>1d,"kb"=>1024d,"mb"=>1048576d,"gb"=>1073741824d,"tb"=>1099511627776d,_=>-1 };
        value=amount*scale;return scale>0&&double.IsFinite(value)&&value<=long.MaxValue;
    }

    internal bool Matches(DiskNode file) => file.Kind is NodeKind.File or NodeKind.Aggregate&&
        terms.All(t=>(file.Kind!=NodeKind.Aggregate||t.Aggregate)&&t.Match(file));

    internal long MatchedSize(DiskNode node) {
        lock(node.Gate) {
            var pending=new Stack<(DiskNode Node,bool Visited)>();pending.Push((node,false));
            while(pending.TryPop(out var item)) {
                var entry=cache.GetValue(item.Node,_=>new());
                if(entry.Revision==item.Node.Revision)continue;
                if(item.Node.Kind!=NodeKind.Directory) {
                    entry.Size=Matches(item.Node)?item.Node.Size:0;entry.Revision=item.Node.Revision;continue;
                }
                if(!item.Visited) {
                    pending.Push((item.Node,true));
                    foreach(var child in item.Node.Children)pending.Push((child,false));
                    continue;
                }
                var children=new List<(DiskNode Node,long Size)>();long size=0;
                foreach(var child in item.Node.Children) {
                    var bytes=cache.GetValue(child,_=>new()).Size;size+=bytes;
                    if(bytes>0)children.Add((child,bytes));
                }
                children.Sort((a,b)=> { var order=b.Size.CompareTo(a.Size);return order!=0?order:DiskOrder.CompareNames(a.Node,b.Node); });
                entry.Children=children.ToArray();entry.Size=size;entry.Revision=item.Node.Revision;
            }
            return cache.GetValue(node,_=>new()).Size;
        }
    }
    internal IReadOnlyList<(DiskNode Node,long Size)> Children(DiskNode node) {
        lock(node.Gate) { MatchedSize(node);return cache.GetValue(node,_=>new()).Children; }
    }
}
