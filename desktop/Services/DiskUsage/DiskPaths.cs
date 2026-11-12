namespace Suhang.Desktop.DiskUsage;

internal static class DiskPaths
{
    internal static StringComparison Comparison => OperatingSystem.IsWindows()?StringComparison.OrdinalIgnoreCase:StringComparison.Ordinal;
    internal static string Canonical(string path) {
        var full=Path.GetFullPath(path);
        if(OperatingSystem.IsWindows()) {
            if(full.StartsWith(@"\\?\UNC\",StringComparison.OrdinalIgnoreCase))full=@"\\"+full[8..];
            else if(full.StartsWith(@"\\?\",StringComparison.Ordinal))full=full[4..];
        }
        return Path.TrimEndingDirectorySeparator(Path.GetFullPath(full));
    }
    internal static string Native(string path) => !OperatingSystem.IsWindows()||path.StartsWith(@"\\?\",StringComparison.Ordinal)?path:
        path.StartsWith(@"\\",StringComparison.Ordinal)?@"\\?\UNC\"+path[2..]:@"\\?\"+path;
    internal static bool Equal(string a,string b) => string.Equals(Canonical(a),Canonical(b),Comparison);
    internal static bool Within(string path,string root,bool includeRoot=false) {
        path=Canonical(path);root=Canonical(root);
        return includeRoot&&string.Equals(path,root,Comparison)||
            path.StartsWith(Path.EndsInDirectorySeparator(root)?root:root+Path.DirectorySeparatorChar,Comparison);
    }
    internal static NodeIssue Issue(FileAttributes attributes) =>
        (attributes&FileAttributes.ReparsePoint)!=0?NodeIssue.Link:
        ((uint)attributes&(0x1000u|0x40000u|0x400000u))!=0?NodeIssue.Offline:NodeIssue.None;

    internal static NodeIssue CheckDirectory(string path,string root) {
        var current=Canonical(path);root=Canonical(root);
        if(!Within(current,root,true))return NodeIssue.Link;
        while(true) {
            var issue=Issue(File.GetAttributes(Native(current)));
            if(issue!=NodeIssue.None)return issue;
            if(string.Equals(current,root,Comparison))return NodeIssue.None;
            current=Path.GetDirectoryName(current)!;
        }
    }
}
