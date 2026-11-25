using System.Runtime.InteropServices;

namespace Suhang.Desktop.DiskUsage;

[ComImport,Guid("43826D1E-E718-42EE-BC55-A1E261C37BFE"),InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
internal interface ShellItem
{
    void BindToHandler(IntPtr context,ref Guid handler,ref Guid iid,out IntPtr result);
    void GetParent(out ShellItem parent);
    void GetDisplayName(uint kind,out IntPtr name);
    void GetAttributes(uint mask,out uint attributes);
    void Compare(ShellItem other,uint hint,out int order);
}
