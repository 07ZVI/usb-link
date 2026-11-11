using System.Runtime.InteropServices;

namespace Suhang.Desktop.DiskUsage;

[ComImport,Guid("947AAB5F-0A5C-4C13-B4D6-4BF7836FC9F8"),InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
internal interface ShellFileOperation
{
    void Advise(IntPtr sink,out uint cookie);
    void Unadvise(uint cookie);
    void SetOperationFlags(uint flags);
    void SetProgressMessage([MarshalAs(UnmanagedType.LPWStr)] string message);
    void SetProgressDialog(IntPtr dialog);
    void SetProperties(IntPtr changes);
    void SetOwnerWindow(IntPtr window);
    void ApplyPropertiesToItem(ShellItem item);
    void ApplyPropertiesToItems(IntPtr items);
    void RenameItem(ShellItem item,[MarshalAs(UnmanagedType.LPWStr)] string name,IntPtr sink);
    void RenameItems(IntPtr items,[MarshalAs(UnmanagedType.LPWStr)] string name);
    void MoveItem(ShellItem item,ShellItem destination,[MarshalAs(UnmanagedType.LPWStr)] string name,IntPtr sink);
    void MoveItems(IntPtr items,ShellItem destination);
    void CopyItem(ShellItem item,ShellItem destination,[MarshalAs(UnmanagedType.LPWStr)] string name,IntPtr sink);
    void CopyItems(IntPtr items,ShellItem destination);
    void DeleteItem(ShellItem item,IntPtr sink);
    void DeleteItems(IntPtr items);
    void NewItem(ShellItem destination,uint attributes,[MarshalAs(UnmanagedType.LPWStr)] string name,
        [MarshalAs(UnmanagedType.LPWStr)] string template,IntPtr sink);
    void PerformOperations();
    void GetAnyOperationsAborted([MarshalAs(UnmanagedType.Bool)] out bool aborted);
}
