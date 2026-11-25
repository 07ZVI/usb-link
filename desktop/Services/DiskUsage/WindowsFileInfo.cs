using System.Runtime.InteropServices;

namespace Suhang.Desktop.DiskUsage;

[StructLayout(LayoutKind.Sequential)]
internal struct WindowsFileInfo
{
    internal uint Attributes;
    internal System.Runtime.InteropServices.ComTypes.FILETIME Creation, Access, Write;
    internal uint VolumeSerial, SizeHigh, SizeLow, Links, IndexHigh, IndexLow;
}
