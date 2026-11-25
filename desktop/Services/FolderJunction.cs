using System.Buffers.Binary;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Text;
using Microsoft.Win32.SafeHandles;

namespace Suhang.Desktop;

internal static class FolderJunction
{
    const uint BackupSemantics = 0x02000000;
    const uint SetReparsePoint = 0x000900A4;
    const uint MountPointTag = 0xA0000003;
    const uint FileRenameInformation = 10;
    const uint FileDispositionInformation = 13;

    internal static void Create(string source, string link)
    {
        if (!OperatingSystem.IsWindows()) throw new PlatformNotSupportedException("需在 Windows 上建立資料夾連結。");
        source = LocalPath(source);
        link = LocalPath(link);
        var parent = Path.GetDirectoryName(link) ?? throw new IOException("連結位置必須包含新資料夾的名稱。");
        if (Path.GetFileName(link).Length == 0) throw new IOException("請輸入新連結的完整路徑。");

        // Resolve existing aliases before checking the source and destination relationship.
        using var sourceDirectory = OpenDirectory(source);
        source = FinalPath(sourceDirectory);
        using var parentDirectory = OpenDirectory(parent);
        parent = FinalPath(parentDirectory);
        if (new DriveInfo(Path.GetPathRoot(parent)!).DriveFormat != "NTFS")
            throw new IOException("連結位置必須位於 NTFS 磁碟。");
        link = Path.Combine(parent, Path.GetFileName(link));
        if (link.Equals(source, StringComparison.OrdinalIgnoreCase) ||
            link.StartsWith(Path.EndsInDirectorySeparator(source) ? source : source + '\\', StringComparison.OrdinalIgnoreCase))
            throw new IOException("無法在來源資料夾內建立指向來源的連結。");
        if (!IsNewPath(link)) throw new IOException("連結位置已存在。請另選一個新名稱。");

        // Create, configure, publish or discard the same object by handle. A
        // writable parent does not allow another process to swap in a link.
        var data = MountPointData(source);
        var stagingName = ".usb-link-" + Guid.NewGuid().ToString("N");
        var rename = RenameData(Path.GetFileName(link));
        using var staging = CreateStagingDirectory(parentDirectory, stagingName);
        try {
            if (!DeviceIoControl(staging, SetReparsePoint, data, (uint)data.Length, IntPtr.Zero, 0, out _, IntPtr.Zero))
                throw new Win32Exception(Marshal.GetLastPInvokeError());
            var result = NtSetInformationFile(staging, out _, rename, (uint)rename.Length, FileRenameInformation);
            if (result < 0 && RtlNtStatusToDosError(result) is 80 or 183) throw new IOException("連結位置已存在。請另選一個新名稱。");
            CheckNt(result);
        } catch (Exception e) {
            if (NtSetInformationFile(staging, out _, [1], 1, FileDispositionInformation) < 0)
                throw new IOException("建立連結失敗，暫存項目無法移除：" + Path.Combine(parent, stagingName) + "\n" + e.Message, e);
            throw;
        }
    }

    static SafeFileHandle CreateStagingDirectory(SafeFileHandle parent, string name)
    {
        var nameBytes = (ushort)(name.Length * sizeof(char));
        var buffer = Marshal.StringToHGlobalUni(name);
        var unicode = Marshal.AllocHGlobal(Marshal.SizeOf<UnicodeString>());
        try {
            Marshal.StructureToPtr(new UnicodeString { Length = nameBytes, MaximumLength = (ushort)(nameBytes + sizeof(char)), Buffer = buffer }, unicode, false);
            const uint caseInsensitive = 0x40;
            const uint writeDeleteSynchronize = 0x40000000 | 0x00010000 | 0x00100000;
            const uint createNew = 2, directoryFile = 1, synchronousIoNonAlert = 0x20;
            var attrs = new ObjectAttributes { Length = (uint)Marshal.SizeOf<ObjectAttributes>(), RootDirectory = parent.DangerousGetHandle(), Name = unicode, Flags = caseInsensitive };
            var result = NtCreateFile(out var handle, writeDeleteSynchronize, ref attrs, out _, IntPtr.Zero, 0, FileShare.None,
                createNew, directoryFile | synchronousIoNonAlert, IntPtr.Zero, 0);
            GC.KeepAlive(parent);
            if (result >= 0) return handle;
            handle?.Dispose();
            throw new Win32Exception((int)RtlNtStatusToDosError(result));
        } finally { Marshal.FreeHGlobal(unicode); Marshal.FreeHGlobal(buffer); }
    }

    static byte[] RenameData(string name)
    {
        // Null RootDirectory with a simple name renames in the same parent.
        // ReplaceIfExists stays false, including when another process wins the race.
        var bytes = Encoding.Unicode.GetBytes(name);
        var info = new byte[Marshal.SizeOf<RenameInformation>() + bytes.Length];
        var lengthOffset = Marshal.OffsetOf<RenameInformation>(nameof(RenameInformation.NameLength)).ToInt32();
        var nameOffset = Marshal.OffsetOf<RenameInformation>(nameof(RenameInformation.FirstCharacter)).ToInt32();
        BinaryPrimitives.WriteUInt32LittleEndian(info.AsSpan(lengthOffset), (uint)bytes.Length);
        bytes.CopyTo(info, nameOffset);
        return info;
    }

    static void CheckNt(int status)
    {
        if (status < 0) throw new Win32Exception((int)RtlNtStatusToDosError(status));
    }

    static bool IsNewPath(string path)
    {
        try { _ = File.GetAttributes(path); return false; }
        catch (FileNotFoundException) { return true; }
    }

    static string LocalPath(string input)
    {
        var path = input.Trim().Replace('/', '\\');
        if (path.Length < 3 || !char.IsAsciiLetter(path[0]) || path[1] != ':' || path[2] != '\\' ||
            path[3..].Split('\\', StringSplitOptions.RemoveEmptyEntries).Any(part =>
                part.EndsWith('.') || part.EndsWith(' ') || part.IndexOfAny(Path.GetInvalidFileNameChars()) >= 0))
            throw new IOException("請輸入本機磁碟的完整路徑，例如 D:\\tmp。");
        path = Path.TrimEndingDirectorySeparator(Path.GetFullPath(path));
        if (new DriveInfo(Path.GetPathRoot(path)!).DriveType is not (DriveType.Fixed or DriveType.Removable or DriveType.Ram))
            throw new IOException("請選擇可存取的本機磁碟。");
        return path;
    }

    static SafeFileHandle OpenDirectory(string path)
    {
        if (!File.GetAttributes(path).HasFlag(FileAttributes.Directory)) throw new IOException("請選擇資料夾：" + path);
        const uint readAttributesAndTraverse = 0x80 | 0x20;
        var handle = CreateFile(@"\\?\" + path, readAttributesAndTraverse, FileShare.ReadWrite, IntPtr.Zero, FileMode.Open, BackupSemantics, IntPtr.Zero);
        if (!handle.IsInvalid) return handle;
        var error = Marshal.GetLastPInvokeError();
        handle.Dispose();
        throw new Win32Exception(error);
    }

    static string FinalPath(SafeFileHandle handle)
    {
        var result = new StringBuilder(32768);
        var length = GetFinalPathNameByHandle(handle, result, (uint)result.Capacity, 0);
        if (length == 0) throw new Win32Exception(Marshal.GetLastPInvokeError());
        var path = result.ToString();
        if (length >= result.Capacity || !path.StartsWith(@"\\?\", StringComparison.Ordinal))
            throw new IOException("無法確認資料夾的實際位置。");
        return LocalPath(path[4..]);
    }

    internal static byte[] MountPointData(string source)
    {
        // REPARSE_DATA_BUFFER mount-point layout. Offsets are in bytes from PathBuffer.
        var substitute = Encoding.Unicode.GetBytes(@"\??\" + source);
        var display = Encoding.Unicode.GetBytes(source);
        var printOffset = substitute.Length + sizeof(char);
        var length = 16 + printOffset + display.Length + sizeof(char);
        if (length > 16384) throw new IOException("來源路徑過長，無法建立連結。");
        var data = new byte[length];
        BinaryPrimitives.WriteUInt32LittleEndian(data, MountPointTag);
        BinaryPrimitives.WriteUInt16LittleEndian(data.AsSpan(4), (ushort)(length - 8));
        BinaryPrimitives.WriteUInt16LittleEndian(data.AsSpan(10), (ushort)substitute.Length);
        BinaryPrimitives.WriteUInt16LittleEndian(data.AsSpan(12), (ushort)printOffset);
        BinaryPrimitives.WriteUInt16LittleEndian(data.AsSpan(14), (ushort)display.Length);
        substitute.CopyTo(data, 16);
        display.CopyTo(data, 16 + printOffset);
        return data;
    }

    [StructLayout(LayoutKind.Sequential)] struct UnicodeString { internal ushort Length, MaximumLength; internal IntPtr Buffer; }
    [StructLayout(LayoutKind.Sequential)] struct ObjectAttributes {
        internal uint Length;
        internal IntPtr RootDirectory, Name;
        internal uint Flags;
        internal IntPtr SecurityDescriptor, SecurityQualityOfService;
    }
    [StructLayout(LayoutKind.Sequential)] struct IoStatusBlock { internal IntPtr Status; internal nuint Information; }
    [StructLayout(LayoutKind.Sequential)] struct RenameInformation {
        internal uint ReplaceIfExists;
        internal IntPtr RootDirectory;
        internal uint NameLength;
        internal ushort FirstCharacter;
    }

    [DllImport("ntdll.dll"), DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    static extern int NtCreateFile(out SafeFileHandle file, uint access, ref ObjectAttributes attrs, out IoStatusBlock status,
        IntPtr allocationSize, uint fileAttributes, FileShare share, uint disposition, uint options, IntPtr eaBuffer, uint eaLength);
    [DllImport("ntdll.dll"), DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    static extern int NtSetInformationFile(SafeFileHandle file, out IoStatusBlock status, byte[] data, uint length, uint infoClass);
    [DllImport("ntdll.dll"), DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    static extern uint RtlNtStatusToDosError(int status);
    [DllImport("kernel32.dll", EntryPoint = "CreateFileW", CharSet = CharSet.Unicode, SetLastError = true), DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    static extern SafeFileHandle CreateFile(string path, uint access, FileShare share, IntPtr security, FileMode mode, uint flags, IntPtr template);
    [DllImport("kernel32.dll", EntryPoint = "GetFinalPathNameByHandleW", CharSet = CharSet.Unicode, SetLastError = true), DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    static extern uint GetFinalPathNameByHandle(SafeFileHandle file, StringBuilder path, uint capacity, uint flags);
    [DllImport("kernel32.dll", SetLastError = true), DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    [return: MarshalAs(UnmanagedType.Bool)] static extern bool DeviceIoControl(SafeFileHandle file, uint code, byte[] input, uint size, IntPtr output, uint capacity, out uint returned, IntPtr overlapped);
}
