using System.Collections.Concurrent;
using System.Runtime.InteropServices;
using Avalonia;
using Avalonia.Media.Imaging;
using Avalonia.Platform;
using Avalonia.Threading;

namespace Suhang.Desktop;

/// Shell icons of program images for the task manager: extracted on one background STA thread, cached by full path
/// (bounded LRU) and delivered to the UI thread. A missing result is cached too, so protected or system processes
/// are asked once and keep the generic icon. Windows only; elsewhere every lookup resolves to the generic icon.
internal static class ProgramIcons
{
    internal const int Capacity = 512;
    const int QueueLimit = 256;
    static readonly object gate = new();
    static readonly Dictionary<string, LinkedListNode<(string Path, Bitmap? Icon)>> cache = new(StringComparer.OrdinalIgnoreCase);
    static readonly LinkedList<(string Path, Bitmap? Icon)> recency = new();
    static readonly Dictionary<string, List<Action<Bitmap?>>> waiting = new(StringComparer.OrdinalIgnoreCase);
    static BlockingCollection<string>? queue;
    static int extractions;

    internal static int CachedCount { get { lock (gate) return cache.Count; } }
    /// Shell lookups started since launch (tests only).
    internal static int Extractions => Volatile.Read(ref extractions);

    /// True when the path has a cached answer; `icon` is null when it is known to have none.
    internal static bool TryGet(string path, out Bitmap? icon)
    {
        lock (gate)
        {
            if (cache.TryGetValue(path, out var node)) { recency.Remove(node); recency.AddFirst(node); icon = node.Value.Icon; return true; }
        }
        icon = null; return false;
    }

    /// Calls `ready` on the UI thread once the icon is known (null: use the generic icon). Never blocks the caller.
    internal static void Request(string path, Action<Bitmap?> ready)
    {
        if (!CanExtract(path)) { Dispatcher.UIThread.Post(() => ready(null), DispatcherPriority.Background); return; }
        BlockingCollection<string> work;
        lock (gate)
        {
            if (waiting.TryGetValue(path, out var pending)) { pending.Add(ready); return; }
            waiting[path] = [ready];
            work = queue ??= StartWorker();
        }
        // A full queue answers with the generic icon now and asks again the next time the row is built.
        if (!work.TryAdd(path)) Complete(path, null, remember: false);
    }

    /// Stores a ready-made icon (design-tools previews).
    internal static void Put(string path, Bitmap? icon) { lock (gate) Store(path, icon); }

    internal static void Clear() { lock (gate) { cache.Clear(); recency.Clear(); } }

    static bool CanExtract(string path) => OperatingSystem.IsWindows() && path.Length > 0 && (path.Length < 3 || !path.StartsWith(@"\\", StringComparison.Ordinal) || path.StartsWith(@"\\?\", StringComparison.Ordinal));

    static void Store(string path, Bitmap? icon)
    {
        if (cache.TryGetValue(path, out var old)) { recency.Remove(old); cache.Remove(path); }
        cache[path] = recency.AddFirst((path, icon));
        while (cache.Count > Capacity && recency.Last is { } last) { recency.RemoveLast(); cache.Remove(last.Value.Path); }
    }

    static void Complete(string path, Bitmap? icon, bool remember)
    {
        List<Action<Bitmap?>>? callbacks;
        lock (gate)
        {
            waiting.Remove(path, out callbacks);
            if (remember) Store(path, icon);
        }
        if (callbacks == null) return;
        Dispatcher.UIThread.Post(() => { foreach (var callback in callbacks) callback(icon); }, DispatcherPriority.Background);
    }

    static BlockingCollection<string> StartWorker()
    {
        var work = new BlockingCollection<string>(QueueLimit);
        // Shell icon handlers are COM objects: give them a single-threaded apartment that lives as long as the process.
        var thread = new Thread(() => {
            foreach (var path in work.GetConsumingEnumerable())
            {
                Bitmap? icon = null;
                try { Interlocked.Increment(ref extractions); icon = Extract(path); } catch { }
                Complete(path, icon, remember: true);
            }
        }) { IsBackground = true, Name = "program-icons" };
        if (OperatingSystem.IsWindows()) thread.SetApartmentState(ApartmentState.STA);
        thread.Start();
        return work;
    }

    // ---------- Windows extraction ----------

    static Bitmap? Extract(string path)
    {
        if (!OperatingSystem.IsWindows()) return null;
        if (path.StartsWith(@"\\?\", StringComparison.Ordinal) && path.Length > 6 && path[5] == ':') path = path[4..];
        var info = new ShFileInfo();
        // The large icon is 32 px at 100% and is shown at 16 DIPs, so it stays sharp up to 200% scaling.
        if (SHGetFileInfo(path, 0, ref info, (uint)Marshal.SizeOf<ShFileInfo>(), 0x100 /* SHGFI_ICON, large */) == IntPtr.Zero || info.Icon == IntPtr.Zero) return null;
        try { return ToBitmap(info.Icon); }
        finally { DestroyIcon(info.Icon); }
    }

    static Bitmap? ToBitmap(IntPtr icon)
    {
        if (!GetIconInfo(icon, out var parts)) return null;
        var screen = IntPtr.Zero;
        try
        {
            if (parts.Color == IntPtr.Zero) return null; // Monochrome cursors and legacy icons keep the generic icon.
            var size = new BitmapObject();
            if (GetObject(parts.Color, Marshal.SizeOf<BitmapObject>(), ref size) == 0) return null;
            int width = size.Width, height = size.Height;
            if (width is < 1 or > 256 || height is < 1 or > 256) return null;
            screen = GetDC(IntPtr.Zero);
            if (screen == IntPtr.Zero) return null;
            var pixels = ReadBits(screen, parts.Color, width, height);
            if (pixels == null) return null;
            // Icons without an alpha channel carry their transparency in the mask bitmap (set bit = transparent).
            if (!HasAlpha(pixels))
            {
                var mask = parts.Mask == IntPtr.Zero ? null : ReadBits(screen, parts.Mask, width, height);
                for (var i = 0; i < pixels.Length; i += 4)
                    pixels[i + 3] = mask == null || mask[i] == 0 && mask[i + 1] == 0 && mask[i + 2] == 0 ? (byte)255 : (byte)0;
            }
            var bitmap = new WriteableBitmap(new PixelSize(width, height), new Vector(96, 96), PixelFormat.Bgra8888, AlphaFormat.Premul);
            using var buffer = bitmap.Lock();
            for (var y = 0; y < height; y++) Marshal.Copy(pixels, y * width * 4, buffer.Address + y * buffer.RowBytes, width * 4);
            return bitmap;
        }
        finally
        {
            if (screen != IntPtr.Zero) ReleaseDC(IntPtr.Zero, screen);
            if (parts.Color != IntPtr.Zero) DeleteObject(parts.Color);
            if (parts.Mask != IntPtr.Zero) DeleteObject(parts.Mask);
        }
    }

    static bool HasAlpha(byte[] bgra)
    {
        for (var i = 3; i < bgra.Length; i += 4) if (bgra[i] != 0) return true;
        return false;
    }

    /// Top-down 32-bit BGRA pixels of a GDI bitmap.
    static byte[]? ReadBits(IntPtr screen, IntPtr bitmap, int width, int height)
    {
        var header = new BitmapHeader { Size = (uint)Marshal.SizeOf<BitmapHeader>(), Width = width, Height = -height, Planes = 1, BitCount = 32 };
        var pixels = new byte[width * height * 4];
        return GetDIBits(screen, bitmap, 0, (uint)height, pixels, ref header, 0) == height ? pixels : null;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    struct ShFileInfo
    {
        public IntPtr Icon; public int IconIndex; public uint Attributes;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 260)] public string DisplayName;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 80)] public string TypeName;
    }
    [StructLayout(LayoutKind.Sequential)] struct IconParts { public bool IsIcon; public uint HotX, HotY; public IntPtr Mask, Color; }
    [StructLayout(LayoutKind.Sequential)] struct BitmapObject { public int Type, Width, Height, WidthBytes; public ushort Planes, BitsPixel; public IntPtr Bits; }
    [StructLayout(LayoutKind.Sequential)]
    struct BitmapHeader
    {
        public uint Size; public int Width, Height; public ushort Planes, BitCount; public uint Compression, SizeImage;
        public int XPelsPerMeter, YPelsPerMeter; public uint ColorsUsed, ColorsImportant;
    }

    [DllImport("shell32.dll", CharSet = CharSet.Unicode), DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    static extern IntPtr SHGetFileInfo(string path, uint attributes, ref ShFileInfo info, uint size, uint flags);
    [DllImport("user32.dll", SetLastError = true), DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    static extern bool GetIconInfo(IntPtr icon, out IconParts parts);
    [DllImport("user32.dll"), DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    static extern bool DestroyIcon(IntPtr icon);
    [DllImport("user32.dll"), DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    static extern IntPtr GetDC(IntPtr window);
    [DllImport("user32.dll"), DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    static extern int ReleaseDC(IntPtr window, IntPtr context);
    [DllImport("gdi32.dll"), DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    static extern int GetObject(IntPtr handle, int size, ref BitmapObject bitmap);
    [DllImport("gdi32.dll"), DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    static extern int GetDIBits(IntPtr context, IntPtr bitmap, uint start, uint lines, byte[] bits, ref BitmapHeader header, uint usage);
    [DllImport("gdi32.dll"), DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    static extern bool DeleteObject(IntPtr handle);
}
