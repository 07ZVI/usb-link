# Disk usage analyzer (SpaceSniffer-style)

Status: backend contract. The renderer (Avalonia views, animation) and the backend
(scanner, layout, filter, actions) are developed against this document.

The analyzer is a **read-only desktop helper**, in the same class as the task manager's
process sampler (`desktop/Services/ProcessMonitor.cs`). It runs inside the desktop
process, enumerates a folder the user picked in the UI, and never talks to the
authenticated IPC or the elevated core. The renderer therefore never hands a path to a
privileged component (see [ARCHITECTURE.md](ARCHITECTURE.md), "IPC and authority").

## Placement and rules

- Backend code lives in `desktop/Services/DiskUsage/`, namespace `Suhang.Desktop.DiskUsage`,
  all types `internal`. One type per file, file names equal type names.
- Views live in `desktop/Views/DiskUsage*.cs` and controls in `desktop/Controls/` (renderer side; the backend must not reference Avalonia).
- No new NuGet packages (`packages.lock.json` is locked). Only BCL and, on Windows, `LibraryImport`/`DllImport` P/Invoke.
- The code must compile and the smoke test must pass on **macOS and Windows** (developers preview on macOS). Windows-only
  behavior sits behind `OperatingSystem.IsWindows()`; other platforms use a documented fallback.
- Never open file contents. Enumerate metadata only. Never trigger cloud-file hydration (OneDrive placeholders:
  `FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS`, `FILE_ATTRIBUTE_RECALL_ON_OPEN`, `Offline`).
- Never follow reparse points / symlinks / junctions / mount points; report them as `NodeIssue.Link` with size 0.
- Windows long paths (`\\?\` prefix) must work. Case-insensitive path comparison on Windows, ordinal elsewhere.
- Code style follows the existing desktop code (dense, `var`, switch expressions, no XML-doc novels).
  Comments only for non-obvious constraints.

## Types

```csharp
namespace Suhang.Desktop.DiskUsage;

enum NodeKind { File, Directory, Aggregate, FreeSpace }
enum NodeIssue { None, AccessDenied, Link, Offline, Error }
enum FileCategory { Other, Video, Audio, Image, Document, Archive, Code, Application, DiskImage, System }

sealed class DiskNode
{
    string Name;            // last path segment; drive root keeps "C:\" / "/"
    string FullPath;        // "" for Aggregate and FreeSpace
    NodeKind Kind;
    long Size;              // bytes ON DISK, including all descendants
    long LogicalSize;       // sum of file lengths
    long FileCount;         // descendant files (1 for a File, N for an Aggregate)
    long DirectoryCount;    // descendant directories
    DateTime LastWriteUtc;  // newest descendant write time for directories
    FileCategory Category;  // file: by extension; directory: dominant category by Size
    NodeIssue Issue;
    DiskNode? Parent;       // null for the root
    IReadOnlyList<DiskNode> Children; // directories only, sorted by Size desc then Name; empty otherwise
    string Extension;       // lower-case with dot, "" for none
}

sealed record ScanOptions(
    int MaxDegreeOfParallelism = 0,       // 0 = auto: min(8, cores); removable/network volumes: 2
    long SmallFileFloor = 256 * 1024,     // files below this are folded unless among the TopFilesPerDirectory largest
    int TopFilesPerDirectory = 128,
    bool UseAllocatedSize = true);

enum ScanPhase { Enumerating, Completed, Canceled, Failed }

sealed record ScanProgress(
    ScanPhase Phase, long Files, long Directories, long Bytes, long Errors,
    string CurrentPath, TimeSpan Elapsed,
    double? Fraction);   // Bytes / used bytes of the volume when scanning a drive root; null otherwise. Clamped to 0..1, monotonic.

sealed record DriveSpace(string Name, string Label, string Format, long TotalBytes, long FreeBytes, bool Removable, bool Network, bool Ready);

static class DriveCatalog { static IReadOnlyList<DriveSpace> List(); }  // never throws; skips drives that throw

sealed class DiskScanner
{
    DiskScanner(string rootPath, ScanOptions? options = null);   // ArgumentException when the root is not an existing directory
    Task<DiskTree> ScanAsync(IProgress<ScanProgress>? progress, CancellationToken ct);
    ScanSnapshot CaptureSnapshot(int maxDepth = 6, int maxChildrenPerNode = 64);  // thread-safe, callable at any time during the scan
}

sealed record ScanSnapshot(DiskNode Root, ScanProgress Progress);   // detached copy: later scanning never mutates it

sealed class DiskTree
{
    DiskNode Root;
    DriveSpace? Space;           // the volume holding Root, when known
    int Version;                 // incremented by every mutation below
    bool Remove(DiskNode node);  // detaches the subtree and subtracts its sizes/counts from every ancestor; false for the root or a detached node
    Task RescanAsync(DiskNode directory, IProgress<ScanProgress>? progress, CancellationToken ct); // replaces that directory's subtree and fixes ancestors
    DiskNode? Find(string fullPath);
}
```

`ScanAsync` returns a complete tree; on cancellation it throws `OperationCanceledException` within 250 ms
of the request and the last progress report has `Phase.Canceled`. A directory that cannot be enumerated yields a
node with `Issue = AccessDenied`, increments `Errors`, and never aborts the scan.

### Memory policy

Individual file nodes are kept when `Size >= SmallFileFloor` or the file is among the `TopFilesPerDirectory` largest
of its directory. All other files of a directory fold into **one** `Aggregate` child (`Name` like `"1 234 個小檔案"`
is composed by the renderer; the node stores only `FileCount`, `Size`, `LogicalSize`). Counts and sizes stay exact, so
every directory's `Size` equals the sum of its children. A scan of 5 million files must stay under ~700 MB of managed
memory; folding makes that reachable.

### On-disk size

Windows: `UseAllocatedSize` rounds file length up to the volume cluster size (cached per volume); compressed or sparse
files use `GetCompressedFileSizeW`; NTFS hard links count once per (volume serial, file index) when cheaply available.
Other platforms: logical length. Zero-length files count as 0.

## Treemap layout (pure, no Avalonia)

```csharp
readonly record struct RectD(double X, double Y, double Width, double Height);

sealed record LayoutOptions(
    int MaxDepth = 8,
    double MinCellArea = 900,        // device-independent px²; smaller items fold into one Aggregate cell
    double HeaderHeight = 18,        // title strip of a directory cell whose rect is at least MinHeaderCell wide/tall
    double Padding = 2,              // inset between a directory cell and its children
    double MinHeaderCell = 64,
    DiskFilter? Filter = null,
    long FreeBytes = 0);             // > 0: append a FreeSpace cell sized FreeBytes at the root

sealed record TreemapCell(
    DiskNode Node,                   // Aggregate/FreeSpace cells carry a synthetic node
    RectD Bounds,                    // the whole cell, in the coordinate space of the requested bounds
    RectD ContentBounds,             // Bounds minus header and padding; equals Bounds for leaves
    int Depth, bool IsLeaf, bool HasHeader,
    string Key);                     // stable identity: FullPath, or "<parentPath>#agg" / "#free"

static class TreemapLayout
{
    static IReadOnlyList<TreemapCell> Build(DiskNode root, RectD bounds, LayoutOptions options);
}
```

Rules, all enforced by the smoke test:

1. Squarified algorithm (Bruls et al.), deterministic for identical input (ties broken by `Name` ordinal).
2. Cells of the same parent never overlap and stay inside the parent's `ContentBounds` (1e-6 tolerance).
3. Cell area is proportional to `Size` (or the filter-matched size) within one parent, up to the fold threshold.
4. The result is a flat list, parents before children. `Key`s are unique and stable across calls so the renderer can
   animate between two layouts by key.
5. A directory is only subdivided when its `ContentBounds` can hold at least one child of `MinCellArea`; otherwise it is a leaf cell.
6. Zero-size nodes are skipped. Huge trees stay cheap: layout visits at most the nodes it can draw.

## Filter (SpaceSniffer-style)

```csharp
sealed class DiskFilter
{
    static bool TryParse(string text, out DiskFilter? filter, out string? error);  // empty text => filter null, no error
    bool Matches(DiskNode file);                    // files and aggregates only (aggregates never match name/type/age terms)
    long MatchedSize(DiskNode node);                // sum of Size of matching files below node; cached per node, thread-safe
}
```

Grammar: terms separated by whitespace or `;`, all terms must hold (AND); `|` inside one term is OR; a leading `!` negates.

| Term | Meaning |
| --- | --- |
| `*.mp4`, `report*`, `log` | case-insensitive wildcard on the file name; a term without `*` or `?` is a substring match |
| `>100MB`, `<=2GB`, `>=1.5GB` | on-disk size; units `B KB MB GB TB` (1024-based), decimals allowed |
| `older:30d`, `newer:12h` | last write; units `h d w m y` |
| `type:video` | `FileCategory` name, case-insensitive; `type:video\|audio` allowed |

Invalid input returns `false` with a short Traditional Chinese `error` suitable to show under the search box
(for example `無法解讀大小：>12XB`).

## Categories

```csharp
static class FileCategories
{
    static FileCategory Classify(string extensionWithDot);
    static string Label(FileCategory category);   // Traditional Chinese: 影片 音訊 圖片 文件 壓縮檔 程式碼 應用程式 磁碟映像 系統 其他
}
```

Cover the common ~150 extensions; unknown is `Other`. `System` includes `.sys .dll .drv .dmp .etl .log` and the Windows
system files `pagefile.sys hiberfil.sys swapfile.sys`.

## File actions

```csharp
enum ActionStatus { Done, NotSupported, NotFound, OutsideRoot, Failed }
sealed record ActionResult(ActionStatus Status, string? Message);

static class FileActions
{
    static ActionResult Reveal(string path, string scanRoot);          // Explorer /select; macOS `open -R`; else open the parent
    static ActionResult Open(string path, string scanRoot);            // only directories; files are never launched from here
    static ActionResult MoveToRecycleBin(string path, string scanRoot);// Windows SHFileOperationW + FOF_ALLOWUNDO|FOF_NOCONFIRMATION|FOF_SILENT; never permanent delete
    static ActionResult CopyPathText(string path);                     // not needed: the renderer owns the clipboard (omit)
}
```

Every action first re-validates: the path exists, is canonical, is inside `scanRoot` (after resolving `..`), and is not
the root itself and not a drive root (`OutsideRoot`). Arguments are passed as an argument list, never through a shell string.
Non-Windows `MoveToRecycleBin` returns `NotSupported`; macOS may use `NSWorkspace` via `osascript` only if it passes the same checks.
(`CopyPathText` is listed for completeness and must not be implemented.)

## Smoke test

`desktop/Tests/DiskUsageSmoke.cs`: `DiskUsageSmoke.Run()` returns a process exit code, uses a temp directory it creates
and removes, no network, no real drives besides `DriveCatalog.List()` returning without throwing. Wire it as
`--disk-usage-smoke` inside the `#if USBLINK_DESIGN_TOOLS` block of `desktop/App/Program.cs` and add it to
`check_desktop_contract()` in `scripts/project.py`. It must cover: totals and folding exactness, access-denied tolerance
(POSIX only), symlink skipping, cancellation latency, snapshot independence, `Remove`/`RescanAsync` ancestor math, every
treemap rule above on a random tree with a fixed seed, filter grammar (valid and invalid), and `FileActions` path rejection.

## Renderer

`desktop/Views/DiskUsage.cs` (`DiskUsageView`) is the whole screen: drive picker, toolbar, map, inspector and status bar.
The map has three interchangeable views with the same events (selection, open, menu), switched by the 方塊 / 環狀 / 清單 control:

| View | Control | Modeled on | Good for |
| --- | --- | --- | --- |
| 方塊 (treemap) | `Controls/TreemapView.cs` | SpaceSniffer, WinDirStat, GrandPerspective | seeing every big file at once |
| 環狀 (sunburst) | `Controls/SunburstView.cs` | DaisyDisk, Filelight | the folder hierarchy and each level's share; center disc goes up a level |
| 清單 (ranked list) | `Controls/DiskListView.cs` | TreeSize, WizTree | exact numbers, sorting, and the 200 largest files below the folder |

A plain pie chart is deliberately not offered: disk usage is a hierarchy with a long tail, which a single pie cannot show.
The sunburst is the circular form that keeps the hierarchy. Its geometry is `SunburstLayout.Build(root, maxDepth, minSweep, filter)`
(pure, in `Services/DiskUsage/`): sweeps are fractions of a turn, children fill their parent's arc exactly, and slices narrower than
`minSweep` fold into one `#agg` slice per parent. The inspector and the drive cards use `Controls/DonutChart.cs` for shares. It is the 磁碟 page of the main window's switcher (`desktop/Views/DiskUsageWindow.cs`, hosted by `desktop/Views/Shell.cs`;
the page stays alive while you visit other pages); `--preview --open=disk [--disk-root=<path>]` scans a real folder in a design build.

- Geometry is always `TreemapLayout.Build` / `SunburstLayout.Build`; the visible view re-runs it on resize, zoom, detail change, scan snapshot and delete.
- Cells and slices are matched across layouts by key: they glide (treemap 520 ms, sunburst 560 ms, ease-out), new ones grow and fade in, removed ones fade out.
- While scanning, a timer takes `CaptureSnapshot()` every 250 ms; the folder being read pulses. When `ScanAsync` returns, the final tree replaces the snapshot and the view resolves the same folder by path.
- Filtering uses `DiskFilter` only (query box plus the category legend, which appends `type:…`). Misses are dimmed, never removed, so layout does not jump while typing.
- Interface prototype with all states: `design/disk-space/prototype.html` (open in a browser; uses invented data).
- Color tokens (`Cat*`, `MapBg`, `Surface`, `Age*`) live in `desktop/Theme/Palette.cs` for both themes.

## Not in this version

Snapshot save/load and comparison, NTFS MFT/USN fast scanning, per-user ownership, duplicate detection.
