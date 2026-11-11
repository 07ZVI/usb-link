# Desktop design system

The Windows desktop app follows Apple's macOS Human Interface Guidelines for type, spacing and control sizes, and
Mole's status board for its look: one borderless window on a warm gold gradient, a centered pill switcher, translucent tiles without outlines and big numbers. Only the overview has an illustration (the connection orb); the other pages get their weight from a 26-pt title and whitespace.
Every value below is a token in `desktop/Controls/Components.cs` (`Scale`) or `desktop/Theme/Palette.cs`; views use the
names, never ad-hoc numbers. 1 pt = 1 DIP, so Windows display scaling stays the only scale.

## Pages

The switcher holds five pages; each has one job, and nothing appears on two pages.

| Page | Content |
| --- | --- |
| 總覽 | No cards. A hero line (「Windows 主機地址」 with the state pill, the 40-pt address with a copy button, who is connected, the warm planet), one shared traffic chart (Mac in `Accent`, iPad in `Olive`, 60 s with value and time axes), then one borderless row per device split by hairlines: tile, name and address, state pill, ↑ / ↓ numbers with link speed and latency, speed-test and reconnect. |
| 共享 | A full-width address banner (SMB address, Mac and iPad how-to chips, the sharing switch and its state, copy), then the shared folders as the main column and a 340-pt side column with account, guest access and repair. Below 820 pt the side column moves under the folders. |
| 安全 | Security center tabs and the task manager. |
| 磁碟 | Disk space map (treemap, sunburst, list) with its inspector. |
| 設定 | 「一般」 switches (start at login, network-only), then 「連線診斷」: internet sharing and the folded detailed diagnostics. |

The overview is a column of at most 1120 pt, centered. Only the chart flexes: it takes the height the window leaves
(140–400 pt) so nothing else stretches. The default window is 1040 × 700. When the window is short, the overview
steps down through the density levels before it scrolls.
Device rows wrap identity, traffic and actions onto separate lines below 900 pt of available row width.

## Type (macOS text styles)

| Token | Size | Weight | Use |
| --- | --- | --- | --- |
| `Display` | 40 | Bold | the one hero number of the overview (host address) |
| `LargeTitle` | 26 | Bold | tool page titles, live traffic, disk totals |
| `Title1` | 22 | Bold | the SMB address on the share page |
| `Title2` | 17 | Semibold | card titles of devices, dialog titles, live traffic |
| `Title3` | 15 | Semibold | card and section headings, brand name |
| `Body` | 13 | Regular / Medium for row titles and buttons | everything else |
| `Callout` | 12 | Regular | secondary lines, captions under values, small buttons |
| `Subheadline` | 11 | Regular | row descriptions, badges, footnotes in cards |
| `Footnote` | 10 | Regular | chart axis notes only |

Older names map onto the same steps: `Caption` = Subheadline, `Secondary` = Callout, `Section` = Title3,
`Title` = Title2, `Page` = Title1, `Hero` = Display.

## Spacing (4-pt grid)

`Hair 2 · Tight 4 · Snug 6 · Small 8 · Medium 12 · Regular 16 · Large 20 · XLarge 24 · XXLarge 32`

| Where | Value |
| --- | --- |
| Window content margin | 20 (`Margin`); top is 8 under the custom title bar |
| Title bar row → page | 16 |
| Page header → page body | 20; banner and footer sit 12 away |
| Between cards (bento gaps, columns) | 12 (`Gutter`) |
| Card padding | 16 (`Inset`); the overview hero and the share banner use 24 × 20 |
| Overview column | at most 1000 wide, centered |
| Inside a card: heading → content | 12; related lines 2–6 |
| Icon → its label | 6 in buttons, 12 in rows |
| Buttons in a row | 8 |

Dense layouts (small windows) use `Scale.Pad(level, value)`, which scales a value and snaps it back onto the grid.

## Shapes

| Token | Radius |
| --- | --- |
| `MarkRadius` | 3 — color dots, bars, legend chips |
| `ControlRadius` / `TileRadius` | 8 — fields, menus, small tiles |
| `CardRadius` | 16 — tiles, grouped lists, flyouts |
| `PanelRadius` | 20 — large surfaces |
| capsules | height / 2 — buttons, pills, the switcher, segmented controls |

Tiles are borderless: a translucent `Card` fill on the gradient, no outline and no shadow (except the selected pill of a
segmented control). Hairline `Stroke` is only for separators and input fields.

## Controls

| Control | Size |
| --- | --- |
| Push button (`Action`) | 30 tall capsule, 14 side padding, 13-pt Medium label, 14-pt symbol 6 away |
| Small button (inside cards) | 26 tall capsule, 12-pt label |
| Icon button | 30 × 30 circle, 16-pt symbol |
| Text field, combo box | 30 tall, radius 8, 10 side padding |
| Segmented control | 30 tall capsule: 24-pt segments inside a 2-pt inset |
| Page switcher | 28-pt segments in a 2-pt inset capsule, centered in the title bar |
| Tabs (security) | 30-pt capsules; the selected one is filled, no underline |
| Status pill | 22 tall: 6-pt dot, 12-pt Semibold label |
| Settings row | at least 44 tall: 12 · 28-pt solid tile · 12 · title and description · 12 · control · 12; separators start under the text (inset 52) |

## Color

- Window: a diagonal gradient `BgFrom` → `BgTo` — paper to gold in light, espresso to amber in dark — behind every page.
- Accent: gold (`Accent`), used for charts, links and selection; status keeps green / amber / red.
- Primary action: `PrimaryFill` / `PrimaryInk` — a cream capsule with espresso text in dark, espresso with cream text in light.
- Settings tiles: `TileBlue`, `TileGreen`, `TileOrange`, `TilePurple`, `TileTeal`, `TileGray`, identical in both themes,
  always under a white (`OnFill`) glyph.
- Text: `Ink` (primary label), `Muted` (secondary), `Subtle` (tertiary). Status: `Ok`, `Busy`, `Warn`, `Error` with
  `…Soft` fills.
- The overview orb (`Orb`) is a warm planet (`OrbWarm`) when connected and takes the status hue otherwise (amber while
  connecting, red on error, gray when idle); the other pages have no illustration.

## Disk space map

- Category hues are one warm family around the gold accent, with no cold grays:

  | Category | Light | Dark |
  | --- | --- | --- |
  | Application | `#D29B3C` gold | `#D6A24A` |
  | System | `#B5794A` caramel | `#BE8556` |
  | Video | `#CC5A47` brick | `#D66A56` |
  | Audio | `#E08F6A` apricot | `#E39A78` |
  | Image | `#93A04E` olive | `#9DAA5C` |
  | Document | `#5F927F` sage | `#6FA08E` |
  | Archive | `#9A6B92` plum | `#A87CA0` |
  | Code | `#4F8C95` muted teal | `#5F9AA2` |
  | Disk image | `#BC6276` rose | `#C67284` |
  | Other | `#B7AA90` sand | `#A89C84` |

- Label ink follows the fill: espresso on light fills (luma above 0.6, e.g. gold and sand), white on the rest.
- Tiles at least 120 × 84 read like a storage card: the size as a 15–26-pt Semibold number, with the name and share
  under it, anchored 10 pt from the bottom-left corner. Smaller tiles keep a 12-pt name and an 11-pt size at the top-left.
  Tiles under 62 × 32 have no label.

## Checking a change

Design builds render every screen to PNG: `--preview [--theme-dark] [--open=security|tasks|smb|details|disk|dialog]
--shot=<dir>`. Compare light and dark, and a small window (the overview steps down to compact and dense levels).
