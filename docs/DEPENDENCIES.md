# Component preparation and official downloads

**English** | [简体中文](DEPENDENCIES.zh-CN.md)

Runtime components belong on the Windows x64 host. Mac-only connections do not require the Apple iPad communication components. End users do not need Go, Python or the .NET SDK.

## Official packages and pinned versions

These versions come from the [runtime catalog](../internal/dependencies/catalog.json). They identify automatic downloads, not a requirement to downgrade all installed components. The Apple support value `20.0.0.35` is the catalog's component version, not the iTunes product version.

| Component | Catalog version | Official file | Usage |
| --- | --- | --- | --- |
| .NET Runtime | 10.0.12 | [ZIP](https://builds.dotnet.microsoft.com/dotnet/Runtime/10.0.12/dotnet-runtime-10.0.12-win-x64.zip) | Private runtime archive managed by USB Link; use the EXE below for a system installation. |
| Apple Mobile Device Support | 20.0.0.35 | [iTunes64Setup.exe](https://secure-appldnld.apple.com/itunes12/140-75773-20260908-6e5e0165-99cb-4b30-b541-1b615fccfc1a/iTunes64Setup.exe) | Run the original Apple installer and follow its UI; it may also install iTunes. |
| Apple USB driver | 486.0.0.0 | [CAB](https://catalog.s.download.windowsupdate.com/d/msdownload/update/driver/drvs/2020/11/01d96dfd-2f6f-46f7-8bc3-fd82088996d2_a31ff7000e504855b3fa124bf27b3fe5bc4d0893.cab) | USB Link prepares the driver for the target device; downloading a CAB does not install it. |
| Wintun | 0.14.1 | [ZIP](https://www.wintun.net/builds/wintun-0.14.1.zip) | Contains multiple architectures; USB Link prepares bin/amd64/wintun.dll. |
| Zadig | 2.9 | [EXE](https://github.com/pbatard/libwdi/releases/download/v1.5.1/zadig-2.9.exe) | Used only when the Mac interfaces need WinUSB binding; follow USB Link for the target interfaces. |

For manual system installation, use the [Microsoft .NET Runtime 10.0.12 Windows x64 installer](https://dotnet.microsoft.com/en-us/download/dotnet/thank-you/runtime-10.0.12-windows-x64-installer). An existing x64 Desktop Runtime or SDK containing .NET 10 can also satisfy the requirement. USB Link uses Avalonia and requires the `Microsoft.NETCore.App` shared framework.

Official pages: [.NET](https://dotnet.microsoft.com/en-us/download/dotnet/10.0), [Apple iTunes](https://www.apple.com/itunes/), [Apple Windows 64-bit installer](https://www.apple.com/itunes/download/win64), [Microsoft Update Catalog](https://www.catalog.update.microsoft.com/Search.aspx?q=Apple%20Mobile%20Device), [Wintun](https://www.wintun.net/), [Zadig](https://zadig.akeo.ie/). Official pages may offer newer packages; automatic preparation uses the pinned files above.

## Check what is already installed

- **.NET:** any valid x64 `Microsoft.NETCore.App 10.0.x` installation is reusable, including one installed by another application, Desktop Runtime or SDK. Detection checks the standard directory, Microsoft's x64 installation registry and the private runtime; no product installer receipt is required. .NET 8/9/11 or preview-only runtimes cannot satisfy the current framework request.
- **Apple communication service:** open Windows Services (`services.msc`) and look for `Apple Mobile Device Service`. Component detection also verifies the service executable's Apple signature. The presence of an Apple app alone does not prove this service is available.
- **USB drivers:** connect the device and let USB Link check its binding. A downloaded or driver-store package does not necessarily mean the target interface uses it; repeated reinstalls are unnecessary.
- **Wintun and Zadig:** compatible original files are recognized by their actual bytes, not who installed them. The supported Wintun DLL can be reused without a product-created receipt. An installed adapter alone cannot replace the userspace DLL. Already bound WinUSB interfaces skip Zadig. Original packages in the shared offline cache are validated and reused instead of downloaded again.

## Prepare before going offline

1. Save the required official packages above on a connected computer and copy them to the Windows host. For manual preinstallation, use the .NET x64 EXE and Apple's original installer; complete any requested restart before running USB Link.
2. If the host can connect temporarily, run USB Link with the intended devices attached. Use the component controls in connection diagnostics to check/install missing components and complete connection preparation.
3. The private offline bundle's plain `install_all.bat` invokes the original Microsoft .NET and Apple installers in sequence, skips installed components, and retains Wintun/Zadig/Apple CAB originals under `%ProgramData%/USB-Link Components`. That shared cache needs no product-created source receipt; compiled hashes and signatures are still checked before use. Restart and reconnect offline to confirm the required components are available.

Verified private installations and caches are reused. Failed verification requires preparation through the application's retry flow. Removing USB Link does not uninstall existing shared .NET, Apple software or unrelated drivers.

## Tools needed only to build from source

| Tool | Project requirement | Official download | Check |
| --- | --- | --- | --- |
| Go | 1.26.0, see `go.mod` | [Go](https://go.dev/dl/#go1.26.0) | `go version` |
| .NET SDK | 10.0.100; `global.json` allows patches within its feature band | [.NET 10](https://dotnet.microsoft.com/en-us/download/dotnet/10.0) | `dotnet --list-sdks` |
| Python | 3.9 or newer | [Python](https://www.python.org/downloads/) | `python3 --version` or `python --version` on Windows |
| Git | Source checkout, source packaging and synchronization | [Git](https://git-scm.com/downloads/) | `git --version` |

Reuse tools that already meet these requirements. Offline builds also need populated Go/NuGet dependency caches; installing the tools alone is insufficient. See [building](BUILDING.md).

## Pinned download checksums

These hashes apply to the exact files above, not future replacement downloads. In PowerShell, use `Get-FileHash -Algorithm SHA256 path-to-file`, or `SHA512` for the .NET ZIP.

- **wintun 0.14.1 (SHA256)**: `07c256185d6ee3652e09fa55c0b673e2624b565e02c4b9091c79ca7d2f24ef51`
- **zadig 2.9 (SHA256)**: `4ecaa95df3da3621486a043aef8b3050b8bafe7c901402871e816229ef82039b`
- **apple-support 20.0.0.35 (SHA256)**: `25b28905a81406a5edbf482f7f3ee4831a8641d32d29dceda5d1eb3e8d534c08`
- **apple-driver 486.0.0.0 (SHA256)**: `9e6aa358c1c8207ccc13bbc52cd637ae2db57086b8727ed45c3cde87def72d89`
- **dotnet 10.0.12 (SHA512)**: `844fa99e16fd6f44e0a7c29def7a82d7846902334d6a955248a9519a4dddb3f5acceb9c9223bef69f8c83b8ae2417537e5b76dddf79fb7117dc85b5039bc1297`

## Packaging, verification and licenses

The fixed [catalog](../internal/dependencies/catalog.json) is the sole runtime source for versions, official URLs, SHA-256/SHA-512, download limits, required signer, license and affected functions. Digests come from retained official-source receipts or Microsoft's published release metadata. A changed package at the same URL is an error, not an automatic catalog update.

| Component | Acquisition and ownership | Distribution |
| --- | --- | --- |
| Apple communication service | Reuse a signed installed Apple service; otherwise download the original official iTunes Windows installer, display its official license/install UI, and retain its reboot prompt. The original installer may offer/install iTunes. | Not in source/package/release attachments |
| Apple USB driver | Existing matching drivers first; when missing, obtain the pinned Microsoft Update CAB, retain INF/SYS/CAT and use existing Windows catalog/native installation validation. | External |
| Wintun 0.14.1 AMD64 | Unmodified official archive embedded in the installer; archive SHA-256, exact DLL digest and original terms retained. Existing compatible DLLs are reused. | Included under the official prebuilt-binary terms and narrow GPL linking permission |
| Zadig 2.9 / libwdi 1.5.1 | Unmodified official executable embedded; selected Mac preparation copies/validates it without starting driver binding. Native signature, hash, GPL/LGPL notices and matching source URL retained. | Included; source: [libwdi v1.5.1](https://github.com/pbatard/libwdi/archive/refs/tags/v1.5.1.zip) |
| .NET 10 runtime | Existing compatible system runtime first; otherwise verified Microsoft Windows x64 runtime ZIP extracted to product-private directory. No shared runtime is removed or downgraded. | External |
| Windows WinUSB/USB NCM/WFP/SMB/WinNAT | Native OS APIs/services and Windows driver installation. | No OS DLL/driver copies |
| Go and NuGet libraries | Version locks and normal compilation/publish with original notices and source references. | Linked libraries included |

Private packages are bounded before extraction; traversal, duplicate names and symlinks are rejected. Installed private trees record hashes and are verified before reuse. Executable downloads also require native Authenticode trust. No network-provided JSON can override the catalog. Downloads accept HTTPS redirects only to the allowed official/CDN hosts. Hash/signature/readback failure keeps the feature unavailable.

Native Go progress is available before .NET. Closing it cancels downloads and extraction. Once an official Apple installer starts, it owns cancellation and its transaction; USB Link does not kill it halfway through. No reboot is forced. Reboot-required is a visible dependency error until a later detection succeeds. Cache damage is retained and rejected. Explicit retry quarantines only known product-private cache/tree locations before redownloading; quarantine is preserved until uninstall. Shared software is never moved. Connectivity errors include the component and affected features; retry is available from the component controls or the next launch.

Uninstall first restores owned network changes and stops the verified core. It then removes only the marked, non-reparse product-private cache/components. A pending gateway recovery journal blocks removal. Existing Apple software, system driver-store packages and shared .NET installations remain installed. Unknown unrelated recovery files remain preserved according to the old ownership contract.

The Apple CAB contains INF/SYS/CAT/DLL files but no explicit redistribution grant. Microsoft Update Catalog states that downloaded updates remain governed by their accompanying terms; Microsoft signing is not a redistribution grant. Therefore Apple packages stay external, including for the interactive wizard. The Apple redistribution exclusion follows [Apple's Windows software license](https://www.apple.com/legal/sla/docs/iTunesWindows.pdf). The GPL linking exception follows [GNU's additional-permission guidance](https://www.gnu.org/licenses/gpl-faq.en.html#GPLIncompatibleLibs). The original [Wintun prebuilt binary terms](https://git.zx2c4.com/wintun/tree/prebuilt-binaries-license.txt) are retained. This exception does not authorize redistribution of Apple packages or other proprietary software.

Library versions, source repositories and license paths are in [libraries.json](../licenses/libraries.json). Imported compatibility SMB has a separate commit/file provenance record and complete MIT notice. These permissions are preserved alongside GPL terms, not replaced by them.

## 0.9.3 installation layout

New desktop files are grouped under `Program Files/USB Link/Desktop/<version>`;
new private runtimes and verified downloads are under
`ProgramData/USB Link/Dependencies`. A previous verified release is retained for
rollback. Existing settings, shares and recovery journals remain at their owned
legacy locations until their transactions are finished. They are never removed
solely because their folder names look old.

Migration can reuse the exact official Wintun DLL from a protected older install,
or a catalog-pinned official runtime ZIP already received by that older version.
Every imported byte is checked and copied into the new owned dependency tree;
changed files cannot authorize reuse. This does not restore file upload or remote
maintenance in the public build.

0.10.0 supersedes the versioned program/desktop layout above with one active `Program Files/USB Link/App` and transaction-only previous content. See [installation lifecycle](INSTALLATION-LIFECYCLE.zh-CN.md). Windows lifecycle and device acceptance remain pending.

## 0.10.2 interactive Windows installer

Running an external Windows EXE opens a native wizard before any download or installation: Welcome → License → Components → Ready → Installing → Finished. The license checkbox starts unchecked and gates both navigation and installation. USB Link/desktop/.NET and embedded Wintun are required; iPad communication/driver preparation and the embedded Mac driver tool are optional and default unchecked. Optional selection prepares packages only; device binding still requires the existing device-specific checks and consent. Apple installs retain their official license UI. Existing compatible components are reused.

The wizard requires no .NET to display. Cancel before installation performs no dependency preparation. Cancel during work waits for safe component completion and the existing installation transaction/rollback. Completion permits opening the installed program. Running a verified installed image retains normal application/service behavior. Remote upgrades retain their existing authorized transaction path. Program Files and ProgramData layouts, source verification, rollback and uninstall ownership are unchanged.

Wintun/Zadig originals are pinned from official sources during builds and kept out of Git/source archives. Package auditing permits only exact official Wintun DLL paths/hashes and the exact Zadig executable hash; Apple CABs, arbitrary replacement DLLs and third-party installers remain rejected. Binary-source locations and original licenses are included in notices. Build/regression checks do not establish Windows UI, reboot or hardware acceptance.
