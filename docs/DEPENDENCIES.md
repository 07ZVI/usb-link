# External dependencies and licenses

The fixed [catalog](../internal/dependencies/catalog.json) is the sole runtime source for versions, official URLs, SHA-256/SHA-512, download limits, required signer, license and affected functions. Digests come from retained official-source receipts or Microsoft's published release metadata. A changed package at the same URL is an error, not an automatic catalog update.

| Component | Acquisition and ownership | Distribution |
| --- | --- | --- |
| Apple communication service | Reuse a signed installed Apple service; otherwise download the original official iTunes Windows installer, display its official license/install UI, and retain its reboot prompt. The original installer may offer/install iTunes. | Not in source/package/release attachments |
| Apple USB driver | Existing matching drivers first; when missing, obtain the pinned Microsoft Update CAB, retain INF/SYS/CAT and use existing Windows catalog/native installation validation. | External |
| Wintun 0.14.1 AMD64 | Official fixed ZIP, archive SHA-256 and exact DLL digest; installed privately under the protected product dependency directory. | External; narrow GPL linking permission only for official DLL |
| Zadig 2.9 / libwdi 1.5.1 | Official executable only when Mac WinUSB preparation needs it; native signature and hash verified; license and matching source URL retained. | External |
| .NET 10 runtime | Existing compatible system runtime first; otherwise verified Microsoft Windows x64 runtime ZIP extracted to product-private directory. No shared runtime is removed or downgraded. | External |
| Windows WinUSB/USB NCM/WFP/SMB/WinNAT | Native OS APIs/services and Windows driver installation. | No OS DLL/driver copies |
| Go and NuGet libraries | Version locks and normal compilation/publish with original notices and source references. | Linked libraries included |

Private packages are bounded before extraction; traversal, duplicate names and symlinks are rejected. Installed private trees record hashes and are verified before reuse. Executable downloads also require native Authenticode trust. No network-provided JSON can override the catalog. Downloads accept HTTPS redirects only to the allowed official/CDN hosts. Hash/signature/readback failure keeps the feature unavailable.

Native Go progress is available before .NET. Closing it cancels downloads and extraction. Once an official Apple installer starts, it owns cancellation and its transaction; USB Link does not kill it halfway through. No reboot is forced. Reboot-required is a visible dependency error until a later detection succeeds. Cache damage is retained and rejected, rather than silently overwritten. Connectivity errors include the component and affected features; retry is available from the component controls or the next launch.

Uninstall first restores owned network changes and stops the verified core. It then removes only the marked, non-reparse product-private cache/components. A pending gateway recovery journal blocks removal. Existing Apple software, system driver-store packages and shared .NET installations remain installed. Unknown unrelated recovery files remain preserved according to the old ownership contract.

The Apple redistribution exclusion follows [Apple's Windows software license](https://www.apple.com/legal/sla/docs/iTunesWindows.pdf). The GPL linking exception follows [GNU's additional-permission guidance](https://www.gnu.org/licenses/gpl-faq.en.html#GPLIncompatibleLibs). The original [Wintun prebuilt binary terms](https://git.zx2c4.com/wintun/tree/prebuilt-binaries-license.txt) are retained. This exception does not authorize redistribution of Apple packages or other proprietary software.

Library versions, source repositories and license paths are in [libraries.json](../licenses/libraries.json). Imported compatibility SMB has a separate commit/file provenance record and complete MIT notice. These permissions are preserved alongside GPL terms, not replaced by them.
