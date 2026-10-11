# USB Link

USB Link connects Windows to an authorized Mac or iPad over the existing USB channel. It provides file transfer, native Windows SMB (445), a separate compatibility SMB service (10690), device/application authorization, and recoverable installation and network changes.

Version: see [VERSION](VERSION). This public source tree starts from the 0.8.140 implementation. The internal Go module name and Windows installation identity remain unchanged so existing receipts, upgrades and rollback paths keep their meaning.

The 0.9.0 candidate adds dependency downloads and opt-in Windows → Mac Internet sharing. **Windows/Mac/iPad hardware acceptance is pending.** Do not interpret cross-compilation or policy tests as hardware acceptance. See [validation](docs/VALIDATION.md).

## Use

Run the Windows x64 launcher with administrator permission and follow its dependency and device authorization prompts. The launcher itself is native Go and does not need .NET. Desktop rendering uses an existing compatible .NET 10 runtime or a separately downloaded private runtime. Existing functions with satisfied dependencies remain available; missing components show their names and affected features.

In “連線診斷與開發者調試”, inspect external components and Internet sharing. Sharing starts off, needs a currently authorized Mac, and stops on authorization/interface loss. After preparation, renew the Mac USB DHCP lease and generate Internet traffic. “Prepared / waiting” is distinct from “available”. IPv4 Internet sharing is the first supported scope; IPv6 forwarding remains blocked. Upstream LAN and other USB peers remain isolated. Exit selection is constrained by Windows' effective default route; USB Link does not rewrite other applications' route configuration.

Apple packages, Wintun, Zadig/libwdi, and the .NET runtime are **not included** in source, installation archives, or release attachments. Their official URLs, versions, checksums and requirements live in [the dependency catalog](internal/dependencies/catalog.json). Libraries linked into Go/Avalonia are distributed with their original notices.

## Build

Install Go 1.26, .NET SDK 10.0.100 and Python 3.9 or newer. On a clean checkout:

```sh
python3 scripts/project.py check
python3 scripts/project.py package
```

Outputs are under `out/`, including an unsigned native Windows launcher, Mac tools, a source archive and `SHA256SUMS`. Build-time network access restores locked Go/NuGet packages; build does not download any external end-user driver, Apple installer, Wintun DLL or .NET runtime. See [build details](docs/BUILDING.md).

## Project

- [Architecture and migration map](docs/ARCHITECTURE.md)
- [External dependencies and licenses](docs/DEPENDENCIES.md)
- [Gateway, recovery and reverse-sharing comparison](docs/INTERNET-SHARING.md)
- [Contributing](CONTRIBUTING.md) · [Security](SECURITY.md)

USB Link's original code is licensed under GPL-3.0-only with the narrowly scoped [official Wintun DLL linking exception](LICENSE-WINTUN-EXCEPTION). Imported code and third-party libraries retain their own licenses; see [notices](licenses/THIRD-PARTY.txt) and [library inventory](licenses/libraries.json).
