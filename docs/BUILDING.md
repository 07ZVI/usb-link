# Rebuilding and packaging

Requirements: Python 3.9+, Go 1.26.0 (matching `go.mod`), .NET SDK 10.0.100 (matching `global.json`), Git. Windows x64 is the supported host target; cross-builds also produce macOS x64/arm64 agents. Driver/service/network acceptance must run on Windows hardware.

`USBLINK_GO` and `USBLINK_DOTNET` optionally select tool executable paths. No paths to one developer's home, legacy installation package, signing key or historical embedded ZIP are required. Normal compiler/module caches may be relocated through their standard environment variables. NuGet restore uses `--locked-mode`; Go uses `go.sum` and immutable versioned modules.

| Command | Result |
| --- | --- |
| `python3 scripts/project.py check` | Go race tests, native vet, architecture checks, public-source audit |
| `python3 scripts/project.py build` | Fresh bridge/resource binaries, framework-dependent Windows desktop ZIP, manifests, native launcher and both Mac agents; Windows vet |
| `python3 scripts/project.py package` | Build plus distribution directory, binary ZIP, committed-source ZIP, recursive audit and checksums |
| `python3 scripts/project.py verify` | Inspect generated packages including ZIP archives embedded in the Go PE; create checksums |

The Windows launcher embeds only freshly built first-party executables, Avalonia's framework-dependent publish output, notices and content manifests. The desktop ZIP must not contain `coreclr.dll`, `hostfxr.dll` or `dotnet.exe`; it does contain the normal .NET apphost and linked Avalonia/Skia/HarfBuzz library binaries. Source archives use `git archive HEAD`; ignored assets, output, cache, .git history and local evidence do not enter them. Commit changes before creating the final source package.

`VERSION` drives Go linker version injection, desktop publish version, generated manifests and output names. The freshly built bridge SHA-256 is injected into the launcher; no old executable is needed to discover it. ZIP metadata is normalized and archive entries sorted. Builds use `-trimpath` and do not embed workstation paths or Git dirty state. Binary determinism should be rechecked after changing SDKs/libraries; reproducible source and independent package inspection are mandatory.

Build telemetry is disabled using .NET's standard opt-out and [Avalonia's documented environment variable](https://github.com/AvaloniaUI/Avalonia.BuildServices#opting-out). Release packaging is unsigned; Authenticode signing and notarization require the distributor's credentials outside this repository. Developer remote upgrades are removed from public builds. Run new installers locally on Windows; see [release scope](RELEASE-SCOPE.md).

CI runs clean checkouts on macOS and Windows, tests source, cross-builds and packages. CI does not install drivers, modify host networking, enable Hyper-V, contact attached devices or publish a GitHub release.

The normal desktop build rejects preview/smoke command-line switches. To render the
README screenshot locally, build the desktop with `-p:USBLinkDesignTools=true`
and run it with `--preview --connection-smoke`. This uses synthetic fixtures.
On macOS, the screenshot is written to `/private/tmp/usb-link-unified-dashboard.png`.
Use a separate NuGet lock path when previewing for a different runtime so the
committed Windows dependency lock remains unchanged. Release packaging always
sets `USBLinkDesignTools=false` and checks a symbol-bearing launcher twin for
removed remote-upgrade and temporary file-transfer handlers before stripping.

After a complete package passes inspection, the package command prunes older
exactly named generated Windows installers and their binary ZIPs. It keeps the
current and previous build by default; this is build retention, not hardware
acceptance. Set `USBLINK_ROLLBACK_VERSION` to the exact previously verified
release when a newer build failed acceptance. That selected installer may remain
in separate private rollback storage, which this cleanup never modifies. Source
archives, evidence, runtime tools, unknown files and symlinks are preserved. The
removal receipt and current checksums remain in `out/`.
