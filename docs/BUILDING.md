# Rebuilding and packaging

Requirements: Python 3.9+, Go 1.26.0 (matching `go.mod`), .NET SDK 10.0.100 (matching `global.json`), Git. Windows x64 is the supported host target; cross-builds also produce macOS x64/arm64 agents. Driver/service/network acceptance must run on Windows hardware.

`USBLINK_GO` and `USBLINK_DOTNET` optionally select tool executable paths. No paths to one developer's home, legacy installation package, signing key or historical embedded ZIP are required. Normal compiler/module caches may be relocated through their standard environment variables. NuGet restore uses `--locked-mode`; Go uses `go.sum` and immutable versioned modules.

| Command | Result |
| --- | --- |
| `python3 scripts/project.py check` | Go race tests, native vet, architecture checks, public-source audit |
| `python3 scripts/project.py build` | Fresh bridge/resource binaries, framework-dependent Windows desktop ZIP, manifests, native launcher, updater and both Mac agents; Windows vet |
| `python3 scripts/project.py package` | Build plus distribution directory, binary ZIP, committed-source ZIP, recursive audit and checksums |
| `python3 scripts/project.py verify` | Inspect generated packages including ZIP archives embedded in the Go PE; create checksums |

The Windows launcher embeds only freshly built first-party executables, Avalonia's framework-dependent publish output, notices and content manifests. The desktop ZIP must not contain `coreclr.dll`, `hostfxr.dll` or `dotnet.exe`; it does contain the normal .NET apphost and linked Avalonia/Skia/HarfBuzz library binaries. Source archives use `git ls-files`; ignored assets, output, cache, .git history and local evidence do not enter them. Commit changes before creating the final source package.

`VERSION` drives Go linker version injection, desktop publish version, generated manifests and output names. The freshly built bridge SHA-256 is injected into the launcher; no old executable is needed to discover it. ZIP metadata is normalized and archive entries sorted. Builds use `-trimpath` and do not embed workstation paths or Git dirty state. Binary determinism should be rechecked after changing SDKs/libraries; reproducible source and independent package inspection are mandatory.

Build telemetry is disabled using .NET's standard opt-out and [Avalonia's documented environment variable](https://github.com/AvaloniaUI/Avalonia.BuildServices#opting-out). Release packaging is unsigned; Authenticode signing and notarization require the distributor's credentials outside this repository. Existing USB Link remote upgrades still require the original signed upgrade contract; this unsigned candidate must not be described as an accepted remote-upgrade package.

CI runs clean checkouts on macOS and Windows, tests source, cross-builds and packages. CI does not install drivers, modify host networking, enable Hyper-V, contact attached devices or publish a GitHub release.
