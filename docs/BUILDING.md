# Rebuilding and packaging

Requirements: Python 3.9+, Go 1.26.0 (matching `go.mod`), .NET SDK 10.0.100 (matching `global.json`), Git. Windows x64 is the supported host target; cross-builds also produce macOS x64/arm64 agents. Driver/service/network acceptance must run on Windows hardware.

`USBLINK_GO` and `USBLINK_DOTNET` optionally select tool executable paths. No paths to one developer's home, legacy installation package, signing key or historical embedded ZIP are required. Normal compiler/module caches may be relocated through their standard environment variables. NuGet restore uses `--locked-mode`; Go uses `go.sum` and immutable versioned modules.

| Command | Result |
| --- | --- |
| `python3 scripts/project.py check` | Go tests (race detector on macOS), native vet, desktop state contract checks, architecture checks, public-source audit |
| `python3 scripts/project.py build` | Local diagnostic build with developer diagnostics and a `-local.exe` filename; fresh binaries and Windows vet |
| `python3 scripts/project.py package` | Build plus distribution directory, binary ZIP, committed-source ZIP, recursive audit and checksums |
| `python3 scripts/project.py verify` | Inspect generated packages including ZIP archives embedded in the Go PE; create checksums |

The Windows launcher embeds only freshly built first-party executables, Avalonia's framework-dependent publish output, notices and content manifests. The desktop ZIP must not contain `coreclr.dll`, `hostfxr.dll` or `dotnet.exe`; it does contain the normal .NET apphost and linked Avalonia/Skia/HarfBuzz library binaries. Source archives use `git archive HEAD`; ignored assets, output, cache, .git history and local evidence do not enter them. Commit changes before creating the final source package.

`VERSION` drives Go linker version injection, desktop publish version, generated manifests and output names. The freshly built bridge SHA-256 is injected into the launcher; no old executable is needed to discover it. ZIP metadata is normalized and archive entries sorted. Builds use `-trimpath` and do not embed workstation paths or Git dirty state. Binary determinism should be rechecked after changing SDKs/libraries; reproducible source and independent package inspection are mandatory.

Build telemetry is disabled using .NET's standard opt-out and [Avalonia's documented environment variable](https://github.com/AvaloniaUI/Avalonia.BuildServices#opting-out). Release packaging is unsigned; Authenticode signing and notarization require the distributor's credentials outside this repository. Developer remote upgrades are removed from public builds. Run new installers locally on Windows; see [release scope](RELEASE-SCOPE.md).

CI runs clean checkouts on macOS and Windows, tests source, cross-builds and packages. CI does not install drivers, modify host networking, enable Hyper-V, contact attached devices or publish a GitHub release.

The desktop contract check builds a separate design-tools output in
`out/desktop-contract` and runs without opening a window. Go compares device
snapshots against captured pre-refactor wire output; C# consumes those same
fixtures plus legacy and missing-device cases. This checks status compatibility,
not native rendering or USB hardware. The normal release build still disables
design-tools entry points.

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
release when a newer build failed acceptance. This explicit choice is retained
for later packages until a publisher selects another rollback, so a failed
candidate does not silently replace it. That selected installer may remain
in separate private rollback storage, which this cleanup never modifies. Source
archives, evidence, runtime tools, unknown files and symlinks are preserved. The
removal receipt and current checksums remain in `out/`.

Local `build` defaults to `--profile local`, enabling `USBLinkLocalDiagnostics` in the desktop. The developer debug master switch controls diagnostic viewing/export and local USB push installation together. Use `build --profile release` for the public desktop surface. `package` always builds the release profile, with local diagnostics disabled, independent of where the command runs. Both profiles disable preview/smoke entry points.

Local diagnostic builds also set `buildinfo.LocalDiagnostics=true` in the launcher. The read-only iPad network sampler runs independently of connection success; its cached output travels over the existing USB diagnostic logs. Public release builds leave this sampler disabled. Developer diagnostics in the UI display this automatically collected snapshot; the explicit developer debug master switch also authorizes signed USB installations.

Local diagnostics also expose an explicitly started Apple service comparison trial. Enabling the diagnostics display alone never starts this trial. Its fixed local actions can temporarily stop AMDS, preserve its original state in a recovery journal, and restore it after the trial or cancellation; they do not change the service startup type. Test and recovery budgets total 120 seconds, but blocked native calls or failed service restoration must be reported rather than treated as a guaranteed deadline. This experiment is unavailable in the public profile and does not add a remote command server.

Local Windows x64 launchers additionally compile the USB push installation capability
with the fixed `usblink_local_remote` build tag. `buildinfo.LocalRemote` is a compile-time
constant, independent of the linker-injected diagnostics string. The capability does
not grant runtime consent: the saved developer debug choice is scoped to the verified installation owner. The single master switch enables diagnostic tools and
USB push together, restricted to the verified USB IPv4 interface. Startup restores the choice using fresh credentials and a fresh process-bound receipt. Package
signature, version, identity and rollback checks remain required.

Public launchers and all bundled helper/macOS binaries receive an explicit empty
`-tags=` argument, overriding inherited `GOFLAGS=-tags=...`. The launcher and its
symbol-bearing audit twin use the same profile tags. Public surface checks reject
the remote server and local installation bridge; both profiles reject the obsolete
`RunUpdateWorker`, raw USB recovery server and temporary file-transfer handlers.
`python3 scripts/test_build_profiles.py` checks command parity, forbidden symbols,
and actual Go file selection under an inherited local tag. `USBLINK_GO` selects the
Go executable for this check; without Go, only the file-selection test is skipped.


### Local USB push identity and client

The local build initializes a development-only Ed25519 identity under
`.local/secrets/local-update.ed25519` (private, mode 0600) and
`.local/secrets/local-update.pub`. Keep this identity for subsequent builds;
do not distribute the private file or delete it during installer cleanup.
Only the public key is embedded in local installers. Public builds retain the
release trust root and do not link the local listener or installation bridge.

The first installer that adds USB push must be installed manually. In its
local developer panel, turn on the developer debug master switch for the current background
process. The choice persists per installation owner; credentials and process-bound authorization are regenerated after restart. The Mac USB peer can
then discover session credentials over the owned USB interface; credentials
are excluded from diagnostic logs. Windows UAC remains part of installation.

On the development Mac, `python3 mac/push-local-update.py --status` checks the
channel. Sign a newer installer with `--sign-key .local/secrets/local-update.ed25519
--version <version> --exe <installer.exe> --manifest <signed-manifest.json>`,
then invoke the same wrapper with `--exe <installer.exe> --manifest
<signed-manifest.json>`. Sending an apply request is not proof of installation;
verify the running version through USB diagnostics after reconnection.

Local installers launch the installed interface with the application directory
as its working directory, so it cannot keep an upgrade staging directory busy.
Before another upload, a terminal job releases only its verified package and
protected empty directory. If package removal succeeded but directory removal
was interrupted, the next request retries the empty-directory cleanup. Unknown
non-empty directories, changed protection and active jobs remain blocked.
The Mac client reports only fixed rejection classifications, never remote error
bodies or reflected credentials. An older listener already blocked by stale
staging directories may require one manual installation of the corrected build.

Local developer diagnostics provide persistent switches for fast detection and
an additional 12-second delay before iPad admission. Fast detection uses a
one-second cached-presence fallback; delay requires fast detection and rechecks
the same candidate after waiting. Settings have no expiry or single-use limit
and are stored separately for the verified installation owner. Disabling the
developer master switch stops their runtime effect; enabling it restores the
saved selection. They never stop Apple services or change identity/consent
checks. General detection retains its 30-second fallback.
Owner wake reasons and admission timing use a separate bounded cached diagnostic
record, so they do not displace trust-popup markers from the existing event ring.

Local diagnostics remain available when startup network-rule cleanup fails.
The USB installation channel stays closed until both local and legacy cleanup
checks succeed; enabling the same developer switch retries pending cleanup.
Protected storage, owner and consent failures remain blocking and are reported
separately from the saved switch value. Startup failures include fixed stage
codes in USB evidence so an unavailable push channel does not hide its cause.
An initial authenticated core response of `CORE_INITIALIZING` or
`CORE_MONITOR_INITIALIZING` keeps the UI waiting with actions disabled. Other
errors, and any error after the first verified status, retain failure reporting.
Opening an installed app checks the desktop runtime quietly; only a missing
runtime opens the prerequisite preparation window.
Disabling developer debug revokes the current cross-process install receipt
before saving preferences or waiting for network cleanup. Receipt writes use an
independent selection epoch, so an older enable cannot restore revoked consent.
A helper still waiting for UAC must recheck that receipt; an installation that
has already passed its final authorization check is not forcibly interrupted.
