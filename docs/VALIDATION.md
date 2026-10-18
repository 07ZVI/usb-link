# Validation record

## Current status (0.10.53)

- Hardware acceptance remains pending for Windows, Mac and iPad. The hardware acceptance checklist below is still the to-do list; no item in it is claimed as passed.
- Hosted Windows CI failed on `go test` as of commit `0ebf3d2`; it passes again (check and release package, macOS and Windows) from `1e0af22`. Hosted runners have UAC disabled, so the non-elevated SMB share-user impersonation path is not exercised there.
- The rest of this file is the historical 0.9.5 candidate record. Its results describe that candidate only and are not a statement about 0.10.53.

## Historical record: 0.9.5 candidate

Baseline: 0.8.140. Public history starts with modular source, then dependency acquisition/rebuilding, then Internet sharing. The source-only refactor checkpoint preserves original runtime compatibility identities; distribution preparation is completed by the subsequent dependency commit. Validate the final HEAD for a public build.

## Software and distribution

| Check | Observed result |
| --- | --- |
| Entire Go suite with race detector on macOS | Passed (56 packages with tests); loopback-network fixtures ran outside the port-restricted sandbox |
| Gateway state machine and routing boundary | Passed: opt-in authorization, DHCP/traffic readiness, revoke, fail-closed exclusions, lease expiry, cleanup ordering, retained recovery, stale observation rejection |
| Dependency policy | Passed: installed reuse, bounded/pinned download, corrupt cache rejection, signature failure, offline failure, cancellation, install readback and repeat use |
| DHCP | Passed: default gateway/DNS absent, enabled prepared lease supplies them, disabled lease removes them, existing identity/checksum/renewal regressions |
| Connection/SMB/auth/local-install/recovery policies | Original Go regression suite retained and passed; native Windows side effects were not executed here |
| Avalonia Windows x64 publish | Passed, framework-dependent; no bundled CLR runtime; native progress itself has no .NET dependency |
| Windows x64 launcher/bridge worker | Cross-compiled; Windows `go vet ./...` passed including Windows source/tests |
| macOS x64 and arm64 agents | Cross-compiled |
| Architecture/source checks | Passed: owned paths, no forbidden lower-layer imports, no public binary archives/private workstation paths or secret material |
| Recursive package checks | Passed for generated nested ZIPs including embedded launcher assets; external drivers/tools/runtimes absent |
| Git whitespace | `git diff --check` passed |
| Clean clone rebuild | Passed: independent clone ran all tests, Windows/macOS builds and recursive package audit; only normal locked module/tool caches were reused |
| Hosted GitHub CI | Baseline run on commit `448126c`: macOS passed, Windows failed; see below |

Software checks do not establish real WinNAT/WFP/Defender behavior, driver installation, visible official-installer UX, macOS DHCP application, local signed installation acceptance, or on-device throughput.

## Hardware acceptance: all pending

| Area | Required device cases | Status |
| --- | --- | --- |
| Architecture regression | Mac/iPad attach, native SMB 445 and compatibility SMB 10690 separately, permissions and accounts, revoke/replug | Pending Windows/Mac/iPad |
| Upgrade and recovery | Existing 0.8.140 installation → candidate, local upgrade verification/rollback, interrupted transactions, no original-value loss, uninstall | Pending Windows hardware and original signing flow |
| Dependency bootstrap | No .NET first start, existing newer Apple/.NET, offline, bad hash/signature, official cancellation, UAC, reboot-required and resume, duplicate launches | Pending clean Windows VM/hardware |
| Gateway connectivity | Mac with other networks off: USB DHCP options, DNS over UDP/TCP, HTTPS, TCP and UDP | Pending Windows/Mac |
| Gateway isolation | Upstream private and publicly addressed LAN, iPad/other USB peer, unauthorized Mac, unsolicited inbound attempts all fail | Pending Windows/Mac/iPad |
| Gateway lifecycle | Manual off, cable loss, revoke, upstream/default-route/DNS/on-link change, core crash, reboot recovery; local transfer still works | Pending Windows/Mac |
| NAT coexistence | Existing NAT/ICS, address conflicts, no WinNAT, recycled interface identity all fail without taking over another configuration | Pending Windows |
| Desktop behavior | Feature-specific missing status, native pre-CLR progress/cancel, new controls, accessibility/window reuse | Pending Windows UI |

## Acceptance procedure

1. Create a fresh Windows VM plus a real Windows/Mac USB setup. Record OS versions and candidate checksums locally, not as public raw logs.
2. Run the dependency cases, checking signer/digest/readback and visible official prompts. Capture missing-component and affected-feature status.
3. Run unchanged local functions first. Treat native/compatibility SMB as independent cases and check access masks/denied directories, not only a successful listing.
4. Enable sharing for the authorized Mac. Renew its USB DHCP lease. Check the actual Mac route/DNS, then DNS UDP/TCP, HTTPS and TCP/UDP transfers with other Mac networks disabled.
5. Test every exclusion and unsolicited return flow. Revoke/unplug/change upstream/kill the core and confirm admission closes; verify owned NAT/DNS/rules and forwarding original values after normal/recovery cleanup.
6. Install over 0.8.140, exercise the local installation/rollback contract, then uninstall without removing preexisting Apple or shared .NET.
7. Write only a sanitized result table here. Keep identifiers, packets, signed installers, raw logs and full old history in local evidence storage. Leave failures/untested cases pending.

## 0.9.1 release scope change

File upload, WebDAV, developer publisher and remote-maintenance network entry points are removed. The table above remains the 0.9.0 baseline. New 0.9.1 checks on macOS: full Go race suite, native and Windows vet, Windows launcher/desktop and both Mac builds passed. The release symbol check confirmed the removed remote HTTP server, update worker, raw USB recovery transport, upload receiver and WebDAV handler are not linked into the launcher. Source/history audits and publication regression tests passed. The actual Avalonia renderer passed the connection smoke test, including repeated diagnostic-window open/close, and generated the README screenshot with synthetic data. Windows-specific runtime tests and physical device acceptance are not established by these checks. Hardware acceptance remains pending. See [release scope](RELEASE-SCOPE.md).


## Hosted Windows checks still failing

The [baseline CI run](https://github.com/07ZVI/usb-link/actions/runs/38111725162)
passed on macOS but failed on Windows before this scope change. Failures include
native log rotation, non-elevated account fixtures, startup-task provider fixtures,
and SMB/catalog handle and directory-metadata cases. They have not been diagnosed
or resolved by the README/feature-removal work. The current push triggers a new
run; no successful Windows runtime acceptance is claimed. These failures block a
stable end-user release, even though local cross-build and package audits pass.

## 0.9.2 browser throughput

Mac throughput measurements now use the browser page on the existing USB-only
Windows listener. No Mac throughput executable or installed script is required.
The desktop shows a selectable URL, browser instructions, progress/results and
cancellation. iPad measurements retain their separate session and URL.

The complete macOS Go race suite, native vet, architecture checks and source/history
audits passed. Focused fixtures also passed for peer/Host/origin/token enforcement,
Mac/iPad labeling, unavailable native routes, browser heartbeat freshness and
inactive-session URL suppression. The actual browser completed both throughput
directions on a loopback fixture, then restarted and cancelled a second test.
Loopback numbers are not USB performance measurements. See
[browser measurement boundaries](BROWSER-SPEED-TEST.md).

The 30-second browser WebSocket test also completed with 3000/3000 echoes on the
loopback fixture. The Avalonia macOS renderer passed the connection smoke test,
including the selectable Mac URL, browser button, unavailable-link state,
cancellation button and existing diagnostic-window lifecycle checks. The Windows
x64 desktop/launcher and both Mac network agents cross-built successfully;
Windows vet and the release-surface symbol check passed.

Windows runtime, Safari on the connected Mac, local installation and physical USB
throughput acceptance remain pending. The hosted Windows failures above are not
resolved by this change.

## 0.9.3 migration and installation layout

The first hardware upgrade from 0.8.139 to 0.9.2 timed out during startup
health checking and rolled back to 0.8.139. USB connectivity returned. The
protected job reported HEALTH_TIMEOUT without a candidate failure receipt;
no exact missing-component diagnosis was available. This is a failed installation,
not successful hardware acceptance of the public candidate.

0.9.3 imports only the exact pinned official AMD64 Wintun DLL from verified
legacy recovery folders. Official .NET/Wintun ZIPs already placed in the old
protected received-files directory can be verified into the new cache before
attempting a download. No Mac runtime, script or new receiving endpoint is added.
Old update consent is retired after signed candidate acceptance, so an unsuccessful
migration retains the previous worker's rollback settings.

New desktop files use Program Files/USB Link/Desktop/<release>, not hashed
folders. New private components and downloads use ProgramData/USB Link/Dependencies.
Bridge folders use readable release names; legacy recovery paths remain discoverable.
A verified previous executable/desktop release is retained during cleanup.
User data and protected legacy journals are preserved; migration of those live
journals is not part of this layout change.

The other completed UI work is included: reuse the dashboard on tray reopen,
background SMB reads, parallel security observations and initial process lists
before file/signature checks. Actual Windows UI latency is still pending.

Migration regression fixtures passed with the race detector: pinned reuse, changed
DLL/ZIP and symlink rejection, preservation of unknown trees and source files,
cancel/readback behavior, and offline import without HTTP. The full Go race suite,
native and Windows vet, architecture/source checks passed. The combined Avalonia
renderer passed connection/tray/credential-lifecycle and process-window smoke
checks. Windows-specific directory mutation fixtures are cross-checked by vet;
execution on Windows is still pending. Initial native preview attempts inside the
restricted sandbox could not start the Mac render timer; the permitted native
window run succeeded.

## 0.9.4 readable bridge compatibility

Code review during the 0.9.3 hardware attempt found three bridge launch/recovery
checks still requiring hash-named runtime folders. The 0.9.4 checks accept exact
numeric release folders as well as legacy hash folders. Kernel-parent, catalog
bytes, native interface, process/session and protected-handle proofs are retained;
a readable folder name cannot authorize ownership. Regression fixtures require
all launch preconditions and reject foreign/malformed release names.

## 0.9.5 component coordination and reinstall preflight

Source/chat reconciliation is recorded in [the startup audit](STARTUP-AUDIT.zh-CN.md). Component preparation now serializes per asset, supports cancelled waiters and leaves active progress intact during refresh. Shared directory creation is separately protected. Native mutex acquisition/release pins its OS thread, accepts and verifies existing handles, and rejects unproven descriptors. Progress windows use independent subscriptions. Local installation checks existing ownership before downloading components or copying another release, with explicit deleted-file/residual-service errors. A fully source-verified interrupted transition still uses the original recovery coordinator.

The complete macOS Go race suite, native vet, Windows x64 vet, architecture and source/history audits passed. New concurrency and progress regressions passed. Elevated Windows mutex fixtures are cross-checked but not executed here. The prior combined renderer smoke results still cover the unchanged desktop code; no Windows responsiveness claim is added. The offline helper is rebuilt from current source and remains private.

The 0.9.3 attempt did not restore the observed USB channel before the user deleted the Windows installation directory. Its exact native failure and final rollback outcome were not read back. 0.9.4 was not installed. 0.9.5 has not been installed. Native Windows runtime/USB/SMB acceptance and the hosted Windows failures above remain unresolved.

A read-only report returned from the affected Windows machine confirms the program root and binding are missing, a stopped core service still points to 0.9.3, and the uninstall registration remains 0.8.139. ProgramData dependencies and the protected recovery directory remain. This confirms orphaned installation metadata; it does not establish the original 0.9.3 startup cause.

The separate [operator recovery tool](../scripts/windows-deleted-install-repair/README.md) cross-builds and passes Windows native vet. It is behind an explicit private build tag and overlay, so ordinary public builds do not include a missing-binding adoption path. Native execution, exact residual removal, fresh 0.9.5 service startup and device acceptance are still pending. The kit preserves existing USB journals, accounts, shares and system settings and distinguishes a verified running core from USB/SMB acceptance.

0.10.0 supersedes the versioned program/desktop layout above with one active `Program Files/USB Link/App` and transaction-only previous content. See [installation lifecycle](INSTALLATION-LIFECYCLE.zh-CN.md). Windows lifecycle and device acceptance remain pending.

## 0.10.4 deleted legacy install and welcome page

The returned installation report confirms missing Program Files content and both binding locations, 0.8.139 uninstall registration pointing to missing content, and a stopped/PID-zero service pointing to missing 0.9.3 content. This identifies the registration gate in 0.10.3; it does not explain the original startup failure.

Normal setup now verifies the exact legacy objects locally, prepares every selected component, then performs the protected-backup/recheck/removal sequence. It retains fixed-layout recovery and pending-reboot gates. Fault tests cover preparation failure/cancellation preserving residuals, failed backup or recheck preventing deletion, partial removal failure stopping installation, and cancellation during the bounded removal finishing cleanup. Native Windows service, ACL and registry validation is cross-compiled; actual residual removal/reinstall remains pending Windows acceptance.

The welcome page no longer starts or displays inspection. Diagnosis is an explicit view with a return action; reports after failure include the installer error and release. No additional recovery executable is required by ordinary setup.
