# Validation record: 0.9.1 candidate

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
