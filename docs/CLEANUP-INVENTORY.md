# Investigation and diagnostic code inventory

Scope: code added while investigating the iPad "Trust This Computer" prompt and
related connection experiments. The owner decided to delete the investigation-only
code instead of keeping it behind the developer build tag.

Build profiles: **public** = default tags (what `project.py package --profile
release` ships); **dev** = tag `usblink_local_remote`. "Public set" = files `go list`
selects for `GOOS=windows GOARCH=amd64` with default tags.

Evidence: the on-device investigation is summarized in
[IPAD-TRUST-PROMPTS.zh-CN.md](IPAD-TRUST-PROMPTS.zh-CN.md) (0.10.41-0.10.55
sections). Its end state, as stated by the project owner: the prompt is produced
by iPadOS itself when the PTP interface appears about 16 s after the mode-3
switch, with the Windows node disabled, 0 MTP commands issued and AMDS stopped.
So the tracing built to catch a Windows-side trigger has nothing left to prove.

Decisions: KEEP-PUBLIC (user-facing diagnostic), DELETED, KEEP (reason given),
DEFER (needs Windows device validation, not done here).

## Deleted

Commits: **A8** `8685208`, **A1-A7** `f093fbd`, **B1-B3** `c4c42b5` (all on top of 0.10.57).

| Item | What was removed | Commit |
|---|---|---|
| A1 WPD/MTP ETW trace | `ipadncm/local_wpd_trace_*` and `local_wpd_critical_*` except the recovery core; WPD status object, desktop WPD section, `wpd-trace-*` actions, preference store | `f093fbd` |
| A2 Windows USB ETW trace | `local_usb_trace_*` except the recovery core and query-ownership comparison; USB trace status and desktop section | `f093fbd` |
| A3 PnP native trace | `local_pnp_trace_*`, `pnp_native_trace` status | `f093fbd` |
| A4 Connection archive | `local_connection_archive_*`, every `Record*` call site, the connection environment sampler, the rearm-gate projection, the sanitized authorization failure projection, the archive HTTP handler on the developer remote, `usb-link-local-update --collect-archives`, `mac/collect-windows.py` archive export and its test, desktop archive status | `f093fbd`, `mac/` in the docs/scripts commit |
| A5 Connection timing trial | `connection_timing*` including `connectionTimingPlan`, the persisted timing preference, `trust-timing-*` actions, desktop timing status. Idle gating keeps the fixed fast-path constants (1 s fallback, no delay). | `f093fbd` |
| A6 Trust timeline sampler | `trust_diagnostics_windows.go`, the trust timeline state machine and its status; only the bounded PnP node types used by NCM Direct remain in `trust_diagnostics.go`. `TrustPromptDiagnostics` is untouched. | `f093fbd` |
| A7 Runtime network sampler | `runtime_network_diagnostics*` and its no-op public stubs | `f093fbd` |
| A8 Standalone tools | `cmd/ipad-probe` + `internal/diagnostics/ipadprobe`; `cmd/ncm-probe`; `cmd/usb-latency`; `cmd/usb-throughput`; `cmd/ipad-ncm-check`; `cmd/ipad-ncm-status-check`; `cmd/ipad-usb-access-check`; `cmd/device-check` + `internal/platform/windows/devicecheck` | `8685208` |
| B1 AMDS mode diagnostic | `amds_mode_diagnostic_windows.go` (job runner), `amds_local_trial*`, the batch-hold gate, the replug gate, `trust-service-trial-*` actions | `c4c42b5` |
| B2 Unpaired experiment | `unpaired_experiment*`, `unpaired_pair_leaf*`, `unpaired_pair_metadata_windows.go`, DHCP/neighbor/TCP event hooks, launcher startup-hold constant | `c4c42b5` |
| B3 Candidate stages | `candidate_control_windows.go`, `candidate_proof*`, the stage machinery in `candidate_features.go` | `c4c42b5` |

The B gates were replaced by the constants they always produced; the proof for
each gate is in the `c4c42b5` commit message. The legacy diagnostic commands
(`IPADUNPAIRED*`, `IPADCANDIDATE*`, `IPADAMDS*`, `IPADDIAGNOSTIC*`) still answer
"legacy isolation diagnostics retired".

## Kept on purpose

| Item | Why |
|---|---|
| A9 recovery cores: `local_wpd_trace_{core,cleanup,store,recovery}`, `local_usb_trace_{core,recovery}`, `RestoreLocalWPDTrace`, `RestoreLocalUSBTrace` | A developer build may have left an ETW session running. `StartLocalWPDTrace` / `StartLocalUSBTrace` only run this restore at startup and uninstall; a failure is logged (`WPD_TRACE_RESTORE_FAILED`, `USB_TRACE_RESTORE_FAILED`) instead of being published in status. |
| `amds_diagnostic_recovery_windows.go` (receipt reader, `RecoverAMDSModeDiagnostic`, `diagnosticServiceState`) | `InitSimplifiedIPadNetwork` still replays an `amds-diagnostic.json` receipt an older build may have left, and the AMDS hold shares the helpers. Host-state restore, same reason as A9. |
| `unpaired_product*.go` | The one-time compatibility migration and the network-only receipt readers still decode the retired owner and choice files. |
| `deviceguard.ChangeMetadataStream` | Plumbed through the public CM callback (`changes_windows.go`); the public stubs are no-ops. Its only consumer, the PnP trace, is gone, so it is a candidate for a later removal together with the callback parameter. |
| `TrustPromptDiagnostics` (the exported line "iPad 首次連線與信任提示診斷"), `usb_authorization_diagnostics*`, `usb_descriptor_*`, `startup_diagnostics`, `monitor_diagnostics`, `netdebug`, `grouping_receipt_diagnostics` | These produce connection status, failure codes and the lines users attach to bug reports. |
| `connection_trace.go`, `mode_arrival*` | Called from the connection flow; cheap and inert. |
| NCM Direct (mode 5): `local_ncm_direct_*` | Developer experiment required by the owner. |
| `internal/diagnostics/grouptrial` | Name is historical; production grouping uses it. |
| `mtutrial`, `latencyprobe`, `rawusb`, `bench`, `throughput`, `probecontrol`, `memorydiag`, `shutdowntrace`, `exitrecord`, `macalias` | On the bridge data path or the browser speed test / exit protocol. `shutdowntrace` still lists the retired `pnp_stop` and `environment_stop` phase names. |
| `local_photo_*`, `local_amds_hold_*`, `network_only_*`, `software_reconnect_*`, photo-policy leftovers | Photo isolation, AMDS hold, mode switching, restore protocol. Explicitly out of scope. |
| Desktop `LocalDiagnostics`, `LocalTrustExperiments` views | Compiled only with `USBLinkLocalDiagnostics`; they now show only the developer-debug switch, photo isolation, NCM Direct, the MTU control and the recovery warnings. |
| `remoteupdate.ReserveIdleActions` signature | Still has candidate and AMDS parameters; the caller passes `false`. |

## Still deferred

| Item | Lines | Evidence | Coupling | Proposed |
|---|---|---|---|---|
| `network_only_phase*` capture | ~500 | capture entry unreachable | network-only restore path | DEFER |
| Wintun lifecycle probe (`launcher/wintun_*probe*`, `netconfig/wintun_lifetime_probe*`) | ~800 | developer-remote only, but the argv dispatcher is in public `main` | Wintun path (out of scope) | MOVE-TO-DEV-BUILD later |
| `netconfig/firewall_resident_diagnostic*`, `host_identity_diagnostic*` | ~430 | feed local remote runtime details | netconfig | DEFER |

## Size effect (`GOOS=windows GOARCH=amd64`, non-test Go files under `internal` and `cmd`)

| | Public files | Public lines | Dev (`usblink_local_remote`) files | Dev lines | All Go incl. tests (files / lines) |
|---|---|---|---|---|---|
| Before (0.10.57, `c6f7702`) | 685 | 103,808 | 767 | 120,332 | 1,271 / 168,156 |
| After | 665 | 100,798 | 708 | 108,039 | 1,150 / 149,200 |

## Mac NCM descriptor summary (read-only)

The Mac bridge now writes one `USB_MAC_NCM_DESCRIPTOR_SUMMARY ...` line from the
descriptors `winusb.initializeNCM` already reads (no new USB request). The
launcher parses it (fixed charset, 2 KiB cap) into `macconnection.Result` and the
Mac card's exported diagnostics detail. Fields: VID/PID/bcdDevice and device class,
configuration count, configuration attributes, IAD present or not, control
interface alternate settings with the endpoint list (address, type, max packet,
interval) and an explicit `interrupt_in`, CDC header/Union/Ethernet/NCM descriptors
(`wMaxSegmentSize`, `bmNetworkCapabilities`, `iMACAddress_present`), data
interface alternates from the configuration view and from the WinUSB queries, active
bulk pipes. `scoped_view=yes` flags a per-function configuration view (usbccgp), in
which an absent IAD or endpoint is not proof about the whole device. No serial, MAC
string or raw bytes are included. Tests: `internal/transport/ncm/descriptor_summary_test.go`
(captured Mac view, inbox-style layout, truncation/random input, bounds) and
`internal/app/macconnection/metrics_test.go`, `internal/app/ipadncm/application_view_test.go`.
