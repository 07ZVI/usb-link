# Investigation and diagnostic code inventory

Scope: code added while investigating the iPad "Trust This Computer" prompt and
related connection experiments. Goal: public builds stop compiling and running
heavy investigation tooling without changing anything on the connection path.

Build profiles: **public** = default tags (what `project.py package --profile
release` ships); **dev** = tag `usblink_local_remote`. Sizes are non-test Go lines.
"Public set" = files `go list` selects for `GOOS=windows GOARCH=amd64` with default tags.

Evidence: the on-device investigation is summarized in
[IPAD-TRUST-PROMPTS.zh-CN.md](IPAD-TRUST-PROMPTS.zh-CN.md) (0.10.41-0.10.55
sections). Its end state, as stated by the project owner: the prompt is produced
by iPadOS itself when the PTP interface appears about 16 s after the mode-3
switch, with the Windows node disabled, 0 MTP commands issued and AMDS stopped.
So the tracing built to catch a Windows-side trigger has nothing left to prove.
Docs have no per-experiment "closed" notes, so a **DELETE** needs both "dev-only or
unreferenced" and an explicit conclusion; none qualified yet (see Deferred).

Decisions: KEEP-PUBLIC (user-facing diagnostic), MOVE-TO-DEV-BUILD (build tag, no
longer in public), DELETE, KEEP (reason given), DEFER (connection-path coupling;
needs Windows device validation, not done here).

## Done in this change

| Area | Files / lines (all builds) | Public set before -> after | Public dependents | Decision |
|---|---|---|---|---|
| WPD/MTP ETW trace: `ipadncm/local_wpd_trace_*`, `local_wpd_critical_*` (decode, manifest, privacy filter, projection, critical queue, query model) | 19 files / 3,533 | 10 / 1,744 -> 5 / 508 | Status field `wpd_trace` stays (null). IPC and local diagnostics tolerate absence. | MOVE-TO-DEV-BUILD. Native consumer was already dev-only. **KEEP** the minimal journal, session-ownership check, store and `RestoreLocalWPDTrace` in public: it stops a session a dev build left running, a host-state restore. |
| Windows USB ETW trace: `local_usb_trace_*` | 8 / 1,445 | 4 / 554 -> 3 / 345 | `local_usb_trace` stays; public stub now returns a small map (same `available`/`phase`/`error`/`coverage`/ownership keys). | MOVE-TO-DEV-BUILD; recovery (`RestoreLocalUSBTrace`) kept for the same reason. |
| PnP native trace: `local_pnp_trace_*` | 3 / 314 | 2 / 279 -> 1 / 9 | `pnp_native_trace` stays null. | MOVE-TO-DEV-BUILD. `deviceguard.ChangeMetadataStream` is KEPT: it is plumbed through the public CM callback (`changes_windows.go`); public stubs are no-ops. |
| Connection archive: `local_connection_archive_*` | 3 / 948 | 2 / 716 -> 1 / 12 | `connection_archive` stays null; `Record*` stubs stay (called from public code). | MOVE-TO-DEV-BUILD. Reader stubs (only dev callers) deleted. |
| Connection timing trial: `connection_timing*.go` | 6 / 595 | 4 / 515 -> 2 / 49 | Public already used the `*_disabled_windows.go` fast-path stubs; only `connectionTimingPlan` kept. | MOVE-TO-DEV-BUILD. |
| Trust timeline sampler: `trust_diagnostics_windows.go` | 188 | in public set -> out | `StartTrustDiagnostics` was a no-op unless `LocalDiagnostics=="true"`. State machine (`trust_diagnostics.go`) stays: `connection_trace.go` calls `RecordTrustOperation`/`stamp` (inert in public). | MOVE-TO-DEV-BUILD (sampler only). |
| Runtime network sampler: `runtime_network_diagnostics*.go` | 3 / 402 | in public set -> out | `StartRuntimeNetworkDiagnostics`/`RuntimeNetworkDiagnostics` now public no-ops (nil value), only read when `LocalDiagnostics=="true"`. | MOVE-TO-DEV-BUILD. |
| Standalone tools, none built by any `project.py` profile: `cmd/ipad-probe` + `internal/diagnostics/ipadprobe`; `cmd/ncm-probe`; `cmd/usb-latency`; `cmd/usb-throughput`; `cmd/ipad-ncm-check`; `cmd/ipad-ncm-status-check`; `cmd/ipad-usb-access-check`; `cmd/device-check` + `internal/platform/windows/devicecheck` | ~2,100 incl. packages | 12 files -> 0 | Nothing imports them (`ncm-probe` appears only as a historical log name / retired-asset hash). `usb-throughput` is named "development diagnostic only" in BROWSER-SPEED-TEST.md. | MOVE-TO-DEV-BUILD (still buildable with the tag). No doc says they concluded, so not deleted. |

## Kept in public on purpose

| Item | Why |
|---|---|
| `TrustPromptDiagnostics` (the exported line "iPad 首次連線與信任提示診斷"), `usb_authorization_diagnostics*`, `usb_descriptor_*`, `startup_diagnostics`, `monitor_diagnostics`, `netdebug`, `grouping_receipt_diagnostics` | These produce connection status, failure codes and the lines users attach to bug reports. The prompt line reads the remembered-photo-instance store and attempt failures, not any removed tracing; verified by compilation without the trace models and by its existing tests. |
| `connection_trace.go`, `rearm_diagnostics.go`, `mode_arrival*` | Called from the connection flow; cheap and inert. |
| NCM Direct (mode 5): `local_ncm_direct_*` | Required by the owner as a developer experiment. Already dev-only (public has a stub). Untouched. |
| `internal/diagnostics/grouptrial` | Name is historical; production grouping uses it. |
| `mtutrial`, `latencyprobe`, `rawusb`, `bench`, `throughput`, `probecontrol`, `memorydiag`, `shutdowntrace`, `exitrecord`, `macalias` | On the bridge data path or the browser speed test / exit protocol. |
| `local_photo_*`, `local_amds_hold_*`, `network_only_*`, `software_reconnect_*`, photo-policy leftovers | Photo isolation, AMDS hold, mode switching, restore protocol. Explicitly out of scope. |
| Desktop `LocalDiagnostics`, `LocalTrustExperiments` views | Already compiled only with `USBLinkLocalDiagnostics`; the parsers use `TryGetProperty`, so null/absent fields from public stubs need no UI change. |

## Deferred: dead or experimental, but wired into connection decisions

Removing these edits `launcher/main_windows.go`, `idle_windows.go`,
`application_windows.go` or the grouping/DHCP flow, which would touch the path
that lets a Mac or iPad connect. Behaviour-preserving in theory, unproven without
a Windows device. Proposed as a separate change with hardware acceptance.

| Item | Lines | Evidence | Coupling | Proposed |
|---|---|---|---|---|
| `amds_mode_diagnostic_windows.go`, `amds_local_trial*` (Apple service comparison) | 554 + 84 | docs 0.10.18 comparison done; `StartAMDSModeDiagnostic` unreachable from every `main` | `AMDSModeDiagnosticActive/Pending` gate `CanConnect` and idle | DELETE once gates become constants |
| `unpaired_*` experiment (Trust/unpaired recovery) | 1,255 | entry points unreachable (deadcode); no doc conclusion | `UnpairedExperimentCanConnect`, idle, DHCP event hooks, upgrade admission | DELETE after device check |
| `candidate_*` (iPad candidate stages) | 345 | entry points unreachable; legacy commands already answer "retired" | idle/launcher gates | DELETE after device check |
| `network_only_phase*` capture | ~500 | capture entry unreachable | network-only restore path | DEFER |
| Wintun lifecycle probe (`launcher/wintun_*probe*`, `netconfig/wintun_lifetime_probe*`) | ~800 | developer-remote only, but the argv dispatcher is in public `main` | Wintun path (out of scope) | MOVE-TO-DEV-BUILD later |
| `netconfig/firewall_resident_diagnostic*`, `host_identity_diagnostic*` | ~430 | feed local remote runtime details | netconfig | DEFER |

## Size effect (public Windows set, `go list` GoFiles, non-test)

| | Files | Lines |
|---|---|---|
| Before | 737 | 113,873 |
| After (includes +330 lines for the new Mac NCM descriptor summary) | 715 | 108,626 |
| Repository, all Go incl. tests (nothing deleted, moved code stays for dev builds; plus new probe, tests and split files) | 1,290 -> 1,300 | 172,630 -> 173,346 |

Dev build (`usblink_local_remote`) code is unchanged in behaviour; developer file set
went 788 -> 794 files only because of the new split files and summary.

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
