# Architecture

One repository, one Go module, Avalonia desktop rendering. The module name `suhang/usbnet`, service names, product markers, address profiles, upgrade verification keys and recovery journal formats are compatibility identities, not branding to rename during this migration.

```mermaid
flowchart TD
    cmd[Thin production command entries] --> app[Application coordination]
    ui[Avalonia views and state] --> client[DesktopClient / authenticated IPC v1]
    client --> app
    app --> deps[Dependency manager / native progress]
    app --> sharing[Files / native SMB / compatibility SMB]
    app --> security[Authorization / WFP / Internet policy]
    app --> transport[USB / NCM / DHCP / routing]
    app --> platform[Windows adapters and recovery]
    deps --> official[Official downloads and installers]
    security --> platform
    transport --> platform
```

| Directory | Responsibility |
| --- | --- |
| `cmd/` | Production argument/start entry wrappers; diagnostic command tools |
| `internal/dependencies` | Pinned official catalog, detection, bounded downloads, verification, native progress and platform installation |
| `internal/app` | Lifecycle, connection coordination, upgrades, installation and recovery orchestration |
| `internal/transport` | WinUSB/Wintun, NCM packets, DHCP, point-to-point addresses and routing admission |
| `internal/sharing` | File transfer, folder/account policy, compatibility SMB implementation and protocol helpers |
| `internal/security` | Device/application authorization, USB WFP scope, native Internet backend |
| `internal/platform/windows` | Native Windows APIs, network configuration, service/driver adaptation |
| `internal/contracts` | Authenticated IPC v1 request/response contract |
| `internal/diagnostics` | Bounded measurements and read-only evidence |
| `desktop/App`, `Views`, `Controls`, `Theme`, `Services`, `Tests` | Application entry, UI composition, components, style, service client/native read-only helpers, synthetic smoke checks |

`architecture-map.json` records every original package path and its new owner. Package names remain stable; imports were updated together. Production commands for launcher, bridge worker, Mac agent and updater contain no business implementations. Their implementations now belong to application modules. The desktop's original single-file classes are separated without changing their controls; outbound intent goes through one synchronized `DesktopClient` writer.

Policy and native mutation have separate boundaries: `dependencies.Platform` controls detect/verify/install; `internet.Backend` controls preflight/journal/create/open/close/readback. Routing policy contains no system calls. Existing Windows implementations remain separated by build tags from pure policy/tests. Go's compiler rejects package cycles, and `scripts/check_architecture.py` checks ownership and lower-layer imports. Integration tests may import application fixtures without changing production dependencies.

## Native SMB and compatibility SMB

Native SMB uses Windows' service, account and folder ACL APIs on port 445. Compatibility SMB stays in `internal/sharing/smbcore` on port 10690 with its original MIT provenance and local security changes. Their authority, account lifecycle, directory access checks, diagnostics and acceptance are separate. Neither a successful compatibility test nor a mount from retained history proves native SMB acceptance.

## IPC and authority

IPC remains v1. Snapshot's existing display gains `dependencies` and `internet_sharing`; action gains dependency refresh and `internet-enable`, `internet-disable`, `internet-refresh`. An elevated owner UI is independently authenticated by the existing pipe server. The core rechecks live Mac/host identity before mutation and again before publication. The renderer never supplies executable paths, PowerShell or filesystem locations.

Official installers that need visible license acceptance run in the authenticated interactive launcher/UI, rather than in the service's noninteractive session. Dependency-install intent is validated against the fixed catalog. Subsequent core refresh detects the actual installed state.

## Recovery

Existing protected journals retain their format. Internet sharing adds a separate protected journal, a five-second session lease and bounded traffic observation. The journal precedes NAT or forwarding mutation. WFP keys are added to the existing gateway recovery journals before installation. On failure, shutdown or loss of identity, packet admission closes first, then DNS/WFP/NAT are removed and forwarding is restored. Unproven cleanup keeps its journal and blocks another enable attempt.

The worker receives a parent-selected Mac attachment identity, reads only the product-owned protected lease and checks the expiry per packet. Lease expiry gives fail-closed behavior even if the core terminates before normal cleanup. Startup recovery removes the recorded NAT; it never restores a prior enabled-sharing preference.
