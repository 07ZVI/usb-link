# Windows → Mac gateway

The first backend uses WinNAT, the existing USB bridge and exact WFP forward permits. It handles IPv4 and one currently authorized Mac. The host address `10.6.9.1`, Mac `10.6.9.2` and iPad `10.6.9.3` stay unchanged. Sharing is off after launch/recovery and requires a new manual enable for the current attachment.

Preflight detects WinNAT availability, other NAT/ICS configurations and current non-USB default-route candidates. It does not enable Hyper-V, replace someone else's NAT, rewrite Windows default routes or take over ICS. The selected upstream must be Windows' effective default Internet route; selecting another adapter shows `INTERNET_SELECTED_UPSTREAM_NOT_DEFAULT` until the Windows routing configuration makes it eligible. The UI can select among detected routes, but this first WinNAT implementation does not supply independent per-peer policy routing.

Before mutation the core records the selected interface index/LUID, original forwarding state, exact NAT name and live attachment identity. It checks the existing USB topology/address-conflict contract, creates only its nonce-named `USBLink-…` NAT for `10.6.9.0/24`, verifies it, enables and reads back selected-upstream forwarding, adds journaled WFP filters to the existing USB sublayer and starts scoped DNS.

DHCP option 3 (gateway) and 6 (DNS) are offered only while a prepared live core lease exists. Existing leases may need manual renewal in macOS Network settings; enabling sharing does not pretend that the Mac has already accepted those options. State becomes `waiting_client`, then `ready` only after an ACK was sent and this epoch has observed outward and return public traffic. This observation is operational evidence; it does not replace hardware testing or prove the macOS UI's displayed route configuration.

Public routing excludes private, CGNAT, loopback, link-local, documentation, benchmarking, multicast/reserved ranges and every observed on-link network, including publicly addressed LANs. IPv6 is not admitted. WFP permits require exact USB and selected upstream LUIDs, exact Mac peer IP and the computed public IPv4 prefixes. Other USB peers are never permitted by these Internet rules. Return forwarding traverses WinNAT's connection state; no static inbound mapping is created. The existing local authorization rules still protect host services.

DNS binds only `10.6.9.1:53`, accepts only the Mac peer address and forwards UDP/TCP to the selected interface's observed DNS servers. Outbound sockets bind the selected interface with `IP_UNICAST_IF`. Work is bounded and has deadlines. DNS is the explicit local relay needed for Internet name resolution; it does not open general upstream LAN forwarding.

Core monitoring rechecks live authorization, host/upstream identity, NAT, effective route, DNS and on-link networks. Changes stop sharing. A five-second lease expires at each packet boundary if the core disappears. Normal close disables packet admission, stops DNS, deletes Internet WFP keys, removes only the recorded NAT and restores the original upstream forwarding setting. Failed removal keeps the journal and shows recovery required. Startup replays cleanup; it never silently reenables sharing. Recovery refuses changed/reused interface identities.

See [Microsoft's WinNAT capabilities and limits](https://techcommunity.microsoft.com/blog/virtualization/windows-nat-winnat----capabilities-and-limitations/382303). Unavailable WinNAT or existing NAT/ICS conflict leaves the original local USB/file functions available.

## Mac → Windows: comparison only

| Route | Compatibility and UDP | Permissions / dependencies | First-install constraint |
| --- | --- | --- | --- |
| macOS system Internet Sharing / NAT | OS routing for TCP/UDP and applications; interface support depends on the actual USB network device | Administrator approval and macOS sharing/firewall policy; should preserve other sharing settings | Cannot download initial Windows external dependencies without an already usable USB/network path |
| HTTP CONNECT / SOCKS proxy on Mac | Application/proxy-aware clients; UDP needs SOCKS UDP support and is often unsupported by clients | A trusted Mac proxy and per-application configuration; system proxy does not cover every app | Can bootstrap HTTP downloads after the USB path exists, but cannot replace missing Windows USB drivers |
| User-space tunnel over USB | Potential application-transparent IP, TCP/UDP with explicit transport design | Privileged Windows adapter/routing and Mac networking; bounded tunnel protocol and strict peer authorization needed | Requires adapter/driver preparation first; adds its own licensing, bootstrap and recovery requirements |

These are future routes, not implemented reverse-sharing functions. Apple's [Internet Sharing documentation](https://support.apple.com/en-ie/guide/mac-help/mchlp1540/27/mac/27) describes the OS route. Actual Mac interface compatibility and coexistence need separate device evaluation.
