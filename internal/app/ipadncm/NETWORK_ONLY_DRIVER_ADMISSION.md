# Expected AMDS stop admission and cold-attachment isolation

Baseline: integrated `3e00285` (0.8.79). Hardware sample 10 failed: the
driver preparation interpreted I7's stopped AMDS as a repair requirement,
the repair was declined, networking paused, and the user reported one trust
prompt plus failed Moonlight. This change fixes that source conflict; it does
not establish the cause or elimination of the trust prompt.

The main launcher accepts an expected AMDS stop only after a read-only native
proof: current stage-5 owner and same-root two-state mode evidence; enabled
policy with no pending/busy/blocked transition; fixed protected recovery store
and valid v1 receipt containing a legal portable node belonging to this exact
root; fresh unchanged descriptor/physical binding; unique healthy official
usbccgp root with AppleLowerFilter; independently readable started/problem-zero
native root and non-disabled flags; existing AMDS stopped at the exact startup
type derived from the owned original receipt. Missing service, missing receipt,
empty or other-root nodes, unreadable native state, changed owner or changed
policy pauses I7. It never falls through to repair or AMDS start.

A distinct preparation-only first-apply reader requires the same current
owner, descriptor/root, official/native health and protected store proof, plus
positive native file-not-found evidence for the service receipt and a stable
Running or Stopped original AMDS state/configuration. Only this reader permits
the pre-preparation Ensure to create the original receipt and apply policy.
An existing, corrupt or partial receipt cannot take this path. prepareDriver
and post-mode admission still require a valid owned receipt and expected stop.

A missing choice file retains InitNetworkOnly's default ON semantics. That
default is insufficient by itself: the current stage-5 owner and same-root dual
proof must exist, with either the owned receipt or the distinct first-apply
proof above. No new choice write or grant
migration is introduced. Native readback cannot install, start/stop services,
disable a node, change pairing data, write a receipt or broaden ACLs.

After the existing USB consent and candidate validation, an active I7 owner
must pass this admission before the first EnsureCurrentNetworkOnly. Driver
preparation repeats fresh admission; the existing post-preparation isolation
check stays. A successful, ready mode result with confirmed service restoration
must again pass fresh same-root admission and isolation before native startup.
Failed mode and non-I7 preparation do not gain a node mutation. All existing
owned receipt append, node-disable and restoration procedures are preserved.
The legacy ipad-usb-setup tool is unchanged and acquires no I7 exemption.

The software-reconnect observation adds only CM and SetupDi class GUID strings,
the CM property type/size, and the existing fixed expected class GUID. They are
typed class metadata, not serials, instance IDs or paths. The fixed-class
predicate and every disable/restore/receipt policy remain unchanged. Pinned
Apple INF class metadata is not proof of the actual installed root class.

Tests cover incomplete ownership/native/service proof, malformed/off choices,
wrong/empty receipt roots, abnormal native status/flags, preparation order,
failed preflight reaching neither driver nor mode nor startup, failed mode
performing no post-isolation, changed target blocking startup, and metadata
being unable to override a failed class predicate. Windows compilation is not
Windows execution. Cold hardware acceptance and OFF/uninstall restoration
remain necessary. In particular, the existing v1 phantom-node restoration
failure is not bypassed by this patch; its receipt remains retained.
