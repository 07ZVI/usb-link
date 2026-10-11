# Exact owned portable-node restoration

The unchanged v1 receipt records the exact USB root, portable instance, class,
original disabled state and original ConfigFlags **value**. It does not record
whether the property originally existed. A successful v1-compatible restoration
therefore proves the recorded value, and the protected audit explicitly retains
`original_presence_unknown=true`. It is not evidence of complete original
presence restoration and is not evidence that iPad trust prompts are fixed.

A phantom is not automatically restored. Restoration requires the protected valid
v1 receipt, a completed bounded ALL enumeration with one exact full instance,
SetupDi and CM class agreement, exact CM instance and native ancestor root,
completed PRESENT enumeration proving that same instance absent, and CM status
`CR_NO_SUCH_DEVINST` (13). SetupDi's ConfigFlags and the independent documented
`CM_Get_DevNode_Registry_PropertyW(CM_DRP_CONFIGFLAGS)` read must agree and be
REG_DWORD/4 bytes or canonical absence=0. The value must be precisely original
or original|DISABLED. Any other bit, identity, class, parent, presence or unreadable
property retains the receipt. A different current MI_00 cannot replace the owned
phantom. No root, class, grouping, driver, paired data or restart bit is changed.

The only phantom mutation is documented
`SetupDiSetDeviceRegistryPropertyW(SPDRP_CONFIGFLAGS)`, writing the recorded
DWORD. Already-original legacy values, including absence=0, cause no write;
Windows normalizing DWORD0 to absence is accepted only for value-only v1
compatibility. The full native ownership and independent property proof is read
again afterward. The audit is atomically synced, WRITE_THROUGH-published and
independently read back before permitting the node's v1 checkpoint. A failed
write, post-write proof, audit or checkpoint cannot remove that obligation.
CM status 13 and API success alone never count as restoration.

Newly owned nodes capture exact original presence/type/value in a separate
protected sidecar **before** adding the main owned receipt and before first
mutation, only with a healthy present native node whose value equals the newly
recorded original and whose disabled bit is clear. Existing legacy nodes never
retroactively capture current presence, even when their current value is 0.
The sidecar's exact identity, class, root, value and immutable metadata must agree;
missing/foreign/corrupt/unprotected metadata is never replaced by inferred facts.
A known sidecar requires full original presence and value restoration, including
NULL/0 property clearing for known original absence. Its original metadata is
pruned only after the main node checkpoint succeeds. The protected restoration
audit stays available through the existing explicit read-only diagnostic even
when the receipt has no remaining nodes or the current root is absent. The explicit
ReadNetworkOnlyPropertyRestoreSummaries(recoveryDir) reader also works before
InitNetworkOnly during recovery maintenance without initializing policy.

Present nodes keep CM_Enable_DevNode and independent present native state
verification. Known presence is then verified/restored separately. Legacy present
restoration also emits the original-presence-unknown audit; the old value-only
receipt remains compatible with older releases.

Public diagnostic summaries contain only the domain-separated exact-ID SHA256,
allowed class GUID, recorded original value, bounded property reads and outcome
booleans. Raw instance, root, serial and registry paths remain private. New file
DACLs are SYSTEM/Administrators only, protected from inheritance and using
concrete FILE_ALL_ACCESS. CREATE_NEW supplies the security descriptor at creation
time; no post-creation WRITE_DAC is needed. Readers verify
the opened handle's DACL and reject reparse points. No UI polling is added.

This implementation is compile/replay tested on macOS. Windows native phantom
CM property availability, protected file ACL behavior, device reappearance races
and end-to-end OFF/uninstall restoration require hardware validation by the main
agent. Any unavailable native proof fails closed. The current bounded audit store
retains up to 64 exact-node/category records; legacy unknown and later known
presence records coexist under the same baseline, so later known restoration
cannot overwrite earlier unknown evidence. Reusing the same exact node after an external
change to its recorded baseline flags intentionally fails closed instead of
overwriting earlier unknown-presence evidence; multi-cycle audit generations are
not added in this patch.

Microsoft primary references:

- [Determining whether a device is plugged in](https://learn.microsoft.com/en-us/windows-hardware/drivers/install/determining-whether-a-device-is-plugged-in)
- [SetupDiSetDeviceRegistryPropertyW](https://learn.microsoft.com/en-us/windows/win32/api/setupapi/nf-setupapi-setupdisetdeviceregistrypropertyw)
- [CM_Get_DevNode_Registry_PropertyW](https://learn.microsoft.com/en-us/windows/win32/api/cfgmgr32/nf-cfgmgr32-cm_get_devnode_registry_propertyw)
- [Microsoft SDK cfgmgr32.h: CM_DRP_CONFIGFLAGS](https://raw.githubusercontent.com/microsoft/win32metadata/main/generation/WinSDK/RecompiledIdlHeaders/um/cfgmgr32.h)
