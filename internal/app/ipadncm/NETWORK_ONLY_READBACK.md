# I7 portable-node disable/readback verification

The 0.8.72 code passed literal `3` to `CM_Disable_DevNode` while labeling it
`UI_NOT_OK | PERSIST`. That interpretation was incorrect.

Microsoft's SDK header defines the actual values at lines 863–870:
[cfgmgr32.h](https://raw.githubusercontent.com/microsoft/win32metadata/main/generation/WinSDK/RecompiledIdlHeaders/um/cfgmgr32.h).
`CM_DISABLE_UI_NOT_OK` is `0x04`, `CM_DISABLE_PERSIST` is `0x08`, and the
correct combined value is `0x0c`. Bits `0x01` and `0x02` mean `ABSOLUTE` and
`HARDWARE`. The latter's header comment says the node will not be restartable.
The `PERSIST` comment explicitly describes setting `CONFIGFLAG_DISABLED` in
the registry; preserving the exact original bits plus this bit is therefore
an SDK-backed readback requirement, not an assumption about SetupDi caching.

The [documented disable API](https://learn.microsoft.com/en-us/windows/win32/api/cfgmgr32/nf-cfgmgr32-cm_disable_devnode)
also specifies persistence across reboots. The shorter API documentation does
not list numeric constants; it must not substitute for checking the ABI header.

The fix uses the named `0x04 | 0x08` constants, without directly writing any
registry property. Both pre- and post-operation observations read the actual
CM instance identity, class GUID, parent root, status/problem, and native
`DEVPKEY_Device_ConfigFlags`. The latter and class keys are defined at lines
46 and 48 of [devpkey.h](https://raw.githubusercontent.com/microsoft/win32metadata/main/generation/WinSDK/RecompiledIdlHeaders/shared/devpkey.h).
Native [CM_Get_DevNode_PropertyW](https://learn.microsoft.com/en-us/windows/win32/api/cfgmgr32/nf-cfgmgr32-cm_get_devnode_propertyw)
type and length are checked. Missing ConfigFlags retains the original
absent-means-zero rule, with the native missing-property return code recorded.

Success still requires the precise owned property value and CM disabled state,
the exact instance/class/root, no `DN_NEED_RESTART`, and no `DN_STARTED` while
disabling. The exact instance is relocated after the operation; a changed
DEVINST is accepted only after identity, class and parent-chain verification.
No extra polling, executables or path inspection are added.

`NetworkOnlyOperationDiagnostics()` returns at most eight cached operations:
original flags, before/after native properties and API return codes, native
identity/ownership checks, actual change flags, relocation and elapsed time.
Full USB instance serials are excluded. `PrepareNetworkOnlyStartup` and
`EnsureNetworkOnly` failures report `ERROR` and block automatic retries.

Recovery of an old flags-3 operation still calls `CM_Enable_DevNode(0)` when
the node remains disabled, then verifies the exact original flags and actual
non-disabled CM state. `RestoreNetworkOnlyPortableNodes(dir)` must run while
the target is present, before grouping restoration can require unplugging it.
After each strictly verified node restoration, the v1 receipt is atomically
checkpointed by removing only that verified node. Unverified nodes, originally
disabled nodes and original AMDS state remain. The old receipt schema stays
compatible. A failed native enable, ownership/readback, or checkpoint write
leaves the recovery obligation intact; it never grants successful recovery.

Validation: pure tests cover the SDK numeric contract, wrong instance/class/root,
temporary disable without the persistent bit, restarted/started/unreadable
nodes, foreign property bits, error-state reporting, bounded immutable diagnostic
history, native failure after an earlier checkpoint, and checkpoint-write failure.
Hardware restoration of an old `HARDWARE` disable remains unverified: the new
helper must return an error and retain the node if Windows refuses to enable it.
