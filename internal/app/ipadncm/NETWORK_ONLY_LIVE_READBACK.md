# Explicit only-network live readback

`IPADNETWORKONLYSTATE` now returns a schema-1 object with live AMDS state/start type, fresh descriptor binding, exact current or owned WPD/PTP node observations, and the previous operation history under `operation_history_not_live_proof`. Previous candidates returned only the history array. The fixed authenticated USB diagnostic accepts no IDs, paths, service names or commands.

The handler is invoked only by that explicit diagnostic. It is not used by ordinary UI refresh, periodic monitoring or the packet path. It does not apply policy, update a service, restart or enable/disable a node, write a receipt, or establish/import consent. An invalid receipt or unproven descriptor target is reported as unreadable, not repaired. Node IDs and descriptor serials remain private; node digests permit before/after comparison.

Capture before enabling I7, after enabling, after opening Explorer/iTunes/Apple Devices, and after OFF. Historical `ACTIVE` and a past successful Stop do not prove the service is still stopped. Manual startup permits a later service start, so actual application isolation remains a hardware acceptance item.

Existing v1 receipts store the original ConfigFlags **value** but do not record whether the property was originally absent. This diagnostic exposes current native absence and explicitly labels that limitation; it does not silently reinterpret a zero value as proof of exact original presence. Before-enable and restored snapshots must be compared by node digest for the tested device. No receipt format migration or relaxed recovery was introduced here.

Windows vet/build can validate this handler's wiring. Its native observations and application isolation cannot be validated by a Mac race test or cross compilation, and must be read back on the target Windows machine.
