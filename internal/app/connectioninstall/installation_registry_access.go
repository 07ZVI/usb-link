package connectioninstall

// Registry generic READ and EXECUTE map to KEY_READ, not mutation rights.
// A blanket 0xf0000000 test also matches those read-only generic bits.
// Include KEY_CREATE_LINK: it is mutating even without KEY_CREATE_SUB_KEY.
func registryAccessCanMutate(mask uint32) bool {
	const writes uint32 = 0x40000000 | 0x10000000 | // GENERIC_WRITE, GENERIC_ALL
		0x2 | 0x4 | 0x20 | // SET_VALUE, CREATE_SUB_KEY, CREATE_LINK
		0x10000 | 0x40000 | 0x80000 // DELETE, WRITE_DAC, WRITE_OWNER
	return mask&writes != 0
}

// The third principal is obtained only from the interactive elevated token;
// a matching SID prefix, an arbitrary owner, or a regular user is insufficient.
func trustedDeletedRegistryWriter(sid, elevatedAdministrator string) bool {
	return sid == "S-1-5-18" || sid == "S-1-5-32-544" || elevatedAdministrator != "" && sid == elevatedAdministrator
}

// Services differ from registry keys: GENERIC_EXECUTE includes starting and
// stopping a service. Preserve the core's existing control/configuration gate,
// but do not reject GENERIC_READ, which only grants inspection rights.
func serviceAccessCanChangeCore(mask uint32) bool {
	const control uint32 = 0x40000000 | 0x20000000 | 0x10000000 |
		0x2 | 0x10 | 0x20 | 0x10000 | 0x40000 | 0x80000
	return mask&control != 0
}
