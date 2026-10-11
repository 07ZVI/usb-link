package connectioninstall

// A NULL/absent DACL is already permissive; an allocated empty ACL denies all.
// The caller retains the separate native share ACL regardless of filesystem mode.
func smbDACLMode(persistent, present, null bool) string {
	if !persistent {
		return "filesystem-no-acl"
	}
	if !present || null {
		return "already-permissive"
	}
	return "managed"
}
