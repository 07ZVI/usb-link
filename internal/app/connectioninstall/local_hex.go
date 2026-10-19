//go:build usblink_local_remote

package connectioninstall

// localArchiveHex validates fixed-length lowercase hexadecimal identifiers.
func localArchiveHex(s string, n int) bool {
	if len(s) != n {
		return false
	}
	for _, c := range s {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}
