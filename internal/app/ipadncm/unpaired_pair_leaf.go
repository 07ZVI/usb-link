package ipadncm

import "strings"

// Names are derived from an exact USB descriptor, never a user suffix or path.
// This does not normalize the native USB identity used to bind a device.
func unpairedPairLeaves(serial string) []string {
	s := strings.ToLower(serial)
	if len(s) == 25 && s[8] == '-' {
		s = s[:8] + s[9:]
	}
	if len(s) != 24 && len(s) != 40 {
		return nil
	}
	for _, c := range s {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return nil
		}
	}
	if len(s) == 24 {
		return []string{s + ".plist", s[:8] + "-" + s[8:] + ".plist"}
	}
	return []string{s + ".plist"}
}
