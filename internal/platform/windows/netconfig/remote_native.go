package netconfig

// Null/empty mean no extra legacy restriction. "Any" is accepted only for
// documented wildcard filters such as package and ICMP, never for owner SID,
// policy application identity or dynamic-keyword address identifiers.
func unrestrictedLegacyConstraint(parts []string, allowAny bool) bool {
	return len(parts) == 0 || len(parts) == 1 && (parts[0] == "NULL" || parts[0] == "S:" || allowAny && parts[0] == "S:Any")
}
