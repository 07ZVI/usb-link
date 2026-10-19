package logfile

// The core's own lifecycle and pipe-failure rows must survive transport
// trimming exactly like the other independent evidence sections.
func init() {
	diagnosticEvidenceSections = append(diagnosticEvidenceSections, "core_lifecycle", "core_ipc")
}
