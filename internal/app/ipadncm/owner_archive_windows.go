//go:build windows && amd64

package ipadncm

func archiveOwnerPhase(phase, edge string) {
	RecordConnectionArchiveEvent("owner_phase", struct {
		Attempt uint64 `json:"software_attempt"`
		Phase   string `json:"phase"`
		Edge    string `json:"edge"`
	}{currentSoftwareAttempt(), phase, edge})
}

func archiveOwnerNotice(phase, source string, code uint32) {
	RecordConnectionArchiveEvent("owner_notice", struct {
		Attempt uint64 `json:"software_attempt"`
		Phase   string `json:"phase"`
		Source  string `json:"source"`
		Code    uint32 `json:"code"`
	}{currentSoftwareAttempt(), phase, source, code})
}

func archiveCandidate(phase string, p idlePresence, allowed bool) {
	RecordConnectionArchiveEvent("candidate_gate", struct {
		Attempt   uint64 `json:"software_attempt"`
		Phase     string `json:"phase"`
		Readable  bool   `json:"presence_readable"`
		Candidate bool   `json:"unique_candidate"`
		Absent    bool   `json:"no_mobile_root"`
		Allowed   bool   `json:"allowed"`
	}{currentSoftwareAttempt(), phase, p.readable, p.candidate, p.absent, allowed})
}

func archiveUSBConsent(phase string, allowed, contextActive bool) {
	RecordConnectionArchiveEvent("usb_authorization", struct {
		Attempt       uint64 `json:"software_attempt"`
		Phase         string `json:"phase"`
		Allowed       bool   `json:"allowed"`
		ContextActive bool   `json:"context_active"`
	}{currentSoftwareAttempt(), phase, allowed, contextActive})
}
