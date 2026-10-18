package ipadncm

// What the user sees for the "network only" switch. Derived only from the
// saved choice and the photo controller's own readbacks.
type networkOnlyIsolationStatus struct {
	Enabled        bool   `json:"enabled"`
	Busy           bool   `json:"busy"`
	Requested      bool   `json:"requested"`
	RequestID      string `json:"request_id"`
	RejectedID     string `json:"rejected_id"`
	Effective      bool   `json:"effective"`
	Restoring      bool   `json:"restoring"`
	RestorePending bool   `json:"restore_pending"`
	Phase          string `json:"phase"`
	Error          string `json:"error,omitempty"`
	KnownNodes     int    `json:"known_nodes"`
	KnownApplied   int    `json:"known_applied"`
	OwnedNodes     int    `json:"owned_nodes"`
}

// Effective means a readback proved isolation: either every present photo node
// is disabled, or none is present and every remembered one was applied.
func networkOnlyEffective(enabled bool, p localPhotoStatus) bool {
	if !enabled || !p.Requested || p.Error != "" {
		return false
	}
	if p.ObservedNodes > 0 {
		return p.Effective
	}
	return p.KnownApplied > 0 && p.KnownCode == ""
}

func networkOnlyError(enabled bool, p localPhotoStatus) string {
	if p.Error != "" {
		return p.Error
	}
	if enabled {
		return p.KnownCode
	}
	return ""
}

func networkOnlyFromPhoto(enabled bool, p localPhotoStatus) networkOnlyIsolationStatus {
	return networkOnlyIsolationStatus{
		Enabled: enabled, Effective: networkOnlyEffective(enabled, p),
		Restoring:      !enabled && p.Phase != "off" && p.Phase != "recovery_pending" && (p.OwnedNodes > 0 || p.Phase == "recovering"),
		RestorePending: p.Phase == "recovery_pending", Phase: p.Phase, Error: networkOnlyError(enabled, p),
		KnownNodes: p.KnownNodes, KnownApplied: p.KnownApplied, OwnedNodes: p.OwnedNodes,
	}
}
