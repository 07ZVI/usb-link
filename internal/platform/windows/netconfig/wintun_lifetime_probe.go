package netconfig

import (
	"errors"
	"strings"
	"suhang/usbnet/internal/transport/wintun"
	"unicode/utf16"
)

// A fixture observation cannot authorize production cleanup or Ready. No
// device instance, source path, GUID, address or arbitrary command is exported.
type WintunLifetimeProbeRead struct {
	Complete             bool   `json:"complete"`
	MIBMatches           uint32 `json:"mib_matches"`
	InstalledMatches     uint32 `json:"installed_matches"`
	ExactInstanceMatches uint32 `json:"exact_instance_matches"`
	IPv4Matches          uint32 `json:"ipv4_matches"`
	TypedPresent         bool   `json:"typed_present"`
}

// This validates a captured child observation, never authorizes an adapter or
// turns the fixture into production readiness. PID/creation come from the
// parent's retained native process handle, not from JSON.
func ValidateWintunLifetimeProbeReport(v WintunLifetimeProbeReport, hold bool, pid uint32, creation uint64) error {
	bad := func() error { return errors.New("WINTUN_PROBE_REPORT_INVALID") }
	if v.Schema != 1 || v.TransportError != "" || !v.ObservationOnly || v.HoldModule != hold || pid == 0 || creation == 0 || v.ProcessID != pid || v.ProcessCreation != creation || len(v.Rounds) > 5 || v.PinnedModules < 0 || v.PinnedModules > 1 || (!hold && v.PinnedModules != 0) {
		return bad()
	}
	switch v.Stage {
	case "preflight", "before_create", "creating", "created_mapping", "closing", "complete":
	default:
		return bad()
	}
	code := func(s string) bool {
		if s == "" {
			return true
		}
		if len(s) > 96 || !strings.HasPrefix(s, "WINTUN_PROBE_") {
			return false
		}
		for _, c := range s {
			if (c < 'A' || c > 'Z') && c != '_' {
				return false
			}
		}
		return true
	}
	if !code(v.Code) {
		return bad()
	}
	for i, r := range v.Rounds {
		if r.Round != i+1 || !code(r.Code) || r.Before.MIBMatches > 65536 || r.After.MIBMatches > 65536 || r.Before.InstalledMatches > 4096 || r.After.InstalledMatches > 4096 || r.Before.ExactInstanceMatches > 65536 || r.After.ExactInstanceMatches > 65536 || r.Before.IPv4Matches > 65536 || r.After.IPv4Matches > 65536 || r.CloseSettleMS > 120000 || (r.CreateReturned && !r.CreateCalled) || (r.CreatorVerified && (!r.CreateCalled || !r.CreateReturned)) || (r.CloseReturned && !r.CreateReturned) {
			return bad()
		}
		if v.Code == "" && (r.Code != "" || !r.CreateCalled || !r.CreateReturned || !r.CreatorVerified || !r.CloseReturned || !r.Before.absent() || !r.After.absent()) {
			return bad()
		}
	}
	if v.Code == "" && (v.Stage != "complete" || len(v.Rounds) != 5 || (hold && v.PinnedModules != 1)) {
		return bad()
	}
	if v.Code != "" && v.Stage == "complete" {
		return bad()
	}
	return nil
}

func (v WintunLifetimeProbeRead) absent() bool {
	return v.Complete && v.MIBMatches == 0 && v.InstalledMatches == 0 && v.ExactInstanceMatches == 0 && v.IPv4Matches == 0
}

type WintunLifetimeProbeRound struct {
	Round           int                     `json:"round"`
	CreateCalled    bool                    `json:"create_called"`
	CreateReturned  bool                    `json:"create_returned"`
	CreatorVerified bool                    `json:"creator_verified"`
	CloseReturned   bool                    `json:"close_returned"`
	Before          WintunLifetimeProbeRead `json:"before"`
	After           WintunLifetimeProbeRead `json:"after"`
	CloseSettleMS   uint32                  `json:"close_settle_ms"`
	Code            string                  `json:"code"`
}
type WintunLifetimeProbeReport struct {
	Schema          int    `json:"schema"`
	ObservationOnly bool   `json:"observation_only"`
	HoldModule      bool   `json:"hold_module"`
	ProcessID       uint32 `json:"process_id"`
	ProcessCreation uint64 `json:"process_creation_filetime"`
	PinnedModules   int    `json:"pinned_modules"`
	Stage           string `json:"stage"`
	// Parent-only failed transport proof; never accepted as a child observation.
	TransportError string                     `json:"transport_error,omitempty"`
	Code           string                     `json:"code"`
	Rounds         []WintunLifetimeProbeRound `json:"rounds"`
}

func validLifecycleProbeNode(n nativeHostNode) bool {
	return n.Instance != "" && len(n.Instance) <= 1024 && !strings.ContainsAny(n.Instance, "*?\x00") && n.Instance == n.CMInstance && n.DevInst != 0 &&
		strings.EqualFold(n.SetupClass, hostNetClass) && strings.EqualFold(n.CMClass, hostNetClass) && n.ClassType == 13 && n.ClassSize == 16 &&
		n.ServiceType == 18 && n.ServiceSize == uint32((len(utf16.Encode([]rune(n.Service)))+1)*2) && strings.EqualFold(n.Service, "Wintun") &&
		n.DriverType == 18 && n.DriverSize == uint32((len(utf16.Encode([]rune(n.CMDriver)))+1)*2) && hostDriverKey.MatchString(n.SetupDriver) && n.SetupDriver == n.CMDriver &&
		strings.EqualFold(n.SetupNetGUID, wintun.LifecycleProbeGUID) && strings.EqualFold(n.CMNetGUID, wintun.LifecycleProbeGUID) && n.StateReadable && n.Problem == 0 && n.StateError == 0
}
