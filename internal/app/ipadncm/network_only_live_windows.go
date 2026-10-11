//go:build windows && amd64

package ipadncm

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"strings"
	"suhang/usbnet/internal/platform/windows/netconfig"
	"time"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"
)

// This explicit diagnostic is never called by UI refresh or the packet path.
// It observes the service and exact current/owned nodes; it cannot start/stop
// services, change a node, create a receipt, or import authorization evidence.
type NetworkOnlyLiveReadback struct {
	FreshDescriptorReadback USBDescriptorRecheckDiagnostic   `json:"fresh_descriptor_readback_not_authorization"`
	DescriptorRechecks      []USBDescriptorRecheckDiagnostic `json:"application_descriptor_rechecks_not_authorization"`

	PropertyRestorations             []PortablePropertyRestoreSummary        `json:"portable_property_restorations"`
	PropertyAuditError               string                                  `json:"portable_property_audit_error,omitempty"`
	Schema                           int                                     `json:"schema"`
	ObservedUTC                      string                                  `json:"observed_utc"`
	CachedPolicy                     NetworkOnlyStatus                       `json:"cached_policy_not_live_proof"`
	AMDS                             networkOnlyServiceReadback              `json:"amds_live"`
	ReceiptPresent                   bool                                    `json:"owned_receipt_present"`
	ReceiptValid                     bool                                    `json:"owned_receipt_valid"`
	PersistentProductConfigured      bool                                    `json:"persistent_product_configured_not_native_proof"`
	ProtectedProductOwnerPresent     bool                                    `json:"protected_product_owner_present"`
	ProtectedProductOwnerValid       bool                                    `json:"protected_product_owner_valid"`
	PersistentOriginalReceiptVersion int                                     `json:"original_receipt_schema"`
	LegacyVersionRestoreBlocked      bool                                    `json:"old_version_receipt_restore_blocked"`
	TargetDescriptor                 *Device                                 `json:"current_usb_descriptor,omitempty"`
	PortableNodes                    []networkOnlyPortableReadback           `json:"portable_nodes"`
	History                          []PortableNodeOperationDiagnostic       `json:"operation_history_not_live_proof"`
	Phases                           []NetworkOnlyPhaseDiagnostic            `json:"ensure_phase_observations_not_continuous_isolation_proof"`
	PhaseCapture                     NetworkOnlyPhaseCaptureState            `json:"ensure_phase_capture"`
	CoreRuleReadback                 netconfig.CorePermissionReadbackSummary `json:"core_permissions_this_parent_process_not_bridge"`
	Error                            string                                  `json:"readback_error,omitempty"`
	OriginalPresenceScope            string                                  `json:"original_config_flags_presence_scope"`
}

type networkOnlyServiceReadback struct {
	Readable          bool   `json:"readable"`
	State             uint32 `json:"state"`
	StartType         uint32 `json:"start_type"`
	OriginalState     uint32 `json:"receipt_original_state,omitempty"`
	OriginalStartType uint32 `json:"receipt_original_start_type,omitempty"`
	MatchesReceipt    bool   `json:"matches_receipt_original_values"`
	Stopped           bool   `json:"currently_stopped"`
	Error             string `json:"read_error,omitempty"`
}

type networkOnlyPortableReadback struct {
	NodeDigest       string                  `json:"node_id_sha256"`
	Prefix           string                  `json:"node_id_prefix"`
	Class            string                  `json:"class_guid"`
	ReceiptOriginal  bool                    `json:"values_from_owned_receipt"`
	OriginalDisabled bool                    `json:"original_disabled"`
	OriginalFlags    uint32                  `json:"original_config_flags_value"`
	Current          PortableNodeObservation `json:"current_native_observation"`
}

func NetworkOnlyLiveDiagnostics() NetworkOnlyLiveReadback {
	d := NetworkOnlyLiveReadback{
		Schema: 1, ObservedUTC: time.Now().UTC().Format(time.RFC3339Nano),
		CachedPolicy: NetworkOnlySnapshot(), History: NetworkOnlyOperationDiagnostics(),
		Phases:                NetworkOnlyPhaseDiagnostics(),
		PhaseCapture:          NetworkOnlyPhaseCaptureStatus(),
		CoreRuleReadback:      netconfig.CorePermissionReadbackStats(),
		OriginalPresenceScope: "v1 restores recorded ConfigFlags value with original_presence_unknown; new protected before-disable metadata verifies original presence separately",
	}
	networkOnly.Lock()
	dir := networkOnly.dir
	networkOnly.Unlock()
	if dir == "" {
		d.Error = "NETWORK_ONLY_STORE_NOT_INITIALIZED"
		return d
	}
	audit, durable, auditErr := readPortableLegacyAudit(dir)
	if auditErr != nil {
		d.PropertyAuditError = "PROTECTED_PORTABLE_RESTORE_AUDIT_UNREADABLE"
	} else {
		d.PropertyRestorations = portableRestoreSummaries(audit, durable)
	}
	r, err := readNetworkOnlyReceipt(dir)
	d.ReceiptPresent = !os.IsNotExist(err)
	d.ReceiptValid = err == nil
	d.PersistentProductConfigured = UnpairedNetworkOnlyProductConfigured()
	o, oe := readUnpairedProductOwner(dir)
	d.ProtectedProductOwnerPresent, d.ProtectedProductOwnerValid = !os.IsNotExist(oe), oe == nil && o.valid()
	if err == nil {
		d.PersistentOriginalReceiptVersion = r.Version
		d.LegacyVersionRestoreBlocked = r.Version == 2 && r.PersistentUSBOwner
	}
	if oe != nil && !os.IsNotExist(oe) {
		d.Error = "PROTECTED_PRODUCT_OWNER_UNREADABLE"
	}
	if err != nil && !os.IsNotExist(err) {
		d.Error = "OWNED_NETWORK_ONLY_RECEIPT_UNREADABLE"
	}
	m, err := mgr.Connect()
	if err != nil {
		d.AMDS.Error = "SERVICE_MANAGER_UNAVAILABLE"
	} else {
		defer m.Disconnect()
		s, err := m.OpenService("Apple Mobile Device Service")
		if err != nil {
			d.AMDS.Error = "AMDS_SERVICE_UNAVAILABLE"
		} else {
			defer s.Close()
			state, se := s.Query()
			cfg, ce := s.Config()
			if se != nil || ce != nil {
				d.AMDS.Error = "AMDS_STATE_OR_CONFIG_UNREADABLE"
			} else {
				d.AMDS.Readable, d.AMDS.State, d.AMDS.StartType = true, uint32(state.State), cfg.StartType
				d.AMDS.Stopped = state.State == svc.Stopped
				if d.ReceiptValid {
					d.AMDS.OriginalState, d.AMDS.OriginalStartType = r.ServiceState, r.StartType
					d.AMDS.MatchesReceipt = d.AMDS.State == r.ServiceState && cfg.StartType == r.StartType
				}
			}
		}
	}
	// Full fresh inventory is deliberate and only on this authenticated request.
	// The private serial/root/hub fields are never serialized.
	started := time.Now()
	snapshot := Inspect()
	d.FreshDescriptorReadback = descriptorRecheckSummary("explicit_readonly", Snapshot{}, snapshot)
	d.FreshDescriptorReadback.QueryDurationMS = time.Since(started).Milliseconds()
	d.DescriptorRechecks = USBDescriptorRecheckDiagnostics()
	if len(snapshot.Devices) == 1 {
		device := snapshot.Devices[0]
		d.TargetDescriptor = &device
	}
	currentVerified := networkOnlyUSBEligible(snapshot)
	if !currentVerified {
		if d.Error == "" {
			d.Error = "CURRENT_DESCRIPTOR_TARGET_UNPROVEN_OR_ABSENT"
		}
		if !d.ReceiptValid || !d.ProtectedProductOwnerValid {
			return d
		}
	}
	root := exactIPadRoot(snapshot)
	if !currentVerified {
		root = o.Root
	}
	nodes := r.Nodes
	fromReceipt := d.ReceiptValid
	if !fromReceipt {
		if d.ReceiptPresent {
			return d
		}
		var err error
		nodes, err = portableNodes(root)
		if err != nil {
			d.Error = "CURRENT_PORTABLE_NODE_ENUMERATION_UNREADABLE"
			return d
		}
	}
	if len(nodes) > 64 {
		d.Error = "OWNED_PORTABLE_NODE_LIMIT"
		return d
	}
	set, err := windows.SetupDiGetClassDevsEx(nil, "", 0, windows.DIGCF_ALLCLASSES, 0, "")
	if err != nil {
		d.Error = "PORTABLE_READBACK_SET_UNAVAILABLE"
		return d
	}
	defer set.Close()
	for _, n := range nodes {
		if !validPortableReceipt(n) || !strings.EqualFold(n.Root, root) {
			d.Error = "CURRENT_DESCRIPTOR_TARGET_DIFFERS_FROM_OWNED_RECEIPT"
			return d
		}
		hash := sha256.Sum256([]byte("USB Link portable observation\x00" + n.ID))
		x := networkOnlyPortableReadback{NodeDigest: hex.EncodeToString(hash[:]), Prefix: portableNodePrefix(n.ID), Class: n.Class, ReceiptOriginal: fromReceipt, OriginalDisabled: n.OriginalDisabled, OriginalFlags: n.ConfigFlags}
		x.Current.Error = "EXACT_PORTABLE_INSTANCE_NOT_FOUND"
		for index := 0; index < 4096; index++ {
			info, err := set.EnumDeviceInfo(index)
			if err == windows.ERROR_NO_MORE_ITEMS {
				break
			}
			if err != nil {
				x.Current.Error = "PORTABLE_READBACK_ENUMERATION_FAILED"
				break
			}
			id, err := set.DeviceInstanceID(info)
			if err != nil {
				x.Current.Error = "PORTABLE_READBACK_INSTANCE_UNREADABLE"
				break
			}
			if strings.EqualFold(id, n.ID) {
				x.Current = portableNativeObservation(info.DevInst, n)
				break
			}
		}
		d.PortableNodes = append(d.PortableNodes, x)
	}
	return d
}
