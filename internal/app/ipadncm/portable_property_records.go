package ipadncm

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"strings"
)

const portablePropertyRecordLimit = 262144

type portableOriginalStore struct {
	Version int                        `json:"version"`
	Records []portablePropertyOriginal `json:"records"`
}

type portableLegacyValueAudit struct {
	Node                     portableNodeReceipt      `json:"node"`
	OriginalPresenceUnknown  bool                     `json:"original_presence_unknown"`
	OriginalPresencePresent  bool                     `json:"original_presence_present"`
	OriginalPresenceVerified bool                     `json:"original_presence_verified"`
	Phantom                  bool                     `json:"phantom"`
	Before                   portablePropertyReadback `json:"before"`
	After                    portablePropertyReadback `json:"after"`
	ValueReadbackVerified    bool                     `json:"recorded_original_value_verified"`
}
type portableLegacyAuditStore struct {
	Version int                        `json:"version"`
	Records []portableLegacyValueAudit `json:"records"`
}

func decodePortableOriginalStore(b []byte) (portableOriginalStore, error) {
	var s portableOriginalStore
	d := json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	var tail any
	if len(b) > portablePropertyRecordLimit || d.Decode(&s) != nil || d.Decode(&tail) != io.EOF || s.Version != 1 || len(s.Records) > 64 {
		return s, fmt.Errorf("portable property original store invalid")
	}
	seen := map[string]bool{}
	for _, p := range s.Records {
		k := strings.ToUpper(p.Node.ID)
		if !p.valid() || seen[k] {
			return s, fmt.Errorf("portable property original record invalid")
		}
		seen[k] = true
	}
	return s, nil
}
func (a portableLegacyValueAudit) valid() bool {
	if !validPortableReceipt(a.Node) || a.Node.OriginalDisabled || !a.Before.valid() || a.Before.Value != a.Node.ConfigFlags && a.Before.Value != a.Node.ConfigFlags|1 {
		return false
	}
	if a.OriginalPresenceUnknown && (a.OriginalPresenceVerified || a.OriginalPresencePresent) {
		return false
	}
	if a.OriginalPresenceVerified && (!a.ValueReadbackVerified || a.After.Present != a.OriginalPresencePresent) {
		return false
	}
	if a.ValueReadbackVerified && (!a.After.valid() || a.After.Value != a.Node.ConfigFlags) {
		return false
	}
	if !a.ValueReadbackVerified && (a.After != portablePropertyReadback{} || a.OriginalPresenceVerified) {
		return false
	}
	return true
}
func decodePortableLegacyAudit(b []byte) (portableLegacyAuditStore, error) {
	var s portableLegacyAuditStore
	d := json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	var tail any
	if len(b) > portablePropertyRecordLimit || d.Decode(&s) != nil || d.Decode(&tail) != io.EOF || s.Version != 1 || len(s.Records) > 64 {
		return s, fmt.Errorf("portable restoration audit store invalid")
	}

	seen := map[string]bool{}
	baseline := map[string]portableNodeReceipt{}
	for _, a := range s.Records {
		id := strings.ToUpper(a.Node.ID)
		key := fmt.Sprintf("%s\x00%t", id, a.OriginalPresenceUnknown)
		if !a.valid() || seen[key] {
			return s, fmt.Errorf("portable restoration audit record invalid")
		}
		if old, ok := baseline[id]; ok && !samePortableReceipt(old, a.Node) {
			return s, fmt.Errorf("portable restoration audit baseline changed")
		}
		seen[key] = true
		baseline[id] = a.Node
	}
	return s, nil
}

// Explicit whitelist; protected raw identities never enter the diagnostic.
type PortablePropertyRestoreSummary struct {
	NodeDigest               string                   `json:"node_id_sha256"`
	Class                    string                   `json:"class_guid"`
	OriginalFlags            uint32                   `json:"recorded_original_config_flags"`
	Before                   portablePropertyReadback `json:"before"`
	After                    portablePropertyReadback `json:"after"`
	OriginalPresenceUnknown  bool                     `json:"original_presence_unknown"`
	OriginalPresencePresent  bool                     `json:"original_presence_present"`
	OriginalPresenceVerified bool                     `json:"original_presence_verified"`
	RecordedValueVerified    bool                     `json:"recorded_original_value_verified"`
	Phantom                  bool                     `json:"phantom_property_restore"`
	DurableAuditVerified     bool                     `json:"protected_audit_readback_verified"`
}

func portableRestoreSummaries(s portableLegacyAuditStore, durable bool) []PortablePropertyRestoreSummary {
	result := make([]PortablePropertyRestoreSummary, 0, len(s.Records))
	for _, a := range s.Records {
		result = append(result, PortablePropertyRestoreSummary{NodeDigest: portableNodeDigest(a.Node), Class: a.Node.Class, OriginalFlags: a.Node.ConfigFlags, Before: a.Before, After: a.After, OriginalPresenceUnknown: a.OriginalPresenceUnknown, OriginalPresencePresent: a.OriginalPresencePresent, OriginalPresenceVerified: a.OriginalPresenceVerified, RecordedValueVerified: a.ValueReadbackVerified, Phantom: a.Phantom, DurableAuditVerified: durable})
	}
	return result
}

func portableOriginalForReceipt(s portableOriginalStore, n portableNodeReceipt) (*portablePropertyOriginal, error) {
	for _, p := range s.Records {
		if strings.EqualFold(p.Node.ID, n.ID) {
			if !samePortableReceipt(p.Node, n) {
				return nil, fmt.Errorf("portable original receipt identity changed")
			}
			q := p
			return &q, nil
		}
	}
	return nil, nil
}

func upsertPortableRestoreAudit(s portableLegacyAuditStore, a portableLegacyValueAudit) (portableLegacyAuditStore, error) {
	if !a.valid() {
		return s, fmt.Errorf("portable restoration audit invalid")
	}
	found := false
	for i, old := range s.Records {
		if strings.EqualFold(old.Node.ID, a.Node.ID) {
			if !samePortableReceipt(old.Node, a.Node) {
				return s, fmt.Errorf("portable restoration audit target changed")
			}
			if old.OriginalPresenceUnknown == a.OriginalPresenceUnknown {
				s.Records[i] = a
				found = true
			}
		}
	}
	if !found {
		if len(s.Records) >= 64 {
			return s, fmt.Errorf("portable restoration audit limit")
		}
		s.Records = append(s.Records, a)
	}
	return s, nil
}
