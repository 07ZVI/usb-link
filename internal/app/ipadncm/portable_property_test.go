package ipadncm

import (
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"
)

func phantomFixtureNode() portableNodeReceipt {
	return portableNodeReceipt{Root: `USB\VID_05AC&PID_12AB\TEST-ROOT`, ID: `USB\VID_05AC&PID_12AB&MI_00\OWNED-EXACT`, Class: portableWPDClass}
}
func propertyDWORD(v uint32) portablePropertyReadback {
	return portablePropertyReadback{Readable: true, Present: true, Type: 4, Size: 4, Value: v}
}
func phantomFixtureProof(v uint32) portablePhantomProof {
	return portablePhantomProof{Unique: true, Instance: true, Class: true, Root: true, PresenceReadable: true, Absent: true, StateCR: 13, Setup: propertyDWORD(v), Registry: propertyDWORD(v)}
}
func TestPhantomOwnershipFaultMatrix(t *testing.T) {
	cases := []struct {
		name string
		bad  func(*portablePhantomProof)
	}{
		{"duplicate", func(p *portablePhantomProof) { p.Unique = false }},
		{"differentCurrentMI00", func(p *portablePhantomProof) { p.Instance = false }},
		{"classChanged", func(p *portablePhantomProof) { p.Class = false }},
		{"rootChanged", func(p *portablePhantomProof) { p.Root = false }},
		{"incompletePresentEnumeration", func(p *portablePhantomProof) { p.PresenceReadable = false }},
		{"present", func(p *portablePhantomProof) { p.Absent = false }},
		{"nativeStateUnavailable", func(p *portablePhantomProof) { p.StateCR = 5 }},
		{"nativePresentState", func(p *portablePhantomProof) { p.StateCR = 0 }},
		{"registryUnreadable", func(p *portablePhantomProof) { p.Registry.Readable = false }},
		{"registryWrongType", func(p *portablePhantomProof) { p.Registry.Type = 11 }},
		{"registryWrongSize", func(p *portablePhantomProof) { p.Registry.Size = 8 }},
		{"differentIndependentProperties", func(p *portablePhantomProof) { p.Registry.Value = 0 }},
		{"foreignFlags", func(p *portablePhantomProof) { p.Registry.Value = 3; p.Setup.Value = 3 }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := phantomFixtureProof(1)
			tc.bad(&p)
			writes, audits := 0, 0
			_, e := restoreOwnedPhantomProperty(phantomFixtureNode(), nil, func() (portablePhantomProof, error) { return p, nil }, func(*portablePropertyOriginal) error { writes++; return nil }, func(portablePhantomProof, portablePhantomProof, bool) error { audits++; return nil })
			if e == nil || writes != 0 || audits != 0 {
				t.Fatalf("unsafe rejection: error=%v writes=%d audits=%d", e, writes, audits)
			}
		})
	}
}
func TestPhantomRestoreAuditBeforeCheckpointAndCrashRetry(t *testing.T) {
	for _, name := range []string{"legacyDWORD", "legacyAbsentAlreadyOriginal", "legacyWindowsNormalizesAbsent", "knownAbsent", "knownPresent", "alreadyRestoredDWORD"} {
		t.Run(name, func(t *testing.T) {
			n := phantomFixtureNode()
			p := phantomFixtureProof(1)
			var original *portablePropertyOriginal
			switch name {
			case "legacyAbsentAlreadyOriginal":
				p.Setup, p.Registry = portablePropertyReadback{Readable: true}, portablePropertyReadback{Readable: true}
			case "alreadyRestoredDWORD":
				p = phantomFixtureProof(0)
			case "knownAbsent":
				original = &portablePropertyOriginal{Node: n}
			case "knownPresent":
				original = &portablePropertyOriginal{Node: n, Present: true, Type: 7, Size: 4}
			}
			var order []string
			writes := 0
			_, e := restoreOwnedPhantomProperty(n, original, func() (portablePhantomProof, error) { order = append(order, "read"); return p, nil }, func(target *portablePropertyOriginal) error {
				order = append(order, "write")
				writes++
				if target.Node != n || target.Value != 0 {
					t.Fatal("wrong exact write target")
				}
				value := propertyDWORD(0)
				if !target.Present || name == "legacyWindowsNormalizesAbsent" {
					value = portablePropertyReadback{Readable: true}
				}
				p.Setup, p.Registry = value, value
				return nil
			}, func(before, after portablePhantomProof, verified bool) error {
				if verified {
					order = append(order, "auditVerified")
					if after.Registry.Value != 0 {
						t.Fatal("audit before valid readback")
					}
				} else {
					order = append(order, "auditPending")
				}
				return nil
			})
			if e != nil {
				t.Fatal(e)
			}
			expected := []string{"read", "auditPending", "write", "read", "auditVerified"}
			if strings.Contains(name, "Already") || name == "alreadyRestoredDWORD" {
				expected = []string{"read", "auditPending", "read", "auditVerified"}
				if writes != 0 {
					t.Fatal("changed original presence on value-only retry")
				}
			}
			if !reflect.DeepEqual(order, expected) {
				t.Fatalf("order %v", order)
			}
		})
	}
}
func TestPhantomRestoreFailuresRetainObligation(t *testing.T) {
	for _, fault := range []string{"pendingAudit", "writeAPI", "afterIdentity", "afterProperty", "verifiedAudit", "checkpoint"} {
		t.Run(fault, func(t *testing.T) {
			n := phantomFixtureNode()
			p := phantomFixtureProof(1)
			reads, writes, checkpoint := 0, 0, 0
			restore := func(portableNodeReceipt) error {
				_, e := restoreOwnedPhantomProperty(n, nil, func() (portablePhantomProof, error) {
					reads++
					if reads > 1 && fault == "afterIdentity" {
						p.Root = false
					}
					if reads > 1 && fault == "afterProperty" {
						p.Setup, p.Registry = propertyDWORD(1), propertyDWORD(1)
					}
					return p, nil
				}, func(*portablePropertyOriginal) error {
					writes++
					if fault == "writeAPI" {
						return errors.New("write failed")
					}
					p.Setup, p.Registry = propertyDWORD(0), propertyDWORD(0)
					return nil
				}, func(_, after portablePhantomProof, verified bool) error {
					if !verified && fault == "pendingAudit" || verified && fault == "verifiedAudit" {
						return errors.New("durable audit failed")
					}
					return nil
				})
				return e
			}
			e := restorePortableNodeReceipts([]portableNodeReceipt{n}, restore, func([]portableNodeReceipt) error {
				checkpoint++
				if fault == "checkpoint" {
					return errors.New("checkpoint failed")
				}
				return nil
			})
			if e == nil {
				t.Fatal("claimed recovery on failed proof/audit/checkpoint")
			}
			if fault == "pendingAudit" && writes != 0 {
				t.Fatal("wrote before audit")
			}
			if fault != "checkpoint" && checkpoint != 0 {
				t.Fatal("pruned unverified obligation")
			}
		})
	}
}
func TestOriginalPresenceCaptureCannotUseLegacyDisabledOrCurrentCache(t *testing.T) {
	n := phantomFixtureNode()
	s := PortableNodeObservation{InstanceMatches: true, ClassMatches: true, RootMatches: true, StateReadable: true, FlagsReadable: true, Status: 8, FlagsType: 7, FlagsSize: 4}
	cases := []struct {
		name   string
		modify func(*portableNodeReceipt, *PortableNodeObservation, *portablePropertyReadback)
	}{
		{"alreadyDisabled", func(_ *portableNodeReceipt, s *PortableNodeObservation, r *portablePropertyReadback) {
			s.ConfigFlags = 1
			r.Value = 1
		}},
		{"originallyDisabled", func(n *portableNodeReceipt, _ *PortableNodeObservation, _ *portablePropertyReadback) {
			n.OriginalDisabled = true
			n.ConfigFlags = 1
		}},
		{"cachedOnly", func(_ *portableNodeReceipt, s *PortableNodeObservation, _ *portablePropertyReadback) {
			s.StateReadable = false
		}},
		{"foreignRoot", func(_ *portableNodeReceipt, s *PortableNodeObservation, _ *portablePropertyReadback) {
			s.RootMatches = false
		}},
		{"serviceLikeProblem", func(_ *portableNodeReceipt, s *PortableNodeObservation, _ *portablePropertyReadback) { s.Problem = 22 }},
		{"notStarted", func(_ *portableNodeReceipt, s *PortableNodeObservation, _ *portablePropertyReadback) { s.Status = 0 }},
		{"pendingRemoval", func(_ *portableNodeReceipt, s *PortableNodeObservation, _ *portablePropertyReadback) {
			s.Status |= 0x40000
		}},
		{"wrongPresence", func(_ *portableNodeReceipt, s *PortableNodeObservation, _ *portablePropertyReadback) {
			s.FlagsAbsent = true
		}},
		{"wrongCMType", func(_ *portableNodeReceipt, s *PortableNodeObservation, _ *portablePropertyReadback) {
			s.FlagsType = 11
		}},
	}
	if _, e := portableOriginalBeforeDisable(n, s, propertyDWORD(0), propertyDWORD(0)); e != nil {
		t.Fatal(e)
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			nn, ss, rr := n, s, propertyDWORD(0)
			tc.modify(&nn, &ss, &rr)
			if _, e := portableOriginalBeforeDisable(nn, ss, rr, rr); e == nil {
				t.Fatal("captured fabricated original presence")
			}
		})
	}
	s.FlagsAbsent = true
	s.FlagsType, s.FlagsSize = 0, 0
	absent := portablePropertyReadback{Readable: true}
	p, e := portableOriginalBeforeDisable(n, s, absent, absent)
	if e != nil || p.Present || !p.valid() {
		t.Fatalf("actual before absence: %v %+v", e, p)
	}
}
func TestSidecarAndAuditStrictFormatAndDiagnosticPrivacy(t *testing.T) {
	n := phantomFixtureNode()
	valid := portableOriginalStore{Version: 1, Records: []portablePropertyOriginal{{Node: n, Present: true, Type: 7, Size: 4}}}
	for _, name := range []string{"valid", "corrupt", "version", "duplicate", "wrongValue", "wrongType", "absentNonzero", "unknownField", "trailing"} {
		t.Run(name, func(t *testing.T) {
			s := valid
			s.Records = append([]portablePropertyOriginal(nil), valid.Records...)
			switch name {
			case "version":
				s.Version = 2
			case "duplicate":
				s.Records = append(s.Records, s.Records[0])
			case "wrongValue":
				s.Records[0].Value = 1
			case "wrongType":
				s.Records[0].Type = 4
			case "absentNonzero":
				s.Records[0].Present = false
			}
			b, _ := json.Marshal(s)
			switch name {
			case "corrupt":
				b = []byte("{")
			case "unknownField":
				b = append(b[:len(b)-1], []byte(",\"untrusted\":true}")...)
			case "trailing":
				b = append(b, []byte(" {}")...)
			}
			_, e := decodePortableOriginalStore(b)
			if (e == nil) != (name == "valid") {
				t.Fatalf("%s: %v", name, e)
			}
		})
	}
	audit := portableLegacyValueAudit{Node: n, OriginalPresenceUnknown: true, Phantom: true, Before: propertyDWORD(1), After: portablePropertyReadback{Readable: true}, ValueReadbackVerified: true}
	store := portableLegacyAuditStore{Version: 1, Records: []portableLegacyValueAudit{audit}}
	b, _ := json.Marshal(store)
	parsed, e := decodePortableLegacyAudit(b)
	if e != nil {
		t.Fatal(e)
	}
	summaries := portableRestoreSummaries(parsed, true)
	out, _ := json.Marshal(summaries)
	for _, secret := range []string{n.ID, n.Root, "OWNED-EXACT", "TEST-ROOT", "node_id_prefix", "registry_path"} {
		if strings.Contains(string(out), secret) {
			t.Fatalf("leaked %s", secret)
		}
	}
	if len(summaries) != 1 || !summaries[0].OriginalPresenceUnknown || summaries[0].OriginalPresenceVerified || !summaries[0].DurableAuditVerified {
		t.Fatalf("false full restoration: %s", out)
	}
	audit.OriginalPresenceVerified = true
	if audit.valid() {
		t.Fatal("unknown audit claims original presence")
	}
}

func TestSidecarMustBelongToExactReceipt(t *testing.T) {
	n := phantomFixtureNode()
	p := portablePropertyOriginal{Node: n, Present: true, Type: 7, Size: 4}
	store := portableOriginalStore{Version: 1, Records: []portablePropertyOriginal{p}}
	for _, name := range []string{"root", "class", "originalFlags", "originalDisabled"} {
		t.Run(name, func(t *testing.T) {
			target := n
			switch name {
			case "root":
				target.Root += "OTHER"
			case "class":
				target.Class = portableImageClass
			case "originalFlags":
				target.ConfigFlags = 2
			case "originalDisabled":
				target.OriginalDisabled = true
			}
			if _, e := portableOriginalForReceipt(store, target); e == nil {
				t.Fatal("foreign sidecar accepted")
			}
		})
	}
	absent := n
	absent.ID += "-different-current"
	original, e := portableOriginalForReceipt(store, absent)
	if e != nil || original != nil {
		t.Fatal("replaced exact old node with current node")
	}
	changed := p
	changed.Present = false
	changed.Type, changed.Size = 0, 0
	proof := phantomFixtureProof(1)
	_, e = restoreOwnedPhantomProperty(n, &changed, func() (portablePhantomProof, error) { return proof, nil }, func(target *portablePropertyOriginal) error {
		proof.Setup, proof.Registry = propertyDWORD(0), propertyDWORD(0)
		return nil
	}, func(portablePhantomProof, portablePhantomProof, bool) error { return nil })
	if e == nil {
		t.Fatal("known original absence accepted present DWORD0 readback")
	}
}

func TestLaterKnownPresenceCannotOverwriteLegacyUnknownAudit(t *testing.T) {
	n := phantomFixtureNode()
	legacy := portableLegacyValueAudit{Node: n, OriginalPresenceUnknown: true, Phantom: true, Before: propertyDWORD(1), After: propertyDWORD(0), ValueReadbackVerified: true}
	s := portableLegacyAuditStore{Version: 1}
	var e error
	s, e = upsertPortableRestoreAudit(s, legacy)
	if e != nil {
		t.Fatal(e)
	}
	known := legacy
	known.OriginalPresenceUnknown = false
	known.OriginalPresencePresent = true
	known.OriginalPresenceVerified = true
	s, e = upsertPortableRestoreAudit(s, known)
	if e != nil {
		t.Fatal(e)
	}
	if len(s.Records) != 2 || s.Records[0] != legacy {
		t.Fatal("overwrote legacy unknown original-presence evidence")
	}
	b, _ := json.Marshal(s)
	s, e = decodePortableLegacyAudit(b)
	if e != nil {
		t.Fatal(e)
	}
	known.Before = propertyDWORD(0)
	s, e = upsertPortableRestoreAudit(s, known)
	if e != nil || len(s.Records) != 2 || s.Records[0] != legacy {
		t.Fatal("same-category update replaced legacy proof")
	}
	other := known
	other.Node.ConfigFlags = 2
	other.Before, other.After = propertyDWORD(2), propertyDWORD(2)
	if _, e = upsertPortableRestoreAudit(s, other); e == nil {
		t.Fatal("changed baseline replaced old audit")
	}
	duplicate := s
	duplicate.Records = append(append([]portableLegacyValueAudit(nil), s.Records...), legacy)
	b, _ = json.Marshal(duplicate)
	if _, e = decodePortableLegacyAudit(b); e == nil {
		t.Fatal("duplicate same-category audit accepted")
	}
	oversized := portableLegacyAuditStore{Version: 1}
	for i := 0; i < 65; i++ {
		entry := legacy
		entry.Node.ID += strings.Repeat("X", i)
		oversized.Records = append(oversized.Records, entry)
	}
	b, _ = json.Marshal(oversized)
	if _, e = decodePortableLegacyAudit(b); e == nil {
		t.Fatal("unbounded audit accepted")
	}
}
