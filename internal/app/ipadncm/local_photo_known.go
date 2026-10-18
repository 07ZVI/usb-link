package ipadncm

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"strings"
)

const localPhotoKnownFile = "local-photo-known-v1.json"
const localPhotoKnownLimit = 65536

// Identities of MI_00 photo instances this program has itself isolated for an
// authorized iPad root. It is a memory of where to look, never a permission to
// write: every apply re-proves the exact instance from the device's own
// properties. Restoring a journal entry never removes its identity here; only
// uninstall retires the record, after a verified restoration.
type localPhotoKnown struct {
	Schema  int                        `json:"schema"`
	Entries []portablePropertyOriginal `json:"entries"`
}

func (k localPhotoKnown) valid() bool {
	return localPhotoJournal{Schema: k.Schema, Entries: k.Entries}.valid()
}
func decodeLocalPhotoKnown(b []byte) (localPhotoKnown, error) {
	var k localPhotoKnown
	d := json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	if len(b) > localPhotoKnownLimit || d.Decode(&k) != nil || d.Decode(new(any)) != io.EOF || !k.valid() {
		return k, errors.New("PHOTO_KNOWN_UNREADABLE")
	}
	return k, nil
}

// A new capture of a known instance replaces its record; the oldest identity
// is dropped at the bound, which only forfeits proactive isolation for it.
func (k localPhotoKnown) with(p portablePropertyOriginal) (localPhotoKnown, bool) {
	if !p.valid() || !localPhotoReceiptValid(p.Node) {
		return k, false
	}
	next := localPhotoKnown{Schema: 1, Entries: append([]portablePropertyOriginal(nil), k.Entries...)}
	for i, v := range next.Entries {
		if strings.EqualFold(v.Node.ID, p.Node.ID) {
			if v == p {
				return k, false
			}
			next.Entries[i] = p
			return next, true
		}
	}
	if len(next.Entries) >= 16 {
		next.Entries = next.Entries[1:]
	}
	next.Entries = append(next.Entries, p)
	return next, true
}

// The compatible-ID form without REV is always present for a USB interface.
func localPhotoHardwareMatch(ids []string) bool {
	for _, id := range ids {
		if strings.EqualFold(id, `USB\VID_05AC&PID_12AB&MI_00`) {
			return true
		}
	}
	return false
}

// A device that is not present has no CM state; ownership of its recorded
// property is proven from SetupDi and CM registry reads that must agree.
func localPhotoPhantomOriginal(n portableNodeReceipt, setup, registry portablePropertyReadback) (portablePropertyOriginal, error) {
	if !validPortableReceipt(n) || n.OriginalDisabled || n.ConfigFlags&1 != 0 || !setup.same(registry) || registry.Value != n.ConfigFlags {
		return portablePropertyOriginal{}, errors.New("PHOTO_ORIGINAL_UNPROVEN")
	}
	p := portablePropertyOriginal{Node: n, Present: registry.Present, Value: registry.Value}
	if p.Present {
		p.Type, p.Size = 7, 4
	}
	if !p.valid() {
		return p, errors.New("PHOTO_ORIGINAL_UNPROVEN")
	}
	return p, nil
}

// Identity facts read from the exact instance itself, present or not.
type localPhotoProbe struct {
	Registered, Present                      bool
	Instance, Class, Root, Service, Hardware bool
	Setup, Registry                          portablePropertyReadback
	Problem                                  uint32
	Original                                 *portablePropertyOriginal
}

const (
	knownSkip     = "skip"
	knownVerified = "verified"
	knownApply    = "apply"
	knownReject   = "reject"
)

type localPhotoKnownPlan struct {
	Kind, Code string
	Original   portablePropertyOriginal
	Journal    bool
}

func sameLocalPhotoInstance(a, b portableNodeReceipt) bool {
	return strings.EqualFold(a.Root, b.Root) && strings.EqualFold(a.ID, b.ID) && strings.EqualFold(a.Class, b.Class)
}

// Decide without touching anything. Anything not exactly proven is rejected
// untouched; an instance the user disabled (not journaled by us) is skipped.
func planLocalPhotoKnown(k portablePropertyOriginal, p localPhotoProbe, j *portablePropertyOriginal) localPhotoKnownPlan {
	reject := func(code string) localPhotoKnownPlan { return localPhotoKnownPlan{Kind: knownReject, Code: code} }
	if !k.valid() || !localPhotoReceiptValid(k.Node) {
		return reject("PHOTO_RECEIPT_INVALID")
	}
	if !p.Registered {
		return localPhotoKnownPlan{Kind: knownSkip}
	}
	if !p.Instance || !p.Class || !p.Root || !p.Service || !p.Hardware || !p.Setup.same(p.Registry) {
		return reject("PHOTO_KNOWN_IDENTITY_MISMATCH")
	}
	if j != nil && (!j.valid() || !sameLocalPhotoInstance(j.Node, k.Node)) {
		return reject("PHOTO_KNOWN_IDENTITY_MISMATCH")
	}
	cur := p.Registry
	if cur.Value&1 != 0 {
		if j == nil {
			return localPhotoKnownPlan{Kind: knownSkip}
		}
		if !cur.Present || cur.Value != j.Value|1 {
			return reject("PHOTO_ORIGINAL_CHANGED")
		}
		if p.Present && p.Problem != 22 {
			return localPhotoKnownPlan{Kind: knownApply, Original: *j}
		}
		return localPhotoKnownPlan{Kind: knownVerified}
	}
	if j != nil {
		if cur.Value != j.Value {
			return reject("PHOTO_ORIGINAL_CHANGED")
		}
		return localPhotoKnownPlan{Kind: knownApply, Original: *j}
	}
	o := p.Original
	if o == nil || !o.valid() || !sameLocalPhotoInstance(o.Node, k.Node) || o.Value != cur.Value || o.Present != cur.Present {
		return reject("PHOTO_ORIGINAL_UNPROVEN")
	}
	return localPhotoKnownPlan{Kind: knownApply, Original: *o, Journal: true}
}

// A journaled node may already carry the persisted disabled bit while its live
// state has not caught up (the write landed while it was absent or racing).
func localPhotoDisableReady(s PortableNodeObservation, p portablePropertyOriginal) bool {
	if s.proofError(p.Value) != nil || s.Problem != 0 || s.Status&8 == 0 {
		return false
	}
	return s.ConfigFlags == p.Value|1 || s.ConfigFlags == p.Value && s.FlagsAbsent != p.Present
}
