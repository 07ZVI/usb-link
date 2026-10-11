package ipadncm

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
)

type portablePropertyOriginal struct {
	Node    portableNodeReceipt `json:"node"`
	Present bool                `json:"original_property_present"`
	Type    uint32              `json:"original_cm_property_type"`
	Size    uint32              `json:"original_property_size"`
	Value   uint32              `json:"original_property_value"`
}

func (p portablePropertyOriginal) valid() bool {
	return validPortableReceipt(p.Node) && !p.Node.OriginalDisabled && p.Value == p.Node.ConfigFlags &&
		(p.Present && p.Type == 7 && p.Size == 4 || !p.Present && p.Type == 0 && p.Size == 0 && p.Value == 0)
}

func samePortableReceipt(a, b portableNodeReceipt) bool {
	return strings.EqualFold(a.Root, b.Root) && strings.EqualFold(a.ID, b.ID) && strings.EqualFold(a.Class, b.Class) && a.ConfigFlags == b.ConfigFlags && a.OriginalDisabled == b.OriginalDisabled
}

type portablePropertyReadback struct {
	Readable bool   `json:"readable"`
	Present  bool   `json:"present"`
	Type     uint32 `json:"registry_type"`
	Size     uint32 `json:"bytes"`
	Value    uint32 `json:"value"`
}

func (p portablePropertyReadback) valid() bool {
	return p.Readable && (p.Present && p.Type == 4 && p.Size == 4 || !p.Present && p.Type == 0 && p.Size == 0 && p.Value == 0)
}
func (p portablePropertyReadback) same(q portablePropertyReadback) bool {
	return p.valid() && q.valid() && p == q
}
func (p portablePropertyReadback) original(q portablePropertyOriginal) bool {
	return q.valid() && p.valid() && p.Present == q.Present && p.Value == q.Value
}

type portablePhantomProof struct {
	Unique, Instance, Class, Root bool
	PresenceReadable, Absent      bool
	StateCR                       uint32
	Setup, Registry               portablePropertyReadback
}

func (p portablePhantomProof) owned(original uint32) error {
	if !p.Unique || !p.Instance || !p.Class || !p.Root || !p.PresenceReadable || !p.Absent || p.StateCR != 13 {
		return fmt.Errorf("portable phantom exact native ownership unproven")
	}
	if !p.Setup.same(p.Registry) {
		return fmt.Errorf("portable phantom independent property unreadable or inconsistent")
	}
	if p.Registry.Value != original && p.Registry.Value != original|1 {
		return fmt.Errorf("portable phantom property ownership changed")
	}
	return nil
}

func portableNodeDigest(n portableNodeReceipt) string {
	h := sha256.Sum256([]byte("USB Link portable observation\x00" + n.ID))
	return hex.EncodeToString(h[:])
}

// Capture is permitted before our first disable only. An already disabled
// legacy node can never manufacture evidence of its original presence.
func portableOriginalBeforeDisable(n portableNodeReceipt, observation PortableNodeObservation, setup, registry portablePropertyReadback) (portablePropertyOriginal, error) {
	if !validPortableReceipt(n) || n.OriginalDisabled || n.ConfigFlags&1 != 0 || observation.proofError(n.ConfigFlags) != nil || observation.ConfigFlags != n.ConfigFlags || observation.Problem != 0 || observation.Status&8 == 0 || observation.Status&0x40000 != 0 || !setup.same(registry) || registry.Value != n.ConfigFlags || observation.FlagsAbsent == registry.Present || !observation.FlagsAbsent && (observation.FlagsType != 7 || observation.FlagsSize != 4) {
		return portablePropertyOriginal{}, fmt.Errorf("portable original property capture unproven")
	}
	p := portablePropertyOriginal{Node: n, Present: registry.Present, Value: registry.Value}
	if p.Present {
		p.Type, p.Size = 7, 4
	}
	if !p.valid() {
		return p, fmt.Errorf("portable original property invalid")
	}
	return p, nil
}

// The native backend must reacquire exact ownership on every read and write.
// This ordering keeps an audit durable before allowing the v1 checkpoint.
func restoreOwnedPhantomProperty(n portableNodeReceipt, original *portablePropertyOriginal, read func() (portablePhantomProof, error), write func(*portablePropertyOriginal) error, audit func(portablePhantomProof, portablePhantomProof, bool) error) (portablePhantomProof, error) {
	var zero portablePhantomProof
	if !validPortableReceipt(n) || n.OriginalDisabled || n.ConfigFlags&1 != 0 {
		return zero, fmt.Errorf("portable phantom receipt invalid")
	}
	if original != nil && (!original.valid() || !samePortableReceipt(original.Node, n)) {
		return zero, fmt.Errorf("portable phantom original metadata changed")
	}
	before, err := read()
	if err != nil {
		return zero, err
	}
	if err = before.owned(n.ConfigFlags); err != nil {
		return zero, err
	}
	if err = audit(before, zero, false); err != nil {
		return zero, err
	}
	target := portablePropertyOriginal{Node: n, Present: true, Type: 7, Size: 4, Value: n.ConfigFlags}
	if original != nil {
		target = *original
	}
	if original == nil && before.Registry.Value != n.ConfigFlags || original != nil && !before.Registry.original(target) {
		if err = write(&target); err != nil {
			return zero, err
		}
	}
	after, err := read()
	if err != nil {
		return zero, err
	}
	if err = after.owned(n.ConfigFlags); err != nil {
		return zero, err
	}
	if original == nil && after.Registry.Value != n.ConfigFlags || original != nil && !after.Registry.original(target) {
		return zero, fmt.Errorf("portable phantom original property not independently read back")
	}
	if err = audit(before, after, true); err != nil {
		return zero, err
	}
	return after, nil
}
