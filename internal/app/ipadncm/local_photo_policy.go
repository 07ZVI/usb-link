package ipadncm

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"strconv"
	"strings"
	"unicode/utf16"
)

const localPhotoPolicyJournalFile = "local-photo-policy-v1.json"
const localPhotoPolicyJournalLimit = 65536
const localPhotoPolicyMaxNodes = 16

type photoPolicyValue struct {
	Present bool   `json:"present"`
	Type    uint32 `json:"type"`
	Data    []byte `json:"data"`
}

func (v photoPolicyValue) same(w photoPolicyValue) bool {
	return v.Present == w.Present && v.Type == w.Type && bytes.Equal(v.Data, w.Data)
}
func (v photoPolicyValue) valid() bool {
	return len(v.Data) <= 4096 && (v.Present || v.Type == 0 && len(v.Data) == 0)
}
func photoPolicyDWORD(n uint32) photoPolicyValue {
	b := make([]byte, 4)
	binary.LittleEndian.PutUint32(b, n)
	return photoPolicyValue{true, 4, b}
}
func photoPolicyString(id string) photoPolicyValue {
	u := append(utf16.Encode([]rune(id)), 0)
	b := make([]byte, len(u)*2)
	for i, n := range u {
		binary.LittleEndian.PutUint16(b[i*2:], n)
	}
	return photoPolicyValue{true, 1, b}
}
func photoPolicyName(n portableNodeReceipt) string {
	h := sha256.Sum256([]byte(strings.ToUpper(n.ID)))
	return strconv.FormatUint(1000000000+uint64(binary.LittleEndian.Uint32(h[:4])), 10)
}

type photoPolicyEntry struct {
	Node     portableNodeReceipt `json:"node"`
	Name     string              `json:"name"`
	Original photoPolicyValue    `json:"original"`
	Owned    photoPolicyValue    `json:"owned"`
}
type photoPolicyJournal struct {
	Schema              int                `json:"schema"`
	Captured            bool               `json:"captured"`
	DenyOriginal        photoPolicyValue   `json:"deny_original"`
	RetroactiveOriginal photoPolicyValue   `json:"retroactive_original"`
	Entries             []photoPolicyEntry `json:"entries"`
}

func (j photoPolicyJournal) valid() bool {
	if j.Schema != 1 || len(j.Entries) > localPhotoPolicyMaxNodes || !j.DenyOriginal.valid() || !j.RetroactiveOriginal.valid() || !j.Captured && (len(j.Entries) > 0 || j.DenyOriginal.Present || j.RetroactiveOriginal.Present) {
		return false
	}
	seen := map[string]bool{}
	root := ""
	for _, e := range j.Entries {
		if !localPhotoReceiptValid(e.Node) || e.Name != photoPolicyName(e.Node) || seen[e.Name] || e.Original.Present || !e.Original.valid() || !e.Owned.same(photoPolicyString(e.Node.ID)) {
			return false
		}
		if root != "" && !strings.EqualFold(root, e.Node.Root) {
			return false
		}
		root = e.Node.Root
		seen[e.Name] = true
	}
	return true
}
func decodePhotoPolicyJournal(b []byte) (photoPolicyJournal, error) {
	var j photoPolicyJournal
	d := json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	if len(b) > localPhotoPolicyJournalLimit || d.Decode(&j) != nil || d.Decode(new(any)) != io.EOF || !j.valid() {
		return j, errors.New("PHOTO_POLICY_JOURNAL_INVALID")
	}
	return j, nil
}

type photoPolicyRegistry struct {
	Deny, Retroactive photoPolicyValue
	Entries           map[string]photoPolicyValue
}

func (s photoPolicyRegistry) same(t photoPolicyRegistry) bool {
	if !s.Deny.same(t.Deny) || !s.Retroactive.same(t.Retroactive) || len(s.Entries) != len(t.Entries) {
		return false
	}
	for k, v := range s.Entries {
		if !v.same(t.Entries[k]) {
			return false
		}
	}
	return true
}

type photoPolicyChange struct {
	Name  string
	Value photoPolicyValue
}
type photoPolicyStore interface {
	load() (photoPolicyJournal, error)
	save(photoPolicyJournal) error
	readRegistry() (photoPolicyRegistry, error)
	// The expectation is rechecked inside a native registry transaction.
	change(photoPolicyRegistry, []photoPolicyChange) error
}

func photoPolicyForeign(s photoPolicyRegistry, j photoPolicyJournal) bool {
	for name := range s.Entries {
		owned := false
		for _, e := range j.Entries {
			if name == e.Name {
				owned = true
				break
			}
		}
		if !owned {
			return true
		}
	}
	return false
}
func photoPolicyGlobalsOwned(s photoPolicyRegistry, j photoPolicyJournal) bool {
	one := photoPolicyDWORD(1)
	return (s.Deny.same(j.DenyOriginal) || s.Deny.same(one)) && (s.Retroactive.same(j.RetroactiveOriginal) || s.Retroactive.same(one))
}

// Only exact owned values are removed. Foreign additions prevent restoring
// global switches when doing so could alter someone else's policy.
func restorePhotoPolicy(b photoPolicyStore) error {
	j, err := b.load()
	if err != nil {
		return err
	}
	for len(j.Entries) > 0 {
		e := j.Entries[0]
		s, err := b.readRegistry()
		if err != nil {
			return err
		}
		current := s.Entries[e.Name]
		if !current.same(e.Original) {
			if !current.same(e.Owned) {
				return errors.New("PHOTO_POLICY_OWNED_VALUE_CHANGED")
			}
			if err = b.change(s, []photoPolicyChange{{"entry:" + e.Name, e.Original}}); err != nil {
				return err
			}
			after, err := b.readRegistry()
			if err != nil || !after.Entries[e.Name].same(e.Original) {
				return errors.New("PHOTO_POLICY_RESTORE_UNCONFIRMED")
			}
		}
		j.Entries = append([]photoPolicyEntry(nil), j.Entries[1:]...)
		if err = b.save(j); err != nil {
			return err
		}
	}
	if !j.Captured {
		return nil
	}
	s, err := b.readRegistry()
	if err != nil {
		return err
	}
	if !photoPolicyGlobalsOwned(s, j) {
		return errors.New("PHOTO_POLICY_GLOBAL_CHANGED")
	}
	var changes []photoPolicyChange
	if !s.Deny.same(j.DenyOriginal) {
		changes = append(changes, photoPolicyChange{"deny", j.DenyOriginal})
	}
	if !s.Retroactive.same(j.RetroactiveOriginal) {
		changes = append(changes, photoPolicyChange{"retroactive", j.RetroactiveOriginal})
	}
	if len(changes) > 0 {
		if len(s.Entries) > 0 {
			return errors.New("PHOTO_POLICY_FOREIGN_ENTRIES_PREVENT_GLOBAL_RESTORE")
		}
		if err = b.change(s, changes); err != nil {
			return err
		}
	}
	after, err := b.readRegistry()
	if err != nil || !after.Deny.same(j.DenyOriginal) || !after.Retroactive.same(j.RetroactiveOriginal) {
		return errors.New("PHOTO_POLICY_RESTORE_UNCONFIRMED")
	}
	return b.save(photoPolicyJournal{Schema: 1})
}

// Pro, Enterprise, Education and IoT Enterprise only, on client build 19041+.
// Unknown editions fail closed, including Home and Windows Server.
func photoPolicySupported(major, build, sku uint32, client bool) bool {
	if major != 10 || build < 19041 || !client {
		return false
	}
	switch sku {
	case 0x30, 0x31, 0xa1, 0xa2, 0xa4, 0x04, 0x1b, 0x48, 0x54, 0x7d, 0x7e, 0x81, 0x82, 0x79, 0x7a, 0xbc, 0xbf:
		return true
	}
	return false
}
