//go:build usblink_local_remote

package ipadncm

import (
	"errors"
	"strings"
)

func applyPhotoPolicy(b photoPolicyStore, nodes []portableNodeReceipt, allowed func() bool) error {
	j, err := b.load()
	if err != nil {
		return err
	}
	if len(nodes) > localPhotoPolicyMaxNodes {
		return errors.New("PHOTO_POLICY_NODE_LIMIT")
	}
	for _, n := range nodes {
		if !localPhotoReceiptValid(n) {
			return errors.New("PHOTO_POLICY_TARGET_UNPROVEN")
		}
		found := false
		for _, e := range j.Entries {
			if !strings.EqualFold(n.Root, e.Node.Root) {
				return errors.New("PHOTO_POLICY_OTHER_TARGET_PENDING")
			}
			if strings.EqualFold(n.ID, e.Node.ID) {
				if !strings.EqualFold(n.Class, e.Node.Class) {
					return errors.New("PHOTO_POLICY_TARGET_CHANGED")
				}
				found = true
			}
		}
		if found {
			continue
		}
		if len(j.Entries) >= localPhotoPolicyMaxNodes {
			return errors.New("PHOTO_POLICY_NODE_LIMIT")
		}
		s, err := b.readRegistry()
		if err != nil {
			return err
		}
		if photoPolicyForeign(s, j) {
			return errors.New("PHOTO_POLICY_FOREIGN_ENTRIES")
		}
		if !j.Captured {
			zero, one := photoPolicyDWORD(0), photoPolicyDWORD(1)
			for _, v := range []photoPolicyValue{s.Deny, s.Retroactive} {
				if v.Present && !v.same(zero) && !v.same(one) {
					return errors.New("PHOTO_POLICY_GLOBAL_UNSUPPORTED")
				}
			}
			j.Captured = true
			j.DenyOriginal = s.Deny
			j.RetroactiveOriginal = s.Retroactive
		}
		if !photoPolicyGlobalsOwned(s, j) {
			return errors.New("PHOTO_POLICY_GLOBAL_CHANGED")
		}
		name := photoPolicyName(n)
		if s.Entries[name].Present {
			return errors.New("PHOTO_POLICY_VALUE_COLLISION")
		}
		j.Entries = append(j.Entries, photoPolicyEntry{Node: n, Name: name, Owned: photoPolicyString(n.ID)})
		if !j.valid() {
			return errors.New("PHOTO_POLICY_JOURNAL_INVALID")
		}
		// Journal must be durable before this ID can enter the active deny list.
		if err = b.save(j); err != nil {
			return err
		}
		if err = continuePhotoPolicy(b, j, allowed); err != nil {
			return err
		}
	}
	return continuePhotoPolicy(b, j, allowed)
}
func continuePhotoPolicy(b photoPolicyStore, j photoPolicyJournal, allowed func() bool) error {
	if len(j.Entries) == 0 {
		return nil
	}
	s, err := b.readRegistry()
	if err != nil {
		return err
	}
	if photoPolicyForeign(s, j) {
		return errors.New("PHOTO_POLICY_FOREIGN_ENTRIES")
	}
	if !photoPolicyGlobalsOwned(s, j) {
		return errors.New("PHOTO_POLICY_GLOBAL_CHANGED")
	}
	changes := []photoPolicyChange{}
	for _, e := range j.Entries {
		v := s.Entries[e.Name]
		if !v.same(e.Owned) {
			if !v.same(e.Original) {
				return errors.New("PHOTO_POLICY_OWNED_VALUE_CHANGED")
			}
			changes = append(changes, photoPolicyChange{"entry:" + e.Name, e.Owned})
		}
	}
	one := photoPolicyDWORD(1)
	if !s.Deny.same(one) {
		changes = append(changes, photoPolicyChange{"deny", one})
	}
	if !s.Retroactive.same(one) {
		changes = append(changes, photoPolicyChange{"retroactive", one})
	}
	if !allowed() {
		return errors.New("PHOTO_POLICY_CANCELLED")
	}
	if len(changes) > 0 {
		if err = b.change(s, changes); err != nil {
			return err
		}
	}
	after, err := b.readRegistry()
	if err != nil || !after.Deny.same(one) || !after.Retroactive.same(one) {
		return errors.New("PHOTO_POLICY_WRITE_UNCONFIRMED")
	}
	for _, e := range j.Entries {
		if !after.Entries[e.Name].same(e.Owned) {
			return errors.New("PHOTO_POLICY_WRITE_UNCONFIRMED")
		}
	}
	if photoPolicyForeign(after, j) {
		return errors.New("PHOTO_POLICY_FOREIGN_ENTRIES")
	}
	if !allowed() {
		return errors.New("PHOTO_POLICY_CANCELLED")
	}
	return nil
}
