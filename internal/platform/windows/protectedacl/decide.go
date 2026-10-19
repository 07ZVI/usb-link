// Package protectedacl restores the exact protected DACL of fixed machine
// directories after a shell prompt ("Continue") added the user's ACE to them.
// The verifying stores keep their exact-ACL checks; this runs only before them.
package protectedacl

import (
	"errors"
	"fmt"
	"sort"
)

const (
	MaxDepth   = 4
	MaxEntries = 4096

	SystemSID = "S-1-5-18"
	AdminsSID = "S-1-5-32-544"
)

type ACE struct {
	Type, Flags byte
	Mask        uint32
	SID         string
}

type ACL struct {
	Protected bool
	ACEs      []ACE
}

// Matches is exact: protected, same ACE count, same type/flags/mask/SID set.
func (a ACL) Matches(want ACL) bool {
	if !a.Protected || len(a.ACEs) != len(want.ACEs) || len(want.ACEs) == 0 {
		return false
	}
	key := func(l []ACE) []string {
		out := make([]string, len(l))
		for i, e := range l {
			out[i] = fmt.Sprintf("%d/%d/%08x/%s", e.Type, e.Flags, e.Mask, e.SID)
		}
		sort.Strings(out)
		return out
	}
	x, y := key(a.ACEs), key(want.ACEs)
	for i := range x {
		if x[i] != y[i] {
			return false
		}
	}
	return true
}

// OwnerAllowed admits SYSTEM, Administrators and the caller-supplied owners:
// an elevated installer's files are owned by the installing administrator
// when Windows uses the default "object creator" owner policy.
func OwnerAllowed(sid string, owners []string) bool {
	if sid == SystemSID || sid == AdminsSID {
		return true
	}
	for _, o := range owners {
		if o != "" && sid == o {
			return true
		}
	}
	return false
}

type Object struct {
	Directory, Reparse bool
	Links              uint32
	Owner              string
	ACL                ACL
}

type Action int

const (
	Keep Action = iota
	Reset
)

var (
	ErrReparse = errors.New("reparse point refused")
	ErrLinks   = errors.New("hard-linked file refused")
	ErrOwner   = errors.New("owner is not SYSTEM, Administrators or the installing owner")
)

// Decide never deletes or reinterprets: an object is kept, reset to the
// expected DACL, or the whole tree is refused.
func Decide(o Object, want ACL, owners []string) (Action, error) {
	switch {
	case o.Reparse:
		return Keep, ErrReparse
	case !o.Directory && o.Links != 1:
		return Keep, ErrLinks
	case !OwnerAllowed(o.Owner, owners):
		return Keep, fmt.Errorf("%w: %s", ErrOwner, o.Owner)
	case o.ACL.Matches(want):
		return Keep, nil
	}
	return Reset, nil
}

// Budget bounds one walk; depth counts directories below the root.
type Budget struct{ entries int }

type Admission int

const (
	Admit Admission = iota
	SkipDeep
	SkipFull
)

func (b *Budget) Admit(depth int) Admission {
	switch {
	case depth > MaxDepth:
		return SkipDeep
	case b.entries >= MaxEntries:
		return SkipFull
	}
	b.entries++
	return Admit
}

type Repair struct {
	Path         string
	Changed      int
	Checked      int
	Skipped      int
	PreviousACEs int
	Missing      bool
}

func (r Repair) Repaired() bool { return r.Changed > 0 }

func (r Repair) String() string {
	if r.Missing {
		return r.Path + " absent"
	}
	if r.Changed == 0 {
		return fmt.Sprintf("%s ok checked=%d", r.Path, r.Checked)
	}
	return fmt.Sprintf("%s reset=%d checked=%d skipped=%d previous_aces=%d", r.Path, r.Changed, r.Checked, r.Skipped, r.PreviousACEs)
}
