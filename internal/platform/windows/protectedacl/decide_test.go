package protectedacl

import (
	"errors"
	"testing"
)

var want = ACL{Protected: true, ACEs: []ACE{{0, 3, 0x1f01ff, SystemSID}, {0, 3, 0x1f01ff, AdminsSID}}}

func TestMatchesIsExactAndOrderInsensitive(t *testing.T) {
	swapped := ACL{true, []ACE{want.ACEs[1], want.ACEs[0]}}
	if !swapped.Matches(want) {
		t.Fatal("order must not matter")
	}
	user := ACL{true, append(append([]ACE{}, want.ACEs...), ACE{0, 0, 0x1f01ff, "S-1-5-21-1-2-3-1001"})}
	for name, a := range map[string]ACL{
		"extra user ace": user,
		"unprotected":    {false, want.ACEs},
		"flags":          {true, []ACE{{0, 0, 0x1f01ff, SystemSID}, want.ACEs[1]}},
		"mask":           {true, []ACE{{0, 3, 0x1200a9, SystemSID}, want.ACEs[1]}},
		"empty":          {true, nil},
	} {
		if a.Matches(want) {
			t.Fatal(name)
		}
	}
	if (ACL{true, nil}).Matches(ACL{true, nil}) {
		t.Fatal("empty expectation must never match")
	}
}

func TestDecide(t *testing.T) {
	good := Object{Directory: true, Links: 1, Owner: AdminsSID, ACL: want}
	if a, e := Decide(good, want); a != Keep || e != nil {
		t.Fatal(a, e)
	}
	explorer := good
	explorer.ACL = ACL{true, append(append([]ACE{}, want.ACEs...), ACE{0, 0, 0x1f01ff, "S-1-5-21-1-2-3-1001"})}
	if a, e := Decide(explorer, want); a != Reset || e != nil {
		t.Fatal(a, e)
	}
	for name, c := range map[string]struct {
		o   Object
		err error
	}{
		"reparse":  {Object{Directory: true, Reparse: true, Owner: SystemSID}, ErrReparse},
		"links":    {Object{Links: 2, Owner: SystemSID}, ErrLinks},
		"owner":    {Object{Directory: true, Owner: "S-1-5-21-1-2-3-1001"}, ErrOwner},
		"no owner": {Object{Directory: true}, ErrOwner},
	} {
		if a, e := Decide(c.o, want); a != Keep || !errors.Is(e, c.err) {
			t.Fatal(name, a, e)
		}
	}
	file := Object{Links: 1, Owner: SystemSID, ACL: ACL{true, want.ACEs[:1]}}
	if a, e := Decide(file, want); a != Reset || e != nil {
		t.Fatal(a, e)
	}
	// Directories may legitimately report any link count.
	if _, e := Decide(Object{Directory: true, Links: 0, Owner: SystemSID, ACL: want}, want); e != nil {
		t.Fatal(e)
	}
}

func TestBudgetBoundsDepthAndEntries(t *testing.T) {
	var b Budget
	if b.Admit(MaxDepth+1) != SkipDeep {
		t.Fatal("deep")
	}
	for i := 0; i < MaxEntries; i++ {
		if b.Admit(1) != Admit {
			t.Fatal(i)
		}
	}
	if b.Admit(1) != SkipFull {
		t.Fatal("full")
	}
}

func TestRepairString(t *testing.T) {
	if s := (Repair{Path: "p", Missing: true}).String(); s != "p absent" {
		t.Fatal(s)
	}
	r := Repair{Path: "p", Changed: 2, Checked: 5, PreviousACEs: 3}
	if !r.Repaired() || r.String() != "p reset=2 checked=5 skipped=0 previous_aces=3" {
		t.Fatal(r.String())
	}
}
