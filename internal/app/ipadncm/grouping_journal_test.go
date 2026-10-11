package ipadncm

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

func testOwnedProductGrouping() groupingJournal {
	return groupingJournal{1, testUnpairedProductOwner().Root, `{88BAE032-5A81-49F0-BC3D-A4FF138216D6}\0001`, true}
}
func TestOwnedPendingProductGroupingNeedsExactWholeRootAndStrictOriginal(t *testing.T) {
	o := testUnpairedProductOwner()
	j := testOwnedProductGrouping()
	b, _ := json.Marshal(j)
	read, e := decodeGroupingJournal(b)
	if e != nil || read != j || !productGroupingOwnerMatches(o, read) {
		t.Fatal(read, e)
	}
	for _, change := range []func(*groupingJournal){func(j *groupingJournal) { j.RootID += "OTHER" }, func(j *groupingJournal) { j.RootID = `USB\VID_05AC&PID_12AB\OTHER123456789` }, func(j *groupingJournal) { j.Version = 2 }, func(j *groupingJournal) { j.OriginalAbsent = false }, func(j *groupingJournal) { j.DriverKey = `{36FC9E60-C465-11CF-8056-444553540000}\0001` }} {
		x := j
		change(&x)
		if productGroupingOwnerMatches(o, x) {
			t.Fatal("unowned/unknown original admitted", x)
		}
	}
	for _, data := range [][]byte{append(append([]byte(nil), b...), []byte(` {}`)...), []byte(`{"version":1,"original_value_absent":true,"unknown":1}`), []byte(strings.Repeat("x", 1025))} {
		if _, e := decodeGroupingJournal(data); e == nil {
			t.Fatal("malformed pending admitted")
		}
	}
}
func TestProductBootGroupingRetainsOnAndNeverRestoresUnknown(t *testing.T) {
	for _, c := range []struct {
		name                   string
		on, found, fail        bool
		wantProve, wantRestore int
		wantKeep               bool
	}{
		{"owned ON pending", true, true, false, 1, 0, true},
		{"ON no pending", true, false, false, 1, 0, false},
		{"ON unreadable owner/registry/duplicate", true, true, true, 1, 0, false},
		{"explicit OFF ordinary recovery", false, true, false, 0, 1, false},
	} {
		t.Run(c.name, func(t *testing.T) {
			prove, restore := 0, 0
			retained, e := runProductStartupGrouping(c.on, func() (bool, error) {
				prove++
				if c.fail {
					return c.found, fmt.Errorf("native proof unproven")
				}
				return c.found, nil
			}, func() error { restore++; return nil })
			if prove != c.wantProve || restore != c.wantRestore || retained != c.wantKeep || (e != nil) != c.fail {
				t.Fatal(prove, restore, retained, e)
			}
		})
	}
}
