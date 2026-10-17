//go:build windows && amd64

package netconfig

import (
	"strings"
	"suhang/usbnet/internal/transport/usbaddress"
	"testing"
)

func TestSessionAbsenceBatchMatchesActualRuleObligations(t *testing.T) {
	token := strings.Repeat("a", 24)
	all, e := nativeSessionSpecs(token, usbaddress.Unified, false)
	if e != nil {
		t.Fatal(e)
	}
	files, e := nativeSessionSpecs(token, usbaddress.Unified, true)
	if e != nil {
		t.Fatal(e)
	}
	all = append(all, files...)
	names := make([]string, len(all))
	for i, s := range all {
		names[i] = s.Name
	}
	q, e := sessionRuleAbsenceQuery(token, names)
	if e != nil {
		t.Fatal(e)
	}
	if len(all) != 5 || strings.Count(q, "InstanceID=") != len(all) {
		t.Fatal("scope changed")
	}
	for _, s := range all {
		if strings.Count(q, "InstanceID='"+s.Name+"'") != 1 {
			t.Fatal("missing/duplicate exact rule")
		}
	}
}
