//go:build usblink_local_remote

package ipadncm

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestWPDQueryEvidenceIsPrivateAndSnapshotIndependent(t *testing.T) {
	j := cleanupWPDMetadataFixture()
	d := wpdCheckSessionQuery(j, "", wpdQueryFixture("PRIVATE_SESSION", "PRIVATE_PATH"), false, ^uint32(0), ^uint32(0), 120, 2168)
	c := &localWPDTraceController{}
	c.publish("recovery_pending", false, &localWPDTraceFailure{Code: "WPD_TRACE_SESSION_NOT_OWNED", Ownership: &d})
	s := c.snapshot()
	if s.Ownership == nil || s.Ownership.Mismatch != 21 {
		t.Fatal(s.Ownership)
	}
	d.Mismatch = 0
	s.Ownership.Mismatch = 0
	if c.snapshot().Ownership.Mismatch != 21 {
		t.Fatal("ownership evidence aliases caller or snapshot")
	}
	b, err := json.Marshal(c.snapshot())
	if err != nil || len(b) > 4096 || strings.Contains(string(b), "PRIVATE") || strings.Contains(string(b), j.Session) {
		t.Fatal("unsafe evidence", err, len(b))
	}
	c.publish("stopped", false, nil)
	if c.snapshot().Ownership != nil {
		t.Fatal("stale failure retained after success")
	}
}
