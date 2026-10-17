package ipadncm

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

func cleanupWPDMetadataFixture() localWPDTraceJournal {
	return localWPDTraceJournal{Schema: 2, Mode: "metadata_session", Session: "USBLink-WPD-" + strings.Repeat("a", 32), GUID: "{12345678-1234-1234-1234-123456789abc}", OwnerSID: "S-1-5-18"}
}

func TestWPDCompletedMetadataCleanupOnlyAfterDurableStop(t *testing.T) {
	for _, tc := range []struct {
		name                                     string
		schema                                   int
		stopped, inactive, writeFail, removeFail bool
		want                                     string
	}{
		{"normal", 2, false, true, false, false, "write,remove"},
		{"retry_completed", 2, true, true, false, false, "remove"},
		{"legacy", 1, false, true, false, false, "write"},
		{"legacy_completed", 1, true, true, false, false, ""},
		{"active", 2, false, false, false, false, ""},
		{"stop_write_failed", 2, false, true, true, false, "write"},
		{"cleanup_failed", 2, false, true, false, true, "write,remove"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			j := cleanupWPDMetadataFixture()
			j.Schema = tc.schema
			j.Stopped = tc.stopped
			if tc.schema == 1 {
				j.Mode = ""
				j.File = localWPDTraceETLFile
			}
			var order []string
			raw, _ := json.Marshal(j)
			err := completeWPDTraceRecovery(j, tc.inactive, func(done localWPDTraceJournal) error {
				order = append(order, "write")
				if tc.writeFail {
					return errors.New("write failed")
				}
				raw, _ = json.Marshal(done)
				return nil
			}, func(done localWPDTraceJournal) error {
				order = append(order, "remove")
				if !wpdCompletedMetadataMatches(raw, done) {
					t.Fatal("cleanup before matching durable receipt")
				}
				if tc.removeFail {
					return errors.New("delete failed")
				}
				raw = nil
				return nil
			})
			if strings.Join(order, ",") != tc.want {
				t.Fatal(order)
			}
			wantErr := !tc.inactive || tc.writeFail || tc.removeFail
			if (err != nil) != wantErr {
				t.Fatal(err)
			}
			if tc.schema == 1 || wantErr {
				if len(raw) == 0 {
					t.Fatal("recovery obligation lost")
				}
			} else if len(raw) != 0 {
				t.Fatal("normal rollback still sees schema2")
			}
		})
	}
}

func TestWPDCompletedMetadataPreservesChangedOrUnknownReceipt(t *testing.T) {
	j := cleanupWPDMetadataFixture()
	j.Stopped = true
	raw, _ := json.Marshal(j)
	if !wpdCompletedMetadataMatches(raw, j) {
		t.Fatal("completed receipt rejected")
	}
	for _, change := range []func(*localWPDTraceJournal){
		func(j *localWPDTraceJournal) { j.Stopped = false }, func(j *localWPDTraceJournal) { j.OwnerSID = "S-1-5-19" },
		func(j *localWPDTraceJournal) { j.Session = "USBLink-WPD-" + strings.Repeat("b", 32) },
		func(j *localWPDTraceJournal) { j.Schema = 1; j.Mode = ""; j.File = localWPDTraceETLFile },
		func(j *localWPDTraceJournal) { j.GUID = "{12345678-1234-1234-1234-123456789abd}" },
	} {
		other := j
		change(&other)
		b, _ := json.Marshal(other)
		if wpdCompletedMetadataMatches(b, j) {
			t.Fatal("changed receipt admitted", other)
		}
	}
	if wpdCompletedMetadataMatches(append(raw, []byte(` {}`)...), j) || wpdCompletedMetadataMatches([]byte(`{"schema":3}`), j) {
		t.Fatal("unknown receipt admitted")
	}
}
