package connectioninstall

import "testing"

func TestSMBReconnectRequiresOriginalOfflineTransition(t *testing.T) {
	tracker := smbReconnectTracker{}
	row := smbReconnectObservation{"selected", "volume-a/folder", "original-id", true}
	if len(tracker.observe([]smbReconnectObservation{row})) != 0 {
		t.Fatal("startup resurrected an externally deleted share")
	}
	row.Online = false
	tracker.observe([]smbReconnectObservation{row})
	row.Online = true
	if got := tracker.observe([]smbReconnectObservation{row}); len(got) != 1 || got[0] != row.ID {
		t.Fatal("returning volume not restored", got)
	}
	tracker.restored(row.ID)
	if len(tracker.observe([]smbReconnectObservation{row})) != 0 {
		t.Fatal("successful restoration repeated")
	}
	row.Online = false
	tracker.observe([]smbReconnectObservation{row})
	row.Online = true
	row.Identity = "different-directory"
	if len(tracker.observe([]smbReconnectObservation{row})) != 0 {
		t.Fatal("different identity inherited restoration intent")
	}
}

func TestSMBReconnectBoundsRetriesAndHonorsDisable(t *testing.T) {
	tracker := smbReconnectTracker{}
	row := smbReconnectObservation{"selected", "volume-a/folder", "original-id", false}
	tracker.observe([]smbReconnectObservation{row})
	row.Online = true
	for i := 0; i < 5; i++ {
		if len(tracker.observe([]smbReconnectObservation{row})) != 1 {
			t.Fatal("retry lost", i)
		}
	}
	if len(tracker.observe([]smbReconnectObservation{row})) != 0 {
		t.Fatal("unbounded retries")
	}
	row.Online = false
	tracker.observe([]smbReconnectObservation{row})
	row.Online = true
	if len(tracker.observe([]smbReconnectObservation{row})) != 1 {
		t.Fatal("new attachment cannot retry")
	}
	tracker.observe(nil) // Closing sharing/removing folder revokes the receipt.
	if len(tracker.observe([]smbReconnectObservation{row})) != 0 {
		t.Fatal("disabled share resurrected")
	}
}

func TestSMBReconnectVolumesRecoverIndependently(t *testing.T) {
	tracker := smbReconnectTracker{}
	rows := []smbReconnectObservation{{"a", "volume-a", "id-a", false}, {"b", "volume-b", "id-b", false}}
	tracker.observe(rows)
	rows[0].Online = true
	if got := tracker.observe(rows); len(got) != 1 || got[0] != "a" {
		t.Fatal(got)
	}
	tracker.restored("a")
	rows[1].Online = true
	if got := tracker.observe(rows); len(got) != 1 || got[0] != "b" {
		t.Fatal(got)
	}
}

func TestSMBStartupActivelyChecksAlreadyOnlineRetainedShares(t *testing.T) {
	tracker := smbReconnectTracker{}
	rows := []smbReconnectObservation{{"online", "volume-a", "original-a", true}, {"offline", "volume-b", "original-b", false}}
	tracker.arm(rows)
	if got := tracker.observe(rows); len(got) != 1 || got[0] != "online" {
		t.Fatal("startup did not restore online publication", got)
	}
	tracker.restored("online")
	if got := tracker.observe(rows); len(got) != 0 {
		t.Fatal("startup recovery repeated", got)
	}
	rows[1].Online = true
	if got := tracker.observe(rows); len(got) != 1 || got[0] != "offline" {
		t.Fatal("late mounting startup volume not restored", got)
	}
	tracker.observe(nil)
	tracker.arm(nil) // A disabled catalog retains no publication intent.
	if len(tracker) != 0 {
		t.Fatal("disabled sharing armed at startup")
	}
}

func TestSMBReconnectCoalescedDetachAttachDoesNotRequireOfflineSample(t *testing.T) {
	tracker := smbReconnectTracker{}
	rows := []smbReconnectObservation{{"disk", "volume", "original", true}}
	tracker.observe(rows)
	// A remove/arrival wake can be delivered after the disk is already back.
	tracker.arm(rows)
	if got := tracker.observe(rows); len(got) != 1 || got[0] != "disk" {
		t.Fatal("coalesced attachment lost", got)
	}
	tracker.restored("disk")
	if len(tracker.observe(rows)) != 0 {
		t.Fatal("successful event kept retrying")
	}
	tracker.observe(nil)
	tracker.arm(nil)
	if len(tracker) != 0 {
		t.Fatal("explicit removal was resurrected by event")
	}
}
