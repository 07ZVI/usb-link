package connectioninstall

// Startup, storage events and observed offline->online transitions grant bounded retries.
// Observations contain only selected folders with retained sharing receipts.
type smbReconnectObservation struct {
	ID, Path, Identity string
	Online             bool
}
type smbReconnectEntry struct {
	Path, Identity string
	Offline        bool
	Attempts       int
}
type smbReconnectTracker map[string]smbReconnectEntry

func (t smbReconnectTracker) observe(rows []smbReconnectObservation) []string {
	present := map[string]bool{}
	var retry []string
	for _, row := range rows {
		present[row.ID] = true
		old, exists := t[row.ID]
		if !exists || old.Path != row.Path || old.Identity != row.Identity {
			old = smbReconnectEntry{Path: row.Path, Identity: row.Identity}
		}
		if !row.Online {
			old.Offline = true
			old.Attempts = 0
		} else if old.Offline && old.Attempts < 5 {
			old.Attempts++
			retry = append(retry, row.ID)
		}
		t[row.ID] = old
	}
	for id := range t {
		if !present[id] {
			delete(t, id)
		}
	}
	return retry
}
func (t smbReconnectTracker) restored(id string) {
	row, ok := t[id]
	if ok {
		row.Offline = false
		row.Attempts = 0
		t[id] = row
	}
}

// Arm retained publications on startup or a storage event, even when
// the disk is already online. Explicit off/remove operations have no receipt.
func (t smbReconnectTracker) arm(rows []smbReconnectObservation) {
	for _, row := range rows {
		t[row.ID] = smbReconnectEntry{Path: row.Path, Identity: row.Identity, Offline: true}
	}
}
