package attemptlog

import (
	"encoding/json"
	"fmt"
	"sync"
)

const MaxAttempts = 8
const MaxEntryBytes = 2 * 1024 * 1024

type Entry struct {
	Number uint64          `json:"attempt"`
	Result json.RawMessage `json:"result"`
}
type Snapshot struct {
	Total    uint64  `json:"total_completed_attempts"`
	Omitted  uint64  `json:"earlier_attempts_omitted"`
	Attempts []Entry `json:"completed_attempts"`
}
type History struct {
	mu      sync.Mutex
	total   uint64
	entries []Entry
}

func (h *History) Add(b []byte) error {
	if len(b) > MaxEntryBytes || !json.Valid(b) {
		return fmt.Errorf("invalid or oversized attempt")
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	h.total++
	h.entries = append(h.entries, Entry{h.total, append(json.RawMessage(nil), b...)})
	if len(h.entries) > MaxAttempts {
		h.entries = append([]Entry(nil), h.entries[len(h.entries)-MaxAttempts:]...)
	}
	return nil
}
func (h *History) Snapshot() Snapshot {
	h.mu.Lock()
	defer h.mu.Unlock()
	s := Snapshot{Total: h.total, Omitted: h.total - uint64(len(h.entries))}
	for _, e := range h.entries {
		s.Attempts = append(s.Attempts, Entry{e.Number, append(json.RawMessage(nil), e.Result...)})
	}
	return s
}
