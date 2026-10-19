//go:build usblink_local_remote

package ipadncm

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"time"
)

const connectionArchiveLimit = 4 << 20
const connectionArchivePayloadLimit = 128 << 10
const connectionArchiveLineLimit = connectionArchivePayloadLimit + 1024
const connectionArchiveQueue = 256
const connectionArchiveRetained = 16

// Export IDs are opaque filenames, never device identities or caller paths.
func validConnectionArchiveID(id string) bool {
	return len(id) == 32 && strings.Trim(id, "0123456789abcdef") == ""
}

type connectionArchiveLine struct {
	Schema    int             `json:"schema"`
	ID        string          `json:"id"`
	UTC       string          `json:"utc"`
	Kind      string          `json:"kind"`
	Attempt   uint64          `json:"attempt"`
	Redacted  int             `json:"redacted,omitempty"`
	Value     json.RawMessage `json:"value"`
	Truncated bool            `json:"truncated,omitempty"`
}
type connectionArchiveRecord struct {
	generation uint64
	kind       string
	utc        string
	value      json.RawMessage
	redacted   int
	attempt    uint64
}
type connectionArchiveFile struct {
	writeBroken bool
	meta        ConnectionArchiveEntry
	body        []byte
	frozen      []byte
	frozenMeta  ConnectionArchiveEntry
}
type connectionArchiveStore interface {
	load() (map[string][]byte, uint64, error)
	appendArchiveBytes(id string, data []byte, create bool) error
	remove(id string) error
	close()
}
type connectionArchiveController struct {
	mu                  sync.Mutex
	wake                chan struct{}
	revision            uint64
	processedGeneration uint64
	closing             bool
	baseline            *connectionArchiveRecord
	state               connectionArchiveStatus
	queue               chan connectionArchiveRecord
	files               []*connectionArchiveFile
	active              *connectionArchiveFile
	pending             []connectionArchiveRecord
	store               connectionArchiveStore
	ready               bool
}

func newConnectionArchiveController() *connectionArchiveController {
	return &connectionArchiveController{queue: make(chan connectionArchiveRecord, connectionArchiveQueue), wake: make(chan struct{}, 1), state: connectionArchiveStatus{Phase: "not_started", RawETL: "disabled_metadata_only_legacy_files_preserved", Completeness: "complete_means_sealed_jsonl_not_complete_capture"}}
}
func archiveKindAllowed(k string) bool {
	switch k {
	case "owner_phase", "owner_notice", "rearm_gate", "candidate_gate", "owner_gate", "usb_authorization", "startup_sample", "startup_result", "mode_result", "mode_sample", "mode_cache_sample", "environment_baseline", "trust_event", "network_stage", "connection_stage", "wpd_event", "wpd_skipped_header", "wpd_snapshot", "wpd_critical_event", "wpd_critical_stats", "wpd_critical_rejected", "usb_native_metadata", "usb_native_trace_status", "pnp_native_metadata", "pnp_native_trace_status", "episode_end":
		return true
	}
	return false
}

// Inputs are internal typed diagnostics, never raw logs or an IPC command body.
// Redaction is explicit on every row; unsafe text is not silently exported.
func connectionArchivePayload(value any) (json.RawMessage, int, error) {
	b, e := json.Marshal(value)
	if e != nil || len(b) > connectionArchivePayloadLimit {
		return nil, 0, errors.New("ARCHIVE_PAYLOAD_BOUND")
	}
	var v any
	d := json.NewDecoder(bytes.NewReader(b))
	d.UseNumber()
	if d.Decode(&v) != nil {
		return nil, 0, errors.New("ARCHIVE_PAYLOAD_INVALID")
	}
	if _, ok := v.(map[string]any); !ok {
		return nil, 0, errors.New("ARCHIVE_OBJECT_REQUIRED")
	}
	redacted := 0
	var scrub func(any, string, int) any
	scrub = func(x any, key string, depth int) any {
		if depth > 16 {
			redacted++
			return "REDACTED_DEPTH"
		}
		switch a := x.(type) {
		case map[string]any:
			for k, item := range a {
				lower := strings.ToLower(k)
				unsafe := false
				for _, word := range []string{"password", "secret", "token", "commandline", "command_line", "userdata", "user_data", "instance_id", "instanceid", "device_path", "executable_path", "serial_number"} {
					if strings.Contains(lower, word) && lower != "id_tokens" {
						unsafe = true
					}
				}
				if lower == "path" || lower == "serial" || lower == "payload" {
					unsafe = true
				}
				if unsafe {
					redacted++
					a[k] = "REDACTED_PRIVATE_FIELD"
				} else {
					a[k] = scrub(item, k, depth+1)
				}
			}
			return a
		case []any:
			if len(a) > 512 {
				redacted++
				return "REDACTED_ARRAY_BOUND"
			}
			for i := range a {
				a[i] = scrub(a[i], key, depth+1)
			}
			return a
		case string:
			if len(a) > 512 || strings.ContainsAny(a, "\x00\r\n") {
				redacted++
				return "REDACTED_TEXT_BOUND"
			}
			if strings.ContainsAny(a, "\\/") {
				parts := strings.Split(a, "\\")
				safe := key == "id_prefix" && len(parts) == 2 && parts[0] == "USB" && strings.HasPrefix(parts[1], "VID_05AC&PID_") && !strings.Contains(parts[1], "/")
				// CIDR addresses are public network metadata, not filesystem paths.
				if !safe && !(strings.Count(a, "/") == 1 && strings.Trim(a, "0123456789abcdefABCDEF:./") == "") {
					redacted++
					return "REDACTED_PATH"
				}
			}
			if strings.Contains(strings.ToLower(key), "error") && a != "" && strings.Trim(a, "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_:. -") != "" {
				redacted++
				return "REDACTED_ERROR_TEXT"
			}
			return a
		default:
			return a
		}
	}
	b, e = json.Marshal(scrub(v, "", 0))
	return b, redacted, e
}
func (c *connectionArchiveController) record(kind string, value any) bool {
	c.mu.Lock()
	enabled := c.state.MasterEnabled
	generation := c.revision
	c.mu.Unlock()
	if !enabled {
		return false
	}
	if !archiveKindAllowed(kind) {
		c.mu.Lock()
		c.state.Rejected++
		c.state.Error = "ARCHIVE_KIND_REJECTED"
		c.mu.Unlock()
		return false
	}
	body, n, e := connectionArchivePayload(value)
	if e != nil {
		c.mu.Lock()
		c.state.Rejected++
		c.state.Error = e.Error()
		c.mu.Unlock()
		return false
	}
	return c.enqueue(connectionArchiveRecord{kind: kind, utc: time.Now().UTC().Format(time.RFC3339Nano), value: body, redacted: n}, generation)
}
func (c *connectionArchiveController) enqueue(r connectionArchiveRecord, expectedGeneration ...uint64) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(expectedGeneration) > 0 && expectedGeneration[0] != c.revision {
		c.state.CancelledEvents++
		return false
	}
	if (!c.ready && c.state.Phase != "not_started") || !c.state.MasterEnabled {
		c.state.QueueDropped++
		return false
	}
	r.generation = c.revision
	select {
	case c.queue <- r:
		c.state.EnqueuedRecords++
		return true
	default:
		c.state.QueueDropped++
		return false
	}
}
func (c *connectionArchiveController) attempt(n uint64) {
	if n != 0 {
		c.enqueue(connectionArchiveRecord{kind: "attempt_bound", attempt: n, utc: time.Now().UTC().Format(time.RFC3339Nano), value: json.RawMessage(`{}`)})
	}
}
func (c *connectionArchiveController) diagnostics() connectionArchiveStatus {
	c.mu.Lock()
	defer c.mu.Unlock()
	s := c.state
	s.QueueDepth = len(c.queue)
	s.Recent = append([]string(nil), s.Recent...)
	return s
}
func archiveHash(b []byte) string { h := sha256.Sum256(b); return hex.EncodeToString(h[:]) }
func connectionArchiveRead(id string, b []byte) (*connectionArchiveFile, error) {
	if !validConnectionArchiveID(id) || len(b) > connectionArchiveLimit {
		return nil, errors.New("ARCHIVE_FILE_INVALID")
	}
	end := bytes.LastIndexByte(b, '\n') + 1
	if end == 0 {
		return nil, errors.New("ARCHIVE_HEADER_INVALID")
	}
	f := &connectionArchiveFile{body: append([]byte(nil), b[:end]...)}
	for i, line := range bytes.Split(b[:end-1], []byte{'\n'}) {
		var r connectionArchiveLine
		if json.Unmarshal(line, &r) != nil || r.Schema != 1 || r.ID != id || len(line) > connectionArchiveLineLimit || f.meta.Complete || (!archiveKindAllowed(r.Kind) && r.Kind != "episode_begin" && r.Kind != "attempt_bound" && r.Kind != "archive_health") {
			return nil, errors.New("ARCHIVE_ROW_INVALID")
		}
		if i == 0 {
			if r.Kind != "episode_begin" {
				return nil, errors.New("ARCHIVE_HEADER_INVALID")
			}
			f.meta = ConnectionArchiveEntry{ID: id, CreatedUTC: r.UTC}
		}
		if r.Kind == "attempt_bound" {
			f.meta.Attempt = r.Attempt
		}
		if r.Kind == "episode_end" {
			f.meta.Complete = true
			f.meta.Truncated = r.Truncated
		}
	}
	f.meta.Truncated = f.meta.Truncated || end != len(b) || !f.meta.Complete
	f.meta.Total = int64(end)
	f.meta.SHA256 = archiveHash(f.body)
	return f, nil
}
func (c *connectionArchiveController) index() (ConnectionArchiveIndex, error) {
	c.mu.Lock()
	out := ConnectionArchiveIndex{Schema: 1, Diagnostics: c.state}
	out.Diagnostics.QueueDepth = len(c.queue)
	out.Diagnostics.Recent = append([]string(nil), c.state.Recent...)
	if !c.ready {
		c.mu.Unlock()
		return out, errors.New("ARCHIVE_NOT_READY")
	}
	type view struct {
		file *connectionArchiveFile
		body []byte
		meta ConnectionArchiveEntry
	}
	files := c.files
	if len(files) > connectionArchiveRetained {
		out.Diagnostics.IndexOmitted = uint64(len(files) - connectionArchiveRetained)
		files = files[len(files)-connectionArchiveRetained:]
	}
	views := make([]view, 0, len(files))
	for _, f := range files {
		views = append(views, view{f, f.body[:len(f.body):len(f.body)], f.meta})
	}
	c.mu.Unlock()
	// Written prefixes are immutable. Hash outside the callback's short mutex;
	// appends cannot modify bytes already captured by this frozen slice.
	for _, v := range views {
		v.meta.Total = int64(len(v.body))
		v.meta.SHA256 = archiveHash(v.body)
		c.mu.Lock()
		v.file.frozen = v.body
		v.file.frozenMeta = v.meta
		c.mu.Unlock()
		out.Entries = append(out.Entries, v.meta)
	}
	return out, nil
}
func (c *connectionArchiveController) chunk(id string, offset int64, length int, expected ...string) (ConnectionArchiveChunk, error) {
	if !validConnectionArchiveID(id) || offset < 0 || length < 1 || length > 32768 || len(expected) > 1 {
		return ConnectionArchiveChunk{}, errors.New("ARCHIVE_CHUNK_INVALID")
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, f := range c.files {
		if f.meta.ID != id {
			continue
		}
		m := f.frozenMeta
		if f.frozen == nil {
			return ConnectionArchiveChunk{}, errors.New("ARCHIVE_INDEX_REQUIRED")
		}
		if len(expected) == 1 && expected[0] != m.SHA256 {
			return ConnectionArchiveChunk{}, errors.New("ARCHIVE_SNAPSHOT_CHANGED")
		}
		if offset > int64(len(f.frozen)) {
			return ConnectionArchiveChunk{}, errors.New("ARCHIVE_OFFSET_INVALID")
		}
		end := min(int64(len(f.frozen)), offset+int64(length))
		return ConnectionArchiveChunk{ID: id, Offset: offset, Total: m.Total, SHA256: m.SHA256, Data: append([]byte(nil), f.frozen[offset:end]...), Complete: m.Complete, Truncated: m.Truncated}, nil
	}
	return ConnectionArchiveChunk{}, errors.New("ARCHIVE_NOT_FOUND")
}
func (c *connectionArchiveController) run(ctx context.Context, store connectionArchiveStore, done chan struct{}) {
	defer close(done)
	defer store.close()
	c.store = store
	loaded, unknown, e := store.load()
	c.mu.Lock()
	c.state.UnknownFiles = unknown
	c.mu.Unlock()
	if e != nil {
		c.fail("ARCHIVE_STORE_UNAVAILABLE")
		return
	}
	for id, body := range loaded {
		f, err := connectionArchiveRead(id, body)
		c.mu.Lock()
		if err != nil {
			c.state.UnknownFiles++
		} else {
			c.files = append(c.files, f)
			if f.meta.Truncated {
				c.state.PartialTails++
			}
		}
		c.mu.Unlock()
	}
	c.sortAndRetain(connectionArchiveRetained)
	c.mu.Lock()
	c.ready = true
	c.state.Available = true
	c.state.Phase = "recording"
	c.mu.Unlock()
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			c.mu.Lock()
			c.ready = false
			c.state.MasterEnabled = false
			c.mu.Unlock()
			for {
				select {
				case r := <-c.queue:
					c.consume(r)
				default:
					c.finish("process_exit")
					c.mu.Lock()
					c.ready = false
					c.state.Phase = "stopped"
					c.mu.Unlock()
					return
				}
			}
		case <-c.wake:
			c.closeIfRequested()
		case r := <-c.queue:
			c.consume(r)
			c.closeIfRequested()
		case <-ticker.C:
			c.closeIfRequested()
			c.mu.Lock()
			active := c.active != nil
			c.mu.Unlock()
			if active {
				v, _ := json.Marshal(c.diagnostics())
				c.write(connectionArchiveRecord{kind: "archive_health", utc: time.Now().UTC().Format(time.RFC3339Nano), value: v})
			}
		}
	}
}
func (c *connectionArchiveController) fail(code string) {
	c.mu.Lock()
	c.state.Error = code
	c.state.WriteFailures++
	c.state.Phase = "write_failed"
	c.mu.Unlock()
}
func (c *connectionArchiveController) sortAndRetain(keep int) {
	// No external callback or filesystem I/O is performed under the snapshot lock.
	c.mu.Lock()
	for i := 1; i < len(c.files); i++ {
		for j := i; j > 0 && c.files[j].meta.CreatedUTC < c.files[j-1].meta.CreatedUTC; j-- {
			c.files[j], c.files[j-1] = c.files[j-1], c.files[j]
		}
	}
	c.mu.Unlock()
	for {
		c.mu.Lock()
		if len(c.files) <= keep {
			c.mu.Unlock()
			return
		}
		f := c.files[0]
		c.mu.Unlock()
		if c.store.remove(f.meta.ID) != nil {
			c.mu.Lock()
			c.state.RetentionFailures++
			c.state.Error = "ARCHIVE_RETENTION_FAILED"
			c.mu.Unlock()
			return
		}
		c.mu.Lock()
		c.files = c.files[1:]
		c.state.RetentionRemoved++
		c.mu.Unlock()
	}
}
func (c *connectionArchiveController) begin(r connectionArchiveRecord) bool {
	c.sortAndRetain(connectionArchiveRetained - 1)
	c.mu.Lock()
	full := len(c.files) >= connectionArchiveRetained
	c.mu.Unlock()
	if full {
		c.fail("ARCHIVE_RETENTION_BLOCKED")
		return false
	}
	var nonce [16]byte
	if _, e := rand.Read(nonce[:]); e != nil {
		c.fail("ARCHIVE_ID_FAILED")
		return false
	}
	id := hex.EncodeToString(nonce[:])
	f := &connectionArchiveFile{meta: ConnectionArchiveEntry{ID: id, CreatedUTC: r.utc}}
	header := connectionArchiveLine{Schema: 1, ID: id, UTC: r.utc, Kind: "episode_begin", Value: json.RawMessage(`{"scope":"software_candidate_not_physical_attachment","raw_etl":"disabled_metadata_only_legacy_files_preserved","schema":1}`)}
	line, _ := json.Marshal(header)
	line = append(line, '\n')
	if c.store.appendArchiveBytes(id, line, true) != nil {
		c.fail("ARCHIVE_CREATE_FAILED")
		return false
	}
	f.body = line
	c.mu.Lock()
	c.files = append(c.files, f)
	c.state.WrittenRecords++
	c.state.WrittenBytes += uint64(len(line))
	c.active = f
	c.state.CurrentID = id
	c.mu.Unlock()
	if c.baseline != nil {
		c.write(*c.baseline)
	}
	return true
}
func (c *connectionArchiveController) finish(reason string) {
	c.mu.Lock()
	has := c.active != nil
	c.mu.Unlock()
	if !has {
		return
	}
	b, _ := json.Marshal(map[string]any{"reason": reason, "health": c.diagnostics()})
	c.write(connectionArchiveRecord{kind: "episode_end", utc: time.Now().UTC().Format(time.RFC3339Nano), value: b})
	c.mu.Lock()
	c.active = nil
	c.state.CurrentID = ""
	c.mu.Unlock()
}
func (c *connectionArchiveController) consume(r connectionArchiveRecord) {
	// Admission already happened under the master mutex. OFF drains these
	// accepted records; a later ON starts a new generation, never revives it.
	if c.processedGeneration != r.generation {
		c.finish("developer_generation_changed")
		c.pending = nil
		c.baseline = nil
		c.processedGeneration = r.generation
	}
	if r.kind == "environment_baseline" {
		copy := r
		c.baseline = &copy
	}
	c.mu.Lock()
	active := c.active
	attempt := uint64(0)
	unwritable := false
	if active != nil {
		attempt = active.meta.Attempt
		unwritable = active.meta.Truncated || active.writeBroken
	}
	c.mu.Unlock()
	if r.kind == "attempt_bound" {
		if active != nil && (unwritable || attempt != 0 && attempt != r.attempt) {
			c.finish("next_attempt")
			active = nil
		}
		created := active == nil
		if created && !c.begin(r) {
			return
		}
		bound := c.write(r)
		if !bound && !created {
			// A provisional file can reach its limit on this binding write itself.
			// Retry once in a fresh file, never pretend the failed append bound it.
			c.finish("attempt_binding_failed")
			if !c.begin(r) {
				return
			}
			created = true
			bound = c.write(r)
		}
		if !bound {
			return
		}
		// The durable binding precedes bounded prehistory: replay can fill the
		// archive, but cannot leave a successful new connection numbered zero.
		if created {
			for _, p := range c.pending {
				c.write(p)
			}
		}
		c.pending = nil
		return
	}
	if r.kind == "owner_notice" || r.kind == "owner_phase" || r.kind == "candidate_gate" || r.kind == "rearm_gate" || r.kind == "owner_gate" {
		if len(c.pending) == 64 {
			c.pending = c.pending[1:]
			c.mu.Lock()
			c.state.PrehistoryEvicted++
			c.mu.Unlock()
		}
		c.pending = append(c.pending, r)
	}
	if active == nil {
		if r.kind == "environment_baseline" {
			return
		}
		if !c.begin(r) {
			return
		}
	}
	c.write(r)
	if r.kind == "episode_end" {
		c.mu.Lock()
		c.active = nil
		c.state.CurrentID = ""
		c.mu.Unlock()
	}
}
func (c *connectionArchiveController) write(r connectionArchiveRecord) bool {
	c.mu.Lock()
	f := c.active
	if f == nil {
		c.mu.Unlock()
		return false
	}
	attempt := f.meta.Attempt
	if r.kind == "attempt_bound" {
		attempt = r.attempt
	}
	id := f.meta.ID
	size := len(f.body)
	blocked := f.meta.Truncated
	broken := f.writeBroken
	c.mu.Unlock()
	if broken {
		c.mu.Lock()
		c.state.QueueDropped++
		c.mu.Unlock()
		return false
	}
	line, e := json.Marshal(connectionArchiveLine{Schema: 1, ID: id, UTC: r.utc, Kind: r.kind, Attempt: attempt, Redacted: r.redacted, Value: r.value, Truncated: blocked})
	line = append(line, '\n')
	if e != nil || len(line) > connectionArchiveLineLimit || size+len(line) > connectionArchiveLimit-4096 && r.kind != "episode_end" || blocked && r.kind != "episode_end" {
		c.mu.Lock()
		c.state.SizeDropped++
		f.meta.Truncated = true
		c.mu.Unlock()
		return false
	}
	if size+len(line) > connectionArchiveLimit {
		c.mu.Lock()
		c.state.SizeDropped++
		f.meta.Truncated = true
		c.mu.Unlock()
		return false
	}
	if c.store.appendArchiveBytes(id, line, false) != nil {
		c.mu.Lock()
		f.writeBroken = true
		f.meta.Truncated = true
		c.mu.Unlock()
		c.fail("ARCHIVE_APPEND_FAILED")
		return false
	}
	c.mu.Lock()
	f.body = append(f.body, line...)
	c.state.WrittenRecords++
	c.state.WrittenBytes += uint64(len(line))
	f.meta.Total = int64(len(f.body))
	if r.kind == "attempt_bound" {
		f.meta.Attempt = r.attempt
	}
	if r.kind == "episode_end" {
		f.meta.Complete = true
	}
	c.state.Redacted += uint64(r.redacted)
	if len(c.state.Recent) == 32 {
		c.state.Recent = c.state.Recent[1:]
	}
	c.state.Recent = append(c.state.Recent, r.kind)
	c.mu.Unlock()
	return true
}

func (c *connectionArchiveController) master(on bool) {
	c.mu.Lock()
	if c.state.MasterEnabled != on {
		c.revision++
		c.state.MasterEnabled = on
		if !on {
			c.closing = true
		}
	}
	c.mu.Unlock()
	select {
	case c.wake <- struct{}{}:
	default:
	}
}
func (c *connectionArchiveController) closeIfRequested() {
	c.mu.Lock()
	close := c.closing && !c.state.MasterEnabled && len(c.queue) == 0
	if close {
		c.closing = false
	}
	c.mu.Unlock()
	if close {
		c.finish("developer_master_off")
		c.pending = nil
		c.baseline = nil
	}
}

type ConnectionArchiveIndex struct {
	Schema      int                      `json:"schema"`
	Entries     []ConnectionArchiveEntry `json:"entries"`
	Diagnostics connectionArchiveStatus  `json:"diagnostics"`
}

type ConnectionArchiveChunk struct {
	ID        string `json:"id"`
	Offset    int64  `json:"offset"`
	Total     int64  `json:"total"`
	SHA256    string `json:"sha256"`
	Data      []byte `json:"data"`
	Complete  bool   `json:"complete"`
	Truncated bool   `json:"truncated"`
}

type ConnectionArchiveEntry struct {
	ID         string `json:"id"`
	Attempt    uint64 `json:"attempt"`
	CreatedUTC string `json:"created_utc"`
	Total      int64  `json:"total"`
	SHA256     string `json:"sha256"`
	Complete   bool   `json:"complete"`
	Truncated  bool   `json:"truncated"`
}

type connectionArchiveStatus struct {
	QueueDepth        int      `json:"queue_depth"`
	EnqueuedRecords   uint64   `json:"enqueued_records"`
	WrittenRecords    uint64   `json:"written_records"`
	WrittenBytes      uint64   `json:"written_bytes"`
	MasterEnabled     bool     `json:"master_enabled"`
	CancelledEvents   uint64   `json:"cancelled_events"`
	Completeness      string   `json:"completeness"`
	Available         bool     `json:"available"`
	Phase             string   `json:"phase"`
	Error             string   `json:"error,omitempty"`
	CurrentID         string   `json:"current_id,omitempty"`
	PrehistoryEvicted uint64   `json:"prehistory_evicted"`
	QueueDropped      uint64   `json:"queue_dropped"`
	SizeDropped       uint64   `json:"size_dropped"`
	WriteFailures     uint64   `json:"write_failures"`
	Rejected          uint64   `json:"rejected"`
	Redacted          uint64   `json:"redacted"`
	RetentionRemoved  uint64   `json:"retention_removed"`
	RetentionFailures uint64   `json:"retention_failures"`
	PartialTails      uint64   `json:"partial_tails"`
	UnknownFiles      uint64   `json:"unknown_files"`
	IndexOmitted      uint64   `json:"index_omitted"`
	Recent            []string `json:"recent_kinds,omitempty"`
	RawETL            string   `json:"raw_etl"`
}
