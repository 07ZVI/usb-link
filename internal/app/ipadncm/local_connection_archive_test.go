package ipadncm

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"
)

type archiveMemoryStore struct {
	mu                              sync.Mutex
	files                           map[string][]byte
	failAppend, partial, failRemove bool
	writes                          int
}

func newArchiveMemoryStore() *archiveMemoryStore {
	return &archiveMemoryStore{files: map[string][]byte{}}
}
func (s *archiveMemoryStore) load() (map[string][]byte, uint64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	v := map[string][]byte{}
	for k, b := range s.files {
		v[k] = append([]byte(nil), b...)
	}
	return v, 0, nil
}
func (s *archiveMemoryStore) appendArchiveBytes(id string, b []byte, create bool) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.writes++
	if s.failAppend {
		if s.partial {
			s.files[id] = append(s.files[id], b[:len(b)/2]...)
		}
		return errors.New("disk full")
	}
	if create && s.files[id] != nil {
		return errors.New("exists")
	}
	s.files[id] = append(s.files[id], b...)
	return nil
}
func (s *archiveMemoryStore) remove(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.failRemove {
		return errors.New("busy")
	}
	delete(s.files, id)
	return nil
}
func (s *archiveMemoryStore) close() {}
func archiveTestController() *connectionArchiveController {
	c := newConnectionArchiveController()
	c.store = newArchiveMemoryStore()
	c.ready = true
	c.master(true)
	return c
}
func archiveDrain(c *connectionArchiveController) {
	for {
		select {
		case r := <-c.queue:
			c.consume(r)
		default:
			return
		}
	}
}
func archiveStart(c *connectionArchiveController, n uint64) {
	c.record("owner_notice", map[string]any{"phase": "watcher_delivery"})
	c.attempt(n)
	archiveDrain(c)
}

func TestConnectionArchiveStoresSafeNativeMetadataAndItsCoverage(t *testing.T) {
	c := archiveTestController()
	archiveStart(c, 1)
	if c.diagnostics().RawETL != "disabled_metadata_only_legacy_files_preserved" {
		t.Fatal("archive still advertises a new raw ETL", c.diagnostics())
	}
	if !bytes.Contains(c.active.body, []byte(`"raw_etl":"disabled_metadata_only_legacy_files_preserved"`)) || bytes.Contains(c.active.body, []byte("local_circular_not_per_connection")) {
		t.Fatal("episode header disagrees with metadata-only capture")
	}
	for _, kind := range []string{"usb_native_metadata", "usb_native_trace_status", "pnp_native_metadata", "pnp_native_trace_status"} {
		if !c.record(kind, map[string]any{"target_scope": "unknown", "coverage": "metadata_only", "event_utc": "2026-10-17T01:02:03.123Z", "port_number": 3}) {
			t.Fatal("safe native metadata was rejected", kind)
		}
	}
	archiveDrain(c)
	for _, kind := range []string{"usb_native_metadata", "usb_native_trace_status", "pnp_native_metadata", "pnp_native_trace_status"} {
		if !bytes.Contains(c.active.body, []byte(`"kind":"`+kind+`"`)) {
			t.Fatal("native evidence missing from automatic export", kind)
		}
	}
	if !bytes.Contains(c.active.body, []byte(`"target_scope":"unknown"`)) || !bytes.Contains(c.active.body, []byte(`"event_utc":"2026-10-17T01:02:03.123Z"`)) {
		t.Fatal("coverage or original observation time lost")
	}
}
func TestConnectionArchiveEpisodeFreezeAndChunks(t *testing.T) {
	c := archiveTestController()
	c.record("environment_baseline", map[string]any{"schema": 1, "core_version": "0.10.36"})
	archiveDrain(c)
	c.record("owner_notice", map[string]any{"phase": "queued"})
	if c.store.(*archiveMemoryStore).writes != 0 {
		t.Fatal("callback did file IO")
	}
	archiveDrain(c)
	c.attempt(1)
	c.record("connection_stage", map[string]any{"stage": "mode_begin"})
	c.record("mode_cache_sample", map[string]any{"cached_connection_information_only": true, "full_identity_check_eligible_not_authorized": true, "read_elapsed_ms": 2})
	archiveDrain(c)
	index, e := c.index()
	if e != nil || len(index.Entries) != 1 || index.Entries[0].Attempt != 1 {
		t.Fatal(index, e)
	}
	entry := index.Entries[0]
	if !bytes.Contains(c.active.body, []byte("environment_baseline")) {
		t.Fatal("pre-notice environment lost")
	}
	if !bytes.Contains(c.active.body, []byte(`"kind":"mode_cache_sample"`)) || !bytes.Contains(c.active.body, []byte(`"full_identity_check_eligible_not_authorized":true`)) {
		t.Fatal("cached observation or its non-authorizing semantics lost")
	}
	c.record("connection_stage", map[string]any{"stage": "mode_end"})
	archiveDrain(c)
	var all []byte
	for offset := int64(0); offset < entry.Total; {
		p, e := c.chunk(entry.ID, offset, 73, entry.SHA256)
		if e != nil || p.Total != entry.Total || p.SHA256 != entry.SHA256 {
			t.Fatal(p, e)
		}
		all = append(all, p.Data...)
		offset += int64(len(p.Data))
	}
	if archiveHash(all) != entry.SHA256 || bytes.Contains(all, []byte("mode_end")) {
		t.Fatal("active append changed export")
	}
	fresh, _ := c.index()
	if fresh.Entries[0].Total <= entry.Total {
		t.Fatal("new snapshot did not advance")
	}
	if _, e = c.chunk(entry.ID, 0, 10, entry.SHA256); e == nil {
		t.Fatal("mixed frozen snapshots")
	}
	for _, id := range []string{"../secret", strings.Repeat("A", 32), entry.ID + "/x"} {
		if _, e = c.chunk(id, 0, 10); e == nil {
			t.Fatal(id)
		}
	}
	for _, v := range []struct {
		o int64
		n int
	}{{-1, 1}, {0, 0}, {0, 32769}, {fresh.Entries[0].Total + 1, 1}} {
		if _, e = c.chunk(entry.ID, v.o, v.n); e == nil {
			t.Fatal(v)
		}
	}
	c.record("owner_notice", map[string]any{"phase": "queued"})
	c.attempt(2)
	archiveDrain(c)
	if len(c.files) != 2 || !c.files[0].meta.Complete || c.files[1].meta.Attempt != 2 || !bytes.Contains(c.files[1].body, []byte("queued")) {
		t.Fatal("episode binding")
	}
}
func TestConnectionArchiveMasterCancellationAndQueueBound(t *testing.T) {
	c := archiveTestController()
	archiveStart(c, 1)
	for i := 0; i < connectionArchiveQueue+5; i++ {
		c.record("owner_phase", map[string]any{"phase": "waiting"})
	}
	if c.diagnostics().QueueDropped != 5 {
		t.Fatal(c.diagnostics())
	}
	c.master(false)
	c.record("owner_notice", map[string]any{"phase": "must_not_capture"})
	archiveDrain(c)
	c.closeIfRequested()
	if c.active != nil || !c.files[0].meta.Complete || bytes.Contains(c.files[0].body, []byte("must_not_capture")) || c.diagnostics().CancelledEvents != 0 || !bytes.Contains(c.files[0].body, []byte("waiting")) {
		t.Fatal(c.diagnostics())
	}
	c.master(true)
	archiveStart(c, 2)
	if len(c.files) != 2 || c.active.meta.Attempt != 2 {
		t.Fatal("re-enable failed")
	}
}
func TestConnectionArchivePayloadPrivacyAndExplicitRejection(t *testing.T) {
	b, n, e := connectionArchivePayload(map[string]any{"serial": "PRIVATE", "token": "PRIVATE", "path": `C:\Users\PRIVATE`, "error": "open C:\\PRIVATE failed", "id_prefix": `USB\VID_05AC&PID_12AB&MI_00`, "ipv4": []string{"10.6.9.254/32"}, "command_code": 4098})
	if e != nil || n != 4 || bytes.Contains(b, []byte(`"PRIVATE"`)) || !bytes.Contains(b, []byte("MI_00")) {
		t.Fatal(string(b), n, e)
	}
	c := archiveTestController()
	c.record("raw_log", "private")
	c.record("owner_phase", "private")
	if c.diagnostics().Rejected != 2 {
		t.Fatal(c.diagnostics())
	}
}
func TestConnectionArchiveSizeFooterAndPartialWriteRecovery(t *testing.T) {
	c := archiveTestController()
	archiveStart(c, 1)
	values := make([]string, 400)
	for i := range values {
		values[i] = strings.Repeat("A", 128)
	}
	for i := 0; i < 90; i++ {
		c.record("startup_sample", map[string]any{"values": values})
		archiveDrain(c)
	}
	c.finish("test_end")
	f := c.files[0]
	if len(f.body) > connectionArchiveLimit || !f.meta.Truncated || !f.meta.Complete || c.diagnostics().SizeDropped == 0 {
		t.Fatal(len(f.body), f.meta, c.diagnostics())
	}
	loaded, e := connectionArchiveRead(f.meta.ID, f.body)
	if e != nil || !loaded.meta.Truncated || !loaded.meta.Complete {
		t.Fatal(loaded, e)
	}
	d := archiveTestController()
	archiveStart(d, 1)
	s := d.store.(*archiveMemoryStore)
	s.failAppend = true
	s.partial = true
	d.record("connection_stage", map[string]any{"stage": "failed_write"})
	archiveDrain(d)
	s.failAppend = false
	d.finish("must_not_append_after_partial")
	if d.files[0].meta.Complete || d.diagnostics().WriteFailures != 1 {
		t.Fatal(d.diagnostics())
	}
	recovered, e := connectionArchiveRead(d.files[0].meta.ID, s.files[d.files[0].meta.ID])
	if e != nil || !recovered.meta.Truncated || recovered.meta.Complete {
		t.Fatal(recovered, e)
	}
}
func TestConnectionArchiveRetentionAndRestart(t *testing.T) {
	c := archiveTestController()
	for i := uint64(1); i <= 19; i++ {
		archiveStart(c, i)
	}
	c.finish("done")
	if len(c.files) != 16 || c.diagnostics().RetentionRemoved != 3 {
		t.Fatal(len(c.files), c.diagnostics())
	}
	store := c.store.(*archiveMemoryStore)
	store.failRemove = true
	archiveStart(c, 20)
	if len(c.files) != 16 || c.active != nil || c.diagnostics().RetentionFailures == 0 {
		t.Fatal(c.diagnostics())
	}
	store.failRemove = false
	ctx, cancel := context.WithCancel(context.Background())
	next := newConnectionArchiveController()
	done := make(chan struct{})
	go next.run(ctx, store, done)
	for i := 0; i < 100 && !next.diagnostics().Available; i++ {
		time.Sleep(time.Millisecond)
	}
	idx, e := next.index()
	if e != nil || len(idx.Entries) != 16 {
		t.Fatal(len(idx.Entries), e)
	}
	cancel()
	<-done
}
func TestConnectionArchiveConcurrentWorkerAndRead(t *testing.T) {
	c := newConnectionArchiveController()
	c.master(true)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go c.run(ctx, newArchiveMemoryStore(), done)
	for i := 0; i < 100 && !c.diagnostics().Available; i++ {
		time.Sleep(time.Millisecond)
	}
	var wg sync.WaitGroup
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 40; j++ {
				c.record("owner_notice", map[string]any{"phase": "queued"})
				c.attempt(1)
				idx, e := c.index()
				if e == nil {
					for _, v := range idx.Entries {
						_, _ = c.chunk(v.ID, 0, 100, v.SHA256)
					}
				}
				_ = c.diagnostics()
			}
		}()
	}
	wg.Wait()
	cancel()
	<-done
	if c.diagnostics().Phase != "stopped" {
		t.Fatal(c.diagnostics())
	}
	for _, f := range c.files {
		var row connectionArchiveLine
		if e := json.Unmarshal(bytes.SplitN(f.body, []byte{'\n'}, 2)[0], &row); e != nil || row.Schema != 1 {
			t.Fatal(e)
		}
	}
}

func TestConnectionArchiveOffDrainsThenNewGeneration(t *testing.T) {
	c := archiveTestController()
	// Even pre-notice WPD evidence starts an explicitly provisional episode.
	if !c.record("wpd_event", map[string]any{"event_id": 2001}) {
		t.Fatal("admission")
	}
	c.master(false)
	if c.record("wpd_event", map[string]any{"event_id": 9999}) {
		t.Fatal("off admission")
	}
	c.master(true)
	c.record("owner_notice", map[string]any{"phase": "new_generation"})
	archiveDrain(c)
	if len(c.files) != 2 || !c.files[0].meta.Complete || !bytes.Contains(c.files[0].body, []byte(`"event_id":2001`)) || bytes.Contains(c.files[1].body, []byte(`"event_id":2001`)) {
		t.Fatal("off lost accepted event or mixed generations")
	}
	c.master(false)
	c.closeIfRequested()
	if !c.files[1].meta.Complete {
		t.Fatal("off seal")
	}
}
func TestConnectionArchiveLargeEnvironmentAndExplicitOversize(t *testing.T) {
	c := archiveTestController()
	rows := make([]string, 240)
	for i := range rows {
		rows[i] = strings.Repeat("a", 500)
	}
	if !c.record("environment_baseline", map[string]any{"pnp": rows}) {
		t.Fatal("120KiB safe environment rejected")
	}
	c.record("owner_notice", map[string]any{"phase": "queued"})
	archiveDrain(c)
	if len(c.active.body) < 120000 || c.diagnostics().Redacted != 0 {
		t.Fatal("safe fields lost", c.diagnostics())
	}
	before := c.diagnostics().Rejected
	if c.record("environment_baseline", map[string]any{"pnp": append(rows, rows...)}) || c.diagnostics().Rejected != before+1 || c.diagnostics().Error != "ARCHIVE_PAYLOAD_BOUND" {
		t.Fatal("oversize not accounted")
	}
	c.master(false)
	c.closeIfRequested()
	if _, err := connectionArchiveRead(c.files[0].meta.ID, c.files[0].body); err != nil {
		t.Fatal(err)
	}
}

type archiveBlockedValue struct {
	entered chan struct{}
	resume  chan struct{}
}

func (v archiveBlockedValue) MarshalJSON() ([]byte, error) {
	close(v.entered)
	<-v.resume
	return []byte(`{"phase":"old_generation"}`), nil
}
func TestConnectionArchiveSerializationCannotCrossMasterGeneration(t *testing.T) {
	c := archiveTestController()
	v := archiveBlockedValue{make(chan struct{}), make(chan struct{})}
	done := make(chan bool, 1)
	go func() { done <- c.record("owner_notice", v) }()
	<-v.entered
	c.master(false)
	c.master(true)
	close(v.resume)
	if <-done || len(c.queue) != 0 || c.diagnostics().CancelledEvents != 1 {
		t.Fatal("old serialization admitted into new generation")
	}
}

type archiveDelayedStore struct {
	*archiveMemoryStore
	entered, release chan struct{}
}

func (s *archiveDelayedStore) load() (map[string][]byte, uint64, error) {
	close(s.entered)
	<-s.release
	return s.archiveMemoryStore.load()
}
func TestConnectionArchiveEarlyAdmissionBeforeProtectedStoreReady(t *testing.T) {
	c := newConnectionArchiveController()
	s := &archiveDelayedStore{newArchiveMemoryStore(), make(chan struct{}), make(chan struct{})}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go c.run(ctx, s, done)
	<-s.entered
	c.master(true)
	if !c.record("owner_notice", map[string]any{"phase": "early_notice"}) {
		t.Fatal("early notice lost")
	}
	c.attempt(91)
	if c.diagnostics().QueueDepth != 2 || s.writes != 0 {
		t.Fatal("early event lost or callback did IO")
	}
	c.master(false)
	close(s.release)
	until := time.Now().Add(3 * time.Second)
	for {
		c.mu.Lock()
		sealed := len(c.files) == 1 && c.files[0].meta.Complete
		enabled := c.state.MasterEnabled
		c.mu.Unlock()
		if sealed {
			if enabled {
				t.Fatal("initialization reopened master")
			}
			break
		}
		if time.Now().After(until) {
			t.Fatal("accepted startup events not sealed", c.diagnostics())
		}
		time.Sleep(time.Millisecond)
	}
	cancel()
	<-done
	if c.files[0].meta.Attempt != 91 || !bytes.Contains(c.files[0].body, []byte("early_notice")) || c.diagnostics().QueueDropped != 0 {
		t.Fatal("startup evidence missing", c.diagnostics())
	}
}

func TestConnectionArchiveUnknownHistoryIsNeverRetainedAsOwned(t *testing.T) {
	s := newArchiveMemoryStore()
	id := strings.Repeat("b", 32)
	s.files[id] = []byte(`{"schema":1,"id":"` + id + `","kind":"unrecognized","value":{}}` + "\n")
	c := newConnectionArchiveController()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go c.run(ctx, s, done)
	until := time.Now().Add(2 * time.Second)
	for !c.diagnostics().Available {
		if time.Now().After(until) {
			t.Fatal("load timeout")
		}
		time.Sleep(time.Millisecond)
	}
	idx, err := c.index()
	if err != nil || len(idx.Entries) != 0 || idx.Diagnostics.UnknownFiles != 1 {
		t.Fatal(idx, err)
	}
	cancel()
	<-done
	if _, ok := s.files[id]; !ok {
		t.Fatal("unknown history deleted")
	}
}

func archiveLargePrehistory(t *testing.T) json.RawMessage {
	t.Helper()
	rows := make([]string, 140)
	for i := range rows {
		rows[i] = strings.Repeat("x", 500)
	}
	b, err := json.Marshal(map[string]any{"samples": rows})
	if err != nil {
		t.Fatal(err)
	}
	return b
}
func TestConnectionArchiveFullProvisionalRotatesAndBindsBeforePrehistory(t *testing.T) {
	c := archiveTestController()
	value := archiveLargePrehistory(t)
	for i := 0; i < 64; i++ {
		if !c.record("owner_phase", json.RawMessage(value)) {
			t.Fatal("enqueue")
		}
	}
	archiveDrain(c)
	old := c.active
	if old == nil || old.meta.Attempt != 0 || !old.meta.Truncated || len(c.pending) != 64 {
		t.Fatal("test did not fill provisional")
	}
	c.attempt(17)
	archiveDrain(c)
	if c.active == old || c.active == nil || c.active.meta.Attempt != 17 || !c.active.meta.Truncated || !old.meta.Complete || len(c.pending) != 0 {
		t.Fatal("full provisional blocked binding or replay", c.diagnostics())
	}
	rows := bytes.Split(c.active.body, []byte{'\n'})
	var binding connectionArchiveLine
	if err := json.Unmarshal(rows[1], &binding); err != nil || binding.Kind != "attempt_bound" || binding.Attempt != 17 {
		t.Fatal("prehistory preceded durable identity", binding, err)
	}
	if len(c.active.body) > connectionArchiveLimit || len(old.body) > connectionArchiveLimit {
		t.Fatal("limit widened")
	}
	recovered, err := connectionArchiveRead(c.active.meta.ID, c.active.body)
	if err != nil || recovered.meta.Attempt != 17 {
		t.Fatal("binding not recoverable", err)
	}
	c.attempt(18)
	archiveDrain(c)
	if c.active == nil || c.active.meta.Attempt != 18 || c.active.meta.Truncated {
		t.Fatal("next connection remained blocked")
	}
}
func TestConnectionArchiveBrokenProvisionalAndBindingFailureRetry(t *testing.T) {
	c := archiveTestController()
	c.record("owner_notice", map[string]any{"phase": "queued"})
	archiveDrain(c)
	old := c.active
	s := c.store.(*archiveMemoryStore)
	s.failAppend, s.partial = true, true
	c.record("connection_stage", map[string]any{"stage": "test"})
	archiveDrain(c)
	if !old.writeBroken {
		t.Fatal("write fault not injected")
	}
	s.failAppend, s.partial = false, false
	c.attempt(21)
	archiveDrain(c)
	if c.active == nil || c.active == old || c.active.meta.Attempt != 21 || old.meta.Complete {
		t.Fatal("broken archive rebound or false seal")
	}
	// A failed append/new-file recovery must never advertise the new attempt.
	s.failAppend = true
	c.attempt(22)
	archiveDrain(c)
	for _, f := range c.files {
		if f.meta.Attempt == 22 {
			t.Fatal("failed binding reported successful")
		}
	}
	if c.diagnostics().WriteFailures == 0 {
		t.Fatal("failure hidden")
	}
	s.failAppend = false
	c.attempt(23)
	archiveDrain(c)
	if c.active == nil || c.active.meta.Attempt != 23 {
		t.Fatal("later recovery did not bind")
	}
}
func TestConnectionArchiveBindingItselfCanReachLimit(t *testing.T) {
	c := archiveTestController()
	c.record("owner_notice", map[string]any{"phase": "queued"})
	archiveDrain(c)
	old := c.active
	// Leave fewer bytes than the binding row without marking Truncated yet.
	value := archiveLargePrehistory(t)
	for len(old.body)+len(value)+512 < connectionArchiveLimit-4096 {
		if !c.write(connectionArchiveRecord{kind: "owner_phase", utc: "2026-10-17T00:00:00Z", value: value}) {
			t.Fatal("filler failed")
		}
	}
	r := connectionArchiveRecord{kind: "owner_phase", utc: "2026-10-17T00:00:00Z", value: json.RawMessage(`{"padding":""}`)}
	base, _ := json.Marshal(connectionArchiveLine{Schema: 1, ID: old.meta.ID, UTC: r.utc, Kind: r.kind, Value: r.value})
	padding := connectionArchiveLimit - 4096 - len(old.body) - 1 - len(base) - 1
	if padding < 0 {
		t.Fatal("invalid fixture margin")
	}
	r.value = json.RawMessage(`{"padding":"` + strings.Repeat("x", padding) + `"}`)
	if !c.write(r) || old.meta.Truncated {
		t.Fatal("fixture prematurely truncated")
	}
	if _, err := connectionArchiveRead(old.meta.ID, old.body); err != nil {
		t.Fatal("invalid prelimit fixture", err)
	}
	c.attempt(31)
	archiveDrain(c)
	if c.active == nil || c.active == old || c.active.meta.Attempt != 31 || !old.meta.Truncated {
		t.Fatal("binding-at-limit did not retry into new archive")
	}
}

func TestConnectionArchiveFailedBindingNeverChangesAttempt(t *testing.T) {
	c := archiveTestController()
	c.record("owner_notice", map[string]any{"phase": "queued"})
	archiveDrain(c)
	original := c.active
	c.store.(*archiveMemoryStore).failAppend = true
	c.attempt(44)
	archiveDrain(c)
	if original.meta.Attempt != 0 || !original.writeBroken || c.active != nil {
		t.Fatal("failed append claimed identity", c.diagnostics())
	}
	for _, f := range c.files {
		if f.meta.Attempt == 44 {
			t.Fatal("failed attempt published")
		}
	}
	c.store.(*archiveMemoryStore).failAppend = false
	c.attempt(45)
	archiveDrain(c)
	if c.active == nil || c.active.meta.Attempt != 45 {
		t.Fatal("later attempt failed to recover")
	}
}
