//go:build usblink_local_remote

package ipadncm

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"strings"
	"sync/atomic"
	"testing"
	"time"
	"unicode/utf16"
)

type wpdFake struct {
	starts, stops, recovers atomic.Int32
	begin, release          chan struct{}
	recoverErr, stopErr     error
}

func (b *wpdFake) recover() error { b.recovers.Add(1); return b.recoverErr }
func (b *wpdFake) start(allowed func() bool) error {
	b.starts.Add(1)
	if b.begin != nil {
		close(b.begin)
		<-b.release
	}
	if !allowed() {
		return wpdTraceError("WPD_TRACE_REQUEST_CANCELLED", 0)
	}
	return nil
}
func (b *wpdFake) stop() error                          { b.stops.Add(1); return b.stopErr }
func (b *wpdFake) sample() (localWPDTraceSample, error) { return localWPDTraceSample{Events: 7}, nil }
func armWPD(c *localWPDTraceController, b *wpdFake) {
	c.backend = b
	c.master = true
	c.state.Requested = true
	c.state.Persistence = "saved"
}
func waitWPDPref(t *testing.T, c *localWPDTraceController, want string) {
	t.Helper()
	for end := time.Now().Add(time.Second); time.Now().Before(end); {
		if c.snapshot().Persistence == want {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal(c.snapshot())
}
func TestLocalWPDTraceOffCancelsSlowStartAndKeepsStatusResponsive(t *testing.T) {
	b := &wpdFake{begin: make(chan struct{}), release: make(chan struct{})}
	c := newLocalWPDTraceController()
	armWPD(c, b)
	done := make(chan struct{})
	go func() { c.step(); close(done) }()
	<-b.begin
	c.masterChanged(false)
	if c.snapshot().Requested || c.snapshot().Effective {
		t.Fatal(c.snapshot())
	}
	close(b.release)
	<-done
	if b.stops.Load() != 1 || c.snapshot().Effective {
		t.Fatal("late start retained authority", c.snapshot())
	}
}
func TestLocalWPDTraceRecoveryBeforeEnableAndRetry(t *testing.T) {
	b := &wpdFake{recoverErr: wpdTraceError("WPD_TRACE_SESSION_NOT_OWNED", 5)}
	c := newLocalWPDTraceController()
	armWPD(c, b)
	c.step()
	if b.starts.Load() != 0 || c.snapshot().Phase != "recovery_pending" || c.snapshot().NativeCode != 5 {
		t.Fatal(c.snapshot())
	}
	b.recoverErr = nil
	c.step()
	if b.starts.Load() != 1 || !c.snapshot().Effective {
		t.Fatal(c.snapshot())
	}
	c.masterChanged(false)
	b.stopErr = wpdTraceError("WPD_TRACE_STOP_FAILED", 5)
	c.step()
	if c.snapshot().Phase != "recovery_pending" {
		t.Fatal(c.snapshot())
	}
	b.stopErr = nil
	c.step()
	if c.snapshot().Effective || c.snapshot().Phase != "off" {
		t.Fatal(c.snapshot())
	}
}
func TestLocalWPDTracePreferenceRaceAndRejectedAck(t *testing.T) {
	c := newLocalWPDTraceController()
	entered, release := make(chan struct{}), make(chan struct{})
	c.configure(func(bool) error { return nil }, func() (bool, error) { close(entered); <-release; return true, nil })
	c.masterChanged(true)
	<-entered
	c.masterChanged(false)
	close(release)
	waitWPDPref(t, c, "saved")
	if c.snapshot().Requested || !c.snapshot().SavedEnabled {
		t.Fatal("stale read reopened", c.snapshot())
	}
	id := strings.Repeat("a", 32)
	if c.set(true, id) == nil || c.snapshot().RejectedID != id || c.snapshot().RejectedError == "" {
		t.Fatal(c.snapshot())
	}
	if c.set(false, id) != nil {
		t.Fatal("off rejected")
	}
	waitWPDPref(t, c, "saved")
}
func TestLocalWPDTraceFailedSaveAndCancelledContextNeverStart(t *testing.T) {
	b := &wpdFake{}
	c := newLocalWPDTraceController()
	c.backend = b
	c.master = true
	c.configure(func(bool) error { return errors.New("private filepath") }, nil)
	if e := c.set(true, strings.Repeat("b", 32)); e != nil {
		t.Fatal(e)
	}
	waitWPDPref(t, c, "failed")
	c.step()
	if b.starts.Load() != 0 || strings.Contains(c.snapshot().Error, "private") {
		t.Fatal(c.snapshot())
	}
	c.state.Persistence = "saved"
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	c.ctx = ctx
	c.step()
	if b.starts.Load() != 0 {
		t.Fatal("cancelled start")
	}
}
func TestLocalWPDTraceContinuousNoExpiryAndStopJoin(t *testing.T) {
	b := &wpdFake{}
	c := newLocalWPDTraceController()
	armWPD(c, b)
	c.step()
	c.step()
	if b.starts.Load() != 1 || !c.snapshot().Effective {
		t.Fatal(c.snapshot())
	}
	ctx, cancel := context.WithCancel(context.Background())
	c.ctx = ctx
	done := make(chan struct{})
	go c.run(ctx, done)
	cancel()
	<-done
	if b.stops.Load() == 0 || c.snapshot().Effective {
		t.Fatal(c.snapshot())
	}
}
func traceMetadata(name string, kind uint16, flags uint32, count uint16) []byte {
	u := utf16.Encode([]rune(name + "\x00"))
	b := make([]byte, 136+2*len(u))
	binary.LittleEndian.PutUint32(b[100:], 1)
	binary.LittleEndian.PutUint32(b[104:], 1)
	binary.LittleEndian.PutUint32(b[112:], flags)
	binary.LittleEndian.PutUint32(b[116:], 136)
	binary.LittleEndian.PutUint16(b[120:], kind)
	binary.LittleEndian.PutUint16(b[128:], count)
	for i, v := range u {
		binary.LittleEndian.PutUint16(b[136+i*2:], v)
	}
	return b
}
func TestLocalWPDTraceOnlyAllowlistedUnsignedScalarCommands(t *testing.T) {
	for _, name := range []string{"MTPOpcode", "MtpOpcode", "OperationCode", "ResponseCode", "CommandId"} {
		p := wpdTraceNumericProperties(traceMetadata(name, 6, 0, 1))
		if len(p) != 1 || p[0].Name != name || p[0].Size != 2 {
			t.Fatal(p)
		}
	}
	for _, b := range [][]byte{traceMetadata("FileName", 8, 0, 1), traceMetadata("CommandId", 1, 0, 1), traceMetadata("CommandId", 14, 0, 1), traceMetadata("CommandId", 8, 1, 1), traceMetadata("CommandId", 8, 0, 2), traceMetadata("EventID", 8, 0, 1), {1, 2}} {
		if len(wpdTraceNumericProperties(b)) != 0 {
			t.Fatal("non-command payload admitted")
		}
	}
}
func wpdProviderMetadata(flags uint32, loggers ...uint16) []byte {
	b := make([]byte, 24+len(loggers)*32)
	binary.LittleEndian.PutUint32(b, 1)
	binary.LittleEndian.PutUint32(b[12:], uint32(len(loggers)))
	binary.LittleEndian.PutUint32(b[20:], flags)
	for i, id := range loggers {
		p := b[24+i*32:]
		binary.LittleEndian.PutUint32(p, 1)
		binary.LittleEndian.PutUint16(p[6:], id)
	}
	return b
}
func TestLocalWPDTraceProviderClassificationsAndExistingSessions(t *testing.T) {
	for _, tc := range []struct {
		flags      uint32
		loggers    []uint16
		kind, skip string
		count      uint32
	}{
		{0, []uint16{1, 2}, "modern", "", 2}, {0, nil, "modern", "", 0}, {1, []uint16{1}, "legacy", "legacy_in_use", 1}, {1, nil, "legacy", "", 0},
		{2, []uint16{1}, "unknown", "type_unknown", 1}, {3, []uint16{1}, "unknown", "type_unknown", 1}, {4, []uint16{1}, "unknown", "type_unknown", 1}, {0, []uint16{1, 1}, "modern", "", 1},
	} {
		got := wpdTraceProviderUnusedMetadata(wpdProviderMetadata(tc.flags, tc.loggers...))
		if got.Kind != tc.kind || got.SkipCode != tc.skip || got.OtherLoggerCount != tc.count {
			t.Fatal(tc, got)
		}
	}
	for _, b := range [][]byte{{1, 2}, wpdProviderMetadata(0, 1)[:30], make([]byte, 8)} {
		if got := wpdTraceProviderUnusedMetadata(b); got.SkipCode == "" {
			t.Fatal("unknown/truncated provider admitted", got)
		}
	}
	// All registered instances matter, including a legacy instance after a modern one.
	a, b := wpdProviderMetadata(0, 1), wpdProviderMetadata(1, 2)
	binary.LittleEndian.PutUint32(a, 2)
	binary.LittleEndian.PutUint32(a[8:], uint32(len(a)-8))
	mixed := append(a, b[8:]...)
	got := wpdTraceProviderUnusedMetadata(mixed)
	if got.Kind != "mixed" || got.SkipCode != "legacy_in_use" || got.OtherLoggerCount != 2 {
		t.Fatal(got)
	}
}
func TestLocalWPDTracePartialEnableDoesNotTouchOccupiedLegacyOrUnknown(t *testing.T) {
	statuses := [3]localWPDTraceProvider{wpdTraceProviderUnusedMetadata(wpdProviderMetadata(0, 1)), wpdTraceProviderUnusedMetadata(wpdProviderMetadata(1, 2)), wpdTraceProviderUnusedMetadata(wpdProviderMetadata(2, 3))}
	sample := newWPDTraceProviderSample()
	var calls []int
	err := enableLocalWPDTraceProviders(func() bool { return true }, func(i int) localWPDTraceProvider { return statuses[i] }, func(i int) uint32 { calls = append(calls, i); return 0 }, func(i int, p localWPDTraceProvider) { sample.Providers[i] = p; sample.providerCoverage() })
	if err != nil || len(calls) != 1 || calls[0] != 0 || sample.ProviderCoverage != "partial" || sample.EnabledProviderCount != 1 || !sample.Providers[0].Enabled || sample.Providers[1].Enabled {
		t.Fatal(err, calls, sample)
	}
}

func TestLocalWPDTraceOnlyEnabledLoggerEntriesAreActive(t *testing.T) {
	for _, flags := range []uint32{0, 1} {
		for _, enabled := range []uint32{0, 1, 2, 4294967295} {
			b := wpdProviderMetadata(flags, 7)
			binary.LittleEndian.PutUint32(b[24:], enabled)
			p := wpdTraceProviderUnusedMetadata(b)
			wantCount := uint32(0)
			wantSkip := ""
			if enabled == 1 {
				wantCount = 1
				if flags == 1 {
					wantSkip = "legacy_in_use"
				}
			} else if enabled != 0 {
				wantSkip = "type_unknown"
			}
			if p.OtherLoggerCount != wantCount || p.SkipCode != wantSkip || (enabled > 1 && p.Kind != "unknown") {
				t.Fatal(flags, enabled, p)
			}
		}
	}
	b := wpdProviderMetadata(1, 7, 8, 9)
	binary.LittleEndian.PutUint32(b[24:], 0)
	binary.LittleEndian.PutUint32(b[88:], 2)
	p := wpdTraceProviderUnusedMetadata(b)
	if p.OtherLoggerCount != 1 || p.Kind != "unknown" || p.SkipCode != "type_unknown" {
		t.Fatal("invalid enable flag must remain unknown alongside active legacy logger", p)
	}
}
func TestLocalWPDTraceCoverageCompleteNoneAndEnableFailure(t *testing.T) {
	for _, tc := range []struct {
		skip      bool
		fail      bool
		coverage  string
		count     int
		wantError bool
	}{{false, false, "complete", 3, false}, {true, false, "none", 0, true}, {false, true, "partial", 2, false}} {
		sample := newWPDTraceProviderSample()
		calls := 0
		err := enableLocalWPDTraceProviders(func() bool { return true }, func(int) localWPDTraceProvider {
			p := localWPDTraceProvider{Kind: "modern"}
			if tc.skip {
				p.Kind = "legacy"
				p.SkipCode = "legacy_in_use"
			}
			return p
		}, func(i int) uint32 {
			calls++
			if tc.fail && i == 1 {
				return 5
			}
			return 0
		}, func(i int, p localWPDTraceProvider) { sample.Providers[i] = p; sample.providerCoverage() })
		if (err != nil) != tc.wantError || sample.ProviderCoverage != tc.coverage || sample.EnabledProviderCount != tc.count || (tc.skip && calls != 0) {
			t.Fatal(tc, err, sample, calls)
		}
		if tc.fail && (sample.Providers[1].SkipCode != "enable_failed" || sample.Providers[1].NativeCode != 5) {
			t.Fatal(sample)
		}
	}
}
func TestLocalWPDTraceJournalAndDiagnosticPrivacyBound(t *testing.T) {
	j := localWPDTraceJournal{Schema: 1, Session: "USBLink-WPD-" + strings.Repeat("a", 32), GUID: "{12345678-1234-1234-1234-123456789abc}", OwnerSID: "S-1-5-18", File: localWPDTraceETLFile}
	b, _ := json.Marshal(j)
	if _, e := decodeLocalWPDTraceJournal(b); e != nil {
		t.Fatal(e)
	}
	for _, bad := range []string{strings.Replace(string(b), localWPDTraceETLFile, "../foreign.etl", 1), string(b) + "{}", strings.Replace(string(b), "USBLink-WPD-", "Other-", 1)} {
		if _, e := decodeLocalWPDTraceJournal([]byte(bad)); e == nil {
			t.Fatal("foreign journal accepted")
		}
	}
	c := newLocalWPDTraceController()
	c.state.RequestID = strings.Repeat("a", 32)
	c.state.RejectedID = strings.Repeat("b", 32)
	c.state.RejectedError = "WPD_TRACE_DEBUG_REQUIRED"
	c.state.SampledUTC = "2026-10-17T12:23:34.123456789Z"
	c.state.RunID = strings.Repeat("a", 32)
	c.stamp = func() (string, string, int64) {
		return "2026-10-17T12:23:34.123456789Z", strings.Repeat("a", 32), 9223372036854775807
	}
	for i := 0; i < 8; i++ {
		c.state.Recent = append(c.state.Recent, localWPDTraceEvent{Provider: "mtp", EventID: 65535, PID: ^uint32(0), Task: 65535, ETWOpcode: 255, MS: 9223372036854775807, EventUTC: c.state.SampledUTC, OpcodeDecoded: true, CommandField: "OperationCode", CommandCode: ^uint64(0)})
	}
	for i := range c.state.Providers {
		c.state.Providers[i].Kind = "unknown"
		c.state.Providers[i].OtherLoggerCount = 65535
		c.state.Providers[i].SkipCode = "metadata_invalid"
		c.state.Providers[i].NativeCode = 4294967295
		c.state.Providers[i].EnabledUTC = "2026-10-17T12:23:34.123456789Z"
		c.state.Providers[i].Registration = "invalid_enable_value"
		c.state.Providers[i].InstanceCount = 1024
		c.state.Providers[i].FlagsOR = 4294967295
		c.state.Providers[i].Schema = "manifest"
		c.state.Providers[i].ModernInstances = 1024
		c.state.Providers[i].LegacyInstances = 1024
		c.state.Providers[i].PreEnabledInstances = 1024
		c.state.Providers[i].UnknownInstances = 1024
	}
	c.publish("recovery_pending", false, errors.New("SECRET_DEVICE_ID SECRET_FILE_NAME"))
	b, _ = json.Marshal(c.snapshot())
	if len(b) > 4096 || strings.Contains(string(b), "SECRET") || strings.Contains(string(b), j.Session) || strings.Contains(string(b), j.OwnerSID) {
		t.Fatal(len(b), string(b))
	}
}

type wpdCoverageBackend struct {
	wpdFake
	data localWPDTraceSample
	err  error
}

func (b *wpdCoverageBackend) start(allowed func() bool) error {
	if b.err != nil {
		return b.err
	}
	return b.wpdFake.start(allowed)
}
func (b *wpdCoverageBackend) sample() (localWPDTraceSample, error) { return b.data, nil }
func (b *wpdCoverageBackend) cachedSample() localWPDTraceSample    { return b.data }
func TestLocalWPDTracePartialEffectiveAndFailureKeepsProviderDetails(t *testing.T) {
	for _, n := range []int{0, 1, 3} {
		b := &wpdCoverageBackend{data: newWPDTraceProviderSample()}
		for i := range b.data.Providers {
			b.data.Providers[i].Kind = "legacy"
			b.data.Providers[i].SkipCode = "legacy_in_use"
			if i < n {
				b.data.Providers[i].Kind = "modern"
				b.data.Providers[i].Enabled = true
				b.data.Providers[i].SkipCode = ""
			}
		}
		b.data.providerCoverage()
		if n == 0 {
			b.err = wpdTraceError("WPD_TRACE_NO_PROVIDER_ENABLED", 0)
		}
		c := newLocalWPDTraceController()
		armWPD(c, &b.wpdFake)
		c.backend = b
		c.step()
		s := c.snapshot()
		if s.EnabledProviderCount != n || s.ProviderCoverage != b.data.ProviderCoverage || s.Providers != b.data.Providers {
			t.Fatal("provider details lost", s)
		}
		if n > 0 {
			if !s.Effective || s.Error != "" {
				t.Fatal("partial/complete capture rejected", s)
			}
			if n == 1 && s.Phase != "recording_partial" {
				t.Fatal(s)
			}
		} else if s.Effective || s.CauseCode != "WPD_TRACE_NO_PROVIDER_ENABLED" {
			t.Fatal(s)
		}
	}
}

func TestLocalWPDTraceWaitingProvidersJoinWithoutRestartOrRepeatedEnable(t *testing.T) {
	b := &wpdCoverageBackend{data: newWPDTraceProviderSample()}
	for i := range b.data.Providers {
		b.data.Providers[i].SkipCode = "type_unknown"
	}
	c := newLocalWPDTraceController()
	armWPD(c, &b.wpdFake)
	c.backend = b
	refresh := func(registered bool) {
		t.Helper()
		calls := 0
		err := enableLocalWPDTraceProviders(func() bool { return true }, func(i int) localWPDTraceProvider {
			if b.data.Providers[i].Enabled {
				return b.data.Providers[i]
			}
			if registered {
				return localWPDTraceProvider{Kind: "modern", OtherLoggerCount: 2}
			}
			return b.data.Providers[i]
		}, func(int) uint32 { calls++; return 0 }, func(i int, p localWPDTraceProvider) { b.data.Providers[i] = p; b.data.providerCoverage() })
		if err != nil {
			t.Fatal(err)
		}
		if (!registered && calls != 0) || (registered && calls != 3) {
			t.Fatal("unexpected enable count", calls)
		}
	}
	refresh(false)
	for range 3 {
		c.step()
	}
	if s := c.snapshot(); s.Phase != "waiting_provider_registration" || s.Effective || s.Error != "" || b.starts.Load() != 1 || b.stops.Load() != 0 {
		t.Fatal(s, b.starts.Load(), b.stops.Load())
	}
	refresh(true)
	c.step()
	if s := c.snapshot(); !s.Effective || s.ProviderCoverage != "complete" || s.Error != "" || b.starts.Load() != 1 {
		t.Fatal(s, b.starts.Load())
	}
	if err := enableLocalWPDTraceProviders(func() bool { return true }, func(i int) localWPDTraceProvider { return b.data.Providers[i] }, func(int) uint32 { t.Fatal("already enabled provider re-enabled"); return 0 }, func(int, localWPDTraceProvider) {}); err != nil {
		t.Fatal(err)
	}
	c.masterChanged(false)
	c.step()
	if b.stops.Load() != 1 || c.snapshot().Effective {
		t.Fatal("waiting/recording session not closed")
	}
}
func TestLocalWPDTraceUnknownDoesNotHideNativeFailureAndCancelPreventsEnable(t *testing.T) {
	for _, code := range []string{"query_failed", "metadata_invalid", "enable_failed"} {
		err := enableLocalWPDTraceProviders(func() bool { return true }, func(i int) localWPDTraceProvider {
			if i == 1 {
				return localWPDTraceProvider{Kind: "unknown", SkipCode: code, NativeCode: 5}
			}
			return localWPDTraceProvider{Kind: "unknown", SkipCode: "type_unknown"}
		}, func(int) uint32 { t.Fatal("unsafe provider enable"); return 0 }, func(int, localWPDTraceProvider) {})
		if err == nil {
			t.Fatal("native failure hidden", code)
		}
	}
	allowed := true
	err := enableLocalWPDTraceProviders(func() bool { return allowed }, func(int) localWPDTraceProvider { allowed = false; return localWPDTraceProvider{Kind: "modern"} }, func(int) uint32 { t.Fatal("enable after cancellation"); return 0 }, func(int, localWPDTraceProvider) {})
	if err == nil {
		t.Fatal("cancellation not observed")
	}
}

func TestLocalWPDTraceRegistrationReasonsDoNotInferFromCatalog(t *testing.T) {
	for _, tc := range []struct {
		flags              uint32
		registration, kind string
	}{
		{0, "registered", "modern"}, {1, "registered", "legacy"}, {2, "pre_enabled", "unknown"}, {3, "pre_enabled", "unknown"}, {4, "unknown_flags", "unknown"},
	} {
		p := wpdTraceProviderUnusedMetadata(wpdProviderMetadata(tc.flags, 42))
		if p.InstanceCount != 1 || p.FlagsOR != tc.flags || p.Registration != tc.registration || p.Kind != tc.kind {
			t.Fatal(tc, p)
		}
	}
	p := wpdTraceProviderUnusedMetadata(make([]byte, 8))
	if p.InstanceCount != 0 || p.Registration != "no_instances" || p.Kind != "unknown" {
		t.Fatal(p)
	}
	b := wpdProviderMetadata(0, 42)
	binary.LittleEndian.PutUint32(b[24:], 2)
	p = wpdTraceProviderUnusedMetadata(b)
	if p.Registration != "invalid_enable_value" || p.Kind != "unknown" {
		t.Fatal(p)
	}
	// Installed XML metadata cannot turn a pre-enabled, unregistered provider
	// into a runtime EventRegister proof or authorize an EnableTraceEx2 call.
	p = wpdTraceProviderUnusedMetadata(wpdProviderMetadata(2, 42))
	p.Schema = "manifest"
	err := enableLocalWPDTraceProviders(func() bool { return true }, func(int) localWPDTraceProvider { return p }, func(int) uint32 { t.Fatal("catalog authorized unknown registration"); return 0 }, func(int, localWPDTraceProvider) {})
	if err != nil {
		t.Fatal("unregistered provider should keep waiting", err)
	}
}

func TestLocalWPDTraceTDHCatalogUsesNameOffsetAndPreservesGUIDBytes(t *testing.T) {
	names := []string{wpdProviders[2], "Foreign-Provider-With-A-Private-Name", wpdProviders[0], wpdProviders[1]}
	b := make([]byte, 8+24*len(names))
	binary.LittleEndian.PutUint32(b, uint32(len(names)))
	for i, name := range names {
		off := 8 + 24*i
		for j := 0; j < 16; j++ {
			b[off+j] = byte(i*16 + j + 1)
		}
		binary.LittleEndian.PutUint32(b[off+16:], uint32(i%2))
		binary.LittleEndian.PutUint32(b[off+20:], uint32(len(b)))
		for _, u := range utf16.Encode([]rune(name + "\x00")) {
			b = append(b, byte(u), byte(u>>8))
		}
	}
	got, e := wpdTraceProviderCatalog(b)
	if e != nil {
		t.Fatal(e)
	}
	for p, i := range []int{2, 3, 0} {
		if !got[p].Found || got[p].GUID[0] != byte(i*16+1) || got[p].GUID[15] != byte(i*16+16) {
			t.Fatal(p, got[p])
		}
		want := "manifest"
		if i%2 == 1 {
			want = "mof"
		}
		if got[p].Schema != want {
			t.Fatal(got[p])
		}
	}
	truncated := append([]byte(nil), b[:8+24*len(names)-1]...)
	if _, e := wpdTraceProviderCatalog(truncated); e == nil {
		t.Fatal("truncated catalog accepted")
	}
	// A duplicate exact known provider must not silently choose a GUID.
	duplicate := append([]byte(nil), b...)
	binary.LittleEndian.PutUint32(duplicate[8+24+20:], binary.LittleEndian.Uint32(b[8+20:]))
	if _, e := wpdTraceProviderCatalog(duplicate); e == nil {
		t.Fatal("ambiguous GUID accepted")
	}
}

func combineWPDProviderInstances(blocks ...[]byte) []byte {
	out := make([]byte, 8)
	binary.LittleEndian.PutUint32(out, uint32(len(blocks)))
	for i, b := range blocks {
		v := append([]byte(nil), b[8:]...)
		if i+1 < len(blocks) {
			binary.LittleEndian.PutUint32(v, uint32(len(v)))
		}
		out = append(out, v...)
	}
	return out
}

func TestLocalWPDTracePreEnableDoesNotHideRegisteredInstances(t *testing.T) {
	for _, tc := range []struct {
		name                                  string
		blocks                                [][]byte
		kind, registration, skip              string
		modern, legacy, pre, unknown, loggers uint32
	}{
		{"modern and placeholder", [][]byte{wpdProviderMetadata(0, 10), wpdProviderMetadata(2, 11)}, "modern", "registered_with_pre_enable", "", 1, 0, 1, 0, 2},
		{"placeholder before modern", [][]byte{wpdProviderMetadata(3), wpdProviderMetadata(0)}, "modern", "registered_with_pre_enable", "", 1, 0, 1, 0, 0},
		{"all placeholders", [][]byte{wpdProviderMetadata(2), wpdProviderMetadata(3, 11)}, "unknown", "pre_enabled", "type_unknown", 0, 0, 2, 0, 1},
		{"idle classic with placeholder", [][]byte{wpdProviderMetadata(1), wpdProviderMetadata(2)}, "legacy", "registered_with_pre_enable", "", 0, 1, 1, 0, 0},
		{"classic occupied in registered block", [][]byte{wpdProviderMetadata(1, 10), wpdProviderMetadata(2)}, "legacy", "registered_with_pre_enable", "legacy_in_use", 0, 1, 1, 0, 1},
		{"classic occupied in placeholder block", [][]byte{wpdProviderMetadata(1), wpdProviderMetadata(2, 11)}, "legacy", "registered_with_pre_enable", "legacy_in_use", 0, 1, 1, 0, 1},
		{"modern cannot conceal unknown flags", [][]byte{wpdProviderMetadata(0), wpdProviderMetadata(4)}, "unknown", "unknown_flags", "type_unknown", 1, 0, 0, 1, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := wpdTraceProviderUnusedMetadata(combineWPDProviderInstances(tc.blocks...))
			if p.Kind != tc.kind || p.Registration != tc.registration || p.SkipCode != tc.skip || p.ModernInstances != tc.modern || p.LegacyInstances != tc.legacy || p.PreEnabledInstances != tc.pre || p.UnknownInstances != tc.unknown || p.OtherLoggerCount != tc.loggers {
				t.Fatal(p)
			}
			calls := 0
			_ = enableLocalWPDTraceProviders(func() bool { return true }, func(int) localWPDTraceProvider { return p }, func(int) uint32 { calls++; return 0 }, func(int, localWPDTraceProvider) {})
			if (calls != 0) != (tc.skip == "") {
				t.Fatalf("unsafe enable decision: calls=%d %+v", calls, p)
			}
		})
	}
}
