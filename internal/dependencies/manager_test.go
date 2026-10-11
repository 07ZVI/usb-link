package dependencies

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"net/http"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type testPlatform struct {
	root      string
	ready     bool
	verifyErr error
	installs  int
	reads     bool
}

type concurrentPlatform struct {
	root     string
	mu       sync.Mutex
	ready    map[string]bool
	installs int
	entered  chan struct{}
	resume   chan struct{}
}

func (p *concurrentPlatform) Root() (string, error)      { return p.root, nil }
func (p *concurrentPlatform) Verify(Asset, string) error { return nil }
func (p *concurrentPlatform) Detect(a Asset, root string) (string, bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	return root, p.ready[a.ID]
}
func (p *concurrentPlatform) Install(ctx context.Context, a Asset, archive, root string) (string, error) {
	p.mu.Lock()
	p.installs++
	p.mu.Unlock()
	close(p.entered)
	select {
	case <-p.resume:
	case <-ctx.Done():
		return "", ctx.Err()
	}
	p.mu.Lock()
	p.ready[a.ID] = true
	p.mu.Unlock()
	return root, nil
}

func TestSlowPreparationDoesNotBlockAvailableComponentOrCancelledWaiter(t *testing.T) {
	m, _, a := fixture(t, "verified")
	p := &concurrentPlatform{root: t.TempDir(), ready: map[string]bool{"wintun": true}, entered: make(chan struct{}), resume: make(chan struct{})}
	m.Platform = p
	finished := make(chan error, 1)
	go func() { _, err := m.ensureAsset(context.Background(), a); finished <- err }()
	select {
	case <-p.entered:
	case <-time.After(2 * time.Second):
		t.Fatal("preparation never started")
	}
	defer close(p.resume)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if _, err := m.Ensure(ctx, "wintun"); err != nil {
		t.Fatalf("ready USB component blocked: %v", err)
	}
	waitCtx, waitCancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer waitCancel()
	if _, err := m.ensureAsset(waitCtx, a); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("queued cancellation: %v", err)
	}
	p.mu.Lock()
	n := p.installs
	p.mu.Unlock()
	if n != 1 {
		t.Fatalf("duplicate installation while busy: %d", n)
	}
	// Resume explicitly, then replace the deferred close to await orderly exit.
	p.resume <- struct{}{}
	if err := <-finished; err != nil {
		t.Fatal(err)
	}
	if _, err := m.ensureAsset(context.Background(), a); err != nil {
		t.Fatal(err)
	}
	p.mu.Lock()
	n = p.installs
	p.mu.Unlock()
	if n != 1 {
		t.Fatalf("ready component reinstalled: %d", n)
	}
}

func TestRefreshPreservesActivePreparationProgressAndChecksOtherComponents(t *testing.T) {
	m, _, _ := fixture(t, "verified")
	p := &concurrentPlatform{root: t.TempDir(), ready: map[string]bool{"wintun": true}}
	m.Platform = p
	a, _ := Lookup("dotnet")
	release, err := m.work.acquire(context.Background(), a.ID)
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	m.update(a, "downloading", 123, 456, nil)
	m.Refresh()
	for _, s := range m.Snapshot() {
		if s.ID == "dotnet" && (s.State != "downloading" || s.Bytes != 123) {
			t.Fatalf("progress overwritten: %+v", s)
		}
		if s.ID == "wintun" && s.State != "ready" {
			t.Fatalf("USB readiness not refreshed: %+v", s)
		}
	}
}

func TestIndependentProgressObserversSurviveClosingAnotherWindow(t *testing.T) {
	m, _, a := fixture(t, "verified")
	var first, second atomic.Int32
	unsubscribeFirst := m.ObserveProgress(func(Status) { first.Add(1) })
	unsubscribeSecond := m.ObserveProgress(func(Status) { second.Add(1) })
	defer unsubscribeSecond()
	m.update(a, "detecting", 0, 0, nil)
	unsubscribeFirst()
	m.update(a, "ready", 0, 0, nil)
	if first.Load() != 1 || second.Load() != 2 {
		t.Fatal(first.Load(), second.Load())
	}
	// A closing observer may overlap an update already captured by the worker.
	var workers sync.WaitGroup
	for i := 0; i < 20; i++ {
		workers.Add(1)
		go func() {
			defer workers.Done()
			close := m.ObserveProgress(func(Status) {})
			m.update(a, "ready", 0, 0, nil)
			close()
		}()
	}
	workers.Wait()
}

func (p *testPlatform) Root() (string, error)               { return p.root, nil }
func (p *testPlatform) Verify(Asset, string) error          { return p.verifyErr }
func (p *testPlatform) Detect(Asset, string) (string, bool) { return p.root, p.ready }
func (p *testPlatform) Install(ctx context.Context, a Asset, path, root string) (string, error) {
	p.installs++
	p.ready = p.reads
	return root, nil
}

type roundTrip func(*http.Request) (*http.Response, error)

func (f roundTrip) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }
func fixture(t *testing.T, body string) (*Manager, *testPlatform, Asset) {
	t.Helper()
	h := sha256.Sum256([]byte(body))
	a := Asset{ID: "fixture", Version: "1", URL: "https://www.wintun.net/fixture.zip", Digest: hex.EncodeToString(h[:]), Algorithm: "sha256", MaxBytes: 1024, Features: []string{"mac"}}
	p := &testPlatform{root: t.TempDir(), reads: true}
	m := &Manager{Platform: p, Client: &http.Client{Transport: roundTrip(func(r *http.Request) (*http.Response, error) {
		if e := r.Context().Err(); e != nil {
			return nil, e
		}
		return &http.Response{StatusCode: 200, ContentLength: int64(len(body)), Body: io.NopCloser(strings.NewReader(body))}, nil
	})}}
	return m, p, a
}
func TestDetectReuseInstallReadbackAndRepeatedLaunch(t *testing.T) {
	m, p, a := fixture(t, "verified")
	if _, e := m.ensureAsset(context.Background(), a); e != nil {
		t.Fatal(e)
	}
	if _, e := m.ensureAsset(context.Background(), a); e != nil || p.installs != 1 {
		t.Fatal(e, p.installs)
	}
}

func TestAlreadyUsableComponentNeedsNoProductReceiptOrInstaller(t *testing.T) {
	for _, a := range Catalog() {
		t.Run(a.ID, func(t *testing.T) {
			m, p, _ := fixture(t, "unused download")
			p.ready = true // An external/system installation is already usable.
			m.Client.Transport = roundTrip(func(*http.Request) (*http.Response, error) {
				t.Fatal("already installed component was downloaded again")
				return nil, errors.New("unexpected network")
			})
			for range 2 {
				if _, e := m.ensureAsset(context.Background(), a); e != nil {
					t.Fatal(e)
				}
			}
			if p.installs != 0 {
				t.Fatal("already installed component was installed again")
			}
		})
	}
}
func TestDamageSignatureOfflineCancellationAndReadbackFailClosed(t *testing.T) {
	for _, kind := range []string{"damage", "signature", "offline", "cancel", "readback"} {
		t.Run(kind, func(t *testing.T) {
			m, p, a := fixture(t, "verified")
			ctx := context.Background()
			switch kind {
			case "damage":
				a.Digest = strings.Repeat("0", 64)
			case "signature":
				p.verifyErr = errors.New("bad signature")
			case "offline":
				m.Client.Transport = roundTrip(func(*http.Request) (*http.Response, error) { return nil, errors.New("offline") })
			case "cancel":
				c, cancel := context.WithCancel(ctx)
				cancel()
				ctx = c
			case "readback":
				p.reads = false
			}
			if _, e := m.ensureAsset(ctx, a); e == nil {
				t.Fatal("unsafe readiness")
			}
			if kind != "readback" && p.installs != 0 {
				t.Fatal("unverified install")
			}
			entries, _ := os.ReadDir(p.root)
			for _, f := range entries {
				if strings.HasPrefix(f.Name(), "download-") {
					t.Fatal("partial retained")
				}
			}
		})
	}
}
func TestCorruptedCacheNeverOverwritten(t *testing.T) {
	m, p, a := fixture(t, "verified")
	if _, e := m.ensureAsset(context.Background(), a); e != nil {
		t.Fatal(e)
	}
	p.ready = false
	entries, _ := os.ReadDir(p.root)
	path := p.root + "/" + entries[0].Name()
	_ = os.WriteFile(path, []byte("corrupted"), 0600)
	if _, e := m.ensureAsset(context.Background(), a); e == nil {
		t.Fatal("cache accepted")
	}
	b, _ := os.ReadFile(path)
	if string(b) != "corrupted" {
		t.Fatal("unproven cache overwritten")
	}
}
func TestOfficialCatalogAndRedirectBoundary(t *testing.T) {
	for _, a := range Catalog() {
		if a.Version == "" || a.Features == nil || a.License == "" {
			t.Fatal(a.ID)
		}
		if _, e := digest(a); e != nil {
			t.Fatal(e)
		}
	}
	c := officialClient()
	for _, u := range []string{"http://www.wintun.net/test", "https://evil.example/test", "https://user@github.com/test"} {
		r, _ := http.NewRequest("GET", u, nil)
		if c.CheckRedirect(r, nil) == nil {
			t.Fatal(u)
		}
	}
}
