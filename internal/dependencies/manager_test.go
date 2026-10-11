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
	"testing"
)

type testPlatform struct {
	root      string
	ready     bool
	verifyErr error
	installs  int
	reads     bool
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
