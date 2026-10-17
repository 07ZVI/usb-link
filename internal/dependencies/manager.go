// Package dependencies owns official downloads, never product payloads.
package dependencies

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/sha512"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"hash"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

//go:embed catalog.json
var catalog []byte

type Asset struct {
	ID        string   `json:"id"`
	Version   string   `json:"version"`
	URL       string   `json:"url"`
	Digest    string   `json:"digest"`
	Algorithm string   `json:"algorithm"`
	MaxBytes  int64    `json:"max_bytes"`
	Features  []string `json:"features"`
	License   string   `json:"license"`
	Signer    string   `json:"signer"`
	SourceURL string   `json:"source_url,omitempty"`
}
type Status struct {
	ID       string   `json:"id"`
	Version  string   `json:"version"`
	Features []string `json:"features"`
	State    string   `json:"state"`
	Bytes    int64    `json:"bytes,omitempty"`
	Total    int64    `json:"total,omitempty"`
	Problem  string   `json:"problem,omitempty"`
}

func Catalog() []Asset {
	var c struct {
		Assets []Asset `json:"assets"`
	}
	if json.Unmarshal(catalog, &c) != nil {
		panic("invalid dependency catalog")
	}
	return c.Assets
}
func Lookup(id string) (Asset, error) {
	for _, a := range Catalog() {
		if a.ID == id {
			return a, nil
		}
	}
	return Asset{}, errors.New("DEPENDENCY_UNKNOWN")
}

// Verify and Install are platform boundaries; Install must retain official UI
// where license acceptance is required. A download is never proof of readiness.
type Platform interface {
	Root() (string, error)
	Verify(Asset, string) error
	Install(context.Context, Asset, string, string) (string, error)
	Detect(Asset, string) (string, bool)
}
type Manager struct {
	Platform       Platform
	Client         *http.Client
	work           assetWork
	rootMu         sync.Mutex
	mu             sync.Mutex
	states         map[string]Status
	Progress       func(Status)
	localSource    func(Asset) string
	offlineArchive func(Asset) string
	bundledArchive func(Asset) []byte
	observers      map[uint64]func(Status)
	nextObserver   uint64
}

// Only redistributable official Wintun/Zadig packages may be supplied by the
// product image. Catalog digest, native signatures and readiness still apply.
func (m *Manager) SetBundledArchiveSource(source func(Asset) []byte) {
	m.mu.Lock()
	m.bundledArchive = source
	m.mu.Unlock()
}

// Progress windows subscribe independently. Restoring a global callback when
// one window closes must not discard another window's updates or race a worker.
func (m *Manager) ObserveProgress(observer func(Status)) func() {
	m.mu.Lock()
	if m.observers == nil {
		m.observers = make(map[uint64]func(Status))
	}
	m.nextObserver++
	id := m.nextObserver
	m.observers[id] = observer
	m.mu.Unlock()
	return func() { m.mu.Lock(); delete(m.observers, id); m.mu.Unlock() }
}

// Application configuration selects known local archive locations, including a
// shared offline cache populated by another installer. Catalog hashes/signatures
// authorize the bytes; a product-created source receipt is not required.
func (m *Manager) SetOfflineArchiveSource(source func(Asset) string) {
	m.mu.Lock()
	m.offlineArchive = source
	m.mu.Unlock()
}

// SetLocalSource is an owner-supplied migration boundary, never a UI path.
func (m *Manager) SetLocalSource(source func(Asset) string) {
	m.mu.Lock()
	m.localSource = source
	m.mu.Unlock()
}

func (m *Manager) update(a Asset, state string, n, total int64, err error) {
	s := Status{ID: a.ID, Version: a.Version, Features: a.Features, State: state, Bytes: n, Total: total}
	if err != nil {
		s.Problem = err.Error()
	}
	m.mu.Lock()
	if m.states == nil {
		m.states = map[string]Status{}
	}
	m.states[a.ID] = s
	callbacks := make([]func(Status), 0, len(m.observers)+1)
	if m.Progress != nil {
		callbacks = append(callbacks, m.Progress)
	}
	for _, observer := range m.observers {
		if observer != nil {
			callbacks = append(callbacks, observer)
		}
	}
	m.mu.Unlock()
	for _, observer := range callbacks {
		observer(s)
	}
}
func (m *Manager) Snapshot() []Status {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := []Status{}
	for _, a := range Catalog() {
		s, ok := m.states[a.ID]
		if !ok {
			s = Status{ID: a.ID, Version: a.Version, Features: a.Features, State: "not_checked"}
		}
		out = append(out, s)
	}
	return out
}
func allowedHost(host string) bool {
	host = strings.ToLower(host)
	for _, h := range []string{"www.wintun.net", "github.com", "release-assets.githubusercontent.com", "objects.githubusercontent.com", "secure-appldnld.apple.com", "catalog.s.download.windowsupdate.com", "builds.dotnet.microsoft.com"} {
		if host == h {
			return true
		}
	}
	return false
}
func officialClient() *http.Client {
	return &http.Client{Timeout: 15 * time.Minute, CheckRedirect: func(req *http.Request, via []*http.Request) error {
		if len(via) >= 5 || req.URL.Scheme != "https" || req.URL.User != nil || !allowedHost(req.URL.Hostname()) {
			return errors.New("DEPENDENCY_REDIRECT_REJECTED")
		}
		return nil
	}}
}
func digest(a Asset) (hash.Hash, error) {
	switch a.Algorithm {
	case "sha256":
		return sha256.New(), nil
	case "sha512":
		return sha512.New(), nil
	}
	return nil, errors.New("DEPENDENCY_DIGEST_UNSUPPORTED")
}
func check(a Asset, path string) error {
	f, e := os.Open(path)
	if e != nil {
		return e
	}
	defer f.Close()
	s, e := f.Stat()
	if e != nil || !s.Mode().IsRegular() || s.Size() > a.MaxBytes {
		return errors.New("DEPENDENCY_FILE_INVALID")
	}
	h, e := digest(a)
	if e != nil {
		return e
	}
	n, e := io.Copy(h, io.LimitReader(f, a.MaxBytes+1))
	if e != nil || n > a.MaxBytes || hex.EncodeToString(h.Sum(nil)) != a.Digest {
		return errors.New("DEPENDENCY_HASH_MISMATCH")
	}
	return nil
}
func (m *Manager) Ensure(ctx context.Context, id string) (path string, err error) {
	a, e := Lookup(id)
	if e != nil {
		return "", e
	}
	return m.ensureAsset(ctx, a)
}

// DetectReady checks the current installation without downloading or installing.
// A ready runtime should not open a preparation window on every app launch.
func (m *Manager) DetectReady(ctx context.Context, id string) (string, bool, error) {
	a, err := Lookup(id)
	if err != nil {
		return "", false, err
	}
	release, err := m.work.acquire(ctx, a.ID)
	if err != nil {
		return "", false, err
	}
	defer release()
	root, err := m.root()
	if err != nil {
		return "", false, err
	}
	if err := ctx.Err(); err != nil {
		return "", false, err
	}
	path, ready := m.Platform.Detect(a, root)
	state := "missing"
	if ready {
		state = "ready"
	}
	m.update(a, state, 0, 0, nil)
	return path, ready, nil
}

func (m *Manager) ensureAsset(ctx context.Context, a Asset) (path string, err error) {
	release, e := m.work.acquire(ctx, a.ID)
	if e != nil {
		return "", e
	}
	defer release()
	defer func() {
		if err != nil {
			state := "failed"
			if errors.Is(err, context.Canceled) {
				state = "cancelled"
			}
			m.update(a, state, 0, 0, err)
		}
	}()
	root, e := m.root()
	if e != nil {
		return "", e
	}
	m.update(a, "detecting", 0, 0, nil)
	if p, ok := m.Platform.Detect(a, root); ok {
		m.update(a, "ready", 0, 0, nil)
		return p, nil
	}
	m.mu.Lock()
	source := m.localSource
	m.mu.Unlock()
	if source != nil && a.ID == "wintun" {
		if local := source(a); local != "" {
			if reuse, ok := m.Platform.(interface {
				ReuseWintun(context.Context, Asset, string, string) error
			}); ok {
				if err := reuse.ReuseWintun(ctx, a, local, root); err != nil {
					return "", err
				}
				if p, ready := m.Platform.Detect(a, root); ready {
					m.update(a, "ready", 0, 0, nil)
					return p, nil
				}
				return "", errors.New("DEPENDENCY_REUSE_READBACK_FAILED")
			}
		}
	}
	u, e := url.Parse(a.URL)
	if e != nil || u.Scheme != "https" || u.User != nil || !allowedHost(u.Hostname()) {
		return "", errors.New("DEPENDENCY_SOURCE_REJECTED")
	}
	archive := filepath.Join(root, a.ID+"-"+a.Version+"-"+a.Digest[:16]+filepath.Ext(u.Path))
	if e = check(a, archive); e != nil {
		if _, stat := os.Lstat(archive); stat == nil {
			return "", errors.New("DEPENDENCY_CACHE_CORRUPTED")
		}
		m.mu.Lock()
		bundled := m.bundledArchive
		m.mu.Unlock()
		if bundled != nil && (a.ID == "wintun" || a.ID == "zadig") {
			if data := bundled(a); len(data) != 0 {
				if err := copyPinnedArchiveReader(ctx, a, bytes.NewReader(data), archive); err != nil {
					return "", err
				}
			}
		}
	}
	if e = check(a, archive); e != nil {
		m.mu.Lock()
		offline := m.offlineArchive
		m.mu.Unlock()
		if offline != nil {
			if source := offline(a); source != "" {
				if err := copyPinnedArchive(ctx, a, source, archive); err != nil {
					return "", err
				}
			}
		}
	}
	if e = check(a, archive); e != nil {
		temp, e := os.CreateTemp(root, "download-")
		if e != nil {
			return "", e
		}
		temporary := temp.Name()
		defer os.Remove(temporary)
		req, e := http.NewRequestWithContext(ctx, "GET", a.URL, nil)
		if e != nil {
			temp.Close()
			return "", e
		}
		client := m.Client
		if client == nil {
			client = officialClient()
		}
		response, e := client.Do(req)
		if e != nil {
			temp.Close()
			return "", fmt.Errorf("DEPENDENCY_NETWORK_UNAVAILABLE: %s required for %s: %w", a.ID, strings.Join(a.Features, ", "), e)
		}
		defer response.Body.Close()
		if response.StatusCode != 200 || response.ContentLength > a.MaxBytes {
			temp.Close()
			return "", errors.New("DEPENDENCY_DOWNLOAD_REJECTED")
		}
		m.update(a, "downloading", 0, response.ContentLength, nil)
		buf := make([]byte, 64<<10)
		var n int64
		for {
			count, re := response.Body.Read(buf)
			if count > 0 {
				n += int64(count)
				if n > a.MaxBytes {
					temp.Close()
					return "", errors.New("DEPENDENCY_SIZE_LIMIT")
				}
				if _, e = temp.Write(buf[:count]); e != nil {
					temp.Close()
					return "", e
				}
				m.update(a, "downloading", n, response.ContentLength, nil)
			}
			if re == io.EOF {
				break
			}
			if re != nil {
				temp.Close()
				return "", re
			}
			if e = ctx.Err(); e != nil {
				temp.Close()
				return "", e
			}
		}
		if e = temp.Close(); e != nil {
			return "", e
		}
		if e = check(a, temporary); e != nil {
			return "", e
		}
		if e = m.Platform.Verify(a, temporary); e != nil {
			return "", e
		}
		if e = os.Rename(temporary, archive); e != nil {
			return "", e
		}
	}
	if e = m.Platform.Verify(a, archive); e != nil {
		return "", e
	}
	m.update(a, "installing", 0, 0, nil)
	path, e = m.Platform.Install(ctx, a, archive, root)
	if e != nil {
		return "", e
	}
	if p, ok := m.Platform.Detect(a, root); !ok {
		return "", errors.New("DEPENDENCY_INSTALL_READBACK_FAILED")
	} else {
		path = p
	}
	m.update(a, "ready", 0, 0, nil)
	return path, nil
}

// Refresh detects availability without downloading or changing system state.
func (m *Manager) Refresh() {
	root, e := m.root()
	if e != nil {
		return
	}
	for _, a := range Catalog() {
		release, available := m.work.tryAcquire(a.ID)
		if !available {
			continue // Keep an active preparation's progress and readiness intact.
		}
		if _, ok := m.Platform.Detect(a, root); ok {
			m.update(a, "ready", 0, 0, nil)
		} else {
			m.update(a, "missing", 0, 0, nil)
		}
		release()
	}
}

func (m *Manager) root() (string, error) {
	m.rootMu.Lock()
	defer m.rootMu.Unlock()
	if m.Platform == nil {
		return "", errors.New("DEPENDENCY_PLATFORM_UNCONFIGURED")
	}
	return m.Platform.Root()
}
