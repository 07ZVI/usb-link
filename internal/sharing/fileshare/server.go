// Package fileshare exposes one explicitly enabled directory over USB WebDAV.
package fileshare

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/net/webdav"
)

// State belongs to the local UI. Sharing is off until explicitly enabled.
type State struct {
	Enabled atomic.Bool
	Native  atomic.Bool
}

var USB State

const URL = "http://10.6.9.1:10690/share/"

type Server struct {
	root      *os.Root
	catalog   *Catalog
	dav       *webdav.Handler
	State     *State
	Peer      string
	Guard     func() bool
	slots     chan struct{}
	smbOnce   sync.Once
	smbEngine smbEngine
	smbError  error
}

func New(dir, peer string, state *State, guard func() bool) (*Server, error) {
	r, e := os.OpenRoot(dir)
	if e != nil {
		return nil, e
	}
	s := &Server{root: r, State: state, Peer: peer, Guard: guard, slots: make(chan struct{}, 4)}
	s.dav = &webdav.Handler{Prefix: "/share", FileSystem: rootFS{r}, LockSystem: webdav.NewMemLS()}
	return s, nil
}
func NewMulti(c *Catalog, peer string, state *State, guard func() bool) (*Server, error) {
	if c == nil {
		return nil, fmt.Errorf("SHARE_CATALOG_UNAVAILABLE")
	}
	s := &Server{catalog: c, State: state, Peer: peer, Guard: guard, slots: make(chan struct{}, 4)}
	s.dav = &webdav.Handler{Prefix: "/share", FileSystem: catalogFS{c}, LockSystem: webdav.NewMemLS()}
	if state == nil || !state.Native.Load() {
		if err := s.prepareSMB(); err != nil {
			return nil, err
		}
	}
	return s, nil
}
func (s *Server) Close() error {
	if s.root != nil {
		return s.root.Close()
	}
	return nil
}
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if s.State != nil && s.State.Native.Load() {
		http.Error(w, "Use Windows SMB on port 445", http.StatusGone)
		return
	}
	peer, _, e := net.SplitHostPort(r.RemoteAddr)
	if e != nil || peer != s.Peer || s.State == nil || !s.State.Enabled.Load() || s.Guard == nil || !s.Guard() {
		http.Error(w, "USB sharing is not enabled", http.StatusForbidden)
		return
	}
	if r.URL.Path != "/share" && !strings.HasPrefix(r.URL.Path, "/share/") {
		http.NotFound(w, r)
		return
	}
	// Finder uses OPTIONS, PROPFIND, LOCK, PUT, MOVE and related DAV methods.
	// Restrict resources and concurrency without buffering file content in RAM.
	select {
	case s.slots <- struct{}{}:
		defer func() { <-s.slots }()
	default:
		http.Error(w, "Share busy", 503)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 64<<30)
	if r.Method == "PROPFIND" && r.Header.Get("Depth") == "" {
		r.Header.Set("Depth", "1")
	}
	if r.Method == "PROPFIND" && r.Header.Get("Depth") == "infinity" {
		http.Error(w, "Use depth zero or one", 403)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	controller := http.NewResponseController(w)
	controller.SetReadDeadline(time.Now().Add(30 * time.Second))
	controller.SetWriteDeadline(time.Now().Add(30 * time.Second))
	selected := func() bool { return true }
	if s.catalog != nil {
		selected = s.catalog.allowed(r.URL.Path)
	}
	allowed := func() bool { return s.State.Enabled.Load() && s.Guard() != false && selected() }
	r.Body = &activeBody{ReadCloser: r.Body, controller: controller, allowed: allowed}
	s.dav.ServeHTTP(&activeResponse{ResponseWriter: w, controller: controller, allowed: allowed}, r)
}

type rootFS struct{ r *os.Root }

func clean(n string) (string, error) {
	if n == "." {
		return ".", nil
	} // rooted filesystem sentinel, never a parent traversal
	if strings.ContainsAny(n, "\\:\x00") {
		return "", os.ErrPermission
	}
	for _, p := range strings.Split(n, "/") {
		if p == ".." || strings.HasSuffix(p, ".") || strings.HasSuffix(p, " ") {
			return "", os.ErrPermission
		}
		base := strings.ToUpper(strings.SplitN(p, ".", 2)[0])
		if base == "CON" || base == "NUL" || base == "AUX" || base == "PRN" || len(base) == 4 && (strings.HasPrefix(base, "COM") || strings.HasPrefix(base, "LPT")) && base[3] >= '0' && base[3] <= '9' {
			return "", os.ErrPermission
		}
	}
	n = strings.TrimPrefix(path.Clean("/"+n), "/")
	if n == "" {
		n = "."
	}
	return n, nil
}
func (f rootFS) Mkdir(ctx context.Context, n string, p os.FileMode) error {
	n, e := clean(n)
	if e != nil {
		return e
	}
	return f.r.Mkdir(n, p)
}
func (f rootFS) OpenFile(ctx context.Context, n string, flag int, p os.FileMode) (webdav.File, error) {
	n, e := clean(n)
	if e != nil {
		return nil, e
	}
	// Check the opened handle before truncation: an existing hard link must
	// never turn an elevated write into a write outside the shared directory.
	h, e := f.r.OpenFile(n, flag&^os.O_TRUNC, p)
	if e != nil {
		return nil, e
	}
	if e = singleLink(h); e != nil {
		h.Close()
		return nil, e
	}
	if flag&os.O_TRUNC != 0 {
		if e = h.Truncate(0); e != nil {
			h.Close()
			return nil, e
		}
	}
	return h, nil
}
func (f rootFS) Stat(ctx context.Context, n string) (os.FileInfo, error) {
	n, e := clean(n)
	if e != nil {
		return nil, e
	}
	return f.r.Stat(n)
}
func (f rootFS) RemoveAll(ctx context.Context, n string) error {
	n, e := clean(n)
	if e != nil {
		return e
	}
	if n == "." {
		return fmt.Errorf("cannot remove share root")
	}
	return f.r.RemoveAll(n)
}
func (f rootFS) Rename(ctx context.Context, old, new string) error {
	a, e := clean(old)
	if e != nil {
		return e
	}
	b, e := clean(new)
	if e != nil {
		return e
	}
	if a == "." || b == "." {
		return os.ErrPermission
	}
	return f.r.Rename(a, b)
}

// Progress-based deadlines allow large files without permitting a stalled peer
// to retain a file descriptor forever. Revocation interrupts active transfers.
type activeBody struct {
	io.ReadCloser
	controller *http.ResponseController
	allowed    func() bool
}

func (b *activeBody) Read(p []byte) (int, error) {
	if !b.allowed() {
		return 0, os.ErrPermission
	}
	b.controller.SetReadDeadline(time.Now().Add(30 * time.Second))
	return b.ReadCloser.Read(p)
}

type activeResponse struct {
	http.ResponseWriter
	controller *http.ResponseController
	allowed    func() bool
}

func (w *activeResponse) Write(p []byte) (int, error) {
	if !w.allowed() {
		return 0, os.ErrPermission
	}
	w.controller.SetWriteDeadline(time.Now().Add(30 * time.Second))
	return w.ResponseWriter.Write(p)
}
