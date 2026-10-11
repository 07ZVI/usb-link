// Package fileshare manages selected folders and the USB compatibility SMB service.
package fileshare

import (
	"context"
	"fmt"
	"io"
	"os"
	"path"
	"strings"
	"sync"
	"sync/atomic"
)

type State struct {
	Enabled atomic.Bool
	Native  atomic.Bool
}

var USB State

type shareFile interface {
	io.Reader
	io.Writer
	io.Seeker
	io.Closer
	Readdir(int) ([]os.FileInfo, error)
	Stat() (os.FileInfo, error)
}

type Server struct {
	catalog   *Catalog
	State     *State
	Peer      string
	Guard     func() bool
	slots     chan struct{}
	smbOnce   sync.Once
	smbEngine smbEngine
	smbError  error
}

func NewMulti(c *Catalog, peer string, state *State, guard func() bool) (*Server, error) {
	if c == nil {
		return nil, fmt.Errorf("SHARE_CATALOG_UNAVAILABLE")
	}
	s := &Server{catalog: c, State: state, Peer: peer, Guard: guard, slots: make(chan struct{}, 4)}
	if state == nil || !state.Native.Load() {
		if err := s.prepareSMB(); err != nil {
			return nil, err
		}
	}
	return s, nil
}

// The catalog is shared between device sessions and owned by the installer.
func (s *Server) Close() error { return nil }

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
func (f rootFS) OpenFile(ctx context.Context, n string, flag int, p os.FileMode) (shareFile, error) {
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
