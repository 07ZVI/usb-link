package fileshare

import (
	"context"
	"errors"
	"io"
	"iter"
	"log/slog"
	"net"
	"os"
	"path"
	"sort"
	"strings"
	"sync"
	"time"

	"suhang/usbnet/internal/sharing/smbcore/ntlmssp"
	"suhang/usbnet/internal/sharing/smbcore/server"
	"suhang/usbnet/internal/sharing/smbcore/vfs"
)

const SMBURL = "smb://10.6.9.1:10690/USB"

func SMBConnectURL() string {
	if USB.Native.Load() {
		return "smb://10.6.9.1"
	}
	return SMBURL
}
func smbShareURL() string { return SMBURL }

type smbEngine interface {
	ServeUSBConnection(context.Context, net.Conn)
}

func (s *Server) prepareSMB() error {
	s.smbOnce.Do(func() {
		backend := &smbCatalog{s: s, ctx: context.Background()}
		s.smbEngine, s.smbError = server.New(server.WithAuth(ntlmssp.NewUSBGuestServer()), server.WithNegotiationToken(ntlmssp.NegotiationToken()), server.WithMaxCredits(32), server.WithObserver(func(command uint16, status uint32) { smbObserve(s.Peer, command, status) }), server.WithShares(vfs.NewDiskShare("USB", backend)), server.WithShareAlias("USB Link", "USB"), server.WithLogger(slog.New(slog.NewTextHandler(io.Discard, nil))))
	})
	return s.smbError
}

// ServeSMB uses the selected folder catalog and explicit sharing consent. It never exports a local
// path directly, creates a Windows account, or opens a listener on other NICs.
func (s *Server) ServeSMB(ctx context.Context, conn net.Conn) {
	defer conn.Close()
	defer smbConnection(s.Peer)()
	peer, _, err := net.SplitHostPort(conn.RemoteAddr().String())
	if err != nil || peer != s.Peer || s.catalog == nil || !s.smbAllowed(ctx) {
		smbRecord(s.Peer, func(v *SMBTrace) { v.Rejected++ })
		return
	}
	select {
	case s.slots <- struct{}{}:
		defer func() { <-s.slots }()
	default:
		return
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	if s.prepareSMB() != nil {
		return
	}
	// Sharing revocation interrupts idle and active connections as well as VFS
	// calls. A removed folder separately revokes every handle into that folder.
	go func() {
		ticker := time.NewTicker(250 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				if !s.smbAllowed(ctx) {
					cancel()
					conn.Close()
					return
				}
			}
		}
	}()
	s.smbEngine.ServeUSBConnection(ctx, conn)
}

func (s *Server) smbAllowed(ctx context.Context) bool {
	return ctx.Err() == nil && s.State != nil && !s.State.Native.Load() && s.State.Enabled.Load() && s.Guard != nil && s.Guard()
}

type smbCatalog struct {
	s   *Server
	ctx context.Context
}

// Display names are stable across enumeration and opening. Duplicate folder
// names get their local, persistent catalog ID as a disambiguator.
func (b *smbCatalog) names() map[string]Folder {
	rows := b.s.catalog.List()
	names := smbFolderNames(rows)
	out := map[string]Folder{}
	for _, r := range rows {
		out[names[r.ID]] = r
	}
	return out
}

func smbFolderNames(rows []Folder) map[string]string {
	counts := map[string]int{}
	for _, r := range rows {
		counts[strings.ToLower(r.Name)]++
	}
	out := map[string]string{}
	for _, r := range rows {
		name := r.Name
		if counts[strings.ToLower(name)] > 1 {
			name += " (" + r.ID + ")"
		}
		out[r.ID] = name
	}
	return out
}

func (b *smbCatalog) resolve(n string) (string, func() bool, error) {
	if !b.s.smbAllowed(b.ctx) {
		return "", nil, os.ErrPermission
	}
	n = strings.ReplaceAll(n, "\\", "/")
	n, err := clean(n)
	if err != nil {
		return "", nil, err
	}
	if n == "." {
		return ".", func() bool { return b.s.smbAllowed(b.ctx) }, nil
	}
	name, sub, _ := strings.Cut(n, "/")
	for display, f := range b.names() {
		if strings.EqualFold(name, display) && f.Available {
			p := f.ID
			if sub != "" {
				p += "/" + sub
			}
			folder := b.s.catalog.allowed(p)
			return p, func() bool { return b.s.smbAllowed(b.ctx) && folder() }, nil
		}
	}
	return "", nil, os.ErrNotExist
}

func (b *smbCatalog) Open(ctx context.Context, opts vfs.OpenOptions) (vfs.Handle, error) {
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	p, allowed, err := b.resolve(opts.Path)
	if err != nil {
		return nil, err
	}
	f := catalogFS{b.s.catalog}
	info, statErr := f.Stat(ctx, p)
	if opts.Disposition > vfs.DispositionOverwriteIf {
		return nil, os.ErrPermission
	}
	writable := opts.DesiredAccess&(0x10000000|0x40000000|0x00000002|0x00000004) != 0
	metadata := opts.DesiredAccess&(0x10000000|0x40000000|0x00000100) != 0
	flags := os.O_RDONLY
	if writable || metadata {
		flags = os.O_RDWR
	}
	switch opts.Disposition {
	case vfs.DispositionCreate:
		flags |= os.O_CREATE | os.O_EXCL
	case vfs.DispositionOpen:
		if statErr != nil {
			return nil, statErr
		}
	case vfs.DispositionOpenIf:
		flags |= os.O_CREATE
	case vfs.DispositionOverwrite:
		if statErr != nil {
			return nil, statErr
		}
		flags |= os.O_TRUNC
	case vfs.DispositionSupersede, vfs.DispositionOverwriteIf:
		flags |= os.O_CREATE | os.O_TRUNC
	}
	if (flags&os.O_TRUNC != 0 || (flags&os.O_CREATE != 0 && statErr != nil)) && !opts.CreateDir && !writable {
		return nil, os.ErrPermission
	}
	if opts.CreateDir {
		if statErr != nil {
			if !errors.Is(statErr, os.ErrNotExist) || (opts.Disposition != vfs.DispositionCreate && opts.Disposition != vfs.DispositionOpenIf) {
				return nil, statErr
			}
			if err := f.Mkdir(ctx, p, 0755); err != nil {
				return nil, err
			}
		} else if !info.IsDir() {
			return nil, os.ErrPermission
		} else if opts.Disposition == vfs.DispositionCreate {
			return nil, os.ErrExist
		}
		flags = smbDirectoryOpenFlags(metadata)
	} else if statErr == nil && info.IsDir() {
		if flags&os.O_TRUNC != 0 {
			return nil, os.ErrPermission
		}
		flags = smbDirectoryOpenFlags(metadata)
	}
	var file shareFile
	if p == "." {
		// The catalog root has no mutable filesystem backing, even if the
		// client asks for directory metadata access while browsing.
		writable = false
		rows := []os.FileInfo{}
		for name, folder := range b.names() {
			if !folder.Available {
				continue
			}
			rows = append(rows, virtualInfo{name: name, dir: true})
		}
		sort.Slice(rows, func(i, j int) bool { return rows[i].Name() < rows[j].Name() })
		file = &virtualDirectory{rows: rows}
	} else {
		file, err = f.OpenFile(ctx, p, flags, 0644)
		if err != nil {
			return nil, err
		}
	}
	return &smbFile{f: file, b: b, path: p, display: opts.Path, allowed: allowed, writable: writable}, nil
}

func (b *smbCatalog) Remove(ctx context.Context, name string) error {
	p, _, err := b.resolve(name)
	if err != nil {
		return err
	}
	c := b.s.catalog
	c.mu.RLock()
	defer c.mu.RUnlock()
	m, sub, err := c.lookup(p)
	if err != nil {
		return err
	}
	if m == nil || sub == "." {
		return os.ErrPermission
	}
	// SMB directory deletion is non-recursive; client must remove its contents.
	return c.user(func() error { return m.root.Remove(sub) })
}

type smbFile struct {
	mu       sync.Mutex
	f        shareFile
	b        *smbCatalog
	path     string
	display  string
	allowed  func() bool
	writable bool
	closed   bool
	locks    int
}

func (h *smbFile) check(ctx context.Context) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if h.closed || !h.allowed() {
		return os.ErrPermission
	}
	return nil
}
func (h *smbFile) Read(ctx context.Context, offset int64, p []byte) (int, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if err := h.check(ctx); err != nil {
		return 0, err
	}
	if offset < 0 || !vfs.ValidFileRange(uint64(offset), uint64(len(p))) {
		return 0, os.ErrPermission
	}
	if _, err := h.f.Seek(offset, io.SeekStart); err != nil {
		return 0, err
	}
	return h.f.Read(p)
}
func (h *smbFile) Write(ctx context.Context, offset int64, p []byte) (int, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if err := h.check(ctx); err != nil {
		return 0, err
	}
	if !h.writable || offset < 0 || !vfs.ValidFileRange(uint64(offset), uint64(len(p))) {
		return 0, os.ErrPermission
	}
	if f, ok := h.f.(*os.File); ok {
		if err := singleLink(f); err != nil {
			return 0, err
		}
	}
	if _, err := h.f.Seek(offset, io.SeekStart); err != nil {
		return 0, err
	}
	return h.f.Write(p)
}
func (h *smbFile) Close(context.Context) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.closed {
		return nil
	}
	h.closed = true
	return h.f.Close()
}
func smbInfo(name string, info os.FileInfo) vfs.FileInfo {
	return vfs.FileInfo{Name: name, Size: info.Size(), IsDir: info.IsDir(), CreationTime: info.ModTime(), LastAccess: info.ModTime(), LastWrite: info.ModTime(), ChangeTime: info.ModTime()}
}
func (h *smbFile) Stat(ctx context.Context) (vfs.FileInfo, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if err := h.check(ctx); err != nil {
		return vfs.FileInfo{}, err
	}
	info, err := h.f.Stat()
	if err != nil {
		return vfs.FileInfo{}, err
	}
	return smbInfo(path.Base(strings.ReplaceAll(h.display, "\\", "/")), info), nil
}
func (h *smbFile) Enumerate(ctx context.Context, pattern string) iter.Seq2[vfs.FileInfo, error] {
	return func(yield func(vfs.FileInfo, error) bool) {
		for {
			h.mu.Lock()
			err := h.check(ctx)
			var rows []os.FileInfo
			if err == nil {
				rows, err = h.f.Readdir(1)
			}
			h.mu.Unlock()
			if err != nil {
				if err != io.EOF {
					yield(vfs.FileInfo{}, err)
				}
				return
			}
			for _, row := range rows {
				match := smbMatchName(pattern, row.Name())
				if match && !yield(smbInfo(row.Name(), row), nil) {
					return
				}
			}
		}
	}
}
func (h *smbFile) ResetEnumeration() error {
	h.mu.Lock()
	defer h.mu.Unlock()
	if err := h.check(context.Background()); err != nil {
		return err
	}
	var next shareFile
	if h.path == "." {
		rows := []os.FileInfo{}
		for name, folder := range h.b.names() {
			if !folder.Available {
				continue
			}
			rows = append(rows, virtualInfo{name: name, dir: true})
		}
		sort.Slice(rows, func(i, j int) bool { return rows[i].Name() < rows[j].Name() })
		next = &virtualDirectory{rows: rows}
	} else {
		var err error
		next, err = (catalogFS{h.b.s.catalog}).OpenFile(context.Background(), h.path, os.O_RDONLY, 0)
		if err != nil {
			return err
		}
	}
	old := h.f
	h.f = next
	return old.Close()
}
func (h *smbFile) SetInfo(ctx context.Context, info *vfs.SetInfoRequest) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	if err := h.check(ctx); err != nil {
		return err
	}
	if info.EndOfFile != nil {
		f, ok := h.f.(*os.File)
		if !ok || !h.writable || *info.EndOfFile < 0 {
			return os.ErrPermission
		}
		if err := singleLink(f); err != nil {
			return err
		}
		if err := f.Truncate(*info.EndOfFile); err != nil {
			return err
		}
	}
	if info.LastWriteTime != nil || info.LastAccessTime != nil || info.CreationTime != nil {
		c := h.b.s.catalog
		file, ok := h.f.(*os.File)
		if !ok {
			return os.ErrPermission
		}
		current, err := h.f.Stat()
		if err != nil {
			return err
		}
		atime, mtime := current.ModTime(), current.ModTime()
		if info.LastAccessTime != nil {
			atime = *info.LastAccessTime
		}
		if info.LastWriteTime != nil {
			mtime = *info.LastWriteTime
		}
		if current.IsDir() {
			c.mu.RLock()
			defer c.mu.RUnlock()
			m, sub, err := c.lookup(h.path)
			if err != nil || m == nil || !m.active.Load() {
				return os.ErrPermission
			}
			// Verify the selected path still identifies this opened directory, then
			// update the handle as the desktop user instead of reopening a path.
			return c.user(func() error {
				atPath, e := m.root.Lstat(sub)
				if e != nil {
					return e
				}
				if !os.SameFile(current, atPath) {
					return os.ErrPermission
				}
				return smbSetDirectoryTimes(file, info, atime, mtime)
			})
		}
		return c.user(func() error { return smbSetFileTimes(file, info, atime, mtime) })
	}
	return nil
}

func (h *smbFile) Flush(ctx context.Context) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	if err := h.check(ctx); err != nil {
		return err
	}
	if f, ok := h.f.(*os.File); ok && h.writable {
		return f.Sync()
	}
	return nil
}

func (h *smbFile) VolumeInfo(ctx context.Context) (vfs.VolumeInfo, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if err := h.check(ctx); err != nil {
		return vfs.VolumeInfo{}, err
	}
	c := h.b.s.catalog
	c.mu.RLock()
	defer c.mu.RUnlock()
	selected, _, err := c.lookup(h.path)
	if err != nil {
		return vfs.VolumeInfo{}, err
	}
	seen := map[string]bool{}
	var result vfs.VolumeInfo
	for _, m := range c.folders {
		if !m.active.Load() || selected != nil && m != selected {
			continue
		}
		var key string
		var total, free uint64
		err := c.user(func() error { var e error; key, total, free, e = smbDiskSpace(m.Path); return e })
		if err != nil {
			return vfs.VolumeInfo{}, err
		}
		if !seen[key] {
			seen[key] = true
			result.TotalBytes += total
			result.FreeBytes += free
		}
	}
	return result, nil
}
func (h *smbFile) Rename(ctx context.Context, name string, replace bool) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	if err := h.check(ctx); err != nil {
		return err
	}
	p, allowed, err := h.b.resolve(name)
	if err != nil {
		return err
	}
	f := catalogFS{h.b.s.catalog}
	if !replace {
		if target, err := f.Stat(ctx, p); err == nil {
			source, statErr := h.f.Stat()
			// A case-only rename on a case-insensitive volume finds the same file.
			// Do not use name equality alone: two distinct files may differ in case.
			if statErr != nil {
				return statErr
			}
			if !strings.EqualFold(h.path, p) || !os.SameFile(source, target) {
				return os.ErrExist
			}
		} else if !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}
	c := h.b.s.catalog
	c.mu.RLock()
	defer c.mu.RUnlock()
	sourceRoot, source, err := c.lookup(h.path)
	if err != nil {
		return err
	}
	targetRoot, target, err := c.lookup(p)
	if err != nil {
		return err
	}
	if sourceRoot == nil || targetRoot == nil || source == "." || target == "." {
		return os.ErrPermission
	}
	if sourceRoot != targetRoot {
		return vfs.ErrNotSameDevice
	}
	file, ok := h.f.(*os.File)
	if !ok {
		return os.ErrPermission
	}
	if err := c.user(func() error {
		opened, e := file.Stat()
		if e != nil {
			return e
		}
		atPath, e := sourceRoot.root.Lstat(source)
		if e != nil {
			return e
		}
		if !os.SameFile(opened, atPath) {
			return os.ErrPermission
		}
		return smbRenameOpened(file, sourceRoot.root, source, target, replace)
	}); err != nil {
		return err
	}
	h.path, h.display, h.allowed = p, name, allowed
	return nil
}

func (h *smbFile) Remove(ctx context.Context) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	if e := h.check(ctx); e != nil {
		return e
	}
	c := h.b.s.catalog
	c.mu.RLock()
	defer c.mu.RUnlock()
	m, sub, e := c.lookup(h.path)
	if e != nil {
		return e
	}
	if m == nil || sub == "." {
		return os.ErrPermission
	}
	file, ok := h.f.(*os.File)
	if !ok {
		return os.ErrPermission
	}
	return c.user(func() error {
		opened, e := file.Stat()
		if e != nil {
			return e
		}
		current, e := m.root.Lstat(sub)
		if e != nil {
			return e
		}
		if !os.SameFile(opened, current) {
			return os.ErrPermission
		}
		return smbRemoveOpened(file, m.root, sub)
	})
}

func (h *smbFile) Lock(ctx context.Context, offset, length uint64, exclusive, unlock bool) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	if err := h.check(ctx); err != nil {
		return err
	}
	f, ok := h.f.(*os.File)
	if !ok {
		return os.ErrPermission
	}
	if !unlock && h.locks >= 64 {
		return os.ErrPermission
	}
	if offset > uint64(1<<63-1) || length == 0 {
		return os.ErrInvalid
	}
	// The native Apple client denotes EOF with all bits set. OS locks are signed.
	if length == ^uint64(0) {
		length = uint64(1<<63-1) - offset
	}
	if length > uint64(1<<63-1)-offset {
		return os.ErrInvalid
	}
	if err := smbLockFile(f, offset, length, exclusive, unlock); err != nil {
		return err
	}
	if unlock {
		if h.locks > 0 {
			h.locks--
		}
	} else {
		h.locks++
	}
	return nil
}
