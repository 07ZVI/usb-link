package fileshare

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"suhang/usbnet/internal/sharing/smbcore/vfs"
	"sync"
	"sync/atomic"
	"time"
)

type Folder struct {
	ID                 string `json:"id"`
	Name               string `json:"name"`
	Path               string `json:"path"`
	URL                string `json:"url"` // Legacy storage field; no HTTP file service.
	SMBURL             string `json:"smb_url"`
	Available          bool   `json:"available"`
	NativeShared       bool   `json:"native_shared,omitempty"`
	PermissionRecovery bool   `json:"permission_recovery,omitempty"`
	ManagedConflict    bool   `json:"managed_conflict,omitempty"`
	ShareName          string `json:"share_name,omitempty"`
	AccountAccess      string `json:"account_access,omitempty"`
	GuestAccess        string `json:"guest_access,omitempty"`
	GuestEnabled       bool   `json:"guest_enabled,omitempty"`
	ExternalShare      bool   `json:"external_share,omitempty"`
	AccessRecovery     bool   `json:"access_recovery,omitempty"`
	Identity           string `json:"-"`
	Problem            string `json:"folder_problem,omitempty"`
}
type mountedFolder struct {
	Folder
	root   *os.Root
	active atomic.Bool
}
type Catalog struct {
	mu           sync.RWMutex
	refreshMu    sync.Mutex
	metadataOnly bool
	folders      map[string]*mountedFolder
	user         func(func() error) error
}

func NewCatalog(user func(func() error) error) *Catalog {
	if user == nil {
		user = func(f func() error) error { return f() }
	}
	return &Catalog{folders: map[string]*mountedFolder{}, user: user}
}
func ValidFolderID(id string) bool {
	if len(id) != 24 {
		return false
	}
	b, e := hex.DecodeString(id)
	return e == nil && len(b) == 12 && strings.ToLower(id) == id
}

// Native Windows SMB needs paths and identities, not pinned Go directory handles.
// Releasing those handles permits drive ejection when no Windows SMB client is
// using it. The compatibility backend retains roots only while available.
func NewMetadataCatalog(user func(func() error) error) *Catalog {
	c := NewCatalog(user)
	c.metadataOnly = true
	return c
}
func (c *Catalog) Add(id, dir string) (Folder, error) { return c.add(id, dir, "") }
func (c *Catalog) add(id, dir, identity string) (Folder, error) {

	if id == "" {
		var b [12]byte
		if _, err := rand.Read(b[:]); err != nil {
			return Folder{}, err
		}
		id = hex.EncodeToString(b[:])
	}
	if !ValidFolderID(id) || !filepath.IsAbs(dir) || len(dir) > 4096 {
		return Folder{}, fmt.Errorf("SHARE_FOLDER_INVALID")
	}
	dir = filepath.Clean(dir)
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, m := range c.folders {
		if sameFolder(m.Path, dir) {
			return m.Folder, fmt.Errorf("SHARE_FOLDER_ALREADY_ADDED")
		}
	}
	if len(c.folders) >= 32 {
		return Folder{}, fmt.Errorf("SHARE_FOLDER_LIMIT")
	}
	if _, ok := c.folders[id]; ok {
		return Folder{}, fmt.Errorf("SHARE_FOLDER_ID_CONFLICT")
	}
	var root *os.Root
	var actual string
	err := c.user(func() error { var e error; root, actual, e = c.openRoot(dir); return e })
	if err != nil {
		return Folder{}, err
	}
	if identity != "" && identity != actual {
		root.Close()
		return Folder{}, fmt.Errorf("SHARE_ROOT_IDENTITY_CHANGED")
	}
	name := filepath.Base(dir)
	if name == "." || name == string(filepath.Separator) {
		name = "共享資料夾"
	}
	m := &mountedFolder{Folder: Folder{ID: id, Name: name, Path: dir, Available: true, Identity: actual}, root: root}
	if c.metadataOnly {
		root.Close()
		m.root = nil
	}
	m.active.Store(true)
	c.folders[id] = m
	return m.Folder, nil
}
func (c *Catalog) List() []Folder {
	c.mu.RLock()
	defer c.mu.RUnlock()
	out := []Folder{}
	for _, m := range c.folders {
		out = append(out, m.Folder)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Name == out[j].Name {
			return out[i].ID < out[j].ID
		}
		return out[i].Name < out[j].Name
	})
	names := smbFolderNames(out)
	for i := range out {
		out[i].SMBURL = smbShareURL() + "/" + url.PathEscape(names[out[i].ID])
	}
	return out
}

func (c *Catalog) openRoot(dir string) (*os.Root, string, error) {
	root, err := openShareRoot(dir)
	if err != nil {
		return nil, "", err
	}
	identity, err := shareRootIdentity(root)
	if err != nil {
		root.Close()
		return nil, "", err
	}
	return root, identity, nil
}

// Disk probes do not hold the catalog lock. Apply a result only if the entry
// still exists; removal/re-addition during a slow probe cannot resurrect it.
// Retain identity after dropping an unavailable root, including across restart.
func (c *Catalog) Refresh() {
	c.refreshMu.Lock()
	defer c.refreshMu.Unlock()
	c.mu.RLock()
	entries := make([]*mountedFolder, 0, len(c.folders))
	for _, m := range c.folders {
		entries = append(entries, m)
	}
	c.mu.RUnlock()
	for _, m := range entries {
		var next *os.Root
		var identity string
		err := c.user(func() error { var e error; next, identity, e = c.openRoot(m.Path); return e })
		c.mu.Lock()
		if c.folders[m.ID] != m {
			c.mu.Unlock()
			if next != nil {
				next.Close()
			}
			continue
		}
		if err == nil && m.Identity != "" && identity != m.Identity {
			err = fmt.Errorf("SHARE_ROOT_IDENTITY_CHANGED: 資料夾已移動或被替換，請重新選擇")
		}
		if err != nil {
			m.Available = false
			m.Problem = err.Error()
			m.active.Store(false)
			if m.root != nil {
				m.root.Close()
				m.root = nil
			}
			if next != nil {
				next.Close()
			}
		} else {
			m.Identity = identity
			m.Problem = ""
			m.Available = true
			if c.metadataOnly {
				next.Close()
			} else {
				if m.root != nil {
					m.root.Close()
				}
				m.root = next
			}
			m.active.Store(true)
		}
		c.mu.Unlock()
	}
}

func (c *Catalog) Path(id string) (string, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	m := c.folders[id]
	if m == nil || !m.active.Load() {
		return "", os.ErrNotExist
	}
	return m.Path, nil
}
func (c *Catalog) Remove(id string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	m := c.folders[id]
	if m == nil {
		return os.ErrNotExist
	}
	m.active.Store(false)
	delete(c.folders, id)
	if m.root != nil {
		return m.root.Close()
	}
	return nil
}
func (c *Catalog) Close() {
	c.mu.Lock()
	defer c.mu.Unlock()
	for id, m := range c.folders {
		m.active.Store(false)
		if m.root != nil {
			m.root.Close()
		}
		delete(c.folders, id)
	}
}
func (c *Catalog) allowed(urlPath string) func() bool {
	parts := strings.Split(strings.TrimPrefix(urlPath, "/"), "/")
	if urlPath == "." || urlPath == "/" {
		return func() bool { return true }
	}
	c.mu.RLock()
	m := c.folders[parts[0]]
	c.mu.RUnlock()
	if m == nil {
		return func() bool { return false }
	}
	return m.active.Load
}
func (c *Catalog) lookup(n string) (*mountedFolder, string, error) {
	n, e := clean(n)
	if e != nil {
		return nil, "", e
	}
	if n == "." {
		return nil, ".", nil
	}
	id, sub, _ := strings.Cut(n, "/")
	m := c.folders[id]
	if m == nil || !m.active.Load() || m.root == nil {
		return nil, "", os.ErrNotExist
	}
	if sub == "" {
		sub = "."
	}
	return m, sub, nil
}

// The mount namespace is immutable to SMB clients. Moving across two roots
// is refused; removing a share never removes the selected local directory.
type catalogFS struct{ c *Catalog }

func (f catalogFS) Mkdir(ctx context.Context, n string, p os.FileMode) error {
	f.c.mu.RLock()
	defer f.c.mu.RUnlock()
	m, sub, e := f.c.lookup(n)
	if e != nil {
		return e
	}
	if m == nil || sub == "." {
		return os.ErrPermission
	}
	return f.c.user(func() error { return (rootFS{m.root}).Mkdir(ctx, sub, p) })
}
func (f catalogFS) OpenFile(ctx context.Context, n string, flags int, p os.FileMode) (out shareFile, err error) {
	f.c.mu.RLock()
	defer f.c.mu.RUnlock()
	m, sub, e := f.c.lookup(n)
	if e != nil {
		return nil, e
	}
	if m == nil {
		if flags != os.O_RDONLY {
			return nil, os.ErrPermission
		}
		rows := []os.FileInfo{}
		for _, x := range f.c.folders {
			if x.active.Load() {
				rows = append(rows, virtualInfo{name: x.ID, dir: true})
			}
		}
		sort.Slice(rows, func(i, j int) bool { return rows[i].Name() < rows[j].Name() })
		return &virtualDirectory{rows: rows}, nil
	}
	err = f.c.user(func() error {
		var e error
		out, e = (rootFS{m.root}).OpenFile(ctx, mountedPath(sub), flags, p)
		return e
	})
	return
}
func (f catalogFS) Stat(ctx context.Context, n string) (info os.FileInfo, err error) {
	f.c.mu.RLock()
	defer f.c.mu.RUnlock()
	m, sub, e := f.c.lookup(n)
	if e != nil {
		return nil, e
	}
	if m == nil {
		return virtualInfo{name: "/", dir: true}, nil
	}
	err = f.c.user(func() error { var e error; info, e = (rootFS{m.root}).Stat(ctx, mountedPath(sub)); return e })
	if err == nil && sub == "." {
		info = virtualInfo{name: m.Name, dir: true}
	}
	return
}
func (f catalogFS) RemoveAll(ctx context.Context, n string) error {
	f.c.mu.RLock()
	defer f.c.mu.RUnlock()
	m, sub, e := f.c.lookup(n)
	if e != nil {
		return e
	}
	if m == nil || sub == "." {
		return os.ErrPermission
	}
	return f.c.user(func() error { return (rootFS{m.root}).RemoveAll(ctx, sub) })
}
func (f catalogFS) Rename(ctx context.Context, a, b string) error {
	f.c.mu.RLock()
	defer f.c.mu.RUnlock()
	ma, sa, e := f.c.lookup(a)
	if e != nil {
		return e
	}
	mb, sb, e := f.c.lookup(b)
	if e != nil {
		return e
	}
	if ma == nil || mb == nil || sa == "." || sb == "." {
		return os.ErrPermission
	}
	if mb != ma {
		return vfs.ErrNotSameDevice
	}
	return f.c.user(func() error { return (rootFS{ma.root}).Rename(ctx, sa, sb) })
}

type virtualInfo struct {
	name string
	dir  bool
}

func (v virtualInfo) Name() string       { return v.name }
func (v virtualInfo) Size() int64        { return 0 }
func (v virtualInfo) Mode() os.FileMode  { return os.ModeDir | 0555 }
func (v virtualInfo) ModTime() time.Time { return time.Unix(0, 0) }
func (v virtualInfo) IsDir() bool        { return v.dir }
func (v virtualInfo) Sys() any           { return nil }

type virtualDirectory struct {
	rows []os.FileInfo
	pos  int
}

func (v *virtualDirectory) Close() error              { return nil }
func (v *virtualDirectory) Read([]byte) (int, error)  { return 0, io.EOF }
func (v *virtualDirectory) Write([]byte) (int, error) { return 0, os.ErrPermission }
func (v *virtualDirectory) Seek(off int64, whence int) (int64, error) {
	if off == 0 && whence == io.SeekStart {
		v.pos = 0
		return 0, nil
	}
	return 0, os.ErrPermission
}
func (v *virtualDirectory) Stat() (os.FileInfo, error) { return virtualInfo{name: "/", dir: true}, nil }
func (v *virtualDirectory) Readdir(n int) ([]os.FileInfo, error) {
	if v.pos >= len(v.rows) {
		if n > 0 {
			return nil, io.EOF
		}
		return []os.FileInfo{}, nil
	}
	end := len(v.rows)
	if n > 0 && v.pos+n < end {
		end = v.pos + n
	}
	r := v.rows[v.pos:end]
	v.pos = end
	return r, nil
}

func mountedPath(sub string) string {
	if sub == "." {
		return "/"
	}
	return sub
}

// A disconnected drive must remain visible and removable in the UI instead of
// making every other share unavailable. An unavailable entry exports no data.
func (c *Catalog) Restore(id, dir string) (Folder, error) { return c.RestoreIdentity(id, dir, "") }
func (c *Catalog) RestoreIdentity(id, dir, identity string) (Folder, error) {
	if len(identity) > 80 {
		return Folder{}, fmt.Errorf("SHARE_IDENTITY_INVALID")
	}
	f, e := c.add(id, dir, identity)
	if e == nil {
		return f, nil
	}
	if !ValidFolderID(id) || !filepath.IsAbs(dir) || len(dir) > 4096 {
		return Folder{}, e
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.folders[id] != nil {
		return Folder{}, e
	}
	for _, m := range c.folders {
		if sameFolder(m.Path, filepath.Clean(dir)) {
			return Folder{}, e
		}
	}
	if len(c.folders) >= 32 {
		return Folder{}, e
	}
	f = Folder{ID: id, Name: filepath.Base(dir), Path: filepath.Clean(dir), Available: false, Identity: identity, Problem: e.Error()}
	c.folders[id] = &mountedFolder{Folder: f}
	return f, nil
}
