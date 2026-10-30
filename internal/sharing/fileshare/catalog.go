package fileshare

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
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
	MigrationPending   bool   `json:"migration_pending,omitempty"`
	DisplayPath        string `json:"display_path,omitempty"`
	Identity           string `json:"-"`
	Problem            string `json:"folder_problem,omitempty"`
}
type mountedFolder struct {
	Folder
	active atomic.Bool
}
type Catalog struct {
	mu        sync.RWMutex
	refreshMu sync.Mutex
	folders   map[string]*mountedFolder
	user      func(func() error) error
}

// Native Windows SMB needs paths and identities, not pinned Go directory handles.
// Releasing those handles permits drive ejection when no Windows SMB client is
// using it, so the catalog never retains a root.
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
	var actual string
	err := c.user(func() error { var e error; actual, e = c.probe(dir); return e })
	if err != nil {
		return Folder{}, err
	}
	for _, m := range c.folders {
		if m.Identity != "" && m.Identity == actual {
			return Folder{}, fmt.Errorf("SHARE_FOLDER_ALREADY_ADDED")
		}
	}
	if identity != "" && identity != actual {
		return Folder{}, fmt.Errorf("SHARE_ROOT_IDENTITY_CHANGED")
	}
	name := filepath.Base(dir)
	if name == "." || name == string(filepath.Separator) {
		name = "共享資料夾"
	}
	m := &mountedFolder{Folder: Folder{ID: id, Name: name, Path: dir, Available: true, Identity: actual}}
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
	return out
}

// probe opens the folder only long enough to read its volume identity.
func (c *Catalog) probe(dir string) (string, error) {
	root, err := openShareRoot(dir)
	if err != nil {
		return "", err
	}
	defer root.Close()
	return shareRootIdentity(root)
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
		var identity string
		err := c.user(func() error { var e error; identity, e = c.probe(m.Path); return e })
		c.mu.Lock()
		if c.folders[m.ID] != m {
			c.mu.Unlock()
			continue
		}
		if err == nil && m.Identity != "" && identity != m.Identity {
			err = fmt.Errorf("SHARE_ROOT_IDENTITY_CHANGED: 資料夾已移動或被替換，請重新選擇")
		}
		if err != nil {
			m.Available = false
			m.Problem = err.Error()
			m.active.Store(false)
		} else {
			m.Identity = identity
			m.Problem = ""
			m.Available = true
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
	return nil
}
func (c *Catalog) Close() {
	c.mu.Lock()
	defer c.mu.Unlock()
	for id, m := range c.folders {
		m.active.Store(false)
		delete(c.folders, id)
	}
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

// Move a catalog entry to an independently verified alias of the same directory.
// Preserve its name, identity and ID, including in the saved membership.
func (c *Catalog) Relocate(id, path string) error {
	c.refreshMu.Lock()
	defer c.refreshMu.Unlock()
	c.mu.Lock()
	defer c.mu.Unlock()
	m := c.folders[id]
	if m == nil {
		return os.ErrNotExist
	}
	var actual string
	err := c.user(func() error { var e error; actual, e = c.probe(path); return e })
	if err != nil {
		return err
	}
	if m.Identity == "" || actual != m.Identity {
		return fmt.Errorf("SHARE_ROOT_IDENTITY_CHANGED")
	}
	m.Path, m.Available, m.Problem = path, true, ""
	m.active.Store(true)
	return nil
}
func (c *Catalog) RestoreName(id, name string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if m := c.folders[id]; m != nil && name != "" {
		m.Name = name
	}
}
