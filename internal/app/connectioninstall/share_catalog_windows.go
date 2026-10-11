//go:build windows && amd64

package connectioninstall

import (
	"bytes"
	"encoding/json"
	"fmt"
	"golang.org/x/sys/windows"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"suhang/usbnet/internal/sharing/fileshare"
	"sync"
	"unsafe"
)

var shareCatalogState struct {
	sync.Mutex
	catalog *fileshare.Catalog
	path    string
}

type shareConfiguration struct {
	Version int                `json:"version"`
	Folders []fileshare.Folder `json:"folders"`
}

// Query failures are errors, never interpreted as a non-elevated token.
func shareTokenDWORD(t windows.Token, kind uint32) (uint32, error) {
	var value, length uint32
	err := windows.GetTokenInformation(t, kind, (*byte)(unsafe.Pointer(&value)), 4, &length)
	if err != nil {
		return 0, err
	}
	if length != 4 {
		return 0, fmt.Errorf("SHARE_TOKEN_INFORMATION_INVALID")
	}
	return value, nil
}
func shareTokenIdentity(t windows.Token) (shareIdentity, error) {
	user, err := t.GetTokenUser()
	if err != nil {
		return shareIdentity{}, err
	}
	session, err := shareTokenDWORD(t, windows.TokenSessionId)
	if err != nil {
		return shareIdentity{}, err
	}
	elevated, err := shareTokenDWORD(t, windows.TokenElevation)
	if err != nil {
		return shareIdentity{}, err
	}
	return shareIdentity{user.User.Sid.String(), session, elevated != 0}, nil
}

// The linked UAC token can be identification-only and cannot necessarily be
// duplicated at SecurityImpersonation. Use the actual unelevated desktop token,
// validating both account and session before any filesystem access. No elevated
// fallback and no added token privileges are permitted.
func shareUser() (func(func() error) error, func(), error) {
	if sid, bound := BoundCoreOwnerSID(); bound {
		return coreShareUser(sid)
	}
	var current windows.Token
	if err := windows.OpenProcessToken(windows.CurrentProcess(), windows.TOKEN_QUERY|windows.TOKEN_DUPLICATE, &current); err != nil {
		return nil, nil, fmt.Errorf("SHARE_PROCESS_TOKEN: %w", err)
	}
	defer current.Close()
	owner, err := shareTokenIdentity(current)
	if err != nil {
		return nil, nil, fmt.Errorf("SHARE_PROCESS_IDENTITY: %w", err)
	}
	token := current
	if owner.Elevated {
		hwnd := windows.GetShellWindow()
		if hwnd == 0 {
			return nil, nil, fmt.Errorf("SHARE_DESKTOP_UNAVAILABLE")
		}
		var pid uint32
		if _, err := windows.GetWindowThreadProcessId(hwnd, &pid); err != nil || pid == 0 {
			return nil, nil, fmt.Errorf("SHARE_DESKTOP_PROCESS_UNAVAILABLE")
		}
		process, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
		if err != nil {
			return nil, nil, fmt.Errorf("SHARE_DESKTOP_PROCESS: %w", err)
		}
		defer windows.CloseHandle(process)
		if err = windows.OpenProcessToken(process, windows.TOKEN_QUERY|windows.TOKEN_DUPLICATE, &token); err != nil {
			return nil, nil, fmt.Errorf("SHARE_DESKTOP_TOKEN: %w", err)
		}
		defer token.Close()
		// Retain the process handle and verify that the window still identifies it.
		var again uint32
		if _, err = windows.GetWindowThreadProcessId(hwnd, &again); err != nil || again != pid {
			return nil, nil, fmt.Errorf("SHARE_DESKTOP_CHANGED")
		}
	}
	identity, err := shareTokenIdentity(token)
	if err != nil {
		return nil, nil, fmt.Errorf("SHARE_USER_IDENTITY: %w", err)
	}
	if err = validateShareIdentity(owner, identity); err != nil {
		return nil, nil, err
	}
	var impersonation windows.Token
	if err = windows.DuplicateTokenEx(token, windows.TOKEN_QUERY|windows.TOKEN_IMPERSONATE, nil, windows.SecurityImpersonation, windows.TokenImpersonation, &impersonation); err != nil {
		return nil, nil, fmt.Errorf("SHARE_DUPLICATE_USER_TOKEN: %w", err)
	}
	// Check the resulting token as well; query/validation failures close it.
	duplicate, err := shareTokenIdentity(impersonation)
	if err == nil {
		err = validateShareIdentity(owner, duplicate)
	}
	if err != nil {
		impersonation.Close()
		return nil, nil, fmt.Errorf("SHARE_DUPLICATE_IDENTITY: %w", err)
	}
	level, err := shareTokenDWORD(impersonation, windows.TokenImpersonationLevel)
	if err != nil || level < windows.SecurityImpersonation {
		impersonation.Close()
		return nil, nil, fmt.Errorf("SHARE_IMPERSONATION_LEVEL_INVALID level=%d error=%v", level, err)
	}
	release := func() { impersonation.Close() }
	// Process-lifetime catalogue holds the token; failed initialization releases it.
	return func(f func() error) (err error) {
		runtime.LockOSThread()
		defer runtime.UnlockOSThread()
		if err = windows.SetThreadToken(nil, impersonation); err != nil {
			return fmt.Errorf("SHARE_SET_USER_TOKEN: %w", err)
		}
		defer func() {
			if e := windows.RevertToSelf(); e != nil {
				os.Exit(1)
			}
		}()
		return f()
	}, release, nil
}
func ShareCatalog() (*fileshare.Catalog, error) {
	shareCatalogState.Lock()
	defer shareCatalogState.Unlock()
	return loadShareCatalog()
}
func loadShareCatalog() (*fileshare.Catalog, error) {
	if shareCatalogState.catalog != nil {
		return shareCatalogState.catalog, nil
	}
	dir, err := SecurityDirectory()
	if err != nil {
		return nil, err
	}
	user, release, err := shareUser()
	if err != nil {
		return nil, err
	}
	c := fileshare.NewMetadataCatalog(user)
	retained := false
	defer func() {
		if !retained {
			c.Close()
			release()
		}
	}()
	path := filepath.Join(dir, "shared-folders.json")
	var conf shareConfiguration
	if err = readShareConfiguration(path, &conf); os.IsNotExist(err) || err == windows.ERROR_FILE_NOT_FOUND {
		defaultDir, e := SharedDirectory()
		if e != nil {
			return nil, e
		}
		if _, e = c.Add("000000000000000000000001", defaultDir); e != nil {
			return nil, e
		}
		conf = shareConfiguration{1, c.List()}
		if e = writeShareConfiguration(path, conf); e != nil {
			c.Close()
			return nil, e
		}
	} else if err != nil {
		c.Close()
		return nil, err
	} else {
		if conf.Version != 1 || len(conf.Folders) > 32 {
			return nil, fmt.Errorf("SHARE_CONFIGURATION_INVALID")
		}
		identities, e := readSharedFolderIdentities(path)
		if e != nil {
			return nil, e
		}
		for _, f := range conf.Folders {
			f.Identity = identities[f.ID]
			if _, err = c.RestoreIdentity(f.ID, f.Path, f.Identity); err != nil {
				c.Close()
				return nil, fmt.Errorf("SHARE_FOLDER_UNAVAILABLE: %s: %w", f.Name, err)
			}
		}
	}
	// Persist identities learned while migrating a legacy catalogue. Unknown
	// identities on still-offline folders remain unknown until an explicit retry.
	if err = writeShareConfiguration(path, shareConfiguration{1, c.List()}); err != nil {
		return nil, err
	}
	retained = true
	shareCatalogState.catalog, shareCatalogState.path = c, path
	return c, nil
}
func AddSharedFolder(path string) error {
	shareCatalogState.Lock()
	defer shareCatalogState.Unlock()
	c, err := loadShareCatalog()
	if err != nil {
		return err
	}
	folder, err := c.Add("", path)
	if err != nil {
		return err
	}
	if err = writeShareConfiguration(shareCatalogState.path, shareConfiguration{1, c.List()}); err != nil {
		c.Remove(folder.ID)
	}
	return err
}
func RemoveSharedFolder(id string) error {
	shareCatalogState.Lock()
	defer shareCatalogState.Unlock()
	c, err := loadShareCatalog()
	if err != nil {
		return err
	}
	folders := c.List()
	next := []fileshare.Folder{}
	found := false
	for _, f := range folders {
		if f.ID == id {
			found = true
		} else {
			next = append(next, f)
		}
	}
	if !found {
		return os.ErrNotExist
	}
	// Persist revocation before applying it; interruption cannot re-enable it.
	if err = writeShareConfiguration(shareCatalogState.path, shareConfiguration{1, next}); err != nil {
		return err
	}
	return c.Remove(id)
}

func readShareConfiguration(path string, conf *shareConfiguration) error {
	if e := noReparse(path); e != nil {
		return e
	}
	b, e := os.ReadFile(path)
	if e != nil {
		return e
	}
	if len(b) > 256<<10 {
		return fmt.Errorf("SHARE_CONFIGURATION_TOO_LARGE")
	}
	d := json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	if e = d.Decode(conf); e != nil {
		return e
	}
	if d.Decode(new(any)) != io.EOF {
		return fmt.Errorf("SHARE_CONFIGURATION_INVALID")
	}
	return nil
}

func RefreshSharedFolders() (*fileshare.Catalog, error) {
	c, e := ShareCatalog()
	if e != nil {
		return nil, e
	}
	c.Refresh()
	shareCatalogState.Lock()
	defer shareCatalogState.Unlock()
	if c != shareCatalogState.catalog {
		return c, fmt.Errorf("SHARE_CATALOG_CHANGED")
	}
	return c, writeShareConfiguration(shareCatalogState.path, shareConfiguration{1, c.List()})
}

func readSharedFolderIdentities(configPath string) (map[string]string, error) {
	identities := map[string]string{}
	e := readRemote(filepath.Join(filepath.Dir(configPath), "shared-folder-identities.json"), &identities)
	if os.IsNotExist(e) {
		return identities, nil
	}
	if e != nil {
		return nil, e
	}
	if len(identities) > 64 {
		return nil, fmt.Errorf("SHARE_IDENTITIES_TOO_LARGE")
	}
	for id, value := range identities {
		if !fileshare.ValidFolderID(id) || len(value) > 80 || value == "" {
			return nil, fmt.Errorf("SHARE_IDENTITY_INVALID")
		}
	}
	return identities, nil
}
func writeShareConfiguration(path string, conf shareConfiguration) error {
	identities := map[string]string{}
	for _, f := range conf.Folders {
		if f.Identity != "" {
			identities[f.ID] = f.Identity
		}
	}
	// Preserve bindings for the old membership until publication is durable.
	// A failed removal save must not erase the identity of a still-selected ID.
	old, e := readSharedFolderIdentities(path)
	if e != nil {
		return e
	}
	var previous shareConfiguration
	e = readShareConfiguration(path, &previous)
	if e != nil && !os.IsNotExist(e) {
		return e
	}
	staged := map[string]string{}
	for _, f := range previous.Folders {
		if value := old[f.ID]; value != "" {
			staged[f.ID] = value
		}
	}
	for id, value := range identities {
		staged[id] = value
	}
	bindingPath := filepath.Join(filepath.Dir(path), "shared-folder-identities.json")
	return publishSharedMembership(func() error { return writeRemote(bindingPath, staged) }, func() error {
		return writeRemote(path, struct {
			Version int                 `json:"version"`
			Folders []storedShareFolder `json:"folders"`
		}{conf.Version, storedSharedFolders(conf.Folders)})
	}, func() error { return writeRemote(bindingPath, identities) })
}
