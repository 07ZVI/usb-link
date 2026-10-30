//go:build windows && amd64

package connectioninstall

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"suhang/usbnet/internal/sharing/fileshare"
)

// This protected intent survives each separate receipt/membership write. It
// never contains a new ACL: migration preserves permissions byte for byte.

func MigrateNativeSMBVolumes() error {
	nativeSMBOperationMu.Lock()
	defer nativeSMBOperationMu.Unlock()
	cat, err := ShareCatalog()
	if err != nil {
		return err
	}
	nativeSMBMu.Lock()
	defer func() { nativeSMBMu.Unlock(); invalidateNativeSMB() }()
	c, err := loadNativeSMB()
	if err != nil {
		return err
	}
	return migrateNativeSMBVolumes(cat, &c)
}

func migrateNativeSMBVolumes(cat *fileshare.Catalog, c *nativeSMBConfiguration) error {
	dir, err := SecurityDirectory()
	if err != nil {
		return err
	}
	journal := filepath.Join(dir, "native-smb-volume-moves.json")
	moves := map[string]smbVolumeMove{}
	if err = readNativeSMBState(journal, &moves); err != nil && !os.IsNotExist(err) {
		return err
	}
	if moves == nil {
		moves = map[string]smbVolumeMove{}
	}
	if len(moves) > 32 {
		return fmt.Errorf("SMB_VOLUME_JOURNAL_INVALID")
	}
	for id, move := range moves {
		if !fileshare.ValidFolderID(id) || !filepath.IsAbs(move.OldPath) || len(move.OldPath) > 4096 || len(move.Path) > 4096 || !fileshare.IsVolumePath(move.Path) || !strings.HasPrefix(move.Identity, "win:") || !validSMBFileIdentity(strings.TrimPrefix(move.Identity, "win:")) {
			return fmt.Errorf("SMB_VOLUME_JOURNAL_INVALID")
		}
	}
	var failures []error
	selected := map[string]bool{}
	for _, f := range cat.List() {
		selected[f.ID] = true
		move, pending := moves[f.ID]
		if !pending && fileshare.IsVolumePath(f.Path) {
			continue
		}
		// A legacy offline folder must wait for its original disk; never scan other
		// disks for similarly named directories or bind the current drive blindly.
		if !pending && !f.Available {
			continue
		}
		if !pending {
			busy := false
			for _, s := range c.Shares {
				if s.ID == f.ID && (s.AccessUpdate || s.GuestUpdate || s.MigrationName != "") {
					busy = true
				}
			}
			if busy {
				continue
			} // Finish the older recovery first.
			user, release, e := shareUser()
			if e != nil {
				return e
			}
			var target string
			e = user(func() error { var e error; target, e = fileshare.StableVolumePath(f.Path, f.Identity); return e })
			release()
			if e != nil {
				failures = append(failures, e)
				continue
			}
			move = smbVolumeMove{OldPath: f.Path, Path: target, Identity: f.Identity}
			for _, s := range c.Shares {
				if s.ID != f.ID {
					continue
				}
				if s.AccessUpdate || s.GuestUpdate || s.MigrationName != "" {
					e = fmt.Errorf("SMB_VOLUME_OTHER_RECOVERY_PENDING")
					break
				}
				got, free, rc, queryErr := getNativeShare(s.Name)
				if queryErr != nil {
					e = queryErr
					break
				}
				if rc == 0 {
					move.Published = ownedNativeShare(s, got)
					free()
					if !move.Published {
						e = fmt.Errorf("NATIVE_SMB_CHANGED_IN_WINDOWS: %s", s.Name)
					}
				} else if rc != 2310 {
					e = fmt.Errorf("NATIVE_SMB_QUERY_FAILED: %d", rc)
				}
			}
			if e != nil {
				failures = append(failures, e)
				continue
			}
			moves[f.ID] = move
			if e = writeSMBVolumeMoves(journal, moves); e != nil {
				return e
			}
		}
		if err = applySMBVolumeMove(cat, c, f, move); err != nil {
			failures = append(failures, fmt.Errorf("共享「%s」磁碟綁定待完成：%w", f.Name, err))
			continue
		}
		delete(moves, f.ID)
		if err = writeSMBVolumeMoves(journal, moves); err != nil {
			return err
		}
	}
	// Removed entries cannot be resurrected by an old migration intent.
	for id := range moves {
		if !selected[id] {
			delete(moves, id)
		}
	}
	if err = writeSMBVolumeMoves(journal, moves); err != nil {
		failures = append(failures, err)
	}
	return errors.Join(failures...)
}

func applySMBVolumeMove(cat *fileshare.Catalog, c *nativeSMBConfiguration, f fileshare.Folder, move smbVolumeMove) error {
	allowed := func(path string) bool {
		return strings.EqualFold(path, move.OldPath) || strings.EqualFold(path, move.Path)
	}
	if !allowed(f.Path) || f.Identity != move.Identity {
		return fmt.Errorf("SMB_VOLUME_IDENTITY_CHANGED")
	}
	user, release, err := shareUser()
	if err != nil {
		return err
	}
	defer release()
	if err = user(func() error { _, e := fileshare.StableVolumePath(move.Path, move.Identity); return e }); err != nil {
		return err
	}
	acls, err := loadSMBACLs()
	if err != nil {
		return err
	}
	next := *c
	next.Shares = append([]nativeSMBShare(nil), c.Shares...)
	next.Access = append([]nativeSMBAccessSetting(nil), c.Access...)
	next.Names = append([]nativeSMBNameBinding(nil), c.Names...)
	for i, r := range acls.Roots {
		if r.ID != f.ID {
			continue
		}
		if !allowed(r.Path) || "win:"+r.FileID != move.Identity {
			return fmt.Errorf("SMB_VOLUME_ACL_IDENTITY_CHANGED")
		}
		acls.Roots[i].Path = move.Path
	}
	for i, p := range next.Access {
		if p.ID != f.ID {
			continue
		}
		if !allowed(p.Path) || "win:"+p.FileID != move.Identity {
			return fmt.Errorf("SMB_VOLUME_ACCESS_IDENTITY_CHANGED")
		}
		next.Access[i].Path = move.Path
	}
	for i, s := range next.Shares {
		if s.ID != f.ID {
			continue
		}
		if !allowed(s.Path) || s.AccessUpdate || s.GuestUpdate || s.MigrationName != "" {
			return fmt.Errorf("SMB_VOLUME_RECEIPT_CHANGED")
		}
		target := s
		target.Path = move.Path
		target.NamePath = move.OldPath
		if !validNativeSMBShareName(target) {
			return fmt.Errorf("SMB_VOLUME_SHARE_NAME_INVALID")
		}
		// Both representations are covered by the durable intent. After a crash
		// Windows may already contain the target while our receipt still has oldPath.
		old := s
		old.Path = move.OldPath
		err = rebindSMBShare(move.Published, func() (string, error) {
			got, free, rc, e := getNativeShare(s.Name)
			if e != nil {
				return "", e
			}
			if rc == 2310 {
				return "missing", nil
			}
			if rc != 0 {
				return "", fmt.Errorf("NATIVE_SMB_QUERY_FAILED: %d", rc)
			}
			defer free()
			if ownedNativeShare(target, got) {
				return "target", nil
			}
			if ownedNativeShare(old, got) {
				return "old", nil
			}
			return "foreign", nil
		}, func() error { return deleteNativeShareExact(old) }, func() error { return addNativeShare(target) })
		if err != nil {
			return err
		}

		next.Shares[i] = target
		rememberSMBShareName(&next, target)
	}
	aclPath, err := smbACLPath()
	if err != nil {
		return err
	}
	if err = writeSMBACLs(aclPath, acls); err != nil {
		return err
	}
	if err = saveNativeSMB(next); err != nil {
		return err
	}
	*c = next
	shareCatalogState.Lock()
	defer shareCatalogState.Unlock()
	if err = cat.Relocate(f.ID, move.Path); err != nil {
		return err
	}
	return writeShareConfiguration(shareCatalogState.path, shareConfiguration{1, cat.List()})
}

func writeSMBVolumeMoves(path string, moves map[string]smbVolumeMove) error {
	if _, err := encodeSMBVolumeMoves(moves); err != nil {
		return err
	}
	return writeRemote(path, moves)
}
