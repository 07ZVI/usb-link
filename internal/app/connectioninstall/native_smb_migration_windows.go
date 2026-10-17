//go:build windows && amd64

package connectioninstall

import (
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"suhang/usbnet/internal/sharing/fileshare"
)

func verifyNativeMigrationRoot(s nativeSMBShare) error {
	id, e := smbRootFileIdentity(s.Path)
	if e != nil {
		return e
	}
	if !validSMBFileIdentity(s.MigrationFileID) || id != s.MigrationFileID {
		return fmt.Errorf("NATIVE_SMB_MIGRATION_ROOT_CHANGED")
	}
	return nil
}

func verifyNativeMigrationShare(s nativeSMBShare) error {
	got, free, rc, e := getNativeShare(s.Name)
	if free != nil {
		defer free()
	}
	if e != nil {
		return e
	}
	if rc == 2310 {
		return nil
	}
	if rc != 0 {
		return fmt.Errorf("NATIVE_SMB_QUERY_FAILED: %d", rc)
	}
	if !ownedNativeShare(s, got) {
		return fmt.Errorf("NATIVE_SMB_CHANGED_IN_WINDOWS: %s", s.Name)
	}
	return nil
}

// Both names remain tracked if either cleanup fails. Check all ownership
// proofs before deleting anything, then recheck each target at its mutation.
func deleteNativeShare(s nativeSMBShare) error {
	if s.MigrationName == "" {
		return deleteNativeShareExact(s)
	}
	return retireSMBMigration(func() error { return verifyNativeMigrationRoot(s) }, []string{s.MigrationName, s.Name}, func(name string) error {
		target := s
		target.Name = name
		return verifyNativeMigrationShare(target)
	}, func(name string) error {
		target := s
		target.Name = name
		if e := deleteNativeShareExact(target); e != nil {
			return e
		}
		_, free, rc, e := getNativeShare(name)
		if free != nil {
			free()
		}
		if e != nil {
			return e
		}
		if rc != 2310 {
			return fmt.Errorf("NATIVE_SMB_MIGRATION_REMOVAL_UNCONFIRMED")
		}
		return nil
	})
}

func requireNativeMigrationTarget(s nativeSMBShare) error {
	got, free, rc, e := getNativeShare(s.Name)
	if free != nil {
		defer free()
	}
	if e != nil {
		return e
	}
	if rc != 0 || !ownedNativeShare(s, got) {
		return fmt.Errorf("NATIVE_SMB_MIGRATION_TARGET_CHANGED")
	}
	return nil
}

func saveNativeSMBMigration(c *nativeSMBConfiguration, index int, share nativeSMBShare) error {
	next := *c
	next.Shares = append([]nativeSMBShare(nil), c.Shares...)
	next.Shares[index] = share
	next.Version = nativeSMBStateVersion(next)
	if e := persistSMBMigration(next, saveNativeSMB, loadNativeSMB); e != nil {
		return e
	}
	*c = next
	return nil
}

func migrateNativeSMBShare(c *nativeSMBConfiguration, s nativeSMBShare, f fileshare.Folder, used map[string]string) (nativeSMBShare, error) {
	index := -1
	for i, v := range c.Shares {
		if v.ID == s.ID {
			index = i
			break
		}
	}
	if index < 0 {
		return s, fmt.Errorf("NATIVE_SMB_RECEIPT_NOT_FOUND")
	}
	pending := s.MigrationName != ""
	if !pending {
		id, e := smbRootFileIdentity(s.Path)
		if e != nil {
			return s, e
		}
		if f.Identity != "win:"+id {
			return s, fmt.Errorf("NATIVE_SMB_MIGRATION_ROOT_CHANGED")
		}
		next, e := availableNativeShareName(s.ID, s.Path, used, func(name string) (bool, error) {
			got, free, rc, e := getNativeShare(name)
			if free != nil {
				defer free()
			}
			if e != nil {
				return false, e
			}
			if rc == 2310 {
				return true, nil
			}
			if rc != 0 {
				return false, fmt.Errorf("NATIVE_SMB_QUERY_FAILED: %d", rc)
			}
			target := s
			target.Name = name
			return ownedNativeShare(target, got), nil
		})
		if e != nil {
			return s, e
		}
		s.MigrationName, s.MigrationFileID = next, id
	}
	if f.Identity != "win:"+s.MigrationFileID || !strings.EqualFold(filepath.Clean(f.Path), filepath.Clean(s.Path)) {
		return s, fmt.Errorf("NATIVE_SMB_MIGRATION_ROOT_CHANGED")
	}
	if !validSMBMigration(s.ID, s.Name, s.Path, s.MigrationName, s.MigrationFileID, s.AccessUpdate || s.GuestUpdate) {
		return s, fmt.Errorf("NATIVE_SMB_MIGRATION_INVALID")
	}
	target := s
	target.Name = s.MigrationName
	err := migrateSMBShare(func() error {
		if e := verifyNativeMigrationRoot(s); e != nil {
			return e
		}
		for _, v := range []nativeSMBShare{s, target} {
			if e := verifyNativeMigrationShare(v); e != nil {
				return e
			}
		}
		// Existing filesystem recovery records must still describe this exact root.
		acls, e := loadSMBACLs()
		if e != nil {
			return e
		}
		roots := make([]smbMigrationACLIdentity, len(acls.Roots))
		for i, r := range acls.Roots {
			roots[i] = smbMigrationACLIdentity{ID: r.ID, Path: filepath.Clean(r.Path), FileID: r.FileID}
		}
		index, e := selectSMBMigrationACLRoot(s.ID, filepath.Clean(s.Path), s.MigrationFileID, roots)
		if e != nil {
			return e
		}
		r := acls.Roots[index]
		sd, id, e := smbRootSecurity(s.Path)
		if e != nil {
			return e
		}
		if id != s.MigrationFileID || !(sameSMBRootDACL(sd.String(), r.Before) || sameSMBRootDACL(sd.String(), r.After) || r.PreviousAfter != "" && sameSMBRootDACL(sd.String(), r.PreviousAfter)) {
			return fmt.Errorf("SMB_FOLDER_ACL_CHANGED")
		}

		return nil
	}, func() error {
		// Re-save/read back even on retry before creating a potentially missing alias.
		return saveNativeSMBMigration(c, index, s)
	}, func() error {
		if e := verifyNativeMigrationRoot(s); e != nil {
			return e
		}
		return addNativeShare(target) // Includes full marker/path/DACL readback.
	}, func() error {
		if e := verifyNativeMigrationRoot(s); e != nil {
			return e
		}
		if e := requireNativeMigrationTarget(target); e != nil {
			return e
		}
		if e := deleteNativeShareExact(s); e != nil {
			return e
		}
		_, oldFree, oldRC, e := getNativeShare(s.Name)
		if oldFree != nil {
			oldFree()
		}
		if e != nil {
			return e
		}
		if oldRC != 2310 {
			return fmt.Errorf("NATIVE_SMB_MIGRATION_REMOVAL_UNCONFIRMED")
		}
		return nil
	}, func() error {
		if e := verifyNativeMigrationRoot(s); e != nil {
			return e
		}
		if e := requireNativeMigrationTarget(target); e != nil {
			return e
		}
		target.MigrationName, target.MigrationFileID = "", ""
		return saveNativeSMBMigration(c, index, target)
	})
	if err != nil {
		return s, err
	}
	return target, nil
}

// Observation never advances the transaction. Either exact owned alias may
// still serve clients while the UI offers retry or removal of both names.
func observeNativeSMBMigration(s nativeSMBShare) (string, error) {
	if e := verifyNativeMigrationRoot(s); e != nil {
		return "", e
	}
	chosen := ""
	var failures []error
	for _, name := range []string{s.Name, s.MigrationName} {
		target := s
		target.Name = name
		got, free, rc, e := getNativeShare(name)
		if e != nil {
			failures = append(failures, e)
		} else if rc == 0 {
			if ownedNativeShare(target, got) {
				if chosen == "" {
					chosen = name
				}
			} else {
				failures = append(failures, fmt.Errorf("NATIVE_SMB_CHANGED_IN_WINDOWS: %s", name))
			}
		} else if rc != 2310 {
			failures = append(failures, fmt.Errorf("NATIVE_SMB_QUERY_FAILED: %d", rc))
		}
		if free != nil {
			free()
		}
	}
	return chosen, errors.Join(failures...)
}
