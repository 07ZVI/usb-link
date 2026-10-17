package connectioninstall

import (
	"fmt"
	"reflect"
	"strings"
)

type nativeSMBShare struct {
	MigrationName                      string `json:",omitempty"`
	MigrationFileID                    string `json:",omitempty"`
	ID, Name, Path, SID, GuestSID      string
	GuestUpdate                        bool
	NextGuestSID                       string
	AccountAccess, GuestAccess         string
	AccessUpdate                       bool
	NextAccountAccess, NextGuestAccess string
}
type nativeSMBConfiguration struct {
	Version int
	Shares  []nativeSMBShare
	Access  []nativeSMBAccessSetting
}

type nativeSMBAccessSetting struct{ ID, Path, FileID, Account, Guest string }

func validSMBFileIdentity(id string) bool {
	return len(id) == 25 && id[8] == ':' && strings.Trim(id[:8], "0123456789abcdefABCDEF") == "" && strings.Trim(id[9:], "0123456789abcdefABCDEF") == ""
}

func validSMBMigration(id, name, path, next, fileID string, accessPending bool) bool {
	if next == "" {
		return fileID == ""
	}
	return !accessPending && legacyNativeShareName(id, name) && !strings.EqualFold(name, next) && validFolderNativeShareName(next, path) && validSMBFileIdentity(fileID)
}

// The durable intent covers both names before creation. Failures deliberately
// retain it, including a failed final commit after the old name was removed.
func migrateSMBShare(preflight, stage, create, retire, commit func() error) error {
	for _, step := range []func() error{preflight, stage, create, retire, commit} {
		if err := step(); err != nil {
			return err
		}
	}
	return nil
}

// A matching path or file identity is not unrelated. Unreadable/legacy
// identities remain blocked rather than hiding a share of the same directory.
func smbRecoveryShareUnrelated(rootPath, rootID, sharePath, shareID string) bool {
	normalize := func(p string) string { return strings.TrimRight(strings.ReplaceAll(p, `\`, "/"), "/") }
	return rootPath != "" && sharePath != "" && validSMBFileIdentity(rootID) && validSMBFileIdentity(shareID) &&
		!strings.EqualFold(normalize(rootPath), normalize(sharePath)) && !strings.EqualFold(rootID, shareID)
}

func nativeSMBStateVersion(c nativeSMBConfiguration) int {
	for _, s := range c.Shares {
		if s.MigrationName != "" {
			return 2
		}
	}
	return 1
}

// Validate every alias before cleanup; a foreign second name must not cause
// the still-owned first name to disappear. Removal callbacks recheck ownership.
func retireSMBMigration(verifyRoot func() error, names []string, verify, remove func(string) error) error {
	if e := verifyRoot(); e != nil {
		return e
	}
	for _, name := range names {
		if e := verify(name); e != nil {
			return e
		}
	}
	for _, name := range names {
		if e := verifyRoot(); e != nil {
			return e
		}
		if e := remove(name); e != nil {
			return e
		}
	}
	return nil
}

func persistSMBMigration(c nativeSMBConfiguration, write func(nativeSMBConfiguration) error, read func() (nativeSMBConfiguration, error)) error {
	c.Version = nativeSMBStateVersion(c)
	if e := write(c); e != nil {
		return e
	}
	got, e := read()
	if e != nil {
		return e
	}
	if !reflect.DeepEqual(got, c) {
		return fmt.Errorf("NATIVE_SMB_MIGRATION_JOURNAL_CHANGED")
	}
	return nil
}

type smbMigrationACLIdentity struct{ ID, Path, FileID string }

func selectSMBMigrationACLRoot(id, path, fileID string, roots []smbMigrationACLIdentity) (int, error) {
	normalize := func(p string) string { return strings.TrimRight(strings.ReplaceAll(p, `\`, "/"), "/") }
	for i, r := range roots {
		if r.ID != id {
			continue
		}
		if r.FileID != fileID || !strings.EqualFold(normalize(r.Path), normalize(path)) {
			return -1, fmt.Errorf("NATIVE_SMB_MIGRATION_ROOT_CHANGED")
		}
		return i, nil
	}
	return -1, fmt.Errorf("NATIVE_SMB_MIGRATION_ACL_RECEIPT_MISSING")
}
