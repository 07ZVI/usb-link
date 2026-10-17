//go:build usblink_local_remote

package connectioninstall

import (
	"errors"
	"os"
	"reflect"
	"testing"
)

func TestLocalInstallCleanupRetriesEmptyDirectoryAfterBusy(t *testing.T) {
	exists, packageExists, busy := true, true, true
	removedPackage, verified := 0, 0
	op := localInstallCleanupOps{
		validateDirectory: func() error {
			if !exists {
				return os.ErrNotExist
			}
			return nil
		},
		entries: func() ([]string, error) {
			if packageExists {
				return []string{"setup.exe"}, nil
			}
			return nil, nil
		},
		verifyPackage: func() error { verified++; return nil },
		removePackage: func() error { removedPackage++; packageExists = false; return nil },
		removeDirectory: func() error {
			if busy {
				return errors.New("directory busy")
			}
			exists = false
			return nil
		},
	}
	if err := cleanupLocalInstallDirectory(op); err == nil || packageExists || !exists {
		t.Fatal("first attempt must preserve busy directory", err)
	}
	busy = false
	if err := cleanupLocalInstallDirectory(op); err != nil || exists || removedPackage != 1 || verified != 1 {
		t.Fatal("retry did not clean only empty directory", err, removedPackage, verified)
	}
	if err := cleanupLocalInstallDirectory(op); err != nil {
		t.Fatal("absent directory not idempotent", err)
	}
}

func TestLocalInstallCleanupRetainsUnknownOrUnverifiedContents(t *testing.T) {
	for _, tc := range []struct {
		name               string
		entries            []string
		protection, verify error
	}{
		{"foreign", []string{"notes.txt"}, nil, nil},
		{"foreign_with_package", []string{"setup.exe", "notes.txt"}, nil, nil},
		{"redirected", []string{"setup.exe"}, errors.New("reparse"), nil},
		{"unprotected_empty", nil, errors.New("ACL"), nil},
		{"tampered_package", []string{"setup.exe"}, nil, errors.New("hash mismatch")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var mutations []string
			err := cleanupLocalInstallDirectory(localInstallCleanupOps{
				validateDirectory: func() error { return tc.protection }, entries: func() ([]string, error) { return tc.entries, nil }, verifyPackage: func() error { return tc.verify },
				removePackage: func() error { mutations = append(mutations, "package"); return nil }, removeDirectory: func() error { mutations = append(mutations, "directory"); return nil },
			})
			if err == nil || len(mutations) != 0 {
				t.Fatal("unsafe cleanup", err, mutations)
			}
		})
	}
}

func TestLocalInstallCleanupRechecksProtectionAndRemoval(t *testing.T) {
	for _, failAt := range []int{2, 3} {
		reads := 0
		var mutations []string
		err := cleanupLocalInstallDirectory(localInstallCleanupOps{
			validateDirectory: func() error {
				reads++
				if reads == failAt {
					return errors.New("protection changed")
				}
				return nil
			},
			entries: func() ([]string, error) { return []string{"setup.exe"}, nil }, verifyPackage: func() error { return nil },
			removePackage: func() error { mutations = append(mutations, "package"); return nil }, removeDirectory: func() error { mutations = append(mutations, "directory"); return nil },
		})
		expected := []string(nil)
		if failAt == 3 {
			expected = []string{"package"}
		}
		if err == nil || !reflect.DeepEqual(mutations, expected) {
			t.Fatal(failAt, err, mutations)
		}
	}
	err := cleanupLocalInstallDirectory(localInstallCleanupOps{validateDirectory: func() error { return nil }, entries: func() ([]string, error) { return nil, nil }, removeDirectory: func() error { return nil }})
	if err == nil {
		t.Fatal("directory deletion falsely confirmed")
	}
}

func TestLocalInstallCleanupRequiresProvenProcessExit(t *testing.T) {
	for _, tc := range []struct {
		pid               uint32
		creation          uint64
		dead, known, want bool
	}{
		{0, 0, false, false, true}, {1, 0, true, true, false}, {0, 1, true, true, false},
		{1, 1, false, true, false}, {1, 1, true, false, false}, {1, 1, false, false, false}, {1, 1, true, true, true},
	} {
		got := localInstallCleanupProcessSafe(tc.pid, tc.creation, func(uint32, uint64) (bool, bool) { return tc.dead, tc.known })
		if got != tc.want {
			t.Fatal(tc, got)
		}
	}
}
