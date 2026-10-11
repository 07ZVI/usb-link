//go:build windows && amd64

package ipadncm

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/windows"
)

// Native fixture only; never uses Apple directories, live USB or pair content.
// Cross-compilation of this fixture is not evidence of Windows execution.
func TestTrustRevokeNativeHandleNoOverwriteAndMetadataOnlyReadback(t *testing.T) {
	base := t.TempDir()
	dir, pins, err := trustRevokeProtectedDirectory(base)
	if err != nil {
		t.Fatal(err)
	}
	defer pins.close()
	source := filepath.Join(base, "synthetic-fixture.bin")
	if err = os.WriteFile(source, []byte("synthetic fixture; no pairing material"), 0600); err != nil {
		t.Fatal(err)
	}
	h, original, err := trustRevokeOpenRecord(source)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if h != 0 {
			windows.CloseHandle(h)
		}
	}()
	occupied := filepath.Join(dir, "occupied.bin")
	if err = os.WriteFile(occupied, []byte("do not overwrite"), 0600); err != nil {
		t.Fatal(err)
	}
	if err = trustRevokeRenameHandle(h, occupied); err == nil {
		t.Fatal("overwrote existing destination")
	}
	if _, err = trustRevokeAttributes(source); err != nil {
		t.Fatal("failed move lost original", err)
	}
	final := filepath.Join(dir, "moved.bin")
	if err = trustRevokeRenameHandle(h, final); err != nil {
		t.Fatal(err)
	}
	if err = trustRevokeProtectFile(h); err != nil {
		t.Fatal(err)
	}
	if err = windows.CloseHandle(h); err != nil {
		t.Fatal(err)
	}
	h = 0
	if err = trustRevokeVerifyBackup(final, original); err != nil {
		t.Fatal(err)
	}
	if _, err = trustRevokeAttributes(source); !errors.Is(err, windows.ERROR_FILE_NOT_FOUND) {
		t.Fatal("source remained", err)
	}
	bad := original
	bad.FileIndexLow++
	if err = trustRevokeVerifyBackup(final, bad); err == nil {
		t.Fatal("accepted another file identity")
	}
}

func TestTrustRevokeNativeProtectedMetadataNoOverwrite(t *testing.T) {
	base := t.TempDir()
	dir, pins, err := trustRevokeProtectedDirectory(base)
	if err != nil {
		t.Fatal(err)
	}
	defer pins.close()
	path := filepath.Join(dir, "intent.json")
	m := trustRevokeMetadata{Version: 1, Stage: "intent", OriginalLeaf: "synthetic.bin", BackupLeaf: "fixture.bin"}
	if err = trustRevokeWriteMetadata(path, m); err != nil {
		t.Fatal(err)
	}
	m.Stage = "must_not_overwrite"
	if err = trustRevokeWriteMetadata(path, m); err == nil {
		t.Fatal("replaced existing durable intent")
	}
}
