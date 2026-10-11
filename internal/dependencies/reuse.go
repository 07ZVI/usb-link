package dependencies

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
)

// Pin for the official 0.14.1 amd64 DLL, also checked after archive extraction.
const WintunAMD64SHA256 = "e5da8447dc2c320edc0fc52fa01885c103de8c118481f683643cacc3220dafce"

type treeReceipt struct {
	Digest string            `json:"digest"`
	Files  map[string]string `json:"files"`
}

// Import a bounded, pinned DLL into the owned cache. Never load it from an old
// runtime that cleanup may retire; leave the source and unknown destinations alone.
func importPinnedWintun(ctx context.Context, a Asset, source, root, want string, safe func(string) error) error {
	if a.ID != "wintun" || a.Version != "0.14.1" {
		return errors.New("DEPENDENCY_REUSE_UNSUPPORTED")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if safe != nil {
		if err := safe(root); err != nil {
			return err
		}
	}
	st, err := os.Lstat(source)
	if err != nil || !st.Mode().IsRegular() || st.Size() > 8<<20 {
		return errors.New("DEPENDENCY_REUSE_SOURCE_INVALID")
	}
	in, err := os.Open(source)
	if err != nil {
		return err
	}
	defer in.Close()
	stage, err := os.MkdirTemp(root, "reuse-wintun-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(stage)
	if safe != nil {
		if err := safe(stage); err != nil {
			return err
		}
	}
	path := filepath.Join(stage, "wintun.dll")
	out, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	h := sha256.New()
	n, err := io.Copy(io.MultiWriter(out, h), io.LimitReader(in, 8<<20+1))
	closeErr := out.Close()
	if err != nil || closeErr != nil || n > 8<<20 || hex.EncodeToString(h.Sum(nil)) != want {
		return errors.New("DEPENDENCY_WINTUN_HASH_MISMATCH")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	data, err := json.Marshal(treeReceipt{Digest: a.Digest, Files: map[string]string{"wintun.dll": want}})
	if err != nil {
		return err
	}
	if err = os.WriteFile(filepath.Join(stage, "dependency-files.json"), data, 0600); err != nil {
		return err
	}
	dir := filepath.Join(root, a.ID+"-"+a.Version)
	if _, err = os.Lstat(dir); !os.IsNotExist(err) {
		return errors.New("DEPENDENCY_EXISTING_TREE_UNVERIFIED")
	}
	return os.Rename(stage, dir)
}

func copyPinnedArchive(ctx context.Context, a Asset, source, target string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	st, err := os.Lstat(source)
	if err != nil || !st.Mode().IsRegular() || st.Size() > a.MaxBytes {
		return errors.New("DEPENDENCY_OFFLINE_SOURCE_INVALID")
	}
	in, err := os.Open(source)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.CreateTemp(filepath.Dir(target), "offline-")
	if err != nil {
		return err
	}
	stage := out.Name()
	defer os.Remove(stage)
	h, err := digest(a)
	if err != nil {
		out.Close()
		return err
	}
	n, err := io.Copy(io.MultiWriter(out, h), io.LimitReader(in, a.MaxBytes+1))
	closeErr := out.Close()
	if err != nil || closeErr != nil || n > a.MaxBytes || hex.EncodeToString(h.Sum(nil)) != a.Digest {
		return errors.New("DEPENDENCY_HASH_MISMATCH")
	}
	if err = ctx.Err(); err != nil {
		return err
	}
	if _, err = os.Lstat(target); !os.IsNotExist(err) {
		return errors.New("DEPENDENCY_CACHE_CORRUPTED")
	}
	return os.Rename(stage, target)
}
