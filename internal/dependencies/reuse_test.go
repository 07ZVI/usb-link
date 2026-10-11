package dependencies

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"testing"
)

func TestPinnedDLLMigrationPreservesSourceAndFailsClosed(t *testing.T) {
	data := []byte("official DLL fixture")
	h := sha256.Sum256(data)
	want := hex.EncodeToString(h[:])
	a, _ := Lookup("wintun")
	for _, kind := range []string{"valid", "changed", "symlink", "existing", "cancelled"} {
		t.Run(kind, func(t *testing.T) {
			root, old := t.TempDir(), t.TempDir()
			source := filepath.Join(old, "wintun.dll")
			os.WriteFile(source, data, 0600)
			ctx := context.Background()
			switch kind {
			case "changed":
				os.WriteFile(source, []byte("wrong DLL"), 0600)
			case "symlink":
				os.Rename(source, source+".real")
				if err := os.Symlink(source+".real", source); err != nil {
					t.Skip(err)
				}
			case "existing":
				os.Mkdir(filepath.Join(root, "wintun-0.14.1"), 0700)
				os.WriteFile(filepath.Join(root, "wintun-0.14.1", "user.txt"), data, 0600)
			case "cancelled":
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			}
			err := importPinnedWintun(ctx, a, source, root, want, nil)
			if (err == nil) != (kind == "valid") {
				t.Fatalf("unexpected migration outcome: %v", err)
			}
			if kind == "valid" {
				b, e := os.ReadFile(filepath.Join(root, "wintun-0.14.1", "wintun.dll"))
				if e != nil || string(b) != string(data) {
					t.Fatal("copied DLL differs", e)
				}
				b, _ = os.ReadFile(filepath.Join(root, "wintun-0.14.1", "dependency-files.json"))
				var receipt treeReceipt
				if json.Unmarshal(b, &receipt) != nil || receipt.Digest != a.Digest || receipt.Files["wintun.dll"] != want {
					t.Fatal("missing pinned cache receipt")
				}
			}
			if _, e := os.Lstat(source); e != nil {
				t.Fatal("source removed", e)
			}
			stages, _ := filepath.Glob(filepath.Join(root, "reuse-wintun-*"))
			if len(stages) != 0 {
				t.Fatal("partial migration left behind")
			}
			if kind == "existing" {
				if _, e := os.Stat(filepath.Join(root, "wintun-0.14.1", "user.txt")); e != nil {
					t.Fatal("unknown existing cache overwritten")
				}
			}
		})
	}
}

type migrationPlatform struct {
	testPlatform
	pin        string
	noReadback bool
}

func (p *migrationPlatform) ReuseWintun(ctx context.Context, a Asset, source, root string) error {
	if err := importPinnedWintun(ctx, a, source, root, p.pin, nil); err != nil {
		return err
	}
	p.ready = !p.noReadback
	return nil
}
func TestExistingOwnerDLLAvoidsDownloadAndRequiresReadback(t *testing.T) {
	for _, noReadback := range []bool{false, true} {
		t.Run(map[bool]string{false: "reuse", true: "no-readback"}[noReadback], func(t *testing.T) {
			data := []byte("verified migration fixture")
			h := sha256.Sum256(data)
			p := &migrationPlatform{testPlatform: testPlatform{root: t.TempDir()}, pin: hex.EncodeToString(h[:]), noReadback: noReadback}
			m := &Manager{Platform: p, Client: &http.Client{Transport: roundTrip(func(*http.Request) (*http.Response, error) {
				t.Fatal("migration attempted a download")
				return nil, errors.New("offline")
			})}}
			source := filepath.Join(t.TempDir(), "wintun.dll")
			os.WriteFile(source, data, 0600)
			m.SetLocalSource(func(a Asset) string { return source })
			_, err := m.Ensure(context.Background(), "wintun")
			if (err != nil) != noReadback {
				t.Fatal("unverified migration admitted", err)
			}
			if !noReadback {
				if _, err = m.Ensure(context.Background(), "wintun"); err != nil {
					t.Fatal("cache not reusable", err)
				}
			}
		})
	}
}

func TestOfflineArchiveSkipsNetworkAndRetainsOfficialVerification(t *testing.T) {
	for _, kind := range []string{"valid", "wrong-hash", "signature-failure", "cancelled"} {
		t.Run(kind, func(t *testing.T) {
			m, p, a := fixture(t, "verified offline archive")
			source := filepath.Join(t.TempDir(), "official.zip")
			os.WriteFile(source, []byte("verified offline archive"), 0600)
			m.SetOfflineArchiveSource(func(Asset) string { return source })
			m.Client.Transport = roundTrip(func(*http.Request) (*http.Response, error) {
				t.Fatal("offline preparation attempted network")
				return nil, errors.New("offline")
			})
			ctx := context.Background()
			switch kind {
			case "wrong-hash":
				os.WriteFile(source, []byte("corrupt"), 0600)
			case "signature-failure":
				p.verifyErr = errors.New("signature rejected")
			case "cancelled":
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			}
			_, err := m.ensureAsset(ctx, a)
			if (err == nil) != (kind == "valid") {
				t.Fatal("unexpected offline acceptance", err)
			}
			if kind != "valid" && p.installs != 0 {
				t.Fatal("unverified archive installed")
			}
			if _, err = os.Stat(source); err != nil {
				t.Fatal("offline source removed")
			}
			partials, _ := filepath.Glob(filepath.Join(p.root, "offline-*"))
			if len(partials) != 0 {
				t.Fatal("unverified partial archive retained")
			}
		})
	}
}
