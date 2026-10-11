package macconnection

import (
	"archive/zip"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

func concurrentRuntimeFixture(t *testing.T) ([]byte, []byte, string, map[string][]byte) {
	t.Helper()
	files := map[string][]byte{"suhang-usbnet.exe": bytes.Repeat([]byte("verified bridge fixture\n"), 8192), "wintun.dll": bytes.Repeat([]byte("verified dll fixture\n"), 8192)}
	var archive bytes.Buffer
	w := zip.NewWriter(&archive)
	hashes := map[string]string{}
	for _, name := range []string{"suhang-usbnet.exe", "wintun.dll"} {
		f, err := w.CreateHeader(&zip.FileHeader{Name: name, Method: zip.Store})
		if err != nil {
			t.Fatal(err)
		}
		if _, err = f.Write(files[name]); err != nil {
			t.Fatal(err)
		}
		h := sha256.Sum256(files[name])
		hashes[name] = hex.EncodeToString(h[:])
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	h := sha256.Sum256(archive.Bytes())
	manifest, err := json.Marshal(map[string]any{"files": hashes, "payload_sha256": hex.EncodeToString(h[:])})
	if err != nil {
		t.Fatal(err)
	}
	return archive.Bytes(), manifest, hashes["suhang-usbnet.exe"], files
}

func TestConcurrentColdRuntimeConsumersPublishSameVerifiedFiles(t *testing.T) {
	data, manifest, hash, files := concurrentRuntimeFixture(t)
	for round := 0; round < 3; round++ {
		parent := t.TempDir()
		start := make(chan struct{})
		var wg sync.WaitGroup
		for consumer := 0; consumer < 12; consumer++ {
			wg.Go(func() {
				<-start
				dir, err := unpackArchiveRuntime(parent, ArchiveBytes(data), manifest, hash)
				if err != nil {
					t.Errorf("concurrent verified consumer failed: %v", err)
					return
				}
				if dir != filepath.Join(parent, runtimeDirectoryName(hash)) {
					t.Error("wrong runtime directory")
					return
				}
				for name, expected := range files {
					actual, err := os.ReadFile(filepath.Join(dir, name))
					if err != nil || !bytes.Equal(actual, expected) {
						t.Errorf("partial or changed publication: %s", name)
					}
				}
			})
		}
		close(start)
		wg.Wait()
	}
}

func TestConcurrentRuntimeWaiterStillVerifiesManifestAndExistingFiles(t *testing.T) {
	data, manifest, hash, files := concurrentRuntimeFixture(t)
	parent := t.TempDir()
	var bad map[string]any
	if err := json.Unmarshal(manifest, &bad); err != nil {
		t.Fatal(err)
	}
	bad["payload_sha256"] = strings.Repeat("0", 64)
	badManifest, err := json.Marshal(bad)
	if err != nil {
		t.Fatal(err)
	}
	start := make(chan struct{})
	var wg sync.WaitGroup
	for _, valid := range []bool{true, false, true, false} {
		wg.Go(func() {
			<-start
			m := manifest
			if !valid {
				m = badManifest
			}
			_, err := unpackArchiveRuntime(parent, ArchiveBytes(data), m, hash)
			if (err == nil) != valid {
				t.Errorf("waiter skipped its own manifest proof: valid=%t err=%v", valid, err)
			}
		})
	}
	close(start)
	wg.Wait()
	path := filepath.Join(parent, runtimeDirectoryName(hash), "suhang-usbnet.exe")
	changed := bytes.Repeat([]byte("x"), len(files["suhang-usbnet.exe"]))
	if err := os.WriteFile(path, changed, 0600); err != nil {
		t.Fatal(err)
	}
	for consumer := 0; consumer < 2; consumer++ {
		wg.Go(func() {
			if _, err := unpackArchiveRuntime(parent, ArchiveBytes(data), manifest, hash); err == nil {
				t.Error("same-size corrupted cached file accepted")
			}
		})
	}
	wg.Wait()
	actual, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(actual, changed) {
		t.Fatal("foreign changed file overwritten")
	}
}

func TestSerializedRuntimeRetainsArchiveAndPathOwnershipGuards(t *testing.T) {
	data, manifest, hash, _ := concurrentRuntimeFixture(t)
	reader := &readAtOnly{data: data}
	if _, err := unpackArchiveRuntime(t.TempDir(), RuntimeArchive{reader, int64(len(data))}, manifest, hash); err != nil {
		t.Fatal(err)
	}
	if reader.largest >= len(data) || reader.largest > 64<<10 {
		t.Fatal("whole archive read")
	}
	for _, attack := range []string{"truncated", "corrupt-payload", "wrong-asset-hash", "runtime-symlink", "asset-symlink"} {
		t.Run(attack, func(t *testing.T) {
			parent := t.TempDir()
			archive, ownership := data, manifest
			size := int64(len(data))
			dir := filepath.Join(parent, runtimeDirectoryName(hash))
			switch attack {
			case "truncated":
				size--
			case "corrupt-payload":
				archive = bytes.Clone(data)
				archive[0] ^= 1
			case "wrong-asset-hash":
				var m map[string]any
				if err := json.Unmarshal(manifest, &m); err != nil {
					t.Fatal(err)
				}
				m["files"].(map[string]any)["wintun.dll"] = strings.Repeat("0", 64)
				var err error
				ownership, err = json.Marshal(m)
				if err != nil {
					t.Fatal(err)
				}
			case "runtime-symlink":
				if err := os.Symlink(t.TempDir(), dir); err != nil {
					t.Fatal(err)
				}
			case "asset-symlink":
				if err := os.Mkdir(dir, 0700); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(filepath.Join(t.TempDir(), "foreign"), filepath.Join(dir, "suhang-usbnet.exe")); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := unpackArchiveRuntime(parent, RuntimeArchive{bytes.NewReader(archive), size}, ownership, hash); err == nil {
				t.Fatal("archive/path ownership bypass")
			}
		})
	}
}
