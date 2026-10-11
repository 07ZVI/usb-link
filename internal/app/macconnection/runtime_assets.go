package macconnection

import (
	"archive/zip"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"suhang/usbnet/internal/buildinfo"
	"sync"
)

var expectedBridgeSHA string // Injected from the freshly built bridge by the release pipeline.

var runtimeName = runtimeDirectoryName(expectedBridgeSHA)

// The host preparer and Mac worker share this cache in the same owner process.
// Hold only while validating/materializing the archive: no host join, topology
// lock acquisition or child launch happens under this mutex. This is not a
// cross-process lock; another writer still causes the existing checks to fail.
var runtimeUnpackMu sync.Mutex

func runtimeDirectoryName(hash string) string {
	if hash == expectedBridgeSHA && regexp.MustCompile(`^[0-9]+\.[0-9]+\.[0-9]+$`).MatchString(buildinfo.Version) {
		return "mac-runtime-" + buildinfo.Version
	}
	return "mac-runtime-" + hash
}

// RuntimeArchive keeps embedded read-only bytes outside the Go heap.
type RuntimeArchive struct {
	Reader io.ReaderAt
	Size   int64
}

func ArchiveBytes(payload []byte) RuntimeArchive {
	return RuntimeArchive{bytes.NewReader(payload), int64(len(payload))}
}
func unpackArchive(parent string, payload RuntimeArchive, manifest []byte) (string, error) {
	return unpackArchiveRuntime(parent, payload, manifest, expectedBridgeSHA)
}
func unpack(parent string, payload, manifest []byte) (string, error) {
	return unpackRuntime(parent, payload, manifest, expectedBridgeSHA)
}

func unpackRuntime(parent string, payload, manifest []byte, bridgeHash string) (string, error) {
	return unpackArchiveRuntime(parent, ArchiveBytes(payload), manifest, bridgeHash)
}
func unpackArchiveRuntime(parent string, payload RuntimeArchive, manifest []byte, bridgeHash string) (string, error) {
	runtimeUnpackMu.Lock()
	defer runtimeUnpackMu.Unlock()
	if payload.Reader == nil || payload.Size < 1 || payload.Size > 64<<20 {
		return "", fmt.Errorf("payload size invalid")
	}

	dir := filepath.Join(parent, runtimeDirectoryName(bridgeHash))
	if e := os.Mkdir(dir, 0700); e != nil && !os.IsExist(e) {
		return "", e
	}
	i, e := os.Lstat(dir)
	if e != nil || !i.IsDir() || i.Mode()&os.ModeSymlink != 0 || !safeRuntimeDirectory(dir) {
		return "", fmt.Errorf("runtime redirected")
	}
	var m struct {
		Files      map[string]string `json:"files"`
		PayloadSHA string            `json:"payload_sha256"`
	}
	digest := sha256.New()
	if n, e := io.Copy(digest, io.NewSectionReader(payload.Reader, 0, payload.Size)); e != nil || n != payload.Size {
		return "", fmt.Errorf("payload read failed")
	}
	h := digest.Sum(nil)
	if json.Unmarshal(manifest, &m) != nil || m.PayloadSHA != hex.EncodeToString(h) || m.Files["suhang-usbnet.exe"] != bridgeHash {
		return "", fmt.Errorf("payload ownership failed")
	}
	z, e := zip.NewReader(payload.Reader, payload.Size)
	if e != nil || len(z.File) != len(m.Files) || len(z.File) > 32 {
		return "", fmt.Errorf("payload invalid")
	}
	seen := map[string]bool{}
	for _, f := range z.File {
		if f.Name != filepath.Base(f.Name) || strings.ContainsAny(f.Name, `/\:`) || f.UncompressedSize64 > 32*1024*1024 || m.Files[f.Name] == "" || seen[f.Name] {
			return "", fmt.Errorf("payload entry invalid")
		}
		seen[f.Name] = true
		r, e := f.Open()
		if e != nil {
			return "", e
		}
		b, e := io.ReadAll(io.LimitReader(r, 32*1024*1024+1))
		r.Close()
		h := sha256.Sum256(b)
		if e != nil || hex.EncodeToString(h[:]) != m.Files[f.Name] {
			return "", fmt.Errorf("asset hash failed")
		}
		p := filepath.Join(dir, f.Name)
		if st, er := os.Lstat(p); er == nil {
			if !safeExisting(p) || st.Size() != int64(len(b)) {
				return "", fmt.Errorf("existing asset changed: %s", f.Name)
			}
			old, er := os.ReadFile(p)
			h := sha256.Sum256(old)
			if er != nil || hex.EncodeToString(h[:]) != m.Files[f.Name] {
				return "", fmt.Errorf("existing asset changed: %s", f.Name)
			}
			continue
		} else if !os.IsNotExist(er) {
			return "", fmt.Errorf("inspect %s: %w", f.Name, er)
		}
		out, e := os.OpenFile(p, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if e != nil {
			return "", e
		}
		_, e = out.Write(b)
		ce := out.Close()
		if e != nil || ce != nil {
			return "", fmt.Errorf("asset write failed")
		}
	}
	return dir, nil
}

// Old layouts remain recoverable; only the exact content-addressed directory
// syntax is admitted, and recovery separately validates its protected journal.
func recoveryRuntimeNames(parent string) ([]string, error) {
	names := []string{"mac-runtime-v1", "mac-runtime-v2", "mac-runtime-v3", "mac-runtime-v4"}
	entries, e := os.ReadDir(parent)
	if e != nil {
		return nil, e
	}
	pattern := regexp.MustCompile(`^mac-runtime-([a-f0-9]{64}|[0-9]+\.[0-9]+\.[0-9]+)$`)
	for _, entry := range entries {
		if pattern.MatchString(entry.Name()) {
			names = append(names, entry.Name())
		}
	}
	sort.Strings(names)
	return names, nil
}
