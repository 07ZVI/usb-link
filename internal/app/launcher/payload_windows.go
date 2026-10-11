//go:build windows && amd64

package launcher

import (
	"archive/zip"
	"bytes"
	"embed"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"suhang/usbnet/internal/app/macconnection"
)

//go:embed assets/desktop-0.8.140.zip assets/apple-payload.zip assets/NOTICES.txt assets/SOURCES.json assets/mac-payload-0.8.140.zip assets/MAC-SOURCES-0.8.140.json assets/MAC-NOTICES.txt assets/SMB-LICENSES-0.8.36.txt assets/SMB-SOURCES-0.8.36.json
var payload embed.FS

// Read only fixed known entries. Existing installer validation then checks each
// exact file digest and native signature before any registration/installation.
func bundledFile(name string) ([]byte, error) {
	limit := int64(1024 * 1024)
	if name == "AppleMobileDeviceSupport64.msi" {
		limit = 64 * 1024 * 1024
	} else if _, ok := driverFiles[filepath.Base(name)]; !ok || name != "AppleUSB/"+filepath.Base(name) {
		return nil, errors.New("unknown bundled file")
	}
	b, e := payload.ReadFile("assets/apple-payload.zip")
	if e != nil {
		return nil, e
	}
	z, e := zip.NewReader(bytes.NewReader(b), int64(len(b)))
	if e != nil {
		return nil, e
	}
	var found *zip.File
	for _, f := range z.File {
		if f.Name == name {
			if found != nil {
				return nil, errors.New("duplicate bundled file")
			}
			found = f
		}
	}
	if found == nil || found.UncompressedSize64 > uint64(limit) {
		return nil, errors.New("missing or oversized bundled file")
	}
	r, e := found.Open()
	if e != nil {
		return nil, e
	}
	defer r.Close()
	content, e := io.ReadAll(io.LimitReader(r, limit+1))
	if e != nil {
		return nil, e
	}
	if int64(len(content)) > limit {
		return nil, errors.New("oversized bundled file")
	}
	return content, nil
}

func writeNotices(dir string) error {
	for name, src := range map[string]string{"SMB-LICENSES.txt": "assets/SMB-LICENSES-0.8.36.txt", "SMB-SOURCES.json": "assets/SMB-SOURCES-0.8.36.json", "LICENSES.txt": "assets/NOTICES.txt", "SOURCES.json": "assets/SOURCES.json", "MAC-SOURCES.json": "assets/MAC-SOURCES-0.8.140.json", "MAC-LICENSES.txt": "assets/MAC-NOTICES.txt"} {
		b, e := payload.ReadFile(src)
		if e != nil {
			return e
		}
		path := filepath.Join(dir, name)
		if old, e := os.ReadFile(path); e == nil {
			if bytes.Equal(old, b) {
				continue
			}
			return errors.New("notice destination already exists")
		}
		f, e := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if e != nil {
			return e
		}
		_, e = f.Write(b)
		ce := f.Close()
		if e != nil {
			return e
		}
		if ce != nil {
			return ce
		}
	}
	return nil
}

// Embedded FS openFile implements ReaderAt over immutable image data.
func macArchive(name string) (macconnection.RuntimeArchive, error) {
	f, e := payload.Open(name)
	if e != nil {
		return macconnection.RuntimeArchive{}, e
	}
	defer f.Close()
	info, e := f.Stat()
	if e != nil {
		return macconnection.RuntimeArchive{}, e
	}
	reader, ok := f.(io.ReaderAt)
	if !ok {
		return macconnection.RuntimeArchive{}, fmt.Errorf("embedded archive is not seekable")
	}
	return macconnection.RuntimeArchive{Reader: reader, Size: info.Size()}, nil
}
