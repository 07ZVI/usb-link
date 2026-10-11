//go:build windows && amd64

package launcher

import (
	"bytes"
	"context"
	"embed"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"suhang/usbnet/internal/app/connectioninstall"
	"suhang/usbnet/internal/app/macconnection"
	"suhang/usbnet/internal/dependencies"
	"time"
)

//go:embed assets/desktop.zip assets/mac-payload.zip assets/mac-sources.json assets/notices.txt assets/setup-license.txt assets/sources.json assets/smb-licenses.txt assets/smb-sources.json assets/wintun-0.14.1.zip assets/zadig-2.9.exe
var payload embed.FS

func bundledDependencyArchive(a dependencies.Asset) []byte {
	name := ""
	if a.ID == "wintun" && a.Version == "0.14.1" {
		name = "assets/wintun-0.14.1.zip"
	}
	if a.ID == "zadig" && a.Version == "2.9" {
		name = "assets/zadig-2.9.exe"
	}
	if name == "" {
		return nil
	}
	b, _ := payload.ReadFile(name)
	return b
}

// Read only fixed known entries. Existing installer validation then checks each
// exact file digest and native signature before any registration/installation.
func bundledFile(name string) ([]byte, error) {
	if name != "AppleUSB/"+filepath.Base(name) {
		return nil, errors.New("unknown external file")
	}
	if _, ok := driverFiles[filepath.Base(name)]; !ok {
		return nil, errors.New("unknown external driver file")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Minute)
	defer cancel()
	dir, e := dependencies.Ensure(ctx, "apple-driver")
	if e != nil {
		return nil, e
	}
	path := filepath.Join(dir, filepath.Base(name))
	if e = connectioninstall.VerifyDependencyPath(path); e != nil {
		return nil, e
	}
	return os.ReadFile(path)
}

func writeNotices(dir string) error {
	for name, src := range map[string]string{"SMB-LICENSES.txt": "assets/smb-licenses.txt", "SMB-SOURCES.json": "assets/smb-sources.json", "LICENSES.txt": "assets/notices.txt", "SOURCES.json": "assets/sources.json", "MAC-SOURCES.json": "assets/mac-sources.json", "MAC-LICENSES.txt": "assets/notices.txt"} {
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
