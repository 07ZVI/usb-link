//go:build windows && amd64

package connectioninstall

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"golang.org/x/sys/windows"
	"io"
	"os"
	"path/filepath"
	"sort"
	"unsafe"
)

const installACL = "D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;0x1200a9;;;BU)"

type Receipt struct {
	Product string `json:"product"`
	Version string `json:"version"`
	SHA     string `json:"sha256"`
}

func Root() (string, error) {
	p, e := windows.KnownFolderPath(windows.FOLDERID_ProgramFiles, 0)
	return filepath.Join(p, "USB Link"), e
}
func noReparse(path string) error {
	p, e := windows.UTF16PtrFromString(path)
	if e != nil {
		return e
	}
	a, e := windows.GetFileAttributes(p)
	if e != nil {
		return &os.PathError{Op: "GetFileAttributes", Path: path, Err: e}
	}
	if a&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
		return fmt.Errorf("installation path redirected")
	}
	return nil
}
func sameACL(actual, wanted *windows.SECURITY_DESCRIPTOR) bool {
	want, _, err := wanted.DACL()
	if err != nil || want == nil || want.AceCount == 0 {
		return false
	}
	count := want.AceCount
	c, _, e := actual.Control()
	if e != nil || c&windows.SE_DACL_PROTECTED == 0 {
		return false
	}
	aces := func(s *windows.SECURITY_DESCRIPTOR) ([]string, bool) {
		a, _, e := s.DACL()
		if e != nil || a == nil || a.AceCount != count {
			return nil, false
		}
		var v []string
		for i := uint32(0); i < uint32(count); i++ {
			var ace *windows.ACCESS_ALLOWED_ACE
			if windows.GetAce(a, i, &ace) != nil || ace == nil || ace.Header.AceSize < 8 || ace.Header.AceSize > 64 {
				return nil, false
			}
			v = append(v, string(unsafe.Slice((*byte)(unsafe.Pointer(ace)), int(ace.Header.AceSize))))
		}
		sort.Strings(v)
		return v, true
	}
	a, ok := aces(actual)
	b, valid := aces(wanted)
	if !ok || !valid {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
func protectedRoot(create bool) (string, error) {
	root, e := Root()
	if e != nil {
		return "", e
	}
	return protectedRootAt(root, create)
}
func protectedRootAt(root string, create bool) (string, error) {
	sd, e := windows.SecurityDescriptorFromString(installACL)
	if e != nil {
		return "", e
	}
	created := false
	if create {
		p, _ := windows.UTF16PtrFromString(root)
		sa := windows.SecurityAttributes{Length: uint32(unsafe.Sizeof(windows.SecurityAttributes{})), SecurityDescriptor: sd}
		e = windows.CreateDirectory(p, &sa)
		created = e == nil
		if e != nil && e != windows.ERROR_ALREADY_EXISTS {
			return "", e
		}
	}
	if noReparse(root) != nil {
		return "", fmt.Errorf("unsafe program directory")
	}
	actual, e := windows.GetNamedSecurityInfo(root, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
	if e != nil || !sameACL(actual, sd) {
		return "", fmt.Errorf("unexpected program directory permissions")
	}
	marker := filepath.Join(root, "product-id.txt")
	if created {
		if e = os.WriteFile(marker, []byte(ProductID), 0600); e != nil {
			return "", e
		}
	}
	if noReparse(marker) != nil {
		return "", fmt.Errorf("unsafe product marker")
	}
	b, e := os.ReadFile(marker)
	if e != nil || string(b) != ProductID {
		return "", fmt.Errorf("unowned program directory")
	}
	return root, nil
}
func readReceipt(dir string) (Receipt, error) {
	var r Receipt
	if noReparse(dir) != nil || noReparse(filepath.Join(dir, "ownership.json")) != nil {
		return r, fmt.Errorf("unowned version directory")
	}
	b, e := os.ReadFile(filepath.Join(dir, "ownership.json"))
	if e != nil || len(b) > 4096 || json.Unmarshal(b, &r) != nil || r.Product != ProductID || !versionPattern.MatchString(r.Version) || filepath.Base(dir) != r.Version {
		return r, fmt.Errorf("invalid ownership receipt")
	}
	h, e := hex.DecodeString(r.SHA)
	if e != nil || len(h) != 32 {
		return r, fmt.Errorf("invalid file hash")
	}
	return r, nil
}
func fileHash(path string) (string, error) {
	if sum, pinned, e := pinnedCoreSelfHash(path); pinned {
		return sum, e
	}
	if noReparse(path) != nil {
		return "", fmt.Errorf("unsafe executable path")
	}
	f, e := os.Open(path)
	if e != nil {
		return "", e
	}
	defer f.Close()
	st, e := f.Stat()
	if e != nil || !st.Mode().IsRegular() || st.Size() < 1024 || st.Size() > 256*1024*1024 {
		return "", fmt.Errorf("invalid executable size")
	}
	h := sha256.New()
	n, e := io.Copy(h, io.LimitReader(f, 256*1024*1024+1))
	if e != nil || n != st.Size() {
		return "", fmt.Errorf("executable read failed")
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}
func Verify(path string) error {
	dir := filepath.Dir(path)
	root, e := Root()
	if e != nil {
		return e
	}
	legacy, e := legacyRoot()
	if e != nil {
		return e
	}
	parent := filepath.Dir(dir)
	if !validInstallLocation(parent, filepath.Base(path), root, legacy) {
		return fmt.Errorf("unowned startup path")
	}
	if _, e = protectedRootAt(parent, false); e != nil {
		return e
	}
	r, e := readReceipt(dir)
	if e != nil {
		return e
	}
	sum, e := fileHash(path)
	if e != nil || sum != r.SHA {
		return fmt.Errorf("installed executable hash changed")
	}
	return nil
}
func Prepare(version string) (string, error) {
	if !versionPattern.MatchString(version) {
		return "", fmt.Errorf("invalid version")
	}
	root, e := protectedRoot(true)
	if e != nil {
		return "", e
	}
	source, e := os.Executable()
	if e != nil {
		return "", e
	}
	sum, e := fileHash(source)
	if e != nil {
		return "", e
	}
	dir := filepath.Join(root, version)
	target := filepath.Join(dir, BinaryName)
	if _, e = os.Stat(dir); e == nil {
		if e = Verify(target); e != nil {
			return "", e
		}
		r, e := readReceipt(dir)
		if e != nil || r.SHA != sum {
			return "", fmt.Errorf("same version differs; existing installation preserved")
		}
		return target, nil
	} else if !os.IsNotExist(e) {
		return "", e
	}
	stage, e := os.MkdirTemp(root, "install-")
	if e != nil {
		return "", e
	}
	stagingBinary := filepath.Join(stage, BinaryName)
	defer func() { os.Remove(stagingBinary); os.Remove(filepath.Join(stage, "ownership.json")); os.Remove(stage) }()
	in, e := os.Open(source)
	if e != nil {
		return "", e
	}
	defer in.Close()
	out, e := os.OpenFile(stagingBinary, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if e != nil {
		return "", e
	}
	_, e = io.Copy(out, io.LimitReader(in, 256*1024*1024+1))
	if e == nil {
		e = out.Sync()
	}
	ce := out.Close()
	if e != nil {
		return "", e
	}
	if ce != nil {
		return "", ce
	}
	actual, e := fileHash(stagingBinary)
	if e != nil || actual != sum {
		return "", fmt.Errorf("installed copy hash mismatch")
	}
	b, _ := json.Marshal(Receipt{ProductID, version, sum})
	if e = os.WriteFile(filepath.Join(stage, "ownership.json"), b, 0600); e != nil {
		return "", e
	}
	from, _ := windows.UTF16PtrFromString(stage)
	to, _ := windows.UTF16PtrFromString(dir)
	if e = windows.MoveFileEx(from, to, windows.MOVEFILE_WRITE_THROUGH); e != nil {
		return "", e
	}
	return target, Verify(target)
}
func taskIdentity() (string, string, error) {
	u, e := windows.GetCurrentProcessToken().GetTokenUser()
	if e != nil {
		return "", "", e
	}
	sid := u.User.Sid.String()
	if nativeStartupEnabled.Load() && u.User.Sid.IsWellKnown(windows.WinLocalSystemSid) {
		// A SYSTEM core may act only for the independently authenticated,
		// protected service owner. SYSTEM itself is never an interactive task
		// principal, and no caller-supplied SID is accepted here.
		bound, ok := BoundCoreOwnerSID()
		if !ok {
			return "", "", fmt.Errorf("core interactive owner unavailable")
		}
		sid = bound
	}
	if !sidPattern.MatchString(sid) {
		return "", "", fmt.Errorf("interactive Windows user required")
	}
	h := sha256.Sum256([]byte(sid))
	return "USB-Link-" + hex.EncodeToString(h[:8]), sid, nil
}

// Task actions are accepted only in our protected Program Files version tree,
// with our marker, receipt, exact hash, principal and fixed --resident argument.
func SetStartup(enabled bool, path string) error {
	mode := "OFF"
	if enabled {
		mode = "ON"
	}
	_, err := runStartupTaskMode(context.Background(), mode, path)
	return err
}
