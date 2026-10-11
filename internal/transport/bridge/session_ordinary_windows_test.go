//go:build windows && amd64

package bridge

import (
	"golang.org/x/sys/windows"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"unsafe"
)

func TestOrdinaryRecordProtectedInheritedLeafFixtures(t *testing.T) {
	if !windows.GetCurrentProcessToken().IsElevated() {
		t.Skip("native ACL fixtures require administrator")
	}
	parent := filepath.Join(t.TempDir(), "store")
	sd, err := windows.SecurityDescriptorFromString("O:BAG:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)")
	if err != nil {
		t.Fatal(err)
	}
	sa := windows.SecurityAttributes{Length: uint32(unsafe.Sizeof(windows.SecurityAttributes{})), SecurityDescriptor: sd}
	p, _ := windows.UTF16PtrFromString(parent)
	if err = windows.CreateDirectory(p, &sa); err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(parent, "mac-runtime-"+strings.Repeat("a", 64))
	if err = os.Mkdir(dir, 0700); err != nil {
		t.Fatal(err)
	}
	record := filepath.Join(dir, "owned-session.json")
	expected, b := ordinarySessionFixture()
	// Match the actual ordinary writer; its inherited BA/SY-only leaf must pass.
	if err = os.WriteFile(record, b, 0600); err != nil {
		t.Fatal(err)
	}
	observed, err := ReadOrdinaryOwnedSession(dir)
	if err != nil || VerifyLiveOrdinarySession(expected, observed) != nil {
		t.Fatalf("actual inherited writer rejected %v", err)
	}
	if _, err = ReadRetainedOwnedSession(dir); err == nil {
		t.Fatal("ordinary record promoted to retained authority")
	}
	link := filepath.Join(dir, "ordinary-record-hardlink")
	if err = os.Link(record, link); err != nil {
		t.Fatal(err)
	}
	if _, err = ReadOrdinaryOwnedSession(dir); err == nil {
		t.Fatal("multi-link ordinary record accepted")
	}
	if err = os.Remove(link); err != nil {
		t.Fatal(err)
	}
	if err = os.Remove(record); err != nil {
		t.Fatal(err)
	}
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		t.Fatal(err)
	}
	for name, sddl := range map[string]string{
		"protected_exact": "O:BAG:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)",
		"foreign_write":   "O:BAG:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FW;;;BU)",
		"missing_system":  "O:BAG:BAD:P(A;;FA;;;BA)",
		"reduced_admin":   "O:BAG:BAD:P(A;;FA;;;SY)(A;;FR;;;BA)",
		"unknown_owner":   "O:" + user.User.Sid.String() + "G:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)",
	} {
		t.Run(name, func(t *testing.T) {
			if name == "unknown_owner" && (user.User.Sid.String() == "S-1-5-18" || user.User.Sid.String() == "S-1-5-32-544") {
				t.Skip("this fixture needs a distinct creator user SID")
			}
			descriptor, e := windows.SecurityDescriptorFromString(sddl)
			if e != nil {
				t.Fatal(e)
			}
			path, _ := windows.UTF16PtrFromString(record)
			h, e := windows.CreateFile(path, windows.GENERIC_WRITE|windows.WRITE_DAC|windows.WRITE_OWNER, 0, nil, windows.CREATE_NEW, windows.FILE_ATTRIBUTE_NORMAL, 0)
			if e != nil {
				t.Fatal(e)
			}
			f := os.NewFile(uintptr(h), "owned-session.json")
			if _, e = f.Write(b); e != nil {
				f.Close()
				t.Fatal(e)
			}
			owner, _, e := descriptor.Owner()
			if e != nil {
				f.Close()
				t.Fatal(e)
			}
			dacl, _, e := descriptor.DACL()
			if e != nil {
				f.Close()
				t.Fatal(e)
			}
			if e = windows.SetSecurityInfo(h, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, owner, nil, dacl, nil); e != nil {
				f.Close()
				t.Fatal(e)
			}
			if e = f.Close(); e != nil {
				t.Fatal(e)
			}
			got, e := ReadOrdinaryOwnedSession(dir)
			if name == "protected_exact" {
				if e != nil || VerifyLiveOrdinarySession(expected, got) != nil {
					t.Fatal("exact protected ACL rejected", e)
				}
			} else if e == nil {
				t.Fatal("unsafe ACL accepted")
			}
			if e = os.Remove(record); e != nil {
				t.Fatal(e)
			}
		})
	}
}

func TestReadableRuntimeNameCannotAuthorizeWritableStore(t *testing.T) {
	parent := t.TempDir()
	dir := filepath.Join(parent, "mac-runtime-0.9.4")
	if err := os.Mkdir(dir, 0700); err != nil {
		t.Fatal(err)
	}
	if !ownedRuntimeName.MatchString(filepath.Base(dir)) {
		t.Fatal("readable release syntax rejected")
	}
	if retainedRuntimeProtected(dir) {
		t.Fatal("release name authorized an unprotected store")
	}
}
