//go:build windows

package protectedacl

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"unsafe"

	"golang.org/x/sys/windows"
)

func parseACL(sddl string) (ACL, *windows.ACL, error) {
	sd, e := windows.SecurityDescriptorFromString(sddl)
	if e != nil {
		return ACL{}, nil, e
	}
	acl, _, e := sd.DACL()
	if e != nil || acl == nil {
		return ACL{}, nil, fmt.Errorf("expected DACL unavailable")
	}
	out, e := readACL(sd)
	out.Protected = true
	return out, acl, e
}

func readACL(sd *windows.SECURITY_DESCRIPTOR) (ACL, error) {
	var out ACL
	control, _, e := sd.Control()
	acl, _, ae := sd.DACL()
	if e != nil || ae != nil || acl == nil || acl.AceCount > 64 {
		return out, fmt.Errorf("DACL unreadable")
	}
	out.Protected = control&windows.SE_DACL_PROTECTED != 0
	for i := uint32(0); i < uint32(acl.AceCount); i++ {
		var a *windows.ACCESS_ALLOWED_ACE
		if windows.GetAce(acl, i, &a) != nil || a == nil {
			return out, fmt.Errorf("ACE unreadable")
		}
		ace := ACE{Type: a.Header.AceType, Flags: a.Header.AceFlags, Mask: uint32(a.Mask), SID: "?"}
		// Only plain allow/deny ACEs share this layout; others never match.
		if a.Header.AceType <= windows.ACCESS_DENIED_ACE_TYPE && a.Header.AceSize >= 12 {
			if sid := (*windows.SID)(unsafe.Pointer(&a.SidStart)); sid.IsValid() {
				ace.SID = sid.String()
			}
		}
		out.ACEs = append(out.ACEs, ace)
	}
	return out, nil
}

func openMeta(path string) (windows.Handle, error) {
	p, e := windows.UTF16PtrFromString(path)
	if e != nil {
		return 0, e
	}
	return windows.CreateFile(p, windows.READ_CONTROL|windows.WRITE_DAC|windows.FILE_READ_ATTRIBUTES, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE, nil, windows.OPEN_EXISTING, windows.FILE_FLAG_OPEN_REPARSE_POINT|windows.FILE_FLAG_BACKUP_SEMANTICS, 0)
}

func inspect(h windows.Handle) (Object, error) {
	var info windows.ByHandleFileInformation
	if e := windows.GetFileInformationByHandle(h, &info); e != nil {
		return Object{}, e
	}
	sd, e := windows.GetSecurityInfo(h, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if e != nil {
		return Object{}, e
	}
	o := Object{Directory: info.FileAttributes&windows.FILE_ATTRIBUTE_DIRECTORY != 0, Reparse: info.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0, Links: info.NumberOfLinks}
	if owner, _, e := sd.Owner(); e == nil && owner != nil {
		o.Owner = owner.String()
	}
	o.ACL, e = readACL(sd)
	return o, e
}

type walker struct {
	dirACL, fileACL   ACL
	dirDACL, fileDACL *windows.ACL
	apply             bool
	budget            Budget
	r                 Repair
}

func (w *walker) visit(path string, depth int) error {
	h, e := openMeta(path)
	if e != nil {
		return fmt.Errorf("%s: %w", path, e)
	}
	defer windows.CloseHandle(h)
	o, e := inspect(h)
	if e != nil {
		return fmt.Errorf("%s: %w", path, e)
	}
	want, dacl := w.fileACL, w.fileDACL
	if o.Directory {
		want, dacl = w.dirACL, w.dirDACL
	}
	act, e := Decide(o, want)
	if e != nil {
		return fmt.Errorf("%s: %w", path, e)
	}
	w.r.Checked++
	if act == Reset {
		w.r.Changed++
		if w.r.PreviousACEs == 0 {
			w.r.PreviousACEs = len(o.ACL.ACEs)
		}
		if w.apply {
			if e := windows.SetSecurityInfo(h, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, dacl, nil); e != nil {
				return fmt.Errorf("%s: set DACL: %w", path, e)
			}
		}
	}
	if !o.Directory {
		return nil
	}
	entries, e := os.ReadDir(path)
	if e != nil {
		return fmt.Errorf("%s: %w", path, e)
	}
	for _, entry := range entries {
		switch w.budget.Admit(depth + 1) {
		case SkipDeep, SkipFull:
			w.r.Skipped++
			continue
		}
		if e := w.visit(filepath.Join(path, entry.Name()), depth+1); e != nil {
			return e
		}
	}
	return nil
}

func rejectRedirected(path string) error {
	for p, depth := path, 0; ; p, depth = filepath.Dir(p), depth+1 {
		u, e := windows.UTF16PtrFromString(p)
		if e != nil {
			return e
		}
		a, e := windows.GetFileAttributes(u)
		if e != nil {
			return e
		}
		if a&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 || depth > 32 {
			return fmt.Errorf("%s: %w", p, ErrReparse)
		}
		if filepath.Dir(p) == p {
			return nil
		}
	}
}

// RepairProtectedDirectory resets path (a fixed absolute directory chosen by
// the caller, never user input) and its bounded subtree to the given protected
// SDDLs. It needs a SYSTEM or elevated Administrators caller, refuses reparse
// points, hard links and objects not owned by SYSTEM/Administrators, and never
// deletes. Nothing is changed unless the whole subtree was first admitted.
func RepairProtectedDirectory(path, dirSDDL, fileSDDL string) (Repair, error) {
	r := Repair{Path: path}
	vol := filepath.VolumeName(path)
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || len(vol) != 2 || vol[1] != ':' || len(path) <= 3 {
		return r, fmt.Errorf("protected directory path must be a fixed local absolute path")
	}
	if !windows.GetCurrentProcessToken().IsElevated() {
		return r, fmt.Errorf("protected directory repair requires an elevated caller")
	}
	dirACL, dirDACL, e := parseACL(dirSDDL)
	if e != nil {
		return r, e
	}
	fileACL, fileDACL, e := parseACL(fileSDDL)
	if e != nil {
		return r, e
	}
	if e := rejectRedirected(path); e != nil {
		if errors.Is(e, windows.ERROR_FILE_NOT_FOUND) || errors.Is(e, windows.ERROR_PATH_NOT_FOUND) {
			r.Missing = true
			return r, nil
		}
		return r, e
	}
	var final Repair
	for _, apply := range []bool{false, true} {
		w := &walker{dirACL: dirACL, fileACL: fileACL, dirDACL: dirDACL, fileDACL: fileDACL, apply: apply, r: Repair{Path: path}}
		w.budget.Admit(0)
		if e := w.visit(path, 0); e != nil {
			return r, e
		}
		final = w.r
		if !apply && final.Changed == 0 {
			break
		}
	}
	return final, nil
}
