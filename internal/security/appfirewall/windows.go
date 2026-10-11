//go:build windows && amd64

package appfirewall

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"golang.org/x/sys/windows"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"
	"unicode/utf16"
)

type WindowsExecutor struct{}

func safeFile(path string) error {
	p, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return err
	}
	a, err := windows.GetFileAttributes(p)
	if err != nil {
		return err
	}
	if a&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
		return fmt.Errorf("FIREWALL_REPARSE_POINT_REFUSED")
	}
	return nil
}

func (WindowsExecutor) Inspect(ctx context.Context, path string) (Identity, error) {
	if !ValidProgramPath(path) {
		return Identity{}, fmt.Errorf("FIREWALL_PROGRAM_PATH_INVALID")
	}
	for p := path; ; p = filepath.Dir(p) {
		if err := safeFile(p); err != nil {
			return Identity{}, err
		}
		if filepath.Dir(p) == p {
			break
		}
	}
	f, err := os.Open(path)
	if err != nil {
		return Identity{}, err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() < 64 || info.Size() > 1<<30 {
		return Identity{}, fmt.Errorf("FIREWALL_PROGRAM_INVALID")
	}
	var dos [64]byte
	if _, err = f.ReadAt(dos[:], 0); err != nil || string(dos[:2]) != "MZ" {
		return Identity{}, fmt.Errorf("FIREWALL_NOT_EXECUTABLE")
	}
	off := int64(binary.LittleEndian.Uint32(dos[60:]))
	var pe [4]byte
	if off < 64 || off > info.Size()-4 {
		return Identity{}, fmt.Errorf("FIREWALL_PE_INVALID")
	}
	if _, err = f.ReadAt(pe[:], off); err != nil || string(pe[:]) != "PE\x00\x00" {
		return Identity{}, fmt.Errorf("FIREWALL_PE_INVALID")
	}
	h := sha256.New()
	buf := make([]byte, 65536)
	for {
		if err = ctx.Err(); err != nil {
			return Identity{}, err
		}
		n, e := f.Read(buf)
		if n > 0 {
			h.Write(buf[:n])
		}
		if e == io.EOF {
			break
		}
		if e != nil {
			return Identity{}, e
		}
	}
	after, err := f.Stat()
	if err != nil || after.Size() != info.Size() || !after.ModTime().Equal(info.ModTime()) {
		return Identity{}, fmt.Errorf("FIREWALL_PROGRAM_CHANGED")
	}
	return Identity{Path: path, SHA256: hex.EncodeToString(h.Sum(nil)), Size: info.Size()}, nil
}

// The system firewall owns enforcement. This adapter changes only exact rules
// from the protected local receipt; it does not change profile defaults.
func (WindowsExecutor) Apply(parent context.Context, c Change) error {
	if !windows.GetCurrentProcessToken().IsElevated() {
		return fmt.Errorf("FIREWALL_ADMIN_REQUIRED")
	}
	script, err := Script(c)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(parent, 25*time.Second)
	defer cancel()
	b, err := runPowerShell(ctx, script)
	if err != nil {
		return err
	}
	marker := "APP_FIREWALL_RULE_APPLIED"
	if c.Operation == "delete" {
		marker = "APP_FIREWALL_RULE_REMOVED"
	}
	if strings.TrimSpace(string(b)) != marker {
		return fmt.Errorf("FIREWALL_RESULT_UNCONFIRMED")
	}
	return nil
}

func runPowerShell(ctx context.Context, script string) ([]byte, error) {
	system, err := windows.GetSystemDirectory()
	if err != nil {
		return nil, err
	}
	u := utf16.Encode([]rune(script))
	encoded := make([]byte, len(u)*2)
	for i, v := range u {
		binary.LittleEndian.PutUint16(encoded[i*2:], v)
	}
	cmd := exec.CommandContext(ctx, filepath.Join(system, "WindowsPowerShell", "v1.0", "powershell.exe"), "-NoProfile", "-NonInteractive", "-EncodedCommand", base64.StdEncoding.EncodeToString(encoded))
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true, CreationFlags: 0x08000000}
	b, err := cmd.CombinedOutput()
	if err != nil {
		if len(b) > 2048 {
			b = b[len(b)-2048:]
		}
		return nil, fmt.Errorf("FIREWALL_EXECUTION_FAILED: %s", strings.TrimSpace(string(b)))
	}
	return b, nil
}

func (WindowsExecutor) Audit(ctx context.Context, rules []Rule) ([]Rule, error) {
	if len(rules) == 0 {
		return rules, nil
	}
	script, err := AuditScript(rules)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	b, err := runPowerShell(ctx, script)
	if err != nil {
		return nil, err
	}
	var result []struct {
		ID    string `json:"id"`
		State string `json:"state"`
		Error string `json:"error"`
	}
	if len(b) > 1<<20 || json.Unmarshal(b, &result) != nil || len(result) != len(rules) {
		return nil, fmt.Errorf("FIREWALL_AUDIT_INVALID")
	}
	for i, v := range result {
		if v.ID != rules[i].ID || (v.State != "applied" && v.State != "error") {
			return nil, fmt.Errorf("FIREWALL_AUDIT_INVALID")
		}
		rules[i].State = v.State
		rules[i].Error = v.Error
	}
	return rules, nil
}

// DiskStore is created in an ACL-verified admin/SYSTEM product directory.
type DiskStore struct{ Dir string }

// Uninstall only removes the known empty receipt. Unknown sibling files and
// interrupted-operation receipts remain available for recovery.
func (d DiskStore) RemoveEmpty() error {
	s, err := d.Load()
	if err != nil {
		return err
	}
	if len(s.Rules) != 0 || s.Pending != nil {
		return fmt.Errorf("FIREWALL_RECEIPT_NOT_EMPTY")
	}
	entries, err := os.ReadDir(d.Dir)
	if err != nil {
		return err
	}
	for _, e := range entries {
		if e.Name() != "application-firewall.json" || e.IsDir() {
			return nil
		}
	}
	path := filepath.Join(d.Dir, "application-firewall.json")
	if err = os.Remove(path); err != nil && !os.IsNotExist(err) {
		return err
	}
	return os.Remove(d.Dir)
}

func (d DiskStore) Load() (Store, error) {
	path := filepath.Join(d.Dir, "application-firewall.json")
	err := safeFile(path)
	if errors.Is(err, windows.ERROR_FILE_NOT_FOUND) {
		return Store{Version: 1, Rules: []Rule{}}, nil
	}
	if err != nil {
		return Store{}, err
	}
	f, err := os.Open(path)
	if err != nil {
		return Store{}, err
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, 1<<20+1))
	if err != nil || len(b) > 1<<20 {
		return Store{}, fmt.Errorf("FIREWALL_STORE_TOO_LARGE")
	}
	var s Store
	decoder := json.NewDecoder(strings.NewReader(string(b)))
	decoder.DisallowUnknownFields()
	if err = decoder.Decode(&s); err != nil {
		return Store{}, err
	}
	if decoder.Decode(new(any)) != io.EOF || !s.Valid() {
		return Store{}, fmt.Errorf("FIREWALL_STORE_INVALID")
	}
	return s, nil
}
func (d DiskStore) Save(s Store) error {
	if !s.Valid() {
		return fmt.Errorf("FIREWALL_STORE_INVALID")
	}
	if err := safeFile(d.Dir); err != nil {
		return err
	}
	path := filepath.Join(d.Dir, "application-firewall.json")
	if err := safeFile(path); err != nil && !errors.Is(err, windows.ERROR_FILE_NOT_FOUND) {
		return err
	}
	b, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	f, err := os.CreateTemp(d.Dir, "app-firewall-*.tmp")
	if err != nil {
		return err
	}
	name := f.Name()
	defer os.Remove(name)
	_, err = f.Write(b)
	if err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err != nil {
		return err
	}
	if closeErr != nil {
		return closeErr
	}
	return windows.MoveFileEx(windows.StringToUTF16Ptr(name), windows.StringToUTF16Ptr(path), windows.MOVEFILE_REPLACE_EXISTING|windows.MOVEFILE_WRITE_THROUGH)
}
