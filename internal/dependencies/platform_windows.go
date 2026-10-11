//go:build windows && amd64

package dependencies

import (
	"archive/zip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc/mgr"
	"io"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"
)

var Default = &Manager{}

func Configure(root func() (string, error), safe func(string) error) {
	Default.Platform = &WindowsPlatform{root, safe}
}

type WindowsPlatform struct {
	RootPath func() (string, error)
	Safe     func(string) error
}

func (p *WindowsPlatform) Root() (string, error) {
	if p.RootPath == nil {
		return "", errors.New("DEPENDENCY_ROOT_UNCONFIGURED")
	}
	return p.RootPath()
}
func systemPath(name string) string {
	d, e := windows.GetSystemDirectory()
	if e != nil {
		return ""
	}
	return filepath.Join(d, name)
}
func runScript(ctx context.Context, script string, env map[string]string) ([]byte, error) {
	c := exec.CommandContext(ctx, systemPath(`WindowsPowerShell\v1.0\powershell.exe`), "-NoProfile", "-NonInteractive", "-Command", script)
	c.SysProcAttr = &syscall.SysProcAttr{CreationFlags: 0x08000000}
	c.Env = os.Environ()
	for k, v := range env {
		filtered := c.Env[:0]
		for _, x := range c.Env {
			if !strings.HasPrefix(strings.ToUpper(x), strings.ToUpper(k)+"=") {
				filtered = append(filtered, x)
			}
		}
		c.Env = append(filtered, k+"="+v)
	}
	return c.CombinedOutput()
}
func (p *WindowsPlatform) Verify(a Asset, path string) error {
	if p.Safe != nil {
		if e := p.Safe(path); e != nil {
			return e
		}
	}
	// Archives are pinned by the official checksum. Executables also need native
	// trust verification; extracted drivers retain their catalog and native check.
	if !strings.EqualFold(filepath.Ext(path), ".exe") && a.ID != "zadig" && a.ID != "apple-support" {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	b, e := runScript(ctx, `$ErrorActionPreference='Stop';$s=Get-AuthenticodeSignature -LiteralPath $env:USBLINK_DEP_FILE;if($s.Status -ne 'Valid' -or $s.SignerCertificate.Subject -notmatch ('(^|,\s*)O='+[regex]::Escape($env:USBLINK_DEP_SIGNER)+'(,|$)')){throw 'DEPENDENCY_SIGNATURE_REJECTED'};'VERIFIED'`, map[string]string{"USBLINK_DEP_FILE": path, "USBLINK_DEP_SIGNER": a.Signer})
	if e != nil || strings.TrimSpace(string(b)) != "VERIFIED" {
		return errors.New("DEPENDENCY_SIGNATURE_REJECTED")
	}
	return nil
}

func (p *WindowsPlatform) tree(a Asset, root string) string {
	return filepath.Join(root, a.ID+"-"+a.Version)
}
func (p *WindowsPlatform) validTree(a Asset, dir string) bool {
	if p.Safe != nil && p.Safe(dir) != nil {
		return false
	}
	b, e := os.ReadFile(filepath.Join(dir, "dependency-files.json"))
	var m treeReceipt
	if e != nil || len(b) > 2<<20 || json.Unmarshal(b, &m) != nil || m.Digest != a.Digest || len(m.Files) == 0 {
		return false
	}
	for name, want := range m.Files {
		path := filepath.Join(dir, filepath.FromSlash(name))
		if !safeEntry(name) || p.Safe != nil && p.Safe(path) != nil {
			return false
		}
		f, e := os.Open(path)
		if e != nil {
			return false
		}
		h := sha256.New()
		_, e = io.Copy(h, io.LimitReader(f, 256<<20))
		f.Close()
		if e != nil || hex.EncodeToString(h.Sum(nil)) != want {
			return false
		}
	}
	return true
}
func (p *WindowsPlatform) Detect(a Asset, root string) (string, bool) {
	if a.ID == "apple-support" {
		m, e := mgr.Connect()
		if e != nil {
			return "", false
		}
		defer m.Disconnect()
		s, e := m.OpenService("Apple Mobile Device Service")
		if e != nil {
			return "", false
		}
		defer s.Close()
		config, e := s.Config()
		if e != nil {
			return "", false
		}
		binary := strings.TrimSpace(config.BinaryPathName)
		if strings.HasPrefix(binary, `"`) {
			if end := strings.Index(binary[1:], `"`); end >= 0 {
				binary = binary[1 : 1+end]
			}
		} else if end := strings.Index(strings.ToLower(binary), ".exe"); end >= 0 {
			binary = binary[:end+4]
		}
		// Existing Apple software stays outside the product-owned dependency root.
		verify := *p
		verify.Safe = nil
		return binary, filepath.IsAbs(binary) && verify.Verify(a, binary) == nil
	}
	if a.ID == "zadig" {
		path := filepath.Join(root, a.ID+"-"+a.Version+"-"+a.Digest[:16]+".exe")
		if check(a, path) == nil && p.Verify(a, path) == nil {
			return path, true
		}
		return "", false
	}
	if a.ID == "dotnet" {
		pf, e := windows.KnownFolderPath(windows.FOLDERID_ProgramFiles, 0)
		if e == nil {
			binary := filepath.Join(pf, "dotnet/dotnet.exe")
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			c := exec.CommandContext(ctx, binary, "--list-runtimes")
			c.SysProcAttr = &syscall.SysProcAttr{CreationFlags: 0x08000000}
			if b, e := c.Output(); e == nil {
				for _, line := range strings.Split(string(b), "\n") {
					if strings.HasPrefix(line, "Microsoft.NETCore.App 10.") {
						return filepath.Dir(binary), true
					}
				}
			}
		}
	}
	dir := p.tree(a, root)
	if !p.validTree(a, dir) {
		return "", false
	}
	switch a.ID {
	case "wintun":
		return filepath.Join(dir, "wintun.dll"), true
	case "dotnet":
		return dir, true
	case "apple-driver":
		return dir, true
	}
	return "", false
}
func safeEntry(name string) bool {
	return name != "" && !strings.ContainsAny(name, "\\:") && !strings.HasPrefix(name, "/") && filepath.ToSlash(filepath.Clean(name)) == name && name != ".." && !strings.HasPrefix(name, "../")
}
func (p *WindowsPlatform) Install(ctx context.Context, a Asset, archive, root string) (string, error) {
	if e := ctx.Err(); e != nil {
		return "", e
	}
	if a.ID == "zadig" {
		return archive, nil
	}
	if a.ID == "apple-support" {
		// The original official installer owns its license UI. Do not kill an MSI
		// transaction on cancellation; wait and retain its reboot-required result.
		c := exec.Command(archive, "/norestart")
		e := c.Run()
		if c.ProcessState == nil {
			return "", errors.New("DEPENDENCY_INSTALLER_LAUNCH_FAILED")
		}
		code := c.ProcessState.ExitCode()
		if code == 3010 || code == 1641 {
			return "", errors.New("DEPENDENCY_REBOOT_REQUIRED")
		}
		if e != nil {
			return "", fmt.Errorf("DEPENDENCY_OFFICIAL_INSTALLER_FAILED_%d", code)
		}
		return archive, nil
	}
	dir := p.tree(a, root)
	if _, e := os.Lstat(dir); e == nil {
		return "", errors.New("DEPENDENCY_EXISTING_TREE_UNVERIFIED")
	}
	stage, e := os.MkdirTemp(root, "extract-")
	if e != nil {
		return "", e
	}
	defer os.RemoveAll(stage)
	if a.ID == "apple-driver" {
		c := exec.CommandContext(ctx, systemPath("expand.exe"), archive, "-F:*", stage)
		c.SysProcAttr = &syscall.SysProcAttr{CreationFlags: 0x08000000}
		if e = c.Run(); e != nil {
			return "", e
		}
	} else {
		z, e := zip.OpenReader(archive)
		if e != nil {
			return "", e
		}
		defer z.Close()
		var total uint64
		seen := map[string]bool{}
		for _, f := range z.File {
			if e = ctx.Err(); e != nil {
				return "", e
			}
			name := f.Name
			if f.FileInfo().IsDir() {
				continue
			}
			if a.ID == "wintun" {
				if name != "wintun/bin/amd64/wintun.dll" && name != "wintun/LICENSE.txt" {
					continue
				}
				name = filepath.Base(name)
			}
			total += f.UncompressedSize64
			if !safeEntry(name) || seen[strings.ToLower(name)] || f.Mode()&os.ModeSymlink != 0 || f.UncompressedSize64 > 256<<20 || total > 512<<20 {
				return "", errors.New("DEPENDENCY_ARCHIVE_INVALID")
			}
			seen[strings.ToLower(name)] = true
			target := filepath.Join(stage, filepath.FromSlash(name))
			if e = os.MkdirAll(filepath.Dir(target), 0700); e != nil {
				return "", e
			}
			in, e := f.Open()
			if e != nil {
				return "", e
			}
			out, e := os.OpenFile(target, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
			if e != nil {
				in.Close()
				return "", e
			}
			n, e := io.Copy(out, io.LimitReader(in, 256<<20+1))
			in.Close()
			ce := out.Close()
			if e != nil || ce != nil || uint64(n) != f.UncompressedSize64 {
				return "", errors.New("DEPENDENCY_ARCHIVE_CORRUPTED")
			}
		}
	}
	m := treeReceipt{Digest: a.Digest, Files: map[string]string{}}
	e = filepath.WalkDir(stage, func(path string, de os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if de.IsDir() {
			return nil
		}
		if de.Type()&os.ModeSymlink != 0 {
			return errors.New("DEPENDENCY_REPARSE_REJECTED")
		}
		b, e := os.ReadFile(path)
		if e != nil {
			return e
		}
		relative, _ := filepath.Rel(stage, path)
		h := sha256.Sum256(b)
		m.Files[filepath.ToSlash(relative)] = hex.EncodeToString(h[:])
		return nil
	})
	if e != nil {
		return "", e
	}
	if a.ID == "wintun" && m.Files["wintun.dll"] != WintunAMD64SHA256 {
		return "", errors.New("DEPENDENCY_WINTUN_HASH_MISMATCH")
	}
	data, _ := json.Marshal(m)
	if e = os.WriteFile(filepath.Join(stage, "dependency-files.json"), data, 0600); e != nil {
		return "", e
	}
	if e = os.Rename(stage, dir); e != nil {
		return "", e
	}
	return dir, nil
}

func (p *WindowsPlatform) ReuseWintun(ctx context.Context, a Asset, source, root string) error {
	return importPinnedWintun(ctx, a, source, root, WintunAMD64SHA256, p.Safe)
}

// Serialize each component across the UI and core processes, without a .NET
// download or Apple installer holding an already usable Mac USB component.
var dependencyProcessLock assetWork

func Ensure(ctx context.Context, id string) (string, error) { return ensureWithRetry(ctx, id, false) }
func Retry(ctx context.Context, id string) (string, error)  { return ensureWithRetry(ctx, id, true) }
func ensureWithRetry(ctx context.Context, id string, retry bool) (string, error) {
	a, e := Lookup(id)
	if e != nil {
		return "", e
	}
	release, e := dependencyProcessLock.acquire(ctx, a.ID)
	if e != nil {
		return "", e
	}
	defer release()
	// Native mutex ownership belongs to an OS thread, not a Go goroutine.
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	name, _ := windows.UTF16PtrFromString(`Global\USBLinkOfficialDependencies-v2-` + a.ID)
	sd, e := windows.SecurityDescriptorFromString("O:BAG:BAD:P(A;;0x001f0001;;;SY)(A;;0x001f0001;;;BA)")
	if e != nil {
		return "", e
	}
	sa := windows.SecurityAttributes{Length: uint32(unsafeSizeSA), SecurityDescriptor: sd}
	h, e := windows.CreateMutex(&sa, false, name)
	if e != nil && e != windows.ERROR_ALREADY_EXISTS {
		return "", e
	}
	defer windows.CloseHandle(h)
	if e = verifyDependencyMutex(h); e != nil {
		return "", e
	}
	for {
		if e = ctx.Err(); e != nil {
			return "", e
		}
		state, e := windows.WaitForSingleObject(h, 200)
		if e != nil {
			return "", e
		}
		if state == windows.WAIT_OBJECT_0 || state == windows.WAIT_ABANDONED {
			break
		}
		if e = ctx.Err(); e != nil {
			return "", e
		}
	}
	defer windows.ReleaseMutex(h)
	if retry {
		p, ok := Default.Platform.(*WindowsPlatform)
		if !ok {
			return "", errors.New("DEPENDENCY_PLATFORM_UNCONFIGURED")
		}
		root, e := p.Root()
		if e != nil {
			return "", e
		}
		if _, ready := p.Detect(a, root); !ready {
			if e = p.prepareRetry(a, root); e != nil {
				return "", e
			}
		}
	}
	return Default.Ensure(ctx, id)
}

const unsafeSizeSA = 24 // SECURITY_ATTRIBUTES layout on Windows amd64.

// Explicit retry preserves invalid product-owned material in quarantine. It is
// never reused, overwritten silently, or confused with shared/system software.
func (p *WindowsPlatform) prepareRetry(a Asset, root string) error {
	u, e := url.Parse(a.URL)
	if e != nil {
		return e
	}
	archive := filepath.Join(root, a.ID+"-"+a.Version+"-"+a.Digest[:16]+filepath.Ext(u.Path))
	paths := []string{}
	if _, e = os.Lstat(archive); e == nil && (check(a, archive) != nil || p.Verify(a, archive) != nil) {
		paths = append(paths, archive)
	}
	tree := p.tree(a, root)
	if _, e = os.Lstat(tree); e == nil && !p.validTree(a, tree) {
		paths = append(paths, tree)
	}
	for _, path := range paths {
		if e = filepath.WalkDir(path, func(file string, de os.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if p.Safe != nil {
				return p.Safe(file)
			}
			return nil
		}); e != nil {
			return e
		}
		if e = os.Rename(path, path+".rejected-"+strconv.FormatInt(time.Now().UnixNano(), 10)); e != nil {
			return e
		}
	}
	return nil
}
