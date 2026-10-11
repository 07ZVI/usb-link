//go:build windows && amd64

package installer

import (
	"context"
	"fmt"
	"golang.org/x/sys/windows"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"suhang/usbnet/internal/transport/winusb"
	"time"
	"unsafe"
)

var ui = windows.NewLazySystemDLL("user32.dll")

func item(h uintptr, id uintptr) uintptr { r, _, _ := ui.NewProc("GetDlgItem").Call(h, id); return r }

//go:uintptrescapes
func message(h, msg, w, l uintptr) (uintptr, error) {
	var result uintptr
	r, _, e := ui.NewProc("SendMessageTimeoutW").Call(h, msg, w, l, 2, 2000, uintptr(unsafe.Pointer(&result)))
	if r == 0 {
		return 0, fmt.Errorf("UI message timeout: %w", e)
	}
	return result, nil
}
func text(h uintptr) (string, error) {
	b := make([]uint16, 4096)
	n, e := message(h, 13, uintptr(len(b)), uintptr(unsafe.Pointer(&b[0])))
	if e != nil {
		return "", e
	}
	if n >= uintptr(len(b)) {
		return "", fmt.Errorf("UI text overflow")
	}
	return windows.UTF16ToString(b), nil
}
func toolLog(h uintptr) (string, error) {
	c := item(h, 1004)
	if c == 0 {
		return "", fmt.Errorf("Zadig log control missing")
	}
	length, err := message(c, 14, 0, 0)
	if err != nil {
		return "", err
	}
	if length > 256*1024 {
		return "", fmt.Errorf("Zadig log exceeds capture limit")
	}
	b := make([]uint16, int(length)+1)
	if _, err = message(c, 13, uintptr(len(b)), uintptr(unsafe.Pointer(&b[0]))); err != nil {
		return "", err
	}
	return windows.UTF16ToString(b), nil
}
func logToolTail(h uintptr, l *log.Logger) {
	s, err := toolLog(h)
	r := []rune(s)
	if len(r) > 8192 {
		r = r[len(r)-8192:]
	}
	l.Printf("Zadig final log tail=%q error=%v", string(r), err)
}
func windowsFor(pid uint32) []uintptr {
	var result []uintptr
	cb := windows.NewCallback(func(h, l uintptr) uintptr {
		var p uint32
		ui.NewProc("GetWindowThreadProcessId").Call(h, uintptr(unsafe.Pointer(&p)))
		if p == pid {
			result = append(result, h)
		}
		return 1
	})
	ui.NewProc("EnumWindows").Call(cb, 0)
	return result
}
func mainDialog(pid uint32) uintptr {
	for _, h := range windowsFor(pid) {
		if item(h, 1001) != 0 && item(h, 1002) != 0 && item(h, 1009) != 0 {
			return h
		}
	}
	return 0
}
func declineUpdateQuestion(pid uint32, l *log.Logger) error {
	for _, h := range windowsFor(pid) {
		title, _ := text(h)
		if title == "" || (item(h, 1001) == 0 && item(h, 1057) == 0) {
			continue
		}
		body, _ := text(item(h, 1057))
		if !isUpdateQuestion(title, body) {
			continue
		}
		// Official v1.5.1 notification_callback handles IDNO (7). This
		// declines online updates only; it cannot accept an install prompt.
		if item(h, 7) == 0 || item(h, 6) == 0 {
			return fmt.Errorf("update dialog controls differ from official source")
		}
		l.Printf("declining official Zadig first-run online update question")
		_, err := message(h, 0x111, 7, item(h, 7))
		return err
	}
	return nil
}
func logUIState(pid uint32, l *log.Logger) {
	for _, h := range windowsFor(pid) {
		title, _ := text(h)
		if title == "" || (item(h, 1001) == 0 && item(h, 1057) == 0) {
			continue
		}
		l.Printf("Zadig window title=%q", title)
		for _, id := range []uintptr{1001, 1002, 1003, 1005, 1009, 1011, 1057} {
			if c := item(h, id); c != 0 {
				value, err := text(c)
				l.Printf("Zadig control=%d text=%q error=%v", id, value, err)
			}
		}
		if item(h, 1004) != 0 {
			logToolTail(h, l)
		}
	}
}
func selected(h uintptr, n int) bool {
	var f [5]string
	for j, id := range []uintptr{1002, 1003, 1005, 1011, 1009} {
		s, e := text(item(h, id))
		if e != nil {
			return false
		}
		f[j] = s
	}
	return MatchFields(f[0], f[1], f[2], f[3], f[4], n)
}
func choose(h uintptr, index int) error {
	combo := item(h, 1001)
	r, e := message(combo, 0x14e, uintptr(index), 0)
	if e != nil {
		return e
	}
	if int64(r) == -1 {
		return fmt.Errorf("combo selection rejected")
	}
	_, e = message(h, 0x111, 1001|(1<<16), combo)
	return e
}
func VerifySignature(path string, l *log.Logger) error {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	// Constant script; the path travels in an environment variable, never command text.
	script := `$ErrorActionPreference='Stop'; $s=Get-AuthenticodeSignature -LiteralPath $env:SUHANG_ZADIG_PATH; Write-Output ($s.Status.ToString()+' '+$s.SignerCertificate.Subject); if($s.Status -ne 'Valid' -or $s.SignerCertificate.Subject -notmatch 'Akeo Consulting'){exit 1}`
	ps := filepath.Join(os.Getenv("SystemRoot"), "System32", "WindowsPowerShell", "v1.0", "powershell.exe")
	cmd := exec.CommandContext(ctx, ps, "-NoProfile", "-NonInteractive", "-Command", script)
	cmd.Env = append(os.Environ(), "SUHANG_ZADIG_PATH="+path)
	b, e := cmd.CombinedOutput()
	l.Printf("official Zadig signature=%s error=%v", strings.TrimSpace(string(b)), e)
	if e != nil {
		return fmt.Errorf("official Zadig signature verification failed; installation stopped: %w", e)
	}
	return nil
}

// ExtractOne controls only an official unmodified Zadig 2.9 process we launch.
// No coordinates, generic install actions, parent binding, or automatic retries.
func ExtractOne(ctx context.Context, path, driverDir string, n int, parent string, l *log.Logger) (result error) {
	if n != 0 && n != 1 {
		return fmt.Errorf("first-group-only package generation")
	}
	cmd := exec.Command(path)
	cmd.Dir = filepath.Dir(path)
	if e := cmd.Start(); e != nil {
		return e
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	pid := uint32(cmd.Process.Pid)
	var h uintptr
	extracting := false
	defer func() {
		if result != nil {
			logUIState(pid, l)
		}
		if h != 0 {
			if !extracting {
				// This owned helper has not started generating/installing anything.
				// Close it on a startup error so the next run cannot hit a stale UI.
				ui.NewProc("PostMessageW").Call(h, 0x10, 0, 0)
			} else if result != nil {
				ui.NewProc("ShowWindow").Call(h, 5)
			}
		}
	}()
	lastCount := ^uintptr(0)
	count, e := waitDeviceList(ctx, 60*time.Second, 250*time.Millisecond, func() (uintptr, error) {
		select {
		case e := <-done:
			return 0, fmt.Errorf("Zadig exited before ready: %v", e)
		default:
		}
		if err := declineUpdateQuestion(pid, l); err != nil {
			return 0, err
		}
		h = mainDialog(pid)
		if h == 0 {
			return 0, nil
		}
		enabled, _, _ := ui.NewProc("IsWindowEnabled").Call(h)
		if enabled == 0 {
			return 0, nil
		}
		c, err := message(item(h, 1001), 0x146, 0, 0)
		if c != lastCount {
			l.Printf("Zadig startup list count=%d error=%v", c, err)
			lastCount = c
		}
		return c, err
	})
	if e != nil {
		return e
	}
	l.Printf("Zadig device list ready rows=%d", count)
	// Never select a parent or another interface. Verify there is exactly one row.
	matches := []int{}
	for index := 0; index < int(count); index++ {
		if e = choose(h, index); e != nil {
			return e
		}
		if selected(h, n) {
			matches = append(matches, index)
		}
	}
	if len(matches) != 1 {
		logUIState(pid, l)
		return fmt.Errorf("expected one Zadig 05AC:1903 MI_%02X WinUSB extraction target, found %d", n, len(matches))
	}
	if e = choose(h, matches[0]); e != nil {
		return e
	}
	nodes, e := winusb.Enumerate(l)
	if e != nil {
		return e
	}
	exact := 0
	for _, node := range nodes {
		mi, ok := InterfaceNumber(node.ID)
		if ok && mi == n && strings.EqualFold(node.Parent, parent) {
			exact++
		}
	}
	if exact != 1 || !selected(h, n) {
		return fmt.Errorf("PnP/UI target changed before install; stop")
	}
	enabled, _, _ := ui.NewProc("IsWindowEnabled").Call(item(h, 1009))
	if enabled == 0 {
		return fmt.Errorf("Zadig install button disabled")
	}
	// Hide UI while automation owns it, preventing a user selection change between
	// verification and click. System security/certificate prompts remain visible.
	ui.NewProc("ShowWindow").Call(h, 0)
	l.Printf("extracting signed WinUSB binding package for exact interface MI_%02X with official Zadig pid=%d", n, pid)
	logUIState(pid, l)
	posted, _, e := ui.NewProc("PostMessageW").Call(h, 0x111, 1009, item(h, 1009))
	if posted == 0 {
		return fmt.Errorf("install click: %w", e)
	}
	extracting = true
	deadline := time.Now().Add(3 * time.Minute)
	for time.Now().Before(deadline) {
		select {
		case <-ctx.Done():
			ui.NewProc("ShowWindow").Call(h, 5)
			return ctx.Err()
		case err := <-done:
			l.Printf("Zadig extraction process exit=%v", err)
			return fmt.Errorf("Zadig exited before extraction was verified: %v", err)
		default:
		}
		// Keep the official tool open until its final log and exact output path
		// are verified. A process exit code alone is not extraction proof.
		for _, w := range windowsFor(pid) {
			if w == h {
				continue
			}
			body := []string{}
			for _, id := range []uintptr{1057} {
				if c := item(w, id); c != 0 {
					s, _ := text(c)
					body = append(body, s)
				}
			}
			joined := strings.Join(body, " ")
			if strings.Contains(joined, "The driver installation failed.") {
				ui.NewProc("ShowWindow").Call(h, 5)
				info, _ := text(item(h, 1004))
				l.Printf("Zadig failure log=%s", info)
				return fmt.Errorf("Zadig reported installation failure")
			}
		}
		info, err := toolLog(h)
		if err == nil && strings.Contains(info, "Successfully extracted driver files.") {
			logToolTail(h, l)
			files, err := filepath.Glob(filepath.Join(driverDir, "*.inf"))
			if err != nil || len(files) != 1 {
				entries, readErr := os.ReadDir(driverDir)
				for _, entry := range entries {
					l.Printf("extraction output entry=%q directory=%v", entry.Name(), entry.IsDir())
				}
				return fmt.Errorf("extraction output mismatch in %q: INF count=%d glob=%v read=%v", driverDir, len(files), err, readErr)
			}
			b, err := os.ReadFile(files[0])
			if err != nil {
				return err
			}
			// Fixed diagnostic copy only. Preserve the original signed INF.
			if len(b) <= 1024*1024 {
				copyErr := os.WriteFile(filepath.Join(filepath.Dir(path), fmt.Sprintf("generated-mi%02x.inf", n)), b, 0600)
				l.Printf("generated INF bytes=%d diagnostic copy error=%v", len(b), copyErr)
			}
			if err = ValidateINF(b, n); err != nil {
				return err
			}
			l.Printf("verified generated INF=%q", files[0])
			ui.NewProc("PostMessageW").Call(h, 0x10, 0, 0)
			select {
			case err := <-done:
				if err != nil {
					return fmt.Errorf("verified Zadig helper exit: %w", err)
				}
				return nil
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(5 * time.Second):
				return fmt.Errorf("verified extraction helper did not close")
			}
		}
		time.Sleep(250 * time.Millisecond)
	}
	ui.NewProc("ShowWindow").Call(h, 5)
	return fmt.Errorf("Zadig installation did not complete; stop without retry")
}
