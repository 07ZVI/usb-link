//go:build windows && amd64

package installer

import (
	"fmt"
	"golang.org/x/sys/windows"
	"log"
	"os"
	"path/filepath"
	"strings"
	"suhang/usbnet/internal/transport/winusb"
	"unsafe"
)

// Binding never depends on Zadig's current UI selection: the INF and hardware
// ID are checked here, then Windows is asked to update only that exact ID.
func BindGenerated(dir string, n int, parent string, l *log.Logger) error {
	if n != 0 && n != 1 {
		return fmt.Errorf("not a permitted first-group interface")
	}
	files, e := filepath.Glob(filepath.Join(dir, "*.inf"))
	if e != nil || len(files) != 1 {
		return fmt.Errorf("expected one generated INF, found %d: %v", len(files), e)
	}
	b, e := os.ReadFile(files[0])
	if e != nil {
		return e
	}
	if e = ValidateINF(b, n); e != nil {
		return e
	}
	want := fmt.Sprintf("VID_05AC&PID_1903&MI_%02X", n)
	nodes, e := winusb.Enumerate(l)
	if e != nil {
		return e
	}
	count := 0
	for _, node := range nodes {
		mi, ok := InterfaceNumber(node.ID)
		if ok && mi == n && strings.EqualFold(node.Parent, parent) {
			count++
		}
	}
	if count != 1 {
		return fmt.Errorf("selected target disconnected/changed before binding")
	}
	hardware, _ := windows.UTF16PtrFromString(`USB\` + want)
	inf, _ := windows.UTF16PtrFromString(files[0])
	var reboot uint32
	l.Printf("UpdateDriverForPlugAndPlayDevices exact ID=%s inf=%s", `USB\`+want, files[0])
	r, _, e := windows.NewLazySystemDLL("newdev.dll").NewProc("UpdateDriverForPlugAndPlayDevicesW").Call(0, uintptr(unsafe.Pointer(hardware)), uintptr(unsafe.Pointer(inf)), 1, uintptr(unsafe.Pointer(&reboot)))
	l.Printf("driver binding result=%d reboot=%d error=%v", r, reboot, e)
	if r == 0 {
		return fmt.Errorf("WinUSB binding failed: %w", e)
	}
	if reboot != 0 {
		return fmt.Errorf("Windows requests reboot; stop and inspect logs")
	}
	return nil
}
