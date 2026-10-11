//go:build windows && amd64

package netconfig

import (
	"context"
	"fmt"
	"golang.org/x/sys/windows"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"suhang/usbnet/internal/transport/usbaddress"
	"syscall"
	"time"
)

// RefreshMacPathCache runs after the negotiated trial, including 1500 fallback,
// IPv4 MTU readback and publication of the bridge packet limit.
// The source-address host also has a path cache, separate from the USB route.
// Never use FlushIpPathTable: that API has no interface/destination scope.
func RefreshMacPathCache(ctx context.Context, mac usbaddress.InterfaceProof, topology []usbaddress.InterfaceProof, mtu int, l *log.Logger) error {
	targets, err := macPathTargets(mac, topology, mtu)
	if err != nil {
		return err
	}
	for _, p := range targets {
		if err := usbaddress.VerifyProofs([]usbaddress.InterfaceProof{p}); err != nil {
			return err
		}
		name, wantMTU := "USB Link", uint32(mtu)
		if p.Role == "host" {
			// The physical Mac interface was checked first. Raise the service
			// receive MTU only to that verified value, including smaller links.
			if err := usbaddress.SetHostMTU(ctx, p, mtu); err != nil {
				return err
			}
			name = usbaddress.HostName
		}
		r := windows.MibIfRow2{InterfaceLuid: p.LUID}
		if err := windows.GetIfEntry2Ex(windows.MibIfEntryNormal, &r); err != nil {
			return err
		}
		if r.InterfaceIndex != p.Index || r.Type != 53 || windows.UTF16ToString(r.Alias[:]) != name {
			return fmt.Errorf("USB path interface identity changed")
		}
		f := windows.MibIpInterfaceRow{Family: windows.AF_INET, InterfaceLuid: p.LUID}
		if err := windows.GetIpInterfaceEntry(&f); err != nil {
			return err
		}
		if f.NlMtu != wantMTU {
			return fmt.Errorf("USB path MTU readback changed")
		}
		commandCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
		// Both limiting arguments are mandatory and generated here, never supplied
		// by a peer. This cannot flush other destinations, IPv6, Wi-Fi or Ethernet.
		cmd := exec.CommandContext(commandCtx, filepath.Join(os.Getenv("SystemRoot"), "System32", "netsh.exe"), "interface", "ipv4", "delete", "destinationcache", "interface="+strconv.FormatUint(uint64(p.Index), 10), "address=10.6.9.2")
		cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true, CreationFlags: 0x08000000}
		output, err := cmd.CombinedOutput()
		cancel()
		if err != nil {
			return fmt.Errorf("USB Mac path cache refresh interface=%d: %w", p.Index, err)
		}
		l.Printf("USB_MAC_PATH_CACHE_REFRESHED interface=%d peer=10.6.9.2 result=%s", p.Index, strings.TrimSpace(string(output)))
	}
	return nil
}
