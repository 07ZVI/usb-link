//go:build windows && amd64

package bridgeworker

import (
	"suhang/usbnet/internal/diagnostics/logfile"
	"suhang/usbnet/internal/transport/bridge"
	"suhang/usbnet/internal/transport/usbaddress"
	"suhang/usbnet/internal/transport/wintun"
)

type statistics struct {
	USBReads, USBWrites, ToWindows, ToMac, ToWindowsBytes, ToMacBytes, Dropped, Filtered, RingOverflow, PendingOverflow uint64
	ToWindowsProfile, ToMacProfile                                                                                      bridge.PacketProfile
	MTUExceeded, MTUExceededBytes                                                                                       uint64
	MaxRejectedIPLength                                                                                                 uint32
}

func diagnostics(dir, nonce string, stats statistics, topology []usbaddress.InterfaceProof, ingress map[string]any) ([]byte, error) {
	return logfile.MarshalDiagnosticSnapshot(map[string]any{
		"version": version, "group": 0, "nonce": nonce, "stats": stats,
		"performance": performanceSnapshot(), "usb_network": usbaddress.NativeDetails(topology),
		"wintun_module_lifetime": wintun.ModuleLifetimeSnapshot(), "ingress": ingress,
	}, logfile.ReadDiagnosticTails(dir))
}
