//go:build windows && amd64 && usblink_local_remote

package ipadncm

import (
	"suhang/usbnet/internal/buildinfo"
	"suhang/usbnet/internal/transport/ncm"
)

var localMacMTUCap = newLocalMacMTUCapController()

func SetLocalMacMTUCapPersistence(save func(string) error, read func() (string, error)) {
	localMacMTUCap.configure(save, read)
}
func SetLocalMacMTUCapMaster(on bool) {
	localMacMTUCap.masterChanged(on && buildinfo.LocalDiagnostics == "true")
}
func SetLocalMacMTUCap(setting, id string) error {
	return localMacMTUCap.set(setting, id)
}
func LocalMacMTUCapDiagnostics() any { return localMacMTUCap.snapshot() }

// LocalMacMTUCapSetting is sampled when a Mac session starts.
func LocalMacMTUCapSetting() string {
	if buildinfo.LocalDiagnostics != "true" {
		return ncm.MTUCapAuto.String()
	}
	return localMacMTUCap.effective().String()
}
