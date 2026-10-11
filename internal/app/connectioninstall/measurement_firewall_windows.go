//go:build windows && amd64

package connectioninstall

import (
	"io"
	"log"
	"os"
	"suhang/usbnet/internal/platform/windows/netconfig"
)

func remoteUDPFirewall(enabled bool, guid, id string) error {
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	script, err := measurementFirewallScript(enabled, guid, id, exe)
	if err != nil {
		return err
	}
	return netconfig.Run(script, log.New(io.Discard, "", 0))
}
