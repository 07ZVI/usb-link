//go:build windows && amd64 && !usblink_local_remote

package launcher

import (
	"fmt"
	"suhang/usbnet/internal/app/connectioninstall"
)

func configureLocalRemote(*connectioninstall.RemoteManager) {}
func configureLocalRemoteUnavailable(error)                 {}
func handleLocalRemoteCommand() bool                        { return false }

func authorizeLocalRestart(id, sid string, session, pid uint32, creation uint64) error {
	return fmt.Errorf("LOCAL_RESTART_UNAVAILABLE")
}
