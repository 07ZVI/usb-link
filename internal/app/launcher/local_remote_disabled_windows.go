//go:build windows && amd64 && !usblink_local_remote

package launcher

import "suhang/usbnet/internal/app/connectioninstall"

func configureLocalRemote(*connectioninstall.RemoteManager) {}
func configureLocalRemoteUnavailable(error)                 {}
func handleLocalRemoteCommand() bool                        { return false }
