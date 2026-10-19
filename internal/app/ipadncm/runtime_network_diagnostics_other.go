//go:build (!windows || !amd64) && usblink_local_remote

package ipadncm

import "context"

func collectRuntimeNetworkDiagnostics(context.Context) RuntimeNetworkDiagnostic {
	return RuntimeNetworkDiagnostic{Status: "PLATFORM_UNSUPPORTED", TCP: RuntimeNetworkTCP{Status: "NOT_READ"}}
}
