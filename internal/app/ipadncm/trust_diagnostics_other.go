//go:build !windows || !amd64 || !usblink_local_remote

package ipadncm

import "context"

func StartTrustDiagnostics(context.Context) {}
