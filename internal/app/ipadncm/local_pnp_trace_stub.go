//go:build !windows || !amd64 || !usblink_local_remote

package ipadncm

import "context"

func StartLocalPnPTrace(context.Context) func() { return func() {} }
func SetLocalPnPTraceMaster(bool)               {}
func LocalPnPTraceDiagnostics() any             { return nil }
