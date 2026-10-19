//go:build !windows || !amd64 || !usblink_local_remote

package ipadncm

import "context"

// Public builds keep no connection archive. The native recorder and its
// reader live in the developer build only.
func StartConnectionArchive(context.Context, string) func() { return func() {} }
func RecordConnectionArchiveEvent(string, any)              {}
func RecordConnectionArchiveAttempt(uint64)                 {}
func ConnectionArchiveDiagnostics() any                     { return nil }
