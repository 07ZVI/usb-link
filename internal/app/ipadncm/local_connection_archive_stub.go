//go:build !windows || !amd64 || !usblink_local_remote

package ipadncm

import (
	"context"
	"errors"
)

func StartConnectionArchive(context.Context, string) func() { return func() {} }
func RecordConnectionArchiveEvent(string, any)              {}
func RecordConnectionArchiveAttempt(uint64)                 {}
func ConnectionArchiveDiagnostics() any                     { return nil }
func ReadConnectionArchiveIndex() (ConnectionArchiveIndex, error) {
	return ConnectionArchiveIndex{}, errors.New("ARCHIVE_LOCAL_BUILD_REQUIRED")
}
func ReadConnectionArchiveChunk(string, int64, int, ...string) (ConnectionArchiveChunk, error) {
	return ConnectionArchiveChunk{}, errors.New("ARCHIVE_LOCAL_BUILD_REQUIRED")
}

func SetConnectionArchiveMaster(bool) {}

func RecordConnectionArchiveEventAccepted(string, any) bool { return false }
