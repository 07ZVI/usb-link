//go:build windows && amd64 && !usblink_local_remote

package deviceguard

import "time"

func emitChangeMetadata(*ChangeMetadataStream, uintptr, string, time.Time) {}
func rejectChangeMetadata(*ChangeMetadataStream, uint32)                   {}
