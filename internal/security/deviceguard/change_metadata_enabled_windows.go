//go:build windows && amd64 && usblink_local_remote

package deviceguard

import (
	"sync"
	"time"
)

func emitChangeMetadata(stream *ChangeMetadataStream, action uintptr, instance string, observedAt time.Time) {
	if stream != nil {
		stream.offer(action, instance, observedAt)
	}
}

func rejectChangeMetadata(stream *ChangeMetadataStream, kind uint32) {
	if stream != nil {
		stream.reject(kind)
	}
}

// Preserve callback order instead of coalescing wake hints. These are Apple
// candidates, never an authorization or a physical-disconnect count.
func SubscribeAppleChangeMetadata() (*ChangeMetadataStream, func(), error) {
	stream, err := newChangeMetadataStream()
	if err != nil {
		return nil, nil, err
	}
	match := func(instance string) bool { _, _, ok := appleChangeIdentity(instance); return ok }
	_, stopInstance, err := subscribeChangesWithMetadata(match, 2, stream)
	if err != nil {
		stream.StopAdmission()
		return stream, func() {}, err
	}
	_, stopInterface, err := subscribeChangesWithMetadata(match, 0, stream)
	if err != nil {
		stream.StopAdmission()
		stopInstance()
		return stream, stopInstance, err
	}
	var once sync.Once
	return stream, func() { once.Do(func() { stream.StopAdmission(); stopInterface(); stopInstance() }) }, nil
}
