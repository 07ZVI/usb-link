//go:build windows && amd64 && usblink_local_remote

package ipadncm

import (
	"context"
	"golang.org/x/sys/windows"
	"testing"
	"time"
)

func TestUSBTraceCallbackSkipsForeignBodiesBeforeApplyingScalarBounds(t *testing.T) {
	const key = ^uintptr(0) - 123
	b := &usbTraceNative{ctx: context.Background(), start: time.Now(), queue: make(chan usbTraceEvent, 1), journal: usbTraceJournal{Name: "USBLink-USBMetadata-0123456789abcdef0123456789abcdef"}}
	b.providers[0].guid = windows.GUID{Data1: 2}
	b.providers[0].schemas = []usbTraceSchema{{}}
	b.admission.Store(true)
	usbTraceConsumers.Lock()
	previous, existed := usbTraceConsumers.items[key]
	usbTraceConsumers.items[key] = b
	usbTraceConsumers.Unlock()
	localUSBTrace.Lock()
	oldStatus, oldRequested := localUSBTrace.status, localUSBTrace.requested
	localUSBTrace.status, localUSBTrace.requested = newUSBTraceStatus(), true
	localUSBTrace.Unlock()
	defer func() {
		usbTraceConsumers.Lock()
		if existed {
			usbTraceConsumers.items[key] = previous
		} else {
			delete(usbTraceConsumers.items, key)
		}
		usbTraceConsumers.Unlock()
		localUSBTrace.Lock()
		localUSBTrace.status, localUSBTrace.requested = oldStatus, oldRequested
		localUSBTrace.Unlock()
	}()
	r := wpdEventRecord{Header: wpdEventHeader{Size: 80, Provider: usbTraceSessionMetadataGUID}, UserContext: key, UserDataLength: 65535, UserData: 1}
	consumeUSBTraceRecord(&r) // Invalid data address is deliberately never read.
	r.Header.Provider = windows.GUID{Data1: 3}
	consumeUSBTraceRecord(&r)
	r.Header.Provider, r.UserDataLength, r.UserData = b.providers[0].guid, 0, 0
	consumeUSBTraceRecord(&r) // Known provider ID zero is not a synthetic event.
	localUSBTrace.Lock()
	s := localUSBTrace.status
	localUSBTrace.Unlock()
	if s.CallbacksReceived != 3 || s.SessionMetadata != 1 || s.UnknownProvider != 1 || s.Received != 1 || s.SchemaRejected != 0 || len(b.queue) != 1 {
		t.Fatal("native callback lost the source distinction", s)
	}
}
