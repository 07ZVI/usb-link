//go:build windows && amd64

package interfaceconfig

import (
	"context"
	"suhang/usbnet/internal/transport/usbaddress"
	"testing"
)

func TestRetainedSecondaryRejectsUnboundOrChangedProofBeforeNative(t *testing.T) {
	var none *RetainedSecondary
	if none.VerifyAddress(context.Background(), usbaddress.InterfaceProof{}) == nil {
		t.Fatal("nil retained authorization")
	}
	r := &RetainedSecondary{scope: Scope{Role: "mac", GUID: MacGUID, Index: 7, LUID: 9}}
	for _, p := range []usbaddress.InterfaceProof{{Index: 8, GUID: MacGUID, LUID: 9}, {Index: 7, GUID: MacGUID, LUID: 10}, {Index: 7, GUID: HostGUID, LUID: 9}, {Index: 7, GUID: MacGUID, LUID: 9, Role: "host"}} {
		if r.VerifyAddress(context.Background(), p) == nil {
			t.Fatal("changed scope accepted")
		}
	}
}
