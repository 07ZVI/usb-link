//go:build windows && amd64

package netconfig

import (
	"context"
	"testing"
)

func TestOwnedMacCloseNativeRejectsUnprovenScopeWithoutObservation(t *testing.T) {
	for _, v := range []struct {
		ctx      context.Context
		index    uint32
		luid     uint64
		instance string
	}{
		{nil, 1, 2, "x"}, {context.Background(), 0, 2, "x"}, {context.Background(), 1, 0, "x"},
		{context.Background(), 1, 2, ""}, {context.Background(), 1, 2, "*"}, {context.Background(), 1, 2, "x\x00y"},
	} {
		if err := WaitOwnedMacCloseAbsentNative(v.ctx, v.index, v.luid, v.instance); err == nil || err.Error() != "USB_MAC_LIFETIME_CLOSE_SCOPE_UNPROVEN" {
			t.Fatal("unproved close scope reached native observation")
		}
	}
}
