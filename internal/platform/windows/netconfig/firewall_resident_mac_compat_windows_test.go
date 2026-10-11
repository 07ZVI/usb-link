//go:build windows && amd64

package netconfig

import (
	"slices"
	"testing"

	"suhang/usbnet/internal/platform/windows/wincom"
)

func TestResidentMacReaderAllowsOnlyPresentRawVTNullAppPath(t *testing.T) {
	const class = "MSFT_NetApplicationFilter"
	parts, e := readFirewallConstraintValue(wincom.Null(), class, "AppPath", true)
	if e != nil || !slices.Equal(parts, []string{"NULL"}) {
		t.Fatal(parts, e)
	}
	for _, c := range []struct {
		v            wincom.Value
		class, field string
		private      bool
	}{
		{wincom.Null(), class, "AppPath", false},
		{wincom.Empty(), class, "AppPath", true},
		{wincom.Int(0), class, "AppPath", true},
		{wincom.Null(), "MSFT_NetServiceFilter", "AppPath", true},
		{wincom.Null(), class, "InstanceID", true},
	} {
		if _, e := readFirewallConstraintValue(c.v, c.class, c.field, c.private); e == nil {
			t.Fatal("NULL compatibility escaped exact field/type/mode")
		}
	}
}
