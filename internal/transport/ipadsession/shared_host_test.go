package ipadsession

import (
	"bytes"
	"testing"
)

func TestSharedHostDHCPAssignsIPadThreeWithHostRouteViaPhysicalHelper(t *testing.T) {
	p := Plan{Version: 5, GUID: "{12345678-1234-1234-1234-123456789abc}", LUID: 7, Index: 9, ServerIP: "10.6.9.1", Token: "0123456789abcdef01234567", PlannedAt: 1, HostFlags: &HostFlags{Send: true}}
	if !p.Valid() || p.PeerIP() != "10.6.9.3" || p.LocalAddress() != "10.6.9.254" || p.AddressPrefix() != 32 {
		t.Fatal(p)
	}
	for _, router := range []bool{false, true} {
		for _, kind := range []byte{1, 3} {
			r := Request{Kind: kind, MAC: testMAC}
			if kind == 3 {
				r.HasRequested = true
				r.Requested = [4]byte{10, 6, 9, 3}
				r.HasServer = true
				r.Server = [4]byte{10, 6, 9, 254}
			}
			b, k := DHCPReplyForPlan(r, p, router)
			if k == 0 || !bytes.Equal(b[16:20], []byte{10, 6, 9, 3}) {
				t.Fatal("no lease", k)
			}
			opts := map[byte][]byte{}
			for i := 240; b[i] != 255; {
				if b[i] == 0 {
					i++
					continue
				}
				n := int(b[i+1])
				opts[b[i]] = b[i+2 : i+2+n]
				i += 2 + n
			}
			want := []byte{32, 10, 6, 9, 1, 10, 6, 9, 254}
			if router {
				want = append(want, 0, 10, 6, 9, 254)
			}
			if !bytes.Equal(opts[121], want) || !bytes.Equal(opts[54], []byte{10, 6, 9, 254}) || !bytes.Equal(opts[1], []byte{255, 255, 255, 0}) || opts[6] != nil {
				t.Fatal("wrong route/server/subnet", opts)
			}
			r.Kind = 3
			r.Requested = [4]byte{10, 6, 9, 2}
			if b, _ := DHCPReplyForPlan(r, p, router); b != nil {
				t.Fatal("wrong peer accepted")
			}
		}
	}
	p.HostFlags = nil
	if p.Valid() {
		t.Fatal("missing restoration snapshot accepted")
	}
}
