package usbgateway

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestBasePolicyCoversIPv4IPv6TCPUDPAndForwarding(t *testing.T) {
	specs, e := BasePolicy(123456)
	if e != nil || len(specs) != 8 {
		t.Fatal(specs, e)
	}
	keys := map[string]bool{}
	for _, s := range specs {
		if s.LUID != 123456 || s.Permit || s.Application != "" {
			t.Fatal("widened default", s)
		}
		keys[s.Layer+":"+s.InterfaceField] = true
	}
	if len(keys) != 8 {
		t.Fatal("duplicate coverage")
	}
	for _, layer := range applicationLayers {
		if !keys[layer+":"+localInterface] {
			t.Fatal("ALE missing", layer)
		}
	}
	for _, layer := range forwardingLayers {
		for _, field := range []string{localInterface, forwardInterface} {
			if !keys[layer+":"+field] {
				t.Fatal("forwarding bypass", layer, field)
			}
		}
	}
	if _, e = BasePolicy(0); e == nil {
		t.Fatal("all-interface fallback")
	}
}
func TestPermitIsOnlyExactApplicationOnExactUSBInterface(t *testing.T) {
	specs, e := PermitPolicy(10, "C:\\Tools\\app.exe")
	if e != nil || len(specs) != 4 {
		t.Fatal(specs, e)
	}
	for _, s := range specs {
		if s.LUID != 10 || s.Application != "C:\\Tools\\app.exe" || !s.Permit || s.InterfaceField != localInterface {
			t.Fatal(s)
		}
		for _, forward := range forwardingLayers {
			if s.Layer == forward {
				t.Fatal("forwarding permit")
			}
		}
	}
	if _, e = PermitPolicy(10, ""); e == nil {
		t.Fatal("wildcard application")
	}
}
func TestFingerprintChangesAndRejectsNonExecutable(t *testing.T) {
	p := filepath.Join(t.TempDir(), "example.exe")
	os.WriteFile(p, []byte("first"), 0600)
	a, e := inspect(p)
	if e != nil || len(a.SHA256) != 64 {
		t.Fatal(a, e)
	}
	os.WriteFile(p, []byte("second"), 0600)
	b, e := inspect(p)
	if e != nil || a.SHA256 == b.SHA256 {
		t.Fatal("fingerprint not changed")
	}
	if _, e = inspect(strings.TrimSuffix(p, ".exe")); e == nil {
		t.Fatal("nonexe")
	}
	a.Decision = "allow"
	if !validGrant(a) {
		t.Fatal("valid grant")
	}
	a.Decision = "maybe"
	if validGrant(a) {
		t.Fatal("unknown action")
	}
}
func TestRememberedAndSessionGrantsNeverDuplicatePermit(t *testing.T) {
	saved := []Grant{{Path: "C:\\Tools\\app.exe", Decision: "allow", SHA256: "old"}}
	once := map[string]Grant{"c:\\tools\\app.exe": {Path: "C:\\TOOLS\\app.exe", Decision: "block", SHA256: "new"}}
	merged := effectiveGrants(saved, once)
	if len(merged) != 1 || merged[0].Decision != "block" || merged[0].SHA256 != "new" {
		t.Fatal(merged)
	}
	once["c:\\tools\\app.exe"] = saved[0]
	merged = effectiveGrants(saved, once)
	if len(merged) != 1 {
		t.Fatal("duplicate permit", merged)
	}
}

func TestLogicalHostPolicyRemainsAddressScopedAndDoesNotPermitForwarding(t *testing.T) {
	SetSharedHostLUID(42)
	defer SetSharedHostLUID(0)
	for _, permit := range []bool{false, true} {
		var s []Specification
		var e error
		if permit {
			s, e = PermitPolicy(42, `C:\USB-Link.exe`)
		} else {
			s, e = BasePolicy(42)
		}
		if e != nil || len(s) != map[bool]int{false: 4, true: 2}[permit] {
			t.Fatal(s, e)
		}
		for _, v := range s {
			if v.Layer == forwardingLayers[0] && !permit {
				if v.Permit || v.LUID != 42 {
					t.Fatal(v)
				}
				continue
			}
			if !v.HostServiceOnly || v.LUID != 42 || v.Permit != permit || (v.Layer != "{c38d57d1-05a7-4c33-904f-7fbceee60e82}" && v.Layer != "{e1cd9fe7-f4b5-4273-96c0-592e487b8650}") {
				t.Fatal(v)
			}
		}
	}
	s, e := BasePolicy(43)
	if e != nil || len(s) != 8 {
		t.Fatal("physical policy changed")
	}
	for _, v := range s {
		if v.HostServiceOnly {
			t.Fatal("host policy leaked")
		}
	}
}

func TestLocalDeliveryPermitsNeverGrantPeerTransitOrInternet(t *testing.T) {
	SetSharedHostLUID(42)
	defer SetSharedHostLUID(0)
	for _, tc := range []struct {
		luid  uint64
		peer  string
		count int
	}{{42, "", 8}, {43, "10.6.9.2", 4}, {44, "10.6.9.3", 4}} {
		specs, e := LocalDeliveryPolicy(tc.luid, tc.peer)
		if e != nil || len(specs) != tc.count {
			t.Fatal(specs, e)
		}
		for _, s := range specs {
			a, b, e := exactLocalDeliveryAddresses(s)
			if e != nil || a == 0 || b == 0 || s.Application != "" || !s.Permit || s.LUID != tc.luid || s.Layer != "{a82acc24-4ee1-4ee1-b465-fd1d25cb10a4}" {
				t.Fatal(s, e)
			}
			if s.ForwardSource != "10.6.9.1" && s.ForwardDestination != "10.6.9.1" {
				t.Fatal("transit permitted")
			}
			if tc.peer != "" && s.ForwardSource != tc.peer && s.ForwardDestination != tc.peer {
				t.Fatal("other peer allowed")
			}
		}
	}
	if _, e := LocalDeliveryPolicy(43, "192.168.1.1"); e == nil {
		t.Fatal("LAN admitted")
	}
	for _, pair := range [][2]string{{"10.6.9.2", "10.6.9.3"}, {"10.6.9.2", "8.8.8.8"}, {"10.6.9.1", "10.6.9.4"}, {"0.0.0.0", "10.6.9.1"}} {
		s := Specification{LUID: 43, Layer: forwardingLayers[0], InterfaceField: localInterface, Permit: true, ForwardSource: pair[0], ForwardDestination: pair[1]}
		if _, _, e := exactLocalDeliveryAddresses(s); e == nil {
			t.Fatal("broad local policy accepted", pair)
		}
	}
}
