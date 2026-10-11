package netconfig

import (
	"suhang/usbnet/internal/transport/usbaddress"
	"testing"
)

func validNonpresentReplay() (nativeHostNode, nativeHostNonpresentProof) {
	n := validNativeHostNode()
	n.StateReadable, n.StateError = false, 13
	p := nativeHostNonpresentProof{PresentMatches: 0, InstalledMatches: 1, NormalReadable: true, NormalResult: 13, PhantomReadable: true, PhantomResult: 0, PhantomExact: true, ConfigReadable: true, ConfigType: 4, ConfigSize: 4, CMConfigReadable: true, CMConfigType: 7, CMConfigSize: 4}
	return n, p
}

func TestExactNonpresentReplayNeverBecomesHealthyHost(t *testing.T) {
	n, p := validNonpresentReplay()
	if e := validateNativeHostNonpresent(n, p); e != nil {
		t.Fatal(e)
	}
	if validateNativeHostNode(n) == nil {
		t.Fatal("proved nonpresent node became healthy admission")
	}
	for name, mutate := range map[string]func(*nativeHostNode){
		"disabled":           func(n *nativeHostNode) { n.StateReadable = true; n.StateError = 0; n.Problem = 22 },
		"unknown-error":      func(n *nativeHostNode) { n.StateError = 5 },
		"unreadable-no-code": func(n *nativeHostNode) { n.StateError = 0 },
		"present-healthy":    func(n *nativeHostNode) { n.StateReadable = true; n.StateError = 0 },
		"service":            func(n *nativeHostNode) { n.Service = "Other" },
		"class":              func(n *nativeHostNode) { n.CMClass = "Other" },
		"driver":             func(n *nativeHostNode) { n.CMDriver = hostNetClass + `\0005` },
		"guid":               func(n *nativeHostNode) { n.CMNetGUID = "Other" },
		"instance":           func(n *nativeHostNode) { n.CMInstance = "Other" },
		"truncated-metadata": func(n *nativeHostNode) { n.ServiceSize = 12 },
	} {
		t.Run(name, func(t *testing.T) {
			bad := n
			mutate(&bad)
			if validateNativeHostNonpresent(bad, p) == nil {
				t.Fatal("foreign or unhealthy replay admitted")
			}
		})
	}
}

func TestNonpresentRequiresIndependentPresenceAndConfigurationProof(t *testing.T) {
	n, p := validNonpresentReplay()
	for name, mutate := range map[string]func(*nativeHostNonpresentProof){
		"unknown-normal":          func(p *nativeHostNonpresentProof) { p.NormalReadable = false },
		"present-normal":          func(p *nativeHostNonpresentProof) { p.NormalResult = 0 },
		"other-normal-error":      func(p *nativeHostNonpresentProof) { p.NormalResult = 5 },
		"unknown-phantom":         func(p *nativeHostNonpresentProof) { p.PhantomReadable = false },
		"failed-phantom":          func(p *nativeHostNonpresentProof) { p.PhantomResult = 13 },
		"different-phantom":       func(p *nativeHostNonpresentProof) { p.PhantomExact = false },
		"present-binding":         func(p *nativeHostNonpresentProof) { p.PresentMatches = 1 },
		"no-installed-binding":    func(p *nativeHostNonpresentProof) { p.InstalledMatches = 0 },
		"ambiguous-installed":     func(p *nativeHostNonpresentProof) { p.InstalledMatches = 2 },
		"config-unreadable":       func(p *nativeHostNonpresentProof) { p.ConfigReadable = false },
		"config-disabled":         func(p *nativeHostNonpresentProof) { p.Config = 1; p.CMConfig = 1 },
		"config-unknown-override": func(p *nativeHostNonpresentProof) { p.Config = 0x80000000; p.CMConfig = p.Config },
		"config-wrong-type":       func(p *nativeHostNonpresentProof) { p.ConfigType = 1 },
		"config-wrong-size":       func(p *nativeHostNonpresentProof) { p.ConfigSize = 8 },
		"cm-config-unreadable":    func(p *nativeHostNonpresentProof) { p.CMConfigReadable = false },
		"cm-config-mismatch":      func(p *nativeHostNonpresentProof) { p.CMConfig = 1 },
		"cm-config-wrong-type":    func(p *nativeHostNonpresentProof) { p.CMConfigType = 4 },
		"cm-config-wrong-size":    func(p *nativeHostNonpresentProof) { p.CMConfigSize = 8 },
	} {
		t.Run(name, func(t *testing.T) {
			bad := p
			mutate(&bad)
			if validateNativeHostNonpresent(n, bad) == nil {
				t.Fatal("incomplete presence/configuration replay admitted")
			}
		})
	}
}

func TestNonpresentFreshRecheckRejectsReplacement(t *testing.T) {
	n, p := validNonpresentReplay()
	f := nativeHostInterface{GUID: usbaddress.HostGUID, Alias: usbaddress.HostName, Type: 53, Index: 24, LUID: 240}
	if e := validateNativeHostNonpresentTransition(f, f, n, n, p, p); e != nil {
		t.Fatal(e)
	}
	other := f
	other.LUID++
	if validateNativeHostNonpresentTransition(f, other, n, n, p, p) == nil {
		t.Fatal("changed mapping admitted")
	}
	otherNode := n
	otherNode.DevInst++
	if validateNativeHostNonpresentTransition(f, f, n, otherNode, p, p) == nil {
		t.Fatal("changed devnode handle admitted")
	}
	otherNode = n
	otherNode.Instance = `SWD\WINTUN\foreign`
	otherNode.CMInstance = otherNode.Instance
	if validateNativeHostNonpresentTransition(f, f, n, otherNode, p, p) == nil {
		t.Fatal("different valid identity adopted")
	}
}
