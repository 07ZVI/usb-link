package ipadncm

import "testing"

func TestSoftwareAttachmentComparesActualRootNotInterfaceChangeNotifications(t *testing.T) {
	a := softwareReconnectAttachment{root: `USB\VID_05AC&PID_12AB\ABC123456789`, parent: `USB\ROOT_HUB30\abc`, hub: `\\?\USB#ROOT_HUB30#abc`, locations: []string{"PCIROOT(0)#USB(4)"}, devInst: 101, port: 4, pid: 0x12ab}
	// Repeated unrelated/self-generated interface notifications leave all
	// physical-root witnesses unchanged, so a queued request remains valid.
	for notificationCount := 0; notificationCount < 46; notificationCount++ {
		if !a.same(a) {
			t.Fatal("same root rejected after cleanup notice", notificationCount)
		}
	}
	for name, change := range map[string]func(*softwareReconnectAttachment){
		"another serial":      func(b *softwareReconnectAttachment) { b.root = `USB\VID_05AC&PID_12AB\OTHER123456789` },
		"another root handle": func(b *softwareReconnectAttachment) { b.devInst++ },
		"another port":        func(b *softwareReconnectAttachment) { b.port++ },
		"another hub":         func(b *softwareReconnectAttachment) { b.hub += "other" },
		"another parent":      func(b *softwareReconnectAttachment) { b.parent += "other" },
		"another location":    func(b *softwareReconnectAttachment) { b.locations = []string{"PCIROOT(0)#USB(5)"} },
		"Mac PID":             func(b *softwareReconnectAttachment) { b.pid = 0x1903 },
		"missing witness":     func(b *softwareReconnectAttachment) { b.locations = nil },
	} {
		t.Run(name, func(t *testing.T) {
			b := a
			change(&b)
			if a.same(b) {
				t.Fatal("replacement or unproven attachment accepted", b)
			}
		})
	}
}

func TestCleanupRefreshMayChangeNativeHandleButNeverPhysicalRootChain(t *testing.T) {
	a := softwareReconnectAttachment{root: `USB\VID_05AC&PID_12AB\ABC123456789`, parent: `USB\ROOT_HUB30\abc`, hub: `\\?\USB#ROOT_HUB30#abc`, locations: []string{"PCIROOT(0)#USB(4)"}, devInst: 101, port: 4, pid: 0x12ab}
	b := a
	b.devInst = 102
	if a.same(b) || !a.samePhysicalRoot(b) {
		t.Fatal("normal preflight and verified-cleanup refresh were conflated")
	}
	for _, change := range []func(*softwareReconnectAttachment){
		func(b *softwareReconnectAttachment) { b.root += "OTHER" },
		func(b *softwareReconnectAttachment) { b.parent += "OTHER" },
		func(b *softwareReconnectAttachment) { b.hub += "OTHER" },
		func(b *softwareReconnectAttachment) { b.port++ },
		func(b *softwareReconnectAttachment) { b.locations = []string{"PCIROOT(0)#USB(5)"} },
		func(b *softwareReconnectAttachment) { b.devInst = 0 },
	} {
		b := a
		b.devInst++
		change(&b)
		if a.samePhysicalRoot(b) {
			t.Fatal("cleanup refresh accepted a different/unproven root", b)
		}
	}
}
