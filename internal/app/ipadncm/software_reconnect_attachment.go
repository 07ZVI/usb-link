package ipadncm

import "strings"

// No notification count appears here: a global node-change event cannot
// distinguish our own interface cleanup from a physical-root replacement.
type softwareReconnectAttachment struct {
	root, parent, hub string
	locations         []string
	devInst, port     uint32
	pid               uint16
}

func (a softwareReconnectAttachment) same(b softwareReconnectAttachment) bool {
	return a.samePhysicalRoot(b) && a.devInst == b.devInst
}

func (a softwareReconnectAttachment) samePhysicalRoot(b softwareReconnectAttachment) bool {
	if a.root == "" || a.parent == "" || a.hub == "" || a.devInst == 0 || b.devInst == 0 || a.port == 0 || a.pid != 0x12ab || len(a.locations) == 0 || !strings.EqualFold(a.root, b.root) || !strings.EqualFold(a.parent, b.parent) || !strings.EqualFold(a.hub, b.hub) || a.port != b.port || a.pid != b.pid || len(a.locations) != len(b.locations) {
		return false
	}
	for i, p := range a.locations {
		if p == "" || p != b.locations[i] {
			return false
		}
	}
	return true
}
