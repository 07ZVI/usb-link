package ipadncm

import "testing"

func TestPortableReceiptRefusesRootMacAndNonPhotoNodes(t *testing.T) {
	n := portableNodeReceipt{Root: `USB\VID_05AC&PID_12AB\ABC123456789`, ID: `USB\VID_05AC&PID_12AB&MI_00\CHILD`, Class: portableWPDClass}
	if !validPortableReceipt(n) {
		t.Fatal("WPD child receipt rejected")
	}
	for _, mutate := range []func(*portableNodeReceipt){
		func(n *portableNodeReceipt) { n.ID = n.Root },
		func(n *portableNodeReceipt) { n.Root = `USB\VID_05AC&PID_1903\ABC123456789` },
		func(n *portableNodeReceipt) { n.Class = "{4d36e972-e325-11ce-bfc1-08002be10318}" },
		func(n *portableNodeReceipt) { n.ID += "\n" },
	} {
		changed := n
		mutate(&changed)
		if validPortableReceipt(changed) {
			t.Fatal("unsupported node accepted", changed)
		}
	}
}

func TestNetworkOnlyServiceDoesNotRelaxOriginalStartup(t *testing.T) {
	for original, want := range map[uint32]uint32{0: 0, 1: 1, 2: 3, 3: 3, 4: 4} {
		if got := networkOnlyServiceStartType(original); got != want {
			t.Fatalf("%d: got %d want %d", original, got, want)
		}
	}
}
