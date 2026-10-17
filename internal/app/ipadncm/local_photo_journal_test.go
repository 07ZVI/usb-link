package ipadncm

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestLocalPhotoJournalRejectsForeignInterfacesAndMalformedOriginals(t *testing.T) {
	n := portableNodeReceipt{Root: `USB\VID_05AC&PID_12AB\PRIVATE12345`, ID: `USB\VID_05AC&PID_12AB&MI_00\PHOTO`, Class: portableImageClass}
	good := portablePropertyOriginal{Node: n}
	j := localPhotoJournal{Schema: 1, Entries: []portablePropertyOriginal{good}}
	b, _ := json.Marshal(j)
	if _, e := decodeLocalPhotoJournal(b); e != nil {
		t.Fatal(e)
	}
	for _, change := range []func(*portablePropertyOriginal){
		func(p *portablePropertyOriginal) { p.Node.ID = strings.ReplaceAll(p.Node.ID, "MI_00", "MI_01") },
		func(p *portablePropertyOriginal) { p.Node.ID = p.Node.Root },
		func(p *portablePropertyOriginal) { p.Node.Class = "network" },
		func(p *portablePropertyOriginal) { p.Node.Root = strings.ReplaceAll(p.Node.Root, "12AB", "12A8") },
		func(p *portablePropertyOriginal) { p.Node.OriginalDisabled = true },
		func(p *portablePropertyOriginal) { p.Present = true },
	} {
		p := good
		change(&p)
		j.Entries = []portablePropertyOriginal{p}
		b, _ = json.Marshal(j)
		if _, e := decodeLocalPhotoJournal(b); e == nil {
			t.Fatal("accepted foreign or incomplete original", p)
		}
	}
	j.Entries = []portablePropertyOriginal{good, good}
	b, _ = json.Marshal(j)
	if _, e := decodeLocalPhotoJournal(b); e == nil {
		t.Fatal("duplicate accepted")
	}
}
