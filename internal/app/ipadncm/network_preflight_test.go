package ipadncm

import (
	"encoding/json"
	"os"
	"testing"
)

func TestMeasuredPhotoModeCanReachRequestBeforeNCMIsPublished(t *testing.T) {
	type state struct {
		Current        byte            `json:"current"`
		Configurations []Configuration `json:"configurations"`
	}
	var f struct{ Before, After state }
	b, e := os.ReadFile("testdata/observed-mode-layout-0.5.2.json")
	if e != nil || json.Unmarshal(b, &f) != nil {
		t.Fatal("missing observed fixture")
	}
	if f.Before.Current != 3 || len(f.Before.Configurations) != 4 || activeNCM(f.Before.Configurations, 3) {
		t.Fatal("fixture not the measured pre-mode state")
	}
	if !networkUSBPreflight(f.Before.Configurations, 3) {
		t.Fatal("deadlock: NCM incorrectly required before requesting mode")
	}
	if !networkUSBPreflight(f.After.Configurations, 5) || !activeNCM(f.After.Configurations, 5) {
		t.Fatal("post-mode topology rejected")
	}
	for _, bad := range []byte{0, 1, 2, 4, 6} {
		if networkUSBPreflight(f.Before.Configurations, bad) {
			t.Fatal("unknown initial configuration accepted")
		}
	}
	f.Before.Configurations[2].Interfaces[1].Protocol = 1
	if networkUSBPreflight(f.Before.Configurations, 3) {
		t.Fatal("unqualified MUX interface accepted")
	}
	f.After.Configurations[4].Interfaces[3].Slaves = []byte{99}
	f.After.Configurations[4].NCMControls = 1
	if networkUSBPreflight(f.After.Configurations, 5) {
		t.Fatal("invalid published NCM topology accepted")
	}
}
