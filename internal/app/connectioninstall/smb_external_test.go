package connectioninstall

import "testing"

func TestExternalSMBSelectionBindsWholeShareSnapshot(t *testing.T) {
	base := []string{"Archive", `E:\Archive`, "Created elsewhere", "D:(A;;FR;;;WD)"}
	id := externalSMBID(base[0], base[1], base[2], base[3])
	if !IsExternalSMBID(id) {
		t.Fatal(id)
	}
	for i := range base {
		changed := append([]string(nil), base...)
		changed[i] += "changed"
		if externalSMBID(changed[0], changed[1], changed[2], changed[3]) == id {
			t.Fatal("changed snapshot remained authorized", i)
		}
	}
	for _, bad := range []string{"Archive", "external:../../Windows", "external:", id + "x", "external:" + id[9:72] + "z"} {
		if IsExternalSMBID(bad) {
			t.Fatal("invalid external selector accepted", bad)
		}
	}
	if externalSMBID("a", "bc", "", "") == externalSMBID("ab", "c", "", "") {
		t.Fatal("ambiguous fields")
	}
}
