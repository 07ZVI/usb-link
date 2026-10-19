package ipadncm

import "testing"

func TestTrustPNPPhotoTransportAndActiveNCMShareBoundedBudget(t *testing.T) {
	nodes := []trustNodeState{
		{Role: "R", Service: "C"},
		{Role: "00", Service: "P", Readable: true, Problem: 22},
		{Role: "01", Service: "W", Readable: true, Started: true},
		{Role: "02", Service: "N", Readable: true, Problem: 10},
		{Role: "04", Service: "N", Readable: true, Started: true},
		{Role: "03", Service: "X"},
		{Role: "05", Service: "F"},
		{Role: "R", Service: "C"},
	}
	p := normalizeTrustPNP(trustPNPState{Read: "ok", Roots: 2, Controls: 2, Nodes: nodes, Omitted: 3})
	if len(p.Nodes) != 4 || p.Omitted != 7 || p.Roots != 2 || p.Controls != 2 {
		t.Fatal("selection concealed omitted nodes or changed counts", p)
	}
	for i, role := range []string{"R", "00", "01", "04"} {
		if p.Nodes[i].Role != role {
			t.Fatalf("slot %d: got %+v, want %s", i, p.Nodes[i], role)
		}
	}
	if p.Nodes[1].Service != "P" || p.Nodes[1].Problem != 22 || p.Nodes[2].Service != "W" {
		t.Fatal("photo disable or Apple transport state lost", p.Nodes)
	}
	nodes[4].Started = false
	nodes[4].Problem = 10
	p = normalizeTrustPNP(trustPNPState{Read: "ok", Nodes: nodes})
	if p.Nodes[3].Role != "02" || p.Nodes[3].Problem != 10 {
		t.Fatal("failed NCM hidden when no active NCM exists", p.Nodes)
	}
	p = normalizeTrustPNP(trustPNPState{Read: "ok", Nodes: []trustNodeState{{Role: "00", Service: "P"}, {Role: "01", Service: "F"}}})
	if p.Nodes[0].Service != "P" || p.Nodes[1].Service != "F" {
		t.Fatal("WPD and generic UMDF services collapsed", p.Nodes)
	}
}
