package fileshare

import "testing"

func TestSMBTraceIsBoundedAndSeparatesPeers(t *testing.T) {
	for _, peer := range []string{"10.6.9.2", "10.6.9.3"} {
		smbTrace.Lock()
		delete(smbTrace.peers, peer)
		smbTrace.Unlock()
		t.Cleanup(func() { smbTrace.Lock(); delete(smbTrace.peers, peer); smbTrace.Unlock() })
	}
	close := smbConnection("10.6.9.3")
	for i := 0; i < 100; i++ {
		smbObserve("10.6.9.3", 3, uint32(i))
	}
	smbObserve("10.6.9.3", 8, 0)
	smbObserve("10.6.9.3", 9, 0)
	close()
	v := SMBDiagnostics("10.6.9.3").(map[string]any)["trace"].(SMBTrace)
	if v.Accepted != 1 || v.Active != 0 || v.Commands != 102 || len(v.Recent) != 12 || v.Recent[0].Status != 88 || v.Recent[11].Status != 99 {
		t.Fatal(v)
	}
	other := SMBDiagnostics("10.6.9.2").(map[string]any)["trace"].(SMBTrace)
	if other.Accepted != 0 || other.Commands != 0 {
		t.Fatal("peer trace mixed", other)
	}
	v.Recent[0].Status = 0
	actual := SMBDiagnostics("10.6.9.3").(map[string]any)["trace"].(SMBTrace)
	if actual.Recent[0].Status != 88 {
		t.Fatal("diagnostic caller mutated live trace")
	}
}
