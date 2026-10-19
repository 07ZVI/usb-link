//go:build usblink_local_remote

package ipadncm

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"net/netip"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func runtimeTCPFixture(state uint32, local string, port uint16, remote string, remotePort uint16) []byte {
	b := make([]byte, 28)
	binary.LittleEndian.PutUint32(b, 1)
	binary.LittleEndian.PutUint32(b[4:], state)
	a, p := netip.MustParseAddr(local).As4(), netip.MustParseAddr(remote).As4()
	copy(b[8:12], a[:])
	copy(b[16:20], p[:])
	binary.BigEndian.PutUint16(b[12:14], port)
	binary.BigEndian.PutUint16(b[20:22], remotePort)
	return b
}

func TestRuntimeNetworkTCPScopesEvidenceToKnownIPadAddressPairs(t *testing.T) {
	pairs := runtimeNetworkPairs([]string{"10.6.9.254/32", "192.168.1.1/24"})
	if len(pairs) != 2 {
		t.Fatalf("shared-host pairs = %v", pairs)
	}
	for _, test := range []struct {
		name, local, remote            string
		state                          uint32
		port, remotePort               uint16
		sunshine, listening, localsend bool
	}{
		{"shared host", "10.6.9.1", "10.6.9.3", 5, 47989, 60000, true, false, false},
		{"NCM local", "10.6.9.254", "10.6.9.3", 5, 48010, 60000, true, false, false},
		{"Mac must not count", "10.6.9.1", "10.6.9.2", 5, 47989, 60000, false, false, false},
		{"LAN must not count", "192.168.1.1", "192.168.1.2", 5, 47989, 60000, false, false, false},
		{"pending must not count", "10.6.9.1", "10.6.9.3", 3, 47989, 60000, false, false, false},
		{"custom port unknown", "10.6.9.1", "10.6.9.3", 5, 12345, 60000, false, false, false},
		{"wildcard listener", "0.0.0.0", "0.0.0.0", 2, 53317, 0, false, true, false},
		{"loopback listener excluded", "127.0.0.1", "0.0.0.0", 2, 53317, 0, false, false, false},
		{"LocalSend inbound", "10.6.9.1", "10.6.9.3", 5, 53317, 60000, false, false, true},
		{"LocalSend outbound", "10.6.9.1", "10.6.9.3", 5, 60000, 53317, false, false, true},
	} {
		t.Run(test.name, func(t *testing.T) {
			r := runtimeNetworkTCP(runtimeTCPFixture(test.state, test.local, test.port, test.remote, test.remotePort), pairs)
			if r.Status != "READ" || r.SunshineEstablished != test.sunshine || r.LocalSendListening != test.listening || r.LocalSendEstablished != test.localsend {
				t.Fatalf("unexpected evidence: %+v", r)
			}
			if !test.sunshine && !test.listening && !test.localsend && len(r.Matches) != 0 {
				t.Fatal("unrelated socket exported")
			}
		})
	}
	if r := runtimeNetworkTCP(runtimeTCPFixture(5, "10.6.9.1", 47989, "10.6.9.3", 60000), nil); r.SunshineEstablished {
		t.Fatal("unmapped adapter accepted")
	}
}

func TestRuntimeNetworkTCPMalformedAndBounded(t *testing.T) {
	for _, table := range [][]byte{nil, {1, 0, 0, 0}, {255, 255, 255, 255}} {
		if runtimeNetworkTCP(table, nil).Status != "TABLE_INVALID" {
			t.Fatal("malformed table accepted")
		}
	}
	buffer := make([]byte, 4)
	for i := 0; i < 10; i++ {
		buffer = append(buffer, runtimeTCPFixture(5, "10.6.9.1", 47989, "10.6.9.3", uint16(60000+i))[4:]...)
	}
	binary.LittleEndian.PutUint32(buffer, 10)
	r := runtimeNetworkTCP(buffer, runtimeNetworkPairs([]string{"10.6.9.254/32"}))
	if len(r.Matches) != 4 || r.MatchesOmitted != 6 || !r.SunshineEstablished {
		t.Fatalf("match bound: %+v", r)
	}
	d := RuntimeNetworkDiagnostic{Status: "ROOT_UNCONFIRMED_OR_AMBIGUOUS", SampledUTC: "2026-10-16T00:00:00Z", AgeMS: 123456, Collecting: true, ElapsedMS: 1234, TCP: r, AdaptersOmitted: 10}
	for i := 0; i < 2; i++ {
		d.Adapters = append(d.Adapters, RuntimeNetworkAdapter{Index: 12345, OperStatus: 7, AdminStatus: 3, MediaState: 2, StatusFlags: 255, StatusRead: true, IPv4: []string{"255.255.255.255/32", "255.255.255.255/32"}, AddressesOmitted: 126, Error: "NCM_INTERFACE_CHANGED_BEFORE_STATISTICS"})
	}
	body, err := json.Marshal(d)
	if err != nil || len(body) > 2000 {
		t.Fatalf("payload budget: %d %v", len(body), err)
	}
	if strings.Contains(string(body), "process_identity_verified\":true") || strings.Contains(string(body), "route_verified\":true") {
		t.Fatal("port observation promoted to application/route proof")
	}
}

func TestRuntimeNetworkCacheSingleWorkerAndNonblockingStaleRead(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var cache runtimeNetworkCache
	entered, release := make(chan struct{}), make(chan struct{})
	var calls atomic.Int32
	collect := func(context.Context) RuntimeNetworkDiagnostic {
		calls.Add(1)
		close(entered)
		<-release
		return RuntimeNetworkDiagnostic{Status: "ROOT_ABSENT"}
	}
	startRuntimeNetworkDiagnostics(ctx, &cache, collect, time.Hour)
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("collector not started")
	}
	startRuntimeNetworkDiagnostics(ctx, &cache, collect, time.Hour)
	cache.Lock()
	cache.started = time.Now().Add(-3 * time.Second)
	cache.Unlock()
	r := cache.snapshot(time.Now())
	if !r.Stale || !r.Collecting || !r.BudgetExceeded || r.Status != "NOT_SAMPLED" || calls.Load() != 1 {
		t.Fatalf("stuck read must be explicit and single: %+v", r)
	}
	cancel()
	close(release)
	deadline := time.Now().Add(time.Second)
	for {
		cache.Lock()
		running := cache.running
		cache.Unlock()
		if !running {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("worker did not stop")
		}
		time.Sleep(time.Millisecond)
	}
}

func TestRuntimeNetworkCacheSnapshotIsImmutableAndAges(t *testing.T) {
	now := time.Now()
	cache := runtimeNetworkCache{sampled: now.Add(-21 * time.Second), value: RuntimeNetworkDiagnostic{Status: "ROOT_SCOPED", Adapters: []RuntimeNetworkAdapter{{IPv4: []string{"10.6.9.254/32"}}}, TCP: RuntimeNetworkTCP{Matches: []RuntimeNetworkTCPMatch{{Kind: "test"}}}}}
	r := cache.snapshot(now)
	if !r.Stale || r.AgeMS != 21000 {
		t.Fatalf("old sample not labeled: %+v", r)
	}
	r.Adapters[0].IPv4[0] = "changed"
	r.TCP.Matches[0].Kind = "changed"
	next := cache.snapshot(now)
	if next.Adapters[0].IPv4[0] != "10.6.9.254/32" || next.TCP.Matches[0].Kind != "test" {
		t.Fatal("snapshot aliases mutable cache")
	}
}
