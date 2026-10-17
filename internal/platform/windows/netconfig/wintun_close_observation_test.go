package netconfig

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"
	"time"
)

func TestNormalCloseMIBOnlyDefersUnconfirmedToParentWithoutPolling(t *testing.T) {
	s := wintunCloseObservation{InterfacesRead: true, IPv4Read: true, PresentNetRead: true, PresentInstancesRead: true, InterfacePresent: true}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	reads, handoff := 0, false
	err := waitWintunCloseSettle(ctx, func() (bool, error) {
		reads++
		absent, parent, err := s.closeResult(nil)
		handoff = parent
		return absent, err
	}, nil, nil)
	if reads != 1 || !handoff || err == nil || err.Error() != "USB_MAC_LIFETIME_CLOSE_ABSENCE_UNCONFIRMED" {
		t.Fatalf("MIB-only observation waited or became success: reads=%d handoff=%t err=%v", reads, handoff, err)
	}
	// Even an apparently disconnected/not-present row is not certified absent.
	for state := uint32(0); state <= 7; state++ {
		s.Matches = wintunCloseMatches{Count: 1, Rows: [4]wintunCloseMatch{{OldLUID: true, Oper: state, Media: 2}}}
		absent, parent, err := s.closeResult(nil)
		if absent || !parent || err == nil {
			t.Fatal("row status changed proof semantics")
		}
	}
}

func TestNormalCloseParentHandoffRequiresAllReadsAndNoOtherLiveObjects(t *testing.T) {
	base := wintunCloseObservation{InterfacesRead: true, IPv4Read: true, PresentNetRead: true, PresentInstancesRead: true, InterfacePresent: true}
	for name, change := range map[string]func(*wintunCloseObservation){
		"interface unread":    func(s *wintunCloseObservation) { s.InterfacesRead = false },
		"ipv4 unread":         func(s *wintunCloseObservation) { s.IPv4Read = false },
		"net unread":          func(s *wintunCloseObservation) { s.PresentNetRead = false },
		"instance unread":     func(s *wintunCloseObservation) { s.PresentInstancesRead = false },
		"address remains":     func(s *wintunCloseObservation) { s.IPv4Present = true },
		"net binding remains": func(s *wintunCloseObservation) { s.NetBindingPresent = true },
		"instance remains":    func(s *wintunCloseObservation) { s.ExactInstancePresent = true },
	} {
		t.Run(name, func(t *testing.T) {
			s := base
			change(&s)
			absent, parent, err := s.closeResult(nil)
			if absent || parent || err != nil {
				t.Fatalf("other pending state bypassed original wait: %+v", s)
			}
		})
	}
	queryError := errors.New("bounded query failed")
	if absent, parent, err := base.closeResult(queryError); absent || parent || !errors.Is(err, queryError) {
		t.Fatal("query failure hidden by handoff")
	}
	base.InterfacePresent = false
	reads := 0
	if err := waitWintunCloseSettle(context.Background(), func() (bool, error) {
		reads++
		absent, parent, err := base.closeResult(nil)
		if parent {
			t.Fatal("absence became handoff")
		}
		return absent, err
	}, nil, nil); err != nil || reads != 2 {
		t.Fatal("successful closure lost two fresh observations")
	}
}

func TestNormalCloseMatchSummaryIsBoundedAndValueCopied(t *testing.T) {
	var m wintunCloseMatches
	m.record(wintunCloseMatch{Oper: 1})
	for i := uint32(0); i < 6; i++ {
		m.record(wintunCloseMatch{OldLUID: true, Oper: i})
	}
	if m.Count != 4 || m.Omitted != 2 {
		t.Fatalf("unbounded matches: %+v", m)
	}
	copy := m
	m.Rows[0].Oper = 99
	if copy.Rows[0].Oper != 0 {
		t.Fatal("summary aliases live state")
	}
	b, err := json.Marshal(copy)
	if err != nil || len(b) > 600 {
		t.Fatal("match summary exceeded fixed scalar budget")
	}
}

func TestNormalCloseScopeRejectsMissingOrUnboundedIdentity(t *testing.T) {
	for _, x := range []struct {
		index    uint32
		luid     uint64
		instance string
	}{
		{0, 9, "owned"}, {4, 0, "owned"}, {4, 9, ""}, {4, 9, "bad\x00id"}, {4, 9, "*"}, {4, 9, "?"}, {4, 9, strings.Repeat("x", 1025)},
	} {
		if wintunCloseScopeValid(x.index, x.luid, x.instance) {
			t.Fatal("invalid close scope accepted")
		}
	}
	if !wintunCloseScopeValid(4, 9, `SWD\WINTUN\owned`) {
		t.Fatal("captured scope refused")
	}
}

func TestNormalCloseRequiresAllFourCompleteLiveObservations(t *testing.T) {
	for blocked := -1; blocked < 4; blocked++ {
		calls := 0
		read := func(i int) wintunCloseRead {
			return func() (uint32, bool, error) { calls++; return uint32(10 + i), i == blocked, nil }
		}
		s, err := collectWintunCloseObservation(read(0), read(1), read(2), read(3))
		if err != nil || calls != 4 || s.absent() != (blocked == -1) {
			t.Fatalf("incomplete or active proof: %+v %v calls=%d", s, err, calls)
		}
		if s.InterfaceRows != 10 || s.IPv4Rows != 11 || s.PresentNetNodes != 12 || s.PresentInstances != 13 {
			t.Fatal("read counters lost")
		}
	}
	if (wintunCloseObservation{}).absent() {
		t.Fatal("unread state treated as absence")
	}
}

func TestNormalCloseReadErrorsCannotCertifyAbsence(t *testing.T) {
	for fail := 0; fail < 4; fail++ {
		problem := errors.New("query or truncation failure")
		read := func(i int) wintunCloseRead {
			return func() (uint32, bool, error) {
				if i == fail {
					return 0, false, problem
				}
				return 1, false, nil
			}
		}
		s, err := collectWintunCloseObservation(read(0), read(1), read(2), read(3))
		if !errors.Is(err, problem) || s.absent() {
			t.Fatalf("unknown query admitted: %d %+v %v", fail, s, err)
		}
	}
}

func TestNormalCloseActiveObjectBetweenFreshReadsRequiresNewPair(t *testing.T) {
	reads := 0
	clear := func() (uint32, bool, error) { return 0, false, nil }
	poll := make(chan time.Time, 1)
	poll <- time.Time{}
	err := waitWintunCloseSettle(context.Background(), func() (bool, error) {
		reads++
		s, err := collectWintunCloseObservation(clear, clear, clear, func() (uint32, bool, error) { return 1, reads == 2, nil })
		return s.absent(), err
	}, nil, poll)
	if err != nil || reads != 4 {
		t.Fatalf("raced present instance admitted: reads=%d err=%v", reads, err)
	}
}

func TestNormalCloseNativeScopeExcludesPhantomsWithoutChangingRemoval(t *testing.T) {
	// The portable fake-reader tests exercise the proof. This contract also
	// protects the native enumeration scope that defines present vs installed.
	b, err := os.ReadFile("wintun_close_observation_windows.go")
	if err != nil {
		t.Fatal(err)
	}
	s := string(b)
	for _, required := range []string{
		`SetupDiGetClassDevsEx(&class, "", 0, windows.DIGCF_PRESENT, 0, "")`,
		`SetupDiGetClassDevsEx(nil, "", 0, windows.DIGCF_ALLCLASSES|windows.DIGCF_PRESENT, 0, "")`,
		`row.InterfaceLuid == luid`,
	} {
		if !strings.Contains(s, required) {
			t.Fatal("live-close scope changed:", required)
		}
	}
	if strings.Contains(s, "row.InterfaceIndex") || strings.Contains(s, "CallClassInstaller") || strings.Contains(s, "nativeWintunRemovalAbsent") {
		t.Fatal("normal close gained index reuse, mutation or uninstall proof")
	}
	b, err = os.ReadFile("host_remove_native_windows.go")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b), `SetupDiGetClassDevsEx(&class, "", 0, 0, 0, "")`) || !strings.Contains(string(b), `SetupDiGetClassDevsEx(nil, "", 0, windows.DIGCF_ALLCLASSES, 0, "")`) {
		t.Fatal("strict installation-removal proof was weakened")
	}
}
