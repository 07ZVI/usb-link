package usbhost

import (
	"errors"
	"suhang/usbnet/internal/transport/usbaddress"
	"testing"
	"time"
)

func retryHost() hostIdentity {
	return hostIdentity{GUID: usbaddress.HostGUID, Alias: usbaddress.HostName, Type: 53, Index: 28, LUID: 280}
}

func TestRecoveryDriverReadbackOnlyRetriesFullQuery(t *testing.T) {
	for _, failures := range []int{0, 1, 2, 3} {
		t.Run(string(rune('0'+failures)), func(t *testing.T) {
			queries, reads, waits := 0, 0, 0
			sentinel := errors.New("provider unavailable")
			n, e := readRecoveryDriverIdentity(retryHost(), func() (hostIdentity, bool, error) { queries++; return retryHost(), true, nil }, func(index uint32) error {
				reads++
				if index != 28 {
					t.Fatal(index)
				}
				if reads <= failures {
					return sentinel
				}
				return nil
			}, func(d time.Duration) {
				waits++
				if d != 500*time.Millisecond {
					t.Fatal(d)
				}
			})
			want := min(failures+1, 3)
			if n != want || reads != want || queries != want || waits != want-1 {
				t.Fatalf("n=%d reads=%d queries=%d waits=%d", n, reads, queries, waits)
			}
			if failures == 3 && !errors.Is(e, sentinel) || failures < 3 && e != nil {
				t.Fatal(e)
			}
		})
	}
}

func TestRecoveryDriverReadbackNeverRetriesNativeChanges(t *testing.T) {
	for _, change := range []func(*hostIdentity){func(h *hostIdentity) { h.Index++ }, func(h *hostIdentity) { h.LUID++ }, func(h *hostIdentity) { h.Type = 6 }, func(h *hostIdentity) { h.GUID = "other" }, func(h *hostIdentity) { h.Alias = "other" }} {
		reads, queries := 0, 0
		_, e := readRecoveryDriverIdentity(retryHost(), func() (hostIdentity, bool, error) {
			queries++
			h := retryHost()
			if queries == 2 {
				change(&h)
			}
			return h, true, nil
		}, func(uint32) error { reads++; return errors.New("provider unavailable") }, func(time.Duration) {})
		if e == nil || reads != 1 || queries != 2 {
			t.Fatalf("e=%v reads=%d queries=%d", e, reads, queries)
		}
	}
	for _, present := range []bool{false, true} {
		reads, waits := 0, 0
		_, e := readRecoveryDriverIdentity(retryHost(), func() (hostIdentity, bool, error) {
			if present {
				return hostIdentity{}, true, errors.New("ambiguous")
			}
			return hostIdentity{}, false, nil
		}, func(uint32) error { reads++; return nil }, func(time.Duration) { waits++ })
		if e == nil || reads != 0 || waits != 0 {
			t.Fatal("native ambiguity/disappearance admitted")
		}
	}
}
