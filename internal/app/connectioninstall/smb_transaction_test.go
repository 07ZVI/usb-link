package connectioninstall

import (
	"errors"
	"reflect"
	"testing"
)

func TestRetireSMBItemsPersistsRemovalDespiteUnavailableACLAndContinues(t *testing.T) {
	offline, foreign := errors.New("offline ACL"), errors.New("foreign share")
	durable := []string{"disk", "local", "foreign"}
	var restored []string
	err := retireSMBItems(durable, func(id string) error {
		if id == "foreign" {
			return foreign
		}
		return nil
	}, func(next []string) error {
		durable = append([]string(nil), next...)
		return nil
	}, func(id string) error {
		restored = append(restored, id)
		if id == "disk" {
			return offline
		}
		return nil
	})
	if !errors.Is(err, offline) || !errors.Is(err, foreign) || !reflect.DeepEqual(durable, []string{"foreign"}) || !reflect.DeepEqual(restored, []string{"disk", "local"}) {
		t.Fatal("partial cleanup lost progress or stopped other shares", durable, restored, err)
	}
}

func TestRetireSMBItemsRetainsReceiptWhenPersistenceFails(t *testing.T) {
	saveErr := errors.New("disk full")
	var durable, restored []string
	err := retireSMBItems([]string{"first", "second"}, func(string) error { return nil }, func(next []string) error {
		if reflect.DeepEqual(next, []string{"second"}) {
			return saveErr
		}
		durable = append([]string(nil), next...)
		return nil
	}, func(id string) error { restored = append(restored, id); return nil })
	if !errors.Is(err, saveErr) || !reflect.DeepEqual(durable, []string{"first"}) || !reflect.DeepEqual(restored, []string{"second"}) {
		t.Fatal(durable, restored, err)
	}
}

func TestSMBIdentityFailureRepublishesOnlyAfterConfirmedRollback(t *testing.T) {
	changeErr, recoveryErr, resumeErr := errors.New("change"), errors.New("rollback"), errors.New("resume")
	for _, rollbackOK := range []bool{false, true} {
		resumed := false
		err := changeSMBIdentity(true, func() error { return changeErr }, func() error {
			if !rollbackOK {
				return recoveryErr
			}
			return nil
		}, func() error { resumed = true; return resumeErr })
		if !errors.Is(err, changeErr) || resumed != rollbackOK || errors.Is(err, recoveryErr) == rollbackOK || errors.Is(err, resumeErr) != rollbackOK {
			t.Fatal(rollbackOK, resumed, err)
		}
	}
}

func TestSMBIdentityDoesNotEnablePreviouslyDisabledShares(t *testing.T) {
	if err := changeSMBIdentity(false, func() error { return nil }, nil, func() error { t.Fatal("enabled previously disabled shares"); return nil }); err != nil {
		t.Fatal(err)
	}
}

func TestPasswordJournalPrecedesMutationAndFailedCommitRestoresOldCredential(t *testing.T) {
	actual, durable, pending := "old", "old", false
	commitErr := errors.New("receipt write failed")
	err := commitSMBPassword(func() error { pending = true; return nil }, func() error {
		if !pending {
			t.Fatal("password changed without recovery intent")
		}
		actual = "new"
		return nil
	}, func() error { return commitErr }, func() error { actual, durable, pending = "old", "old", false; return nil })
	if !errors.Is(err, commitErr) || actual != durable || pending {
		t.Fatal(actual, durable, pending, err)
	}
}

func TestPasswordJournalSurvivesInterruptedMutation(t *testing.T) {
	pending, actual, stored := false, "old", "old"
	func() {
		defer func() {
			if recover() == nil {
				t.Fatal("missing simulated interruption")
			}
		}()
		_ = commitSMBPassword(func() error { pending = true; return nil }, func() error { actual = "new"; panic("process interrupted") }, func() error { stored = "new"; pending = false; return nil }, func() error { actual = "old"; pending = false; return nil })
	}()
	if !pending || actual == stored {
		t.Fatal("interrupted change not marked recoverable", pending, actual, stored)
	}
}

func TestNativeShareNamesKeepLegacyNamesAndDisambiguatePrefixCollision(t *testing.T) {
	first, second := "123456780000000000000001", "123456780000000000000002"
	used := map[string]string{"USB-12345678": first}
	if selectNativeShareName(first, used) != "USB-12345678" || selectNativeShareName(second, used) != "USB-"+second || !validNativeShareName(second, "USB-"+second) {
		t.Fatal("colliding shared names")
	}
}

func TestNativeConnectionAddressUsesAnActuallyPublishedShare(t *testing.T) {
	for _, tc := range []struct {
		name   string
		shared []string
		want   string
	}{
		{"closed", nil, "smb://10.6.9.1"},
		{"default", []string{"USB-78cfc564", "USB"}, "smb://10.6.9.1/USB"},
		{"custom-only", []string{"USB-78cfc564"}, "smb://10.6.9.1/USB-78cfc564"},
		{"default-name-collision", []string{"USB-000000000000000000000001"}, "smb://10.6.9.1/USB-000000000000000000000001"},
		{"receipt-order", []string{"USB-ffffffff", "USB-12345678"}, "smb://10.6.9.1/USB-12345678"},
		{"receipt-reordered", []string{"USB-12345678", "USB-ffffffff"}, "smb://10.6.9.1/USB-12345678"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := nativeSMBConnectURL(tc.shared); got != tc.want {
				t.Fatalf("connection URL = %q; want %q", got, tc.want)
			}
		})
	}
}

func TestNativeNameChecksExternalWindowsSharesAndStopsOnProbeFailure(t *testing.T) {
	id := "000000000000000000000001"
	name, e := availableNativeShareName(id, map[string]string{}, func(name string) (bool, error) { return name != "USB", nil })
	if e != nil || name != "USB-"+id || !validNativeShareName(id, name) {
		t.Fatal(name, e)
	}
	failure := errors.New("Windows query unavailable")
	if _, e = availableNativeShareName(id, nil, func(string) (bool, error) { return false, failure }); !errors.Is(e, failure) {
		t.Fatal(e)
	}
	if _, e = availableNativeShareName(id, nil, func(string) (bool, error) { return false, nil }); e == nil {
		t.Fatal("foreign share names accepted")
	}
}
func TestSMBGrantIdentityComparisonDoesNotHideDifferentGuest(t *testing.T) {
	if !sameSMBGrants([]string{"user", "guest"}, []string{"guest", "user"}) || sameSMBGrants([]string{"user", "user"}, []string{"user", "guest"}) {
		t.Fatal("incorrect identity comparison")
	}
}

func TestSharedMembershipFailureKeepsOldBindingsAndPruneFailureKeepsRevocation(t *testing.T) {
	for _, failPublish := range []bool{true, false} {
		oldSelected, oldBound, newBound := true, true, false
		failure := errors.New("disk error")
		e := publishSharedMembership(func() error { newBound = true; return nil }, func() error {
			if failPublish {
				return failure
			}
			oldSelected = false
			return nil
		}, func() error { return failure })
		if oldSelected != failPublish || !oldBound || !newBound || errors.Is(e, failure) != failPublish {
			t.Fatal("publication lost binding or falsely failed a revocation", oldSelected, oldBound, newBound, e)
		}
	}
}

func TestGuestRevocationPrecedesOfflineACLAndFailedGrantNeverOpensShare(t *testing.T) {
	offline := errors.New("drive offline")
	for _, disabling := range []bool{false, true} {
		allowed, committed := disabling, false
		var calls []string
		e := changeSMBGuestPermissions(disabling, func() error { calls = append(calls, "filesystem"); return offline }, func() error { calls = append(calls, "network"); allowed = !disabling; return nil }, func() error { committed = true; return nil })
		if !errors.Is(e, offline) || allowed || committed {
			t.Fatal("failed operation left network entry open or cleared recovery", disabling, allowed, committed, e)
		}
		if disabling && !reflect.DeepEqual(calls, []string{"network", "filesystem"}) || !disabling && !reflect.DeepEqual(calls, []string{"filesystem"}) {
			t.Fatal(calls)
		}
	}
}

func TestGuestReversalReconcilesFolderEvenWhenNetworkAlreadyMatches(t *testing.T) {
	for _, tc := range []struct {
		previous, pendingTarget, desired, current string
		atTarget                                  bool
	}{
		{"", "guest", "", "", false},           // Folder granted; share update interrupted; user disables.
		{"guest", "", "guest", "guest", false}, // Share revoke interrupted; user enables.
		{"guest", "", "guest", "", true},       // Share revoked; folder cleanup interrupted.
		{"", "guest", "", "guest", true},       // Share granted; completion interrupted.
	} {
		current, update := planSMBGuestChange(tc.previous, tc.pendingTarget, tc.desired, true, tc.atTarget)
		if !update || current != tc.current {
			t.Fatal("interrupted folder reconciliation lost", tc, current, update)
		}
	}
	if _, update := planSMBGuestChange("guest", "", "guest", false, false); update {
		t.Fatal("completed settings caused an unnecessary permission rewrite")
	}
}

func TestShareHandoffRevokesMembershipBeforeRelinquishingRecovery(t *testing.T) {
	for failAt := 0; failAt < 3; failAt++ {
		selected, permissionJournal, shareReceipt := true, true, true
		failure := errors.New("storage unavailable")
		e := handoffSMBItem(func() error {
			if failAt == 0 {
				return failure
			}
			selected = false
			return nil
		}, func() error {
			if selected {
				t.Fatal("selected folder lost recovery before revocation")
			}
			if failAt == 1 {
				return failure
			}
			permissionJournal = false
			return nil
		}, func() error {
			if selected || permissionJournal {
				t.Fatal("handoff receipt removed before its prerequisites")
			}
			if failAt == 2 {
				return failure
			}
			shareReceipt = false
			return nil
		})
		if !errors.Is(e, failure) || selected != (failAt == 0) || !shareReceipt {
			t.Fatal("failed handoff could republish a folder or lost its retry record", failAt, selected, shareReceipt, e)
		}
	}
}

func TestGuestDisablesSharesBeforeRestoringOriginallyEnabledIdentity(t *testing.T) {
	allowed, restored := true, false
	offline := errors.New("folder cleanup pending")
	e := disableSMBGuest(func() error { allowed = false; return offline }, func() error {
		if allowed {
			t.Fatal("restored enabled Windows Guest while share grant remained open")
		}
		restored = true
		return nil
	})
	if !errors.Is(e, offline) || !restored {
		t.Fatal("offline folder prevented restoring global Guest policy", restored, e)
	}
}
