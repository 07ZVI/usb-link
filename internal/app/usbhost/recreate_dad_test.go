package usbhost

import (
	"bytes"
	"encoding/json"
	"errors"
	"reflect"
	"testing"
)

func TestRecreatedDADUsesBothGenerationsBeforeAddressReady(t *testing.T) {
	old, raw, attempt := recreateFixture()
	mapped := mappedRecreate(attempt)
	handle := recreatedDADHandle{FactoryHeld: true, GUID: mapped.Next.GUID, Index: mapped.Next.Index, LUID: mapped.Next.LUID, Instance: mapped.Instance}
	// This exactly reproduces the former callback's cold-boot bug: old completed
	// bytes are still intentionally durable while the returned mapping is NEW.
	if old.Token == mapped.Next.Token || old.Index == mapped.Next.Index || old.LUID == mapped.Next.LUID {
		t.Fatal("fixture did not recreate both generations")
	}
	if err := validateRecreateTransition(attempt, mapped); err != nil {
		t.Fatal(err)
	}
	if err := validateRecreatedDADOwnership(mapped, raw, mapped.Next, handle); err != nil {
		t.Fatal("valid cold-start DAD owner rejected", err)
	}
	if !bytes.Equal(raw, mustJournalJSON(t, old)) {
		t.Fatal("old completed journal changed before address")
	}
	// DAD does not create an address, alter immutable stamps, or publish ready.
	if mapped.State != "mapped" || mapped.Next.Created != 0 {
		t.Fatal("DAD synthesized ownership")
	}
	// Address planning can advance only in the same mapping and token.
	planned := mapped
	planned.Next.Planned++
	if err := validateRecreateTransition(mapped, planned); err != nil {
		t.Fatal(err)
	}
	if err := validateRecreatedDADOwnership(planned, raw, planned.Next, handle); err != nil {
		t.Fatal(err)
	}
	ready := planned
	ready.State = "ready"
	ready.Next.Created = ready.Next.Planned + 1
	if err := validateRecreateTransition(planned, ready); err != nil {
		t.Fatal(err)
	}
	if pos, err := recreateJournalPosition(ready, raw); err != nil || pos != "old" {
		t.Fatal("ready lost old proof", pos, err)
	}
	if pos, err := recreateJournalPosition(ready, mustJournalJSON(t, ready.Next)); err != nil || pos != "new" {
		t.Fatal("ready commit unproven", pos, err)
	}
	if validateRecreatedDADOwnership(ready, raw, ready.Next, handle) == nil {
		t.Fatal("post-address phase admitted for pre-address DAD")
	}
}

func mustJournalJSON(t *testing.T, p journal) []byte {
	t.Helper()
	b, e := json.Marshal(p)
	if e != nil {
		t.Fatal(e)
	}
	return b
}

func TestRecreatedDADRejectsChangedReceiptOrLiveCreator(t *testing.T) {
	_, raw, attempt := recreateFixture()
	mapped := mappedRecreate(attempt)
	handle := recreatedDADHandle{FactoryHeld: true, GUID: mapped.Next.GUID, Index: mapped.Next.Index, LUID: mapped.Next.LUID, Instance: mapped.Instance}
	type sample struct {
		txn    recreateTransaction
		old    []byte
		p      journal
		handle recreatedDADHandle
	}
	for name, change := range map[string]func(*sample){
		"attempt_not_mapped": func(s *sample) { s.txn = attempt }, "ready_not_mapped": func(s *sample) { s.txn.State = "ready"; s.txn.Next.Created = s.txn.Next.Planned + 1 },
		"unknown_version": func(s *sample) { s.txn.Version++ }, "changed_original_hash": func(s *sample) { s.txn.OldSHA256 = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" },
		"changed_old_luid": func(s *sample) { s.txn.OriginalLUID++ }, "old_journal_changed": func(s *sample) { s.old = append(s.old, ' ') },
		"old_replaced_by_next": func(s *sample) { s.old = mustJournalJSON(t, s.txn.Next) }, "caller_index": func(s *sample) { s.p.Index++ }, "caller_luid": func(s *sample) { s.p.LUID++ },
		"caller_token": func(s *sample) { s.p.Token = "222222222222222222222222" }, "new_created_address": func(s *sample) { s.p.Created = s.p.Planned + 1 },
		"changed_txn_token": func(s *sample) { s.txn.Token = "222222222222222222222222" }, "closed_creator": func(s *sample) { s.handle.FactoryHeld = false },
		"wrong_factory_guid": func(s *sample) { s.handle.GUID = "{A4611646-E050-4D25-B83E-633A5598F302}" }, "wrong_factory_index": func(s *sample) { s.handle.Index++ },
		"wrong_factory_luid": func(s *sample) { s.handle.LUID++ }, "wrong_typed_instance": func(s *sample) { s.handle.Instance += "OTHER" },
	} {
		t.Run(name, func(t *testing.T) {
			s := sample{mapped, append([]byte{}, raw...), mapped.Next, handle}
			change(&s)
			if validateRecreatedDADOwnership(s.txn, s.old, s.p, s.handle) == nil {
				t.Fatal("changed authority admitted")
			}
			// A failed callback/known local handle close must not manufacture ready or
			// turn the saved mapped receipt into a same-boot retry authorization.
			if recreateUnknownRecoveryGate(mapped, mapped.Ticks+1) == nil {
				t.Fatal("DAD failure/close bypassed unknown-outcome fence")
			}
			if mapped.State != "mapped" || mapped.Next.Created != 0 {
				t.Fatal("failed callback changed durable outcome")
			}
		})
	}
}

func TestRecreateAbsenceRequiresBothSavedLUIDs(t *testing.T) {
	_, _, attempt := recreateFixture()
	for _, txn := range []recreateTransaction{attempt, mappedRecreate(attempt), readyRecreate(attempt)} {
		expected := []uint64{txn.OriginalLUID}
		if txn.Next.LUID != 0 && txn.Next.LUID != txn.OriginalLUID {
			expected = append(expected, txn.Next.LUID)
		}
		var got []uint64
		if err := verifyRecreateAbsentAddressReads(txn, func(luid uint64) (int, error) { got = append(got, luid); return 0, nil }); err != nil || !reflect.DeepEqual(got, expected) {
			t.Fatal("saved lifecycle omitted", got, expected, err)
		}
		for _, badLUID := range expected {
			if verifyRecreateAbsentAddressReads(txn, func(luid uint64) (int, error) {
				if luid == badLUID {
					return 1, nil
				}
				return 0, nil
			}) == nil {
				t.Fatal("dangling old/new address accepted", txn.State, badLUID)
			}
			if verifyRecreateAbsentAddressReads(txn, func(luid uint64) (int, error) {
				if luid == badLUID {
					return 0, errors.New("query unavailable")
				}
				return 0, nil
			}) == nil {
				t.Fatal("unknown address query accepted", txn.State, badLUID)
			}
		}
	}
	same := mappedRecreate(attempt)
	same.Next.LUID = same.OriginalLUID
	if got := recreateAbsenceLUIDs(same); len(got) != 1 || got[0] != same.OriginalLUID {
		t.Fatal("same lifecycle query is not bounded", got)
	}
	if verifyRecreateAbsentAddressReads(attempt, nil) == nil {
		t.Fatal("missing proof provider accepted")
	}
}

func TestRecreatedDADAcceptsActualBootSameLUIDNewIndexAndToken(t *testing.T) {
	old, _, attempt := recreateFixture()
	old.Index = 27
	old.LUID = 14918723521478656
	raw := mustJournalJSON(t, old)
	attempt.OldSHA256 = journalDigest(raw)
	attempt.OriginalLUID = old.LUID
	mapped := mappedRecreate(attempt)
	mapped.Next.Index = 24
	mapped.Next.LUID = old.LUID
	handle := recreatedDADHandle{FactoryHeld: true, GUID: mapped.Next.GUID, Index: 24, LUID: old.LUID, Instance: mapped.Instance}
	if old.Token == mapped.Next.Token {
		t.Fatal("old-token compare bug not reproduced")
	}
	if err := validateRecreatedDADOwnership(mapped, raw, mapped.Next, handle); err != nil {
		t.Fatal("actual cold-boot shape rejected", err)
	}
}
