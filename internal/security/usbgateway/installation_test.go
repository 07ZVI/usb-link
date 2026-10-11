package usbgateway

import (
	"errors"
	"fmt"
	"testing"
)

func TestPolicyReadbackFollowsCommit(t *testing.T) {
	published := false
	err := commitThenVerify(func() error { published = true; return nil }, func() error {
		if !published {
			t.Fatal("queried unpublished policy")
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}
func TestFailedCommitNeverReadsBack(t *testing.T) {
	failure := errors.New("commit failed")
	err := commitThenVerify(func() error { return failure }, func() error { t.Fatal("readback after failed commit"); return nil })
	if !errors.Is(err, failure) {
		t.Fatal(err)
	}
}
func TestReadbackFailurePreventsReadiness(t *testing.T) {
	failure := errors.New("readback failed")
	err := commitThenVerify(func() error { return nil }, func() error { return failure })
	if !errors.Is(err, failure) {
		t.Fatal(err)
	}
}

func TestWFPDWORDNormalizationAndRecovery(t *testing.T) {
	for _, result := range []uint64{0x80320003, 0xffffffff80320003, 0x80320007, 0xffffffff80320007} {
		e := wfpCallResult("readback", result)
		if !isNotFound(e) || !isNotFound(fmt.Errorf("wrapped: %w", e)) {
			t.Fatalf("not recognized: %v", e)
		}
	}
	if wfpCallResult("success", 0) != nil || isNotFound(nil) || isNotFound(wfpCallResult("denied", 5)) {
		t.Fatal("incorrect success or missing-object classification")
	}
	if got := wfpCallResult("readback", 0xffffffff80320003).Error(); got != "readback: 0x80320003" {
		t.Fatal(got)
	}
}
