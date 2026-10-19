package launcher

import (
	"context"
	"errors"
	"syscall"
	"testing"
	"time"

	"suhang/usbnet/internal/contracts/coreipc"
)

func TestCoreRecoveryStartsAMissingCoreWithBoundedBackoff(t *testing.T) {
	var r coreRecovery
	now := time.Unix(1000, 0)
	absent := &coreipc.CallError{Stage: "connect", Code: "CORE_IPC_PIPE_ABSENT", Win32: 2}
	if r.Decide(now, absent, time.Second, 1) != coreRecoveryNone {
		t.Fatal("one failed poll is not an outage")
	}
	if r.Decide(now, absent, 2*time.Second, 2) != coreRecoveryStart {
		t.Fatal("a missing core was not started")
	}
	if r.Decide(now, absent, 2*time.Second, 3) != coreRecoveryNone {
		t.Fatal("two attempts at once")
	}
	r.Finish(now)
	want := []time.Duration{2 * time.Second, 4 * time.Second, 8 * time.Second, 16 * time.Second, 30 * time.Second, 30 * time.Second}
	for i, d := range want {
		if i > 0 {
			if r.Decide(now, absent, time.Minute, 9) != coreRecoveryStart {
				t.Fatal("attempt not allowed after backoff", i)
			}
			r.Finish(now)
		}
		if r.Decide(now.Add(d-time.Millisecond), absent, time.Minute, 9) != coreRecoveryNone {
			t.Fatal("backoff ignored", i, d)
		}
		now = now.Add(d)
	}
	r.Healthy()
	if r.Decide(now, absent, time.Second, 2) != coreRecoveryStart {
		t.Fatal("recovery did not reset after a healthy call")
	}
}

func TestCoreRecoveryNeverFightsAnIntentionalStop(t *testing.T) {
	var r coreRecovery
	absent := &coreipc.CallError{Stage: "connect", Code: "CORE_IPC_PIPE_ABSENT", Win32: 2}
	r.Suppress()
	if r.Decide(time.Now(), absent, time.Hour, 100) != coreRecoveryNone {
		t.Fatal("restarted a core the program just exited")
	}
}

func TestCoreRecoveryDistinguishesHungFromRefusing(t *testing.T) {
	var r coreRecovery
	now := time.Now()
	timeout := &coreipc.CallError{Stage: "read", Code: "CORE_IPC_READ_TIMEOUT", Err: context.DeadlineExceeded}
	if r.Decide(now, timeout, 30*time.Second, 30) != coreRecoveryNone {
		t.Fatal("a slow core was bounced too early")
	}
	if r.Decide(now, timeout, 91*time.Second, 91) != coreRecoveryRestart {
		t.Fatal("a core silent for 90s was not restarted")
	}
	r.Finish(now)
	r.Healthy()
	for _, err := range []error{errors.New("CORE_INITIALIZING"), errors.New("CORE_EXIT_IN_PROGRESS"), errors.New("CORE_REQUEST_REJECTED")} {
		if r.Decide(now, err, time.Hour, 1000) != coreRecoveryNone {
			t.Fatal("restarted a core that answered:", err)
		}
	}
	broken := &coreipc.CallError{Stage: "read", Code: "CORE_IPC_READ_FAILED", Win32: uint32(syscall.Errno(109))}
	down, unresponsive := coreLinkKind(broken)
	if down || !unresponsive {
		t.Fatal("a dropped request is unresponsiveness, not absence")
	}
}
