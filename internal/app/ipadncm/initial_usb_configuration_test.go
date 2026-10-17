package ipadncm

import (
	"context"
	"testing"
	"time"
)

func TestInitialConfigurationWaitOnlyVerifiesOnceAfterCachedReady(t *testing.T) {
	ctx := context.Background()
	notices := make(chan struct{}, 1)
	reads, proofs := 0, 0
	got := awaitInitialUSBConfiguration(ctx, notices, time.Second, time.Hour, func(context.Context) string {
		reads++
		if reads < 3 {
			notices <- struct{}{}
			return "INITIAL_CONFIGURATION_ZERO"
		}
		return "INITIAL_CONFIGURATION_CACHE_READY"
	}, func() bool { proofs++; return true })
	if got != "INITIAL_CONFIGURATION_VERIFIED_NOT_AUTHORIZED" || reads != 3 || proofs != 1 {
		t.Fatalf("%s reads=%d proofs=%d", got, reads, proofs)
	}
}

func TestInitialConfigurationWaitStopsWithoutRetryingFailures(t *testing.T) {
	for _, fail := range []string{"INITIAL_CONFIGURATION_TARGET_CHANGED_OR_UNREADABLE", "INITIAL_CONFIGURATION_UNSUPPORTED"} {
		t.Run(fail, func(t *testing.T) {
			reads, proofs := 0, 0
			got := awaitInitialUSBConfiguration(context.Background(), nil, time.Second, time.Millisecond, func(context.Context) string { reads++; return fail }, func() bool { proofs++; return true })
			if got != fail || reads != 1 || proofs != 0 {
				t.Fatalf("%s %d %d", got, reads, proofs)
			}
		})
	}
	proofs := 0
	got := awaitInitialUSBConfiguration(context.Background(), nil, time.Second, time.Millisecond, func(context.Context) string { return "INITIAL_CONFIGURATION_CACHE_READY" }, func() bool { proofs++; return false })
	if got != "INITIAL_CONFIGURATION_FULL_PROOF_FAILED" || proofs != 1 {
		t.Fatalf("failed proof retried: %s %d", got, proofs)
	}
}

func TestInitialConfigurationWaitCancellationTimeoutAndClosedNotification(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	reads, proofs := 0, 0
	got := awaitInitialUSBConfiguration(ctx, nil, time.Second, time.Hour, func(context.Context) string { reads++; cancel(); return "INITIAL_CONFIGURATION_CACHE_READY" }, func() bool { proofs++; return true })
	if got != "INITIAL_CONFIGURATION_CANCELLED" || reads != 1 || proofs != 0 {
		t.Fatalf("%s %d %d", got, reads, proofs)
	}
	closed := make(chan struct{})
	close(closed)
	got = awaitInitialUSBConfiguration(context.Background(), closed, 10*time.Millisecond, time.Millisecond, func(context.Context) string { return "INITIAL_CONFIGURATION_ZERO" }, func() bool { proofs++; return true })
	if got != "INITIAL_CONFIGURATION_TIMEOUT" || proofs != 0 {
		t.Fatal(got, proofs)
	}
	got = awaitInitialUSBConfiguration(context.Background(), nil, time.Millisecond, time.Second, func(ctx context.Context) string { <-ctx.Done(); return "INITIAL_CONFIGURATION_CACHE_READY" }, func() bool { proofs++; return true })
	if got != "INITIAL_CONFIGURATION_TIMEOUT" || proofs != 0 {
		t.Fatal("deadline must not schedule proof", got, proofs)
	}
}

func TestInitialConfigurationPrivateTargetRejectsEveryIdentityChange(t *testing.T) {
	a := initialUSBConfigurationTarget{root: "root", hub: "hub", serial: "serial", product: "product", port: 1, pid: 0x12ab, bcd: 0x1316}
	if !a.same(a) {
		t.Fatal("same target")
	}
	for _, change := range []func(*initialUSBConfigurationTarget){
		func(b *initialUSBConfigurationTarget) { b.root = "other" }, func(b *initialUSBConfigurationTarget) { b.hub = "other" },
		func(b *initialUSBConfigurationTarget) { b.serial = "other" }, func(b *initialUSBConfigurationTarget) { b.product = "other" },
		func(b *initialUSBConfigurationTarget) { b.port++ }, func(b *initialUSBConfigurationTarget) { b.pid++ }, func(b *initialUSBConfigurationTarget) { b.bcd++ },
	} {
		b := a
		change(&b)
		if a.same(b) {
			t.Fatal("changed target accepted")
		}
	}
	if (initialUSBConfigurationTarget{}).same(initialUSBConfigurationTarget{}) {
		t.Fatal("empty target")
	}
}

func TestInitialConfigurationCancellationDuringFullProofStaysCancelled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	got := awaitInitialUSBConfiguration(ctx, nil, time.Second, time.Millisecond, func(context.Context) string {
		return "INITIAL_CONFIGURATION_CACHE_READY"
	}, func() bool { cancel(); return false })
	if got != "INITIAL_CONFIGURATION_CANCELLED" {
		t.Fatal(got)
	}
}
