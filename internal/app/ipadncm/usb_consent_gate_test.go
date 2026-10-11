package ipadncm

import (
	"context"
	"sync/atomic"
	"testing"
	"time"
)

func TestRememberedUSBConsentBypassesPendingOtherDevice(t *testing.T) {
	g := newUSBConsentGate()
	entered, release, done := make(chan struct{}), make(chan struct{}), make(chan bool, 1)
	go func() {
		done <- g.run(context.Background(), func() (bool, bool) { return false, false }, func() bool {
			close(entered)
			<-release
			return false
		})
	}()
	<-entered
	defer func() { close(release); <-done }()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if !g.run(ctx, func() (bool, bool) { return true, true }, func() bool { t.Error("remembered device prompted"); return false }) {
		t.Fatal("remembered device blocked behind unanswered other-device prompt")
	}
	if g.run(ctx, func() (bool, bool) { return false, true }, func() bool { t.Error("changed identity prompted"); return true }) {
		t.Fatal("failed fresh cached identity admitted")
	}
}

func TestUSBConsentRechecksSavedConsentAfterInteractiveWait(t *testing.T) {
	g := newUSBConsentGate()
	g.slot <- struct{}{}
	var checks atomic.Int32
	checked, done := make(chan struct{}), make(chan bool, 1)
	go func() {
		done <- g.run(context.Background(), func() (bool, bool) {
			if checks.Add(1) == 1 {
				close(checked)
				return false, false
			}
			return true, true
		}, func() bool { t.Error("newly saved consent prompted twice"); return false })
	}()
	<-checked
	<-g.slot
	if !<-done || checks.Load() != 2 {
		t.Fatal("consent was not rechecked after waiting")
	}
}

func TestUSBConsentWaitCancellationAndNoImplicitApproval(t *testing.T) {
	g := newUSBConsentGate()
	g.slot <- struct{}{}
	ctx, cancel := context.WithCancel(context.Background())
	checked, done := make(chan struct{}), make(chan bool, 1)
	go func() {
		done <- g.run(ctx, func() (bool, bool) { close(checked); return false, false }, func() bool { t.Error("cancelled wait prompted"); return true })
	}()
	<-checked
	cancel()
	if <-done {
		t.Fatal("cancelled wait admitted")
	}
	<-g.slot
	var asked bool
	if g.run(context.Background(), func() (bool, bool) { return false, false }, func() bool { asked = true; return false }) || !asked {
		t.Fatal("unknown device must ask and preserve refusal")
	}
	ctx2, cancel2 := context.WithCancel(context.Background())
	if g.run(ctx2, func() (bool, bool) { cancel2(); return true, true }, func() bool { return true }) {
		t.Fatal("cancellation during fresh consent check admitted")
	}
}
