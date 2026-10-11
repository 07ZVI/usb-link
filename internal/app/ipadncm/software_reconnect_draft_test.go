package ipadncm

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

func draftTarget() softwareReconnectTarget {
	return softwareReconnectTarget{RootID: `USB\VID_05AC&PID_12AB\ABC123456789`, HardwarePrefix: `USB\VID_05AC&PID_12AB`, Class: softwareReconnectRootClass, Service: "usbccgp", Status: 0x0180600a, AuthorizedFixedAction: true, CurrentLauncherIdentity: true, ExactPhysicalRoot: true, StateAndPropertiesReadable: true, CleanupVerified: true}
}

type draftBackend struct {
	target           softwareReconnectTarget
	calls            []string
	fail             string
	flags            uint32
	pause            time.Duration
	recoveryCanceled bool
	cancelAtWait     context.CancelFunc
}

func (b *draftBackend) call(step string) error {
	b.calls = append(b.calls, step)
	if b.fail == step {
		return errors.New(step + " failed")
	}
	return nil
}
func (b *draftBackend) CurrentIdentifiedTarget(context.Context) (softwareReconnectTarget, error) {
	return b.target, b.call("identify")
}
func (b *draftBackend) SaveProtectedReceipt(softwareReconnectReceipt) error { return b.call("save") }
func (b *draftBackend) QuietDisableAndVerify(_ context.Context, _ softwareReconnectReceipt, flags uint32) error {
	b.flags = flags
	return b.call("disable")
}
func (b *draftBackend) Wait(ctx context.Context, pause time.Duration) error {
	b.pause = pause
	if b.cancelAtWait != nil {
		b.cancelAtWait()
	}
	if ctx.Err() != nil {
		b.calls = append(b.calls, "cancel")
		return ctx.Err()
	}
	return b.call("wait")
}
func (b *draftBackend) EnableAndVerifyOriginal(ctx context.Context, _ softwareReconnectReceipt) error {
	b.recoveryCanceled = ctx.Err() != nil
	return b.call("restore")
}
func (b *draftBackend) RemoveVerifiedReceipt(softwareReconnectReceipt) error { return b.call("remove") }
func TestDraftCannotTargetControllersHubMacOrPreviouslyDisabledDevices(t *testing.T) {
	base := draftTarget()
	if !base.eligible() {
		t.Fatal("fully proven root rejected")
	}
	cases := []func(*softwareReconnectTarget){
		func(t *softwareReconnectTarget) { t.HardwarePrefix = `USB\ROOT_HUB30` },
		func(t *softwareReconnectTarget) { t.RootID = `PCI\VEN_8086&DEV_1234\CONTROLLER` },
		func(t *softwareReconnectTarget) {
			t.HardwarePrefix = `USB\VID_05AC&PID_1903`
			t.RootID = `USB\VID_05AC&PID_1903\ABC123456789`
		},
		func(t *softwareReconnectTarget) { t.HardwarePrefix += `&MI_02` },
		func(t *softwareReconnectTarget) { t.Service = "USBHUB3" },
		func(t *softwareReconnectTarget) { t.Service = "UsbNcm" },
		func(t *softwareReconnectTarget) { t.Class = portableWPDClass },
		func(t *softwareReconnectTarget) { t.Problem = 22 },
		func(t *softwareReconnectTarget) { t.ConfigFlags = 1 },
		func(t *softwareReconnectTarget) { t.Status &^= 0x2000 },
		func(t *softwareReconnectTarget) { t.Status |= 0x100 },
		func(t *softwareReconnectTarget) { t.Status |= 0x400 },
		func(t *softwareReconnectTarget) { t.Status |= 0x40000 },
		func(t *softwareReconnectTarget) { t.AuthorizedFixedAction = false },
		func(t *softwareReconnectTarget) { t.CurrentLauncherIdentity = false },
		func(t *softwareReconnectTarget) { t.ExactPhysicalRoot = false },
		func(t *softwareReconnectTarget) { t.CleanupVerified = false },
		func(t *softwareReconnectTarget) { t.RecoveryPending = true },
	}
	for i, change := range cases {
		target := base
		change(&target)
		b := &draftBackend{target: target}
		out, err := runSoftwareReconnectDraft(context.Background(), b)
		if err == nil || out.SoftwareAttempt || strings.Join(b.calls, ",") != "identify" {
			t.Fatal("unsafe target reached receipt/change", i, out, err, b.calls)
		}
	}
}
func TestDraftWritesReceiptBeforeDisableAndRestoresBeforeRemovingReceipt(t *testing.T) {
	b := &draftBackend{target: draftTarget()}
	out, err := runSoftwareReconnectDraft(context.Background(), b)
	if err != nil || !out.DisabledVerified || !out.RestoredVerified || out.RecoveryPending || strings.Join(b.calls, ",") != "identify,save,disable,wait,restore,remove" {
		t.Fatal(out, err, b.calls)
	}
	if b.flags != 4 || b.flags&(8|2|1) != 0 || b.pause != 5*time.Second {
		t.Fatal("wrong SDK flags or bounded pause", b.flags, b.pause)
	}
}
func TestDraftEveryPartialFailureRetainsOrStrictlyRecoversObligation(t *testing.T) {
	for _, fail := range []string{"save", "disable", "wait", "restore", "remove"} {
		t.Run(fail, func(t *testing.T) {
			b := &draftBackend{target: draftTarget(), fail: fail}
			out, err := runSoftwareReconnectDraft(context.Background(), b)
			if err == nil {
				t.Fatal("failure not reported")
			}
			calls := strings.Join(b.calls, ",")
			if fail == "save" {
				if out.SoftwareAttempt || strings.Contains(calls, "disable") || strings.Contains(calls, "restore") {
					t.Fatal("mutation after failed journal", calls)
				}
				return
			}
			if !strings.Contains(calls, "restore") {
				t.Fatal("partial mutation lacked recovery", calls)
			}
			if fail == "restore" {
				if !out.RecoveryPending || strings.Contains(calls, "remove") {
					t.Fatal("unverified recovery removed receipt", out, calls)
				}
			}
			if fail == "remove" && !out.RecoveryPending {
				t.Fatal("uncommitted recovery accepted", out)
			}
		})
	}
}
func TestDraftCanceledJobStillUsesIndependentRecoveryContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	b := &draftBackend{target: draftTarget(), cancelAtWait: cancel}
	out, err := runSoftwareReconnectDraft(ctx, b)
	if !errors.Is(err, context.Canceled) || !out.RestoredVerified || b.recoveryCanceled || !strings.Contains(strings.Join(b.calls, ","), "restore,remove") {
		t.Fatal(out, err, b.calls)
	}
}

func TestDraftCanceledBeforeAdmissionNeverTouchesADevice(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	b := &draftBackend{target: draftTarget()}
	out, err := runSoftwareReconnectDraft(ctx, b)
	if !errors.Is(err, context.Canceled) || len(b.calls) != 0 || out.SoftwareAttempt {
		t.Fatal("canceled queued action reached a device", out, err, b.calls)
	}
}
