package ipadncm

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"suhang/usbnet/internal/transport/ipadsession"
)

// A pure, unbound draft. No Windows adapter, RPC or automatic trigger uses it.
// Microsoft cfgmgr32.h: quiet=0x04; no PERSIST(0x08), HARDWARE(0x02),
// ABSOLUTE(0x01). CM_Enable_DevNode's reserved flags must be zero.
const softwareReconnectQuietFlags = uint32(0x04)
const softwareReconnectPause = 5 * time.Second
const softwareReconnectRootClass = "{88bae032-5a81-49f0-bc3d-a4ff138216d6}" // USBDevice; Apple root is not class USB

type softwareReconnectTarget struct {
	RootID, HardwarePrefix, Class, Service                            string
	Status, Problem, ConfigFlags                                      uint32
	AuthorizedFixedAction, CurrentLauncherIdentity, ExactPhysicalRoot bool
	StateAndPropertiesReadable, CleanupVerified, RecoveryPending      bool
}

func (t softwareReconnectTarget) eligible() bool {
	return t.AuthorizedFixedAction && t.CurrentLauncherIdentity && t.ExactPhysicalRoot && t.StateAndPropertiesReadable && t.CleanupVerified && !t.RecoveryPending &&
		ipadsession.USBGrant(t.RootID, "12AB", "software-reconnect").Valid() && strings.EqualFold(t.HardwarePrefix, `USB\VID_05AC&PID_12AB`) && strings.EqualFold(t.Class, softwareReconnectRootClass) && strings.EqualFold(t.Service, "usbccgp") &&
		t.Problem == 0 && t.Status&8 != 0 && t.Status&0x2000 != 0 && t.Status&(0x100|0x400|0x40000) == 0 && t.ConfigFlags&1 == 0
}

type softwareReconnectReceipt struct{ Target softwareReconnectTarget }

// The future Windows adapter must validate each current instance, class,
// service, USB root/hub/port and owned original property values immediately
// before CM changes. Its durable store must be the existing protected recovery
// directory, with strict bounded decode, ownership and no-reparse checks.
type softwareReconnectDraftBackend interface {
	CurrentIdentifiedTarget(context.Context) (softwareReconnectTarget, error)
	SaveProtectedReceipt(softwareReconnectReceipt) error
	QuietDisableAndVerify(context.Context, softwareReconnectReceipt, uint32) error
	Wait(context.Context, time.Duration) error
	EnableAndVerifyOriginal(context.Context, softwareReconnectReceipt) error
	RemoveVerifiedReceipt(softwareReconnectReceipt) error
}

type softwareReconnectDraftResult struct {
	DisabledVerified bool
	RestoredVerified bool
	RecoveryPending  bool
	// Never feeds physical replug counts or an AMDS physical-proof controller.
	SoftwareAttempt bool
}

func recoverSoftwareReconnectDraft(b softwareReconnectDraftBackend, r softwareReconnectReceipt) error {
	// Cancel/exit cannot cancel restoration. A deadline prevents an indefinite
	// claim of busy recovery; failure retains the receipt and blocks connection.
	recoveryCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := b.EnableAndVerifyOriginal(recoveryCtx, r); err != nil {
		return err
	}
	return b.RemoveVerifiedReceipt(r)
}

func runSoftwareReconnectDraft(ctx context.Context, b softwareReconnectDraftBackend) (out softwareReconnectDraftResult, err error) {
	if err := ctx.Err(); err != nil {
		return out, err
	}
	target, err := b.CurrentIdentifiedTarget(ctx)
	if err != nil {
		return out, err
	}
	if !target.eligible() {
		return out, fmt.Errorf("exact enabled iPad root or controlled-action admission unproven")
	}
	if err := ctx.Err(); err != nil {
		return out, err
	}
	receipt := softwareReconnectReceipt{Target: target}
	if err := b.SaveProtectedReceipt(receipt); err != nil {
		return out, err
	}
	// Recovery is installed before the first CM call. A non-success result may
	// still have changed device state, so partial disable always needs readback.
	defer func() {
		recoveryErr := recoverSoftwareReconnectDraft(b, receipt)
		if recoveryErr != nil {
			out.RecoveryPending = true
			err = errors.Join(err, fmt.Errorf("software reconnect recovery pending: %w", recoveryErr))
			return
		}
		out.RestoredVerified = true
	}()
	if err := ctx.Err(); err != nil {
		return out, err
	}
	out.SoftwareAttempt = true
	if err := b.QuietDisableAndVerify(ctx, receipt, softwareReconnectQuietFlags); err != nil {
		return out, err
	}
	out.DisabledVerified = true
	if err := b.Wait(ctx, softwareReconnectPause); err != nil {
		return out, err
	}
	// Finally performs enable+exact original readback. This result proves only
	// CM restoration; main must separately revalidate NCM, policy, DHCP and peer.
	return out, nil
}
