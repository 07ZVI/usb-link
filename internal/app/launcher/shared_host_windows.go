//go:build windows && amd64

package launcher

import (
	"context"
	"fmt"
	"log"
	"os"
	"suhang/usbnet/internal/app/connectioninstall"
	"suhang/usbnet/internal/platform/windows/interfaceconfig"
	"suhang/usbnet/internal/app/macconnection"
	"suhang/usbnet/internal/platform/windows/netconfig"
	"suhang/usbnet/internal/transport/usbaddress"
	"suhang/usbnet/internal/security/usbgateway"
	"suhang/usbnet/internal/app/usbhost"
	"time"
)

// Diagnostic only: this never represents a prepared interface or USB readiness.
type earlyHostRecoveryReport struct {
	ObservationOnly bool   `json:"observation_only"`
	Attempted       bool   `json:"attempted"`
	Settled         bool   `json:"settled"`
	DurationMS      int64  `json:"duration_ms"`
	Problem         string `json:"problem,omitempty"`
}

// Call before legacy script work, while the verified core owns its recovery
// store and before any device worker starts. Keep the normal topology -> host
// operation lock order, and release topology here rather than at main exit.
func recoverInterruptedHostEarly(ctx context.Context, dir string) (report earlyHostRecoveryReport) {
	report.ObservationOnly = true
	started := time.Now()
	defer func() { report.DurationMS = time.Since(started).Milliseconds() }()
	lockContext, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	release, err := usbaddress.ConfigurationLock(lockContext)
	if err != nil {
		report.Problem = err.Error()
		return
	}
	defer release()
	if err = ctx.Err(); err != nil {
		report.Problem = err.Error()
		return
	}
	report.Attempted, err = usbhost.RecoverInterruptedRecreate(dir)
	report.Settled = report.Attempted && err == nil
	if err != nil {
		report.Problem = err.Error()
		log.Printf("USB host early interrupted recreation: %s", err)
	}
	return
}

// One supervisor is the exclusive host resource owner. Failed preparation
// returns its cleanup obligation, so another attempt cannot overlap it.
func prepareSupervisedHost(ctx context.Context, dir string, payload macconnection.RuntimeArchive, manifest []byte) (out usbhost.PreparedHost, problem error) {
	releaseTopology, e := usbaddress.ConfigurationLock(ctx)
	if e != nil {
		return out, e
	}
	defer releaseTopology()
	dll, e := macconnection.PrepareSharedHostDLLArchive(dir, payload, manifest)
	if e != nil {
		return out, e
	}
	hostClose, e := usbhost.Start(ctx, dir, dll)
	usbhost.SetProblem(e)
	if e != nil {
		return out, e
	}
	var gateClose func() error
	out.Cleanup = func() error {
		cleanupCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		release, e := usbaddress.ConfigurationLock(cleanupCtx)
		if e != nil {
			return e
		}
		defer release()
		if gateClose != nil {
			if e := gateClose(); e != nil {
				return e
			}
			gateClose = nil
		}
		usbgateway.SetSharedHostLUID(0)
		if e := hostClose(); e != nil {
			return usbhost.Recover(dir)
		}
		return nil
	}
	proof, ready := usbhost.PreparedProof()
	if !ready {
		return out, fmt.Errorf("USB_HOST_PREPARED_PROOF_UNAVAILABLE")
	}
	securityDir, e := connectioninstall.SecurityDirectory()
	if e != nil {
		return out, e
	}
	exe, e := os.Executable()
	if e != nil {
		return out, e
	}
	if e = connectioninstall.Verify(exe); e != nil {
		return out, e
	}
	logger := log.New(os.Stderr, "USB host: ", 0)
	if netconfig.ResidentFirewallEnabled() {
		pin, pinErr := connectioninstall.PinCoreSourceBatchSelf()
		if pinErr != nil {
			return out, &netconfig.HostPreparationFailure{Code: "USB_HOST_SOURCE_PIN_FAILED", Cause: pinErr}
		}
		defer pin.Close()
		owner := func() error {
			current, valid := usbhost.PreparedProof()
			if !valid || current != proof {
				return fmt.Errorf("USB_HOST_RESIDENT_OWNER_CHANGED")
			}
			return pin.Refresh()
		}
		var plan *netconfig.PreparedResidentFirewall
		plan, e = netconfig.PrepareResidentHostFirewall(ctx, dir, proof, exe, owner, connectioninstall.VerifyCoreExecutable)
		if e != nil {
			return out, &netconfig.HostPreparationFailure{Code: "USB_HOST_RESIDENT_PREPARE_FAILED", Cause: e}
		}
		if e == nil {
			e = netconfig.CompleteResidentPermissionBatch(ctx, "", []netconfig.ResidentPermissionPlan{plan}, func(c context.Context, script string) error {
				return netconfig.RunContext(c, script, logger)
			})
			if e != nil {
				return out, &netconfig.HostPreparationFailure{Code: "USB_HOST_RESIDENT_BATCH_FAILED", Cause: e}
			}
			if e == nil {
				e = pin.Complete()
				if e != nil {
					return out, &netconfig.HostPreparationFailure{Code: "USB_HOST_SOURCE_COMPLETE_FAILED", Cause: e}
				}
			}
		}
	} else if netconfig.NativeNetworkEnabled() {
		e = netconfig.EnsureSharedHostServicesNative(ctx, proof, exe, logger)
	} else {
		var rule string
		rule, e = netconfig.SharedHostServicesRule(exe)
		if e == nil {
			e = netconfig.RunLegacyRoleContext(ctx, "shared_host", rule, logger)
		}
	}
	if e != nil {
		return out, e
	}
	if ctx.Err() != nil {
		return out, ctx.Err()
	}
	usbgateway.SetSharedHostLUID(proof.LUID)
	gate, e := usbgateway.New(securityDir)
	if e != nil {
		return out, e
	}
	gateClose, e = gate.Attach(proof.LUID, exe)
	if e != nil {
		return out, e
	}
	out.Healthy = func() bool {
		current, valid := usbhost.PreparedProof()
		return valid && current == proof && gate.VerifiedSharedHostAttachment(proof.LUID)
	}
	if !out.Healthy() {
		return out, fmt.Errorf("USB_HOST_COMPLETE_PREPARATION_UNCONFIRMED")
	}
	usbhost.SetProblem(nil)
	return out, nil
}

func ownedDADDiagnostics(dir string) any {
	rows, e := interfaceconfig.ReadOwnedDADObservations(dir)
	if e != nil {
		return map[string]any{"observation_only": true, "code": "OWNED_DAD_LEDGER_UNREADABLE"}
	}
	return rows
}
