//go:build windows && amd64

package ipadncm

import (
	"context"
	"fmt"
	"io"
	"log"
	"os"
	"suhang/usbnet/internal/app/connectioninstall"
	"suhang/usbnet/internal/transport/ipadsession"
	"suhang/usbnet/internal/platform/windows/netconfig"
	"suhang/usbnet/internal/transport/usbaddress"
)

// Each fragment comes from the native full-scope verifier and its protected
// ledger. Ordinary matching connections execute no firewall script.
func (b *groupingBackend) prepareResidentIPadPermissions(ctx context.Context, p ipadsession.Plan, sharedHost bool, guard func() (NetworkAdapter, string)) error {
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	pin, err := connectioninstall.PinCoreSourceBatchSelf()
	if err != nil {
		return err
	}
	defer pin.Close()
	owner := func() error {
		if _, problem := guard(); problem != "" {
			return fmt.Errorf("%s", problem)
		}
		return pin.Refresh()
	}
	if err := owner(); err != nil {
		return err
	}
	application, err := netconfig.PrepareResidentIPadFirewall(ctx, b.dir, p, owner)
	if err != nil {
		return err
	}
	plans := []netconfig.ResidentPermissionPlan{application}
	if sharedHost {
		proof := usbaddress.InterfaceProof{Index: p.Index, GUID: p.GUID, LUID: p.LUID}
		core, err := netconfig.PrepareResidentCoreFirewall(ctx, b.dir, proof, p.PeerIP(), exe, owner, connectioninstall.VerifyCoreExecutable)
		if err != nil {
			// One bounded read-only diagnosis preserves the original typed error.
			netconfig.ObserveCoreIPadAddressFailureOnce(ctx, proof, exe, err, owner, pin.Complete)
			return err
		}
		plans = append(plans, core)
	}
	// Provider details stay local to the protected ledger. Counters still use
	// the same core-local timer as the previous connection scripts.
	logger := log.New(io.Discard, "", 0)
	if err := netconfig.CompleteResidentPermissionBatch(ctx, "", plans, func(c context.Context, script string) error {
		return netconfig.RunContext(c, script, logger)
	}); err != nil {
		return err
	}
	return pin.Complete()
}
