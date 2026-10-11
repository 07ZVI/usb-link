//go:build windows && amd64

package macconnection

import (
	"context"
	"fmt"
	"golang.org/x/sys/windows"
	"strings"
	"suhang/usbnet/internal/app/connectioninstall"
	"suhang/usbnet/internal/platform/windows/netconfig"
	"suhang/usbnet/internal/transport/bridge"
)

// Called only by the ordinary connection's successful FILES-ready event. This
// job owns its source pin; no HostLease/configuration lock or readiness/cleanup
// wait is retained. COM cancellation is cooperative and never cancels the core.
func observeLegacyMacFirewallShadow(ctx context.Context, dir, root, bridgeExe, parentExe string, epoch uint64, child nativeChildBinding, session sessionRecord) {
	if ctx == nil || ctx.Err() != nil || !netconfig.FirewallShadowEnabled() || !nativeFailureSourceBindingCurrent(epoch, child) {
		return
	}
	proof, err := netconfig.ResolveMacProofNative(ctx, session.GUID)
	if err != nil {
		return
	}
	pin, err := connectioninstall.PinCoreSourceBatchSelf()
	if err != nil {
		return
	}
	defer pin.Close()
	pid, creation, sha, err := pin.BoundSourceObservation()
	if err != nil {
		return
	}
	owner := func() error {
		if ctx.Err() != nil || CurrentRoot() != root || !nativeFailureSourceBindingCurrent(epoch, child) {
			return fmt.Errorf("MAC_FIREWALL_SHADOW_CURRENT_ATTEMPT_CHANGED")
		}
		currentRoot, pairs, e := currentPair()
		if e != nil || currentRoot != root || !strings.EqualFold(pairs[0].Service, "WinUSB") || !strings.EqualFold(pairs[1].Service, "WinUSB") || pairs[0].Problem != 0 || pairs[1].Problem != 0 || len(pairs[0].Paths) == 0 || len(pairs[1].Paths) == 0 {
			return fmt.Errorf("MAC_FIREWALL_SHADOW_USB_PAIR_CHANGED")
		}
		before, valid := captureNativeFailureChild(child.pid, bridgeExe, child.nonce)
		if !valid || before != child || !nativeFailureChildLive(child.pid) {
			return fmt.Errorf("MAC_FIREWALL_SHADOW_CHILD_CHANGED")
		}
		fresh, e := bridge.ReadOrdinaryOwnedSession(dir)
		if e != nil || bridge.VerifyLiveOrdinarySession(session, fresh) != nil {
			return fmt.Errorf("MAC_FIREWALL_SHADOW_SESSION_CHANGED")
		}
		current, e := netconfig.ResolveMacProofNative(ctx, session.GUID)
		if e != nil || current != proof {
			return fmt.Errorf("MAC_FIREWALL_SHADOW_INTERFACE_CHANGED")
		}
		if e = pin.Refresh(); e != nil {
			return e
		}
		after, valid := captureNativeFailureChild(child.pid, bridgeExe, child.nonce)
		if !valid || after != child || !nativeFailureChildLive(child.pid) {
			return fmt.Errorf("MAC_FIREWALL_SHADOW_CHILD_CHANGED")
		}
		return ctx.Err()
	}
	if owner() != nil {
		return
	}
	netconfig.ObserveLegacyFirewallShadow(ctx, netconfig.FirewallShadowScope{
		Role: "mac", Proof: proof, Executable: bridgeExe, MacToken: session.Token,
		PID: child.pid, Creation: child.creation, ConnectionEpoch: epoch, SourceSHA256: expectedBridgeSHA,
	}, owner)
	if owner() != nil {
		return
	}
	netconfig.ObserveLegacyFirewallShadow(ctx, netconfig.FirewallShadowScope{
		Role: "core_mac", Proof: proof, Executable: parentExe,
		PID: pid, Creation: creation, ConnectionEpoch: epoch, SourceSHA256: sha,
	}, owner)
	// Full source checks close the same observation batch; failure is diagnostic
	// only and cannot replace a connection's successful legacy permissions.
	_ = pin.Complete()
}

func nativeFailureChildLive(pid uint32) bool {
	h, err := windows.OpenProcess(windows.SYNCHRONIZE|windows.PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
	if err != nil {
		return false
	}
	defer windows.CloseHandle(h)
	actual, err := windows.GetProcessId(h)
	if err != nil || actual != pid {
		return false
	}
	state, err := windows.WaitForSingleObject(h, 0)
	return err == nil && state == uint32(windows.WAIT_TIMEOUT)
}
