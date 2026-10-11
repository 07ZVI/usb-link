//go:build windows && amd64

package netconfig

import (
	"bytes"
	"context"
	"golang.org/x/sys/windows"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"suhang/usbnet/internal/transport/usbaddress"
	"suhang/usbnet/internal/platform/windows/wincom"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

var ipadAddressObserved atomic.Bool
var ipadAddressState struct {
	sync.Mutex
	value *IPadAddressProjectionReport
}

func IPadAddressProjectionSnapshot() *IPadAddressProjectionReport {
	ipadAddressState.Lock()
	defer ipadAddressState.Unlock()
	if ipadAddressState.value == nil {
		return nil
	}
	v := *ipadAddressState.value
	v.Rows = append([]IPadAddressProjectionRow{}, v.Rows...)
	return &v
}

// ObserveCoreIPadAddressFailureOnce runs only after the original typed error
// has been recorded. No success here changes that error or any network state.
// One process-local attempt; no timer, remote selector, receipt or retry loop.
// Public subprocess has a 12s deadline. Synchronous COM checks cannot be
// preempted; expired or changed owner observations are discarded, not trusted.
func ObserveCoreIPadAddressFailureOnce(parent context.Context, p usbaddress.InterfaceProof, exe string, cause error, owner, complete func() error) {
	detail := ResidentFirewallErrorDetails(cause)
	if detail.Code != "USB_NATIVE_FIREWALL_CONSTRAINT_NULL" || detail.Field != "MSFT_NetAddressFilter/LocalAddress" || parent == nil || owner == nil || complete == nil {
		return
	}
	self, e := os.Executable()
	if e != nil || !validCoreExecutable(exe) || !strings.EqualFold(filepath.Clean(exe), filepath.Clean(self)) || p.Index == 0 || p.LUID == 0 || strings.EqualFold(p.GUID, NativeMacGUID) || strings.EqualFold(p.GUID, usbaddress.HostGUID) {
		return
	}
	if ipadAddressObserved.Load() {
		return
	}
	if owner() != nil || complete() != nil {
		return
	}
	if !ipadAddressObserved.CompareAndSwap(false, true) {
		return
	}
	started := time.Now()
	ctx, cancel := context.WithTimeout(parent, 12*time.Second)
	defer cancel()
	verify := residentVerifier(p, owner)
	if verify(ctx) != nil {
		return
	}
	alias, e := nativeRuleInterface(ctx, p)
	if e != nil {
		return
	}
	specs, e := residentSpecs("core_ipad", p.GUID, alias, exe)
	if e != nil {
		return
	}
	report := ipadAddressReport()
	if public, e := ipadAddressPublicRead(ctx, specs); e == nil {
		report = *public
	}
	if verify(ctx) != nil {
		return
	}
	_ = withFirewall(ctx, func(svc *wincom.Dispatch) error {
		for i, s := range specs {
			if e := verify(ctx); e != nil {
				return e
			}
			row := ipadAddressUnread()
			rule, e := matchingRule(svc, s.Name)
			if e != nil {
				report.Rows[i].Native = row
				continue
			}
			if rule == nil {
				row.Status = "rule_absent"
				report.Rows[i].Native = row
				continue
			}
			row.RuleCount = 1
			row.MarkersMatch = ipadAddressNativeString(rule, "RuleGroup", s.Group, false) && ipadAddressNativeString(rule, "Description", s.Description, false)
			app, ae := cimRelated(rule, "MSFT_NetApplicationFilter")
			if ae == nil {
				row.ProgramMatch = ipadAddressNativeString(app, "AppPath", s.Program, true)
				app.Close()
			}
			nic, ne := cimRelated(rule, "MSFT_NetInterfaceFilter")
			if ne == nil {
				value, ve := cimProperty(nic, "InterfaceAlias")
				if ve == nil {
					row.InterfaceMatch = ipadAddressNativeValue(value, s.Alias).ExpectedExact
				}
				value.Clear()
				nic.Close()
			}
			filter, fe := cimRelated(rule, "MSFT_NetAddressFilter")
			rule.Close()
			if fe != nil {
				row.Status = "filter_not_unique"
				report.Rows[i].Native = row
				continue
			}
			row.FilterCount = 1
			row.Status = "observed"
			lv, le := cimProperty(filter, "LocalAddress")
			if le == nil {
				row.Local = ipadAddressNativeValue(lv, s.Local)
			} else {
				row.Local.Kind = "missing"
			}
			lv.Clear()
			rv, re := cimProperty(filter, "RemoteAddress")
			if re == nil {
				row.Remote = ipadAddressNativeValue(rv, s.Remote)
			} else {
				row.Remote.Kind = "missing"
			}
			rv.Clear()
			filter.Close()
			report.Rows[i].Native = row
		}
		return verify(ctx)
	})
	if verify(ctx) != nil || complete() != nil || ctx.Err() != nil {
		return
	}
	report.DurationMS = uint32(time.Since(started).Milliseconds())
	report.Status = "observed"
	for _, r := range report.Rows {
		if r.Public.Status != "observed" || r.Native.Status != "observed" {
			report.Status = "partly_unavailable"
		}
	}
	if !IPadAddressProjectionValid(&report) {
		return
	}
	ipadAddressState.Lock()
	ipadAddressState.value = &report
	ipadAddressState.Unlock()
}
func ipadAddressNativeString(d *wincom.Dispatch, key, want string, fold bool) bool {
	got, e := cimString(d, key)
	return e == nil && ((fold && strings.EqualFold(got, want)) || (!fold && got == want))
}
func ipadAddressNativeValue(v wincom.Value, expected string) IPadAddressShape {
	if v.IsNull() {
		return IPadAddressShape{Kind: "null"}
	}
	if v.IsEmpty() {
		return IPadAddressShape{Kind: "empty"}
	}
	if values, e := v.Strings(64); e == nil {
		return ipadAddressShape(values, "array", expected)
	}
	if value, e := v.String(); e == nil {
		return ipadAddressShape([]string{value}, "string", expected)
	}
	return IPadAddressShape{Kind: "other"}
}

type ipadAddressBoundedOutput struct {
	bytes.Buffer
	overflow bool
}

func (w *ipadAddressBoundedOutput) Write(p []byte) (int, error) {
	n := len(p)
	room := 8192 + len(IPadAddressProjectionPrefix) + 2 - w.Len()
	if room < n {
		w.overflow = true
		if room > 0 {
			w.Buffer.Write(p[:room])
		}
	} else {
		w.Buffer.Write(p)
	}
	return n, nil
}
func ipadAddressPublicRead(ctx context.Context, specs []nativeRuleSpec) (out *IPadAddressProjectionReport, err error) {
	// The same real subprocess attempt appears in the existing aggregate and
	// this fixed diagnostic category; these durations are not additive.
	legacy := beginNetworkTiming("legacy_network_script")
	diagnostic := beginNetworkTiming("ipad_address_diagnostic_script")
	defer func() { legacy(err); diagnostic(err) }()
	dir, e := windows.GetWindowsDirectory()
	if e != nil {
		return nil, e
	}
	cmd := exec.CommandContext(ctx, filepath.Join(dir, "System32", "WindowsPowerShell", "v1.0", "powershell.exe"), "-NoProfile", "-NonInteractive", "-Command", ipadAddressPublicScript(specs))
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true, CreationFlags: 0x08000000}
	var output ipadAddressBoundedOutput
	cmd.Stdout = &output
	cmd.Stderr = &output
	if e = cmd.Run(); e != nil {
		return nil, e
	}
	if output.overflow {
		return nil, syscall.EINVAL
	}
	line := bytes.TrimSpace(output.Bytes())
	if !bytes.HasPrefix(line, []byte(IPadAddressProjectionPrefix)) {
		return nil, syscall.EINVAL
	}
	return DecodeIPadAddressProjection(line[len(IPadAddressProjectionPrefix):])
}
