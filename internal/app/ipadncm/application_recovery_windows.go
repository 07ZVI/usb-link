//go:build windows && amd64

package ipadncm

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"golang.org/x/sys/windows"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"suhang/usbnet/internal/diagnostics/grouptrial"
	"suhang/usbnet/internal/platform/windows/netconfig"
	"suhang/usbnet/internal/transport/ipadsession"
	"syscall"
	"time"
	"unsafe"
)

type applicationJournal struct {
	Root   string           `json:"local_root_id"`
	Driver string           `json:"local_driver_key"`
	Plan   ipadsession.Plan `json:"plan"`
	// Resident rules are owned by their separate protected ledger. Session
	// cleanup never removes them, including when the next release disables reuse.
	ResidentFirewall bool `json:"resident_firewall,omitempty"`
}

func (j applicationJournal) valid() bool {
	return grouptrial.ValidRecoveryTarget(j.Root, j.Driver, 1, true) && j.Plan.Valid()
}
func appJournalPath(dir string) string { return filepath.Join(dir, "application-session.json") }
func runApplicationPermissionScript(system, script string) (output, problem string) {
	return runApplicationPermissionContext(context.Background(), system, script)
}
func runApplicationPermissionContext(ctx context.Context, system, script string) (output, problem string) {
	finish := netconfig.BeginLegacyRoleScriptTiming("ipad_permissions")
	defer func() {
		var err error
		if problem != "" {
			err = fmt.Errorf("%s", problem)
		}
		finish(err)
	}()
	return runApplicationScriptContext(ctx, system, script)
}
func runApplicationScript(system, script string) (string, string) {
	return runApplicationScriptContext(context.Background(), system, script)
}
func runApplicationScriptContext(parent context.Context, system, script string) (string, string) {
	ctx, cancel := context.WithTimeout(parent, 25*time.Second)
	defer cancel()
	c := exec.CommandContext(ctx, filepath.Join(system, "WindowsPowerShell", "v1.0", "powershell.exe"), "-NoProfile", "-NonInteractive", "-Command", script)
	c.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	// Only short, predefined status/subnet output is retained. Never export stderr.
	b, e := c.Output()
	if ctx.Err() != nil {
		return "", "APPLICATION_SYSTEM_TOOL_TIMEOUT"
	}
	if e != nil {
		return "", "APPLICATION_SYSTEM_TOOL_FAILED"
	}
	if len(b) > 2048 {
		return "", "APPLICATION_SYSTEM_TOOL_OUTPUT_LIMIT"
	}
	output, readbackError := netconfig.CompleteCorePermissionReadback(script, strings.TrimSpace(string(b)), func(clean string) bool {
		return clean == "USB_CORE_PERMISSION_READY" || applicationPermissionBatchReady(clean)
	})
	if readbackError != nil {
		return "", "APPLICATION_CORE_READBACK_FAILED"
	}
	return output, ""
}
func saveApplicationJournal(dir string, j applicationJournal, replace bool) string {
	if !j.valid() {
		return "APPLICATION_RECOVERY_PLAN_INVALID"
	}
	data, e := json.Marshal(j)
	if e != nil {
		return "APPLICATION_RECOVERY_ENCODING_FAILED"
	}
	path := appJournalPath(dir)
	if replace {
		path += ".new-" + j.Plan.Token
	}
	f, e := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if e != nil {
		return "APPLICATION_RECOVERY_CREATE_FAILED"
	}
	_, e = f.Write(data)
	if e == nil {
		e = f.Sync()
	}
	ce := f.Close()
	if e != nil || ce != nil {
		os.Remove(path)
		return "APPLICATION_RECOVERY_WRITE_FAILED"
	}
	if replace {
		from, _ := windows.UTF16PtrFromString(path)
		to, _ := windows.UTF16PtrFromString(appJournalPath(dir))
		if e = windows.MoveFileEx(from, to, windows.MOVEFILE_REPLACE_EXISTING|windows.MOVEFILE_WRITE_THROUGH); e != nil {
			os.Remove(path)
			return "APPLICATION_RECOVERY_COMMIT_FAILED"
		}
	}
	return ""
}
func readApplicationJournal(dir string) (applicationJournal, bool, string) {
	var j applicationJournal
	f, e := os.Open(appJournalPath(dir))
	if os.IsNotExist(e) {
		return j, false, ""
	}
	if e != nil {
		return j, true, "APPLICATION_RECOVERY_OPEN_FAILED"
	}
	b, e := io.ReadAll(io.LimitReader(f, 4097))
	ce := f.Close()
	if e != nil || ce != nil || len(b) > 4096 {
		return j, true, "APPLICATION_RECOVERY_READ_FAILED"
	}
	d := json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	if d.Decode(&j) != nil || !j.valid() {
		return j, true, "APPLICATION_RECOVERY_INVALID"
	}
	var tail any
	if d.Decode(&tail) != io.EOF {
		return j, true, "APPLICATION_RECOVERY_INVALID"
	}
	return j, true, ""
}
func addressRow(p ipadsession.Plan) windows.MibUnicastIpAddressRow {
	var r windows.MibUnicastIpAddressRow
	init := windows.NewLazySystemDLL("iphlpapi.dll").NewProc("InitializeUnicastIpAddressEntry")
	init.Call(uintptr(unsafe.Pointer(&r)))
	r.InterfaceLuid = p.LUID
	r.InterfaceIndex = p.Index
	v := (*windows.RawSockaddrInet4)(unsafe.Pointer(&r.Address))
	v.Family = windows.AF_INET
	copy(v.Addr[:], parseV4(p.LocalAddress()))
	r.PrefixOrigin = 1
	r.SuffixOrigin = 1
	r.OnLinkPrefixLength = p.AddressPrefix()
	r.ValidLifetime = p.AddressLifetime()
	r.PreferredLifetime = p.AddressLifetime()
	r.SkipAsSource = 0
	if p.Version == 5 || p.Version == 6 {
		r.SkipAsSource = 1
	}
	return r
}
func addressStamp(r windows.MibUnicastIpAddressRow) int64 {
	return int64(uint64(r.CreationTimeStamp.HighDateTime)<<32 | uint64(r.CreationTimeStamp.LowDateTime))
}
func verifyApplicationLUID(p ipadsession.Plan) string {
	r := windows.MibIfRow2{InterfaceLuid: p.LUID}
	e := windows.GetIfEntry2Ex(windows.MibIfEntryNormal, &r)
	if e == windows.ERROR_NOT_FOUND || e == windows.ERROR_FILE_NOT_FOUND {
		return "ADAPTER_ABSENT"
	}
	if e != nil {
		return "APPLICATION_ADAPTER_QUERY_FAILED"
	}
	if r.InterfaceIndex != p.Index || !strings.EqualFold(r.InterfaceGuid.String(), p.GUID) {
		return "APPLICATION_ADAPTER_IDENTITY_CHANGED"
	}
	return ""
}
func createApplicationAddress(p ipadsession.Plan) (int64, string) {
	for _, n := range []string{"InitializeUnicastIpAddressEntry", "CreateUnicastIpAddressEntry", "DeleteUnicastIpAddressEntry"} {
		if windows.NewLazySystemDLL("iphlpapi.dll").NewProc(n).Find() != nil {
			return 0, "APPLICATION_IP_API_UNAVAILABLE"
		}
	}
	if e := verifyApplicationLUID(p); e != "" {
		return 0, e
	}
	r := addressRow(p)
	e := windows.GetUnicastIpAddressEntry(&r)
	if e != windows.ERROR_NOT_FOUND && e != windows.ERROR_FILE_NOT_FOUND {
		return 0, "APPLICATION_ADDRESS_NOT_CONFIRMED_ABSENT"
	}
	r = addressRow(p)
	rc, _, _ := windows.NewLazySystemDLL("iphlpapi.dll").NewProc("CreateUnicastIpAddressEntry").Call(uintptr(unsafe.Pointer(&r)))
	if rc != 0 {
		return 0, "APPLICATION_ADDRESS_CREATE_" + fmt.Sprint(rc)
	}
	for i := 0; i < 20; i++ {
		if e := verifyApplicationLUID(p); e != "" {
			return 0, e
		}
		r = addressRow(p)
		if e = windows.GetUnicastIpAddressEntry(&r); e != nil {
			return 0, "APPLICATION_ADDRESS_QUERY_FAILED"
		}
		if r.DadState == 4 {
			return addressStamp(r), ""
		}
		if r.DadState != 1 {
			return 0, "APPLICATION_ADDRESS_DAD_FAILED"
		}
		time.Sleep(500 * time.Millisecond)
	}
	return 0, "APPLICATION_ADDRESS_DAD_TIMEOUT"
}
func removeApplicationAddress(p ipadsession.Plan) string {
	if e := verifyApplicationLUID(p); e == "ADAPTER_ABSENT" {
		return ""
	} else if e != "" {
		return e
	}
	r := addressRow(p)
	e := windows.GetUnicastIpAddressEntry(&r)
	if e == windows.ERROR_NOT_FOUND || e == windows.ERROR_FILE_NOT_FOUND {
		return ""
	}
	if e != nil {
		return "APPLICATION_ADDRESS_RECOVERY_QUERY_FAILED"
	}
	if !ipadsession.OwnedAddress(p, ipadsession.AddressIdentity{LUID: r.InterfaceLuid, Index: r.InterfaceIndex, Prefix: uint32(r.OnLinkPrefixLength), PrefixOrigin: uint32(r.PrefixOrigin), SuffixOrigin: uint32(r.SuffixOrigin), ValidLifetime: r.ValidLifetime, PreferredLifetime: r.PreferredLifetime, CreatedAt: addressStamp(r)}) {
		return "APPLICATION_ADDRESS_OWNERSHIP_CHANGED"
	}
	proc := windows.NewLazySystemDLL("iphlpapi.dll").NewProc("DeleteUnicastIpAddressEntry")
	if proc.Find() != nil {
		return "APPLICATION_DELETE_IP_API_UNAVAILABLE"
	}
	rc, _, _ := proc.Call(uintptr(unsafe.Pointer(&r)))
	if rc != 0 && rc != uintptr(windows.ERROR_NOT_FOUND) {
		return "APPLICATION_ADDRESS_DELETE_FAILED"
	}
	r = addressRow(p)
	e = windows.GetUnicastIpAddressEntry(&r)
	if e != windows.ERROR_NOT_FOUND && e != windows.ERROR_FILE_NOT_FOUND {
		return "APPLICATION_ADDRESS_ABSENCE_UNCONFIRMED"
	}
	return ""
}
func RecoverApplicationSession(dir, system string) (r ApplicationRecovery) {
	j, pending, e := readApplicationJournal(dir)
	r.Pending = pending
	r.Error = e
	if !pending || e != "" {
		return
	}
	script, e2 := j.Plan.FirewallCleanup()
	if e2 != nil {
		r.Error = "APPLICATION_RECOVERY_PLAN_INVALID"
		return
	}
	if j.ResidentFirewall {
		r.ResidentFirewallPreserved = true
	} else if netconfig.NativeNetworkEnabled() {
		ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
		err := netconfig.CleanupIPadSessionRulesNative(ctx, j.Plan, nil)
		cancel()
		r.FirewallRemoved = err == nil
	} else {
		output, fwErr := runApplicationScript(system, script)
		r.FirewallRemoved = fwErr == "" && output == "OWNED_FIREWALL_REMOVED"
	}
	cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 35*time.Second)
	defer cleanupCancel()
	if err := RestoreOwnedIPadDADForClose(cleanupCtx, dir, j.Root, j.Driver, j.Plan); err != nil {
		r.Error = err.Error()
		return // retain the application journal and originals.
	}
	routeErr := removePeerRoute(j.Plan)
	ipErr := routeErr
	preserved := false
	if routeErr == "" {
		var ce error
		preserved, ce = recoverIPadConfigurationBeforeAddress(cleanupCtx, dir, j)
		if ce != nil {
			ipErr = ce.Error()
		} else if !preserved {
			ipErr = removeApplicationAddress(j.Plan)
		}
	}
	r.PersistentAddressPreserved = preserved && ipErr == ""
	r.AddressRemoved = !preserved && ipErr == ""
	if !r.FirewallRemoved && !r.ResidentFirewallPreserved {
		r.Error = "APPLICATION_FIREWALL_RESTORE_UNCONFIRMED"
	} else if ipErr != "" {
		r.Error = ipErr
	}
	if r.Error == "" {
		r.Error = restoreUSBHostFlags(j.Plan)
	}
	if r.Error == "" && !preserved {
		if ce := finishIPadFailedApplication(cleanupCtx, dir, j); ce != nil {
			r.Error = ce.Error()
		}
	}
	if r.Error == "" {
		if e2 = os.Remove(appJournalPath(dir)); e2 != nil {
			r.Error = "APPLICATION_RECOVERY_REMOVE_FAILED"
		} else {
			r.JournalCleared = true
		}
	}
	return
}
