//go:build windows && amd64

package usbhost

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"golang.org/x/sys/windows"
	"io"
	"log"
	"os"
	"path/filepath"
	"suhang/usbnet/internal/platform/windows/netconfig"
	"suhang/usbnet/internal/transport/usbaddress"
	"suhang/usbnet/internal/transport/wintun"
	"time"
	"unsafe"
)

var errOwnedNonpresentRecreate = errors.New("USB_HOST_OWNED_NONPRESENT_RECREATE_REQUIRED")
var errClosedOwnedNonpresent = errors.New("USB_HOST_CLOSED_OWNED_NONPRESENT")

type RecreateJournalProtectionDiagnostic struct {
	ObservationOnly      bool   `json:"observation_only"`
	Present              bool   `json:"present"`
	OwnerIsAdministrator bool   `json:"owner_is_administrator"`
	OwnerIsSystem        bool   `json:"owner_is_system"`
	ACECount             uint16 `json:"ace_count"`
	ACLValid             bool   `json:"acl_valid"`
	SingleLink           bool   `json:"single_link"`
	ReparseFree          bool   `json:"reparse_free"`
	Problem              string `json:"problem,omitempty"`
}

// Numeric/boolean observation of the fixed local journal only. It neither
// changes security descriptors nor authorizes the creation transaction.
func inspectRecreateJournalProtection(dir string) RecreateJournalProtectionDiagnostic {
	d := RecreateJournalProtectionDiagnostic{ObservationOnly: true}
	if !removalDirectoryProtected(dir) {
		d.Problem = "USB_HOST_RECREATE_STORE_UNPROVEN"
		return d
	}
	p, _ := windows.UTF16PtrFromString(filepath.Join(dir, "usb-host-address.json"))
	h, e := windows.CreateFile(p, windows.GENERIC_READ, windows.FILE_SHARE_READ, nil, windows.OPEN_EXISTING, windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if e == windows.ERROR_FILE_NOT_FOUND {
		return d
	}
	if e != nil {
		d.Problem = "USB_HOST_RECREATE_JOURNAL_UNREADABLE"
		return d
	}
	defer windows.CloseHandle(h)
	d.Present = true
	var info windows.ByHandleFileInformation
	if windows.GetFileInformationByHandle(h, &info) == nil {
		d.SingleLink = info.NumberOfLinks == 1
		d.ReparseFree = info.FileAttributes&(windows.FILE_ATTRIBUTE_DIRECTORY|windows.FILE_ATTRIBUTE_REPARSE_POINT) == 0
	}
	sd, e := windows.GetSecurityInfo(h, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION|windows.OWNER_SECURITY_INFORMATION)
	if e != nil {
		d.Problem = "USB_HOST_RECREATE_JOURNAL_PROTECTION_UNPROVEN"
		return d
	}
	owner, _, oe := sd.Owner()
	admin, ae := windows.CreateWellKnownSid(windows.WinBuiltinAdministratorsSid)
	system, se := windows.CreateWellKnownSid(windows.WinLocalSystemSid)
	if oe == nil && ae == nil && se == nil && owner != nil {
		d.OwnerIsAdministrator = owner.Equals(admin)
		d.OwnerIsSystem = owner.Equals(system)
	}
	if acl, _, e := sd.DACL(); e == nil && acl != nil {
		d.ACECount = acl.AceCount
	}
	d.ACLValid = recreateJournalACLMatches(sd)
	if !d.ACLValid || !d.SingleLink || !d.ReparseFree {
		d.Problem = "USB_HOST_RECREATE_JOURNAL_PROTECTION_UNPROVEN"
	}
	return d
}

func recreateJournalACLMatches(sd *windows.SECURITY_DESCRIPTOR) bool {
	if sd == nil {
		return false
	}
	owner, _, e := sd.Owner()
	admin, ae := windows.CreateWellKnownSid(windows.WinBuiltinAdministratorsSid)
	system, se := windows.CreateWellKnownSid(windows.WinLocalSystemSid)
	if e != nil || ae != nil || se != nil || owner == nil || (!owner.Equals(admin) && !owner.Equals(system)) {
		return false
	}
	acl, _, e := sd.DACL()
	if e != nil || acl == nil || acl.AceCount != 2 {
		return false
	}
	seenAdmin, seenSystem := false, false
	for i := uint32(0); i < 2; i++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if windows.GetAce(acl, i, &ace) != nil || ace == nil || ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE || (ace.Header.AceFlags != 0 && ace.Header.AceFlags != windows.INHERITED_ACE) || ace.Header.AceSize < 20 || ace.Header.AceSize > 64 || ace.Mask != 0x001f01ff {
			return false
		}
		sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
		if !sid.IsValid() || sid.Len() > int(ace.Header.AceSize)-8 {
			return false
		}
		if sid.Equals(admin) && !seenAdmin {
			seenAdmin = true
		} else if sid.Equals(system) && !seenSystem {
			seenSystem = true
		} else {
			return false
		}
	}
	return seenAdmin && seenSystem
}

// Closing admits zero addresses or the one exact original owned row. It does
// not relax the stronger healthy/DAD/one-address requirement of ready commit.
func verifyClosingTarget(original journal, instance string) (journal, error) {
	r, present, e := findHost()
	if e != nil || !present || r.InterfaceLuid != original.LUID {
		return journal{}, fmt.Errorf("USB_HOST_CLOSE_MAPPING_UNPROVEN")
	}
	id, _, e := netconfig.CaptureSharedHostClosingNative(r.InterfaceIndex, r.InterfaceLuid)
	if e != nil || id != instance {
		return journal{}, fmt.Errorf("USB_HOST_CLOSE_NODE_CHANGED")
	}
	addresses, e := recoveryAddresses(r.InterfaceIndex, r.InterfaceLuid)
	if e != nil {
		return journal{}, fmt.Errorf("USB_HOST_CLOSE_ADDRESS_QUERY_FAILED")
	}
	local, _, e := rebindClosing(original, r.InterfaceIndex, r.InterfaceLuid, addresses)
	if e != nil || len(addresses) > 1 {
		return journal{}, fmt.Errorf("USB_HOST_CLOSE_ADDRESS_OWNERSHIP_UNPROVEN")
	}
	return local, nil
}

// Normal shutdown records a distinct known Close obligation before either
// address deletion or the exact returned-handle Close. It never enters the
// older DIF removal path while asynchronous PnP retirement is still PRESENT.
func closeOwnedHost(dir string, p journal, d *wintun.Device) error {
	path := filepath.Join(dir, "usb-host-address.json")
	b, e := readRecreateJournal(dir, path)
	if e != nil {
		return e
	}
	got, e := decodeJournal(b)
	if e != nil || got != p || p.Created <= 0 || d.LUID != p.LUID {
		return fmt.Errorf("USB_HOST_CLOSE_JOURNAL_CHANGED")
	}
	if _, found, e := readRemovalIntentFile(dir); e != nil || found {
		return fmt.Errorf("USB_HOST_RECREATE_CONFLICTS_WITH_REMOVAL")
	}
	if _, found, e := readRecreateTransactionFile(dir); e != nil || found {
		return fmt.Errorf("USB_HOST_RECREATE_ATTEMPT_PENDING")
	}
	current, present, e := findHost()
	if e != nil || !present || current.InterfaceLuid != p.LUID {
		return fmt.Errorf("USB_HOST_CLOSE_MAPPING_UNPROVEN")
	}
	instance, _, e := netconfig.CaptureSharedHostClosingNative(current.InterfaceIndex, p.LUID)
	if e != nil {
		return e
	}
	var token [12]byte
	if _, e = rand.Read(token[:]); e != nil {
		return fmt.Errorf("USB_HOST_RECREATE_RANDOM_FAILED")
	}
	t := recreateTransaction{Version: 1, OldSHA256: journalDigest(b), OriginalLUID: p.LUID, Instance: instance, Token: hex.EncodeToString(token[:]), Ticks: systemTicks(), State: "closing"}
	if _, e = verifyClosingTarget(p, instance); e != nil {
		return e
	}
	if e = writeRecreateTransactionFile(dir, t, false); e != nil {
		return e
	}
	fresh, e := readRecreateJournal(dir, path)
	if e != nil || !bytes.Equal(fresh, b) {
		return fmt.Errorf("USB_HOST_CLOSE_JOURNAL_CHANGED")
	}
	local, e := verifyClosingTarget(p, instance)
	if e != nil {
		return e
	}
	if e = remove(local); e != nil {
		return e
	}
	d.Close()
	recordRecreate("closing", "", nil)
	// Only read-only completion checks after Close. The caller retains its
	// operation lease, so a temporary gap cannot trigger another Create.
	deadline := time.NewTimer(10 * time.Second)
	defer deadline.Stop()
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	for {
		e = finishClosingTransaction(dir, path, t, b)
		if e == nil || e == errClosedOwnedNonpresent {
			return nil
		}
		if e.Error() != "USB_HOST_CLOSE_COMPLETION_PENDING" {
			return e
		}
		select {
		case <-deadline.C:
			return e
		case <-ticker.C:
		}
	}
}

func finishClosingTransaction(dir, path string, t recreateTransaction, b []byte) error {
	if t.State != "closing" {
		return fmt.Errorf("USB_HOST_RECREATE_PHASE_INVALID")
	}
	position, e := recreateJournalPosition(t, b)
	if e != nil || position != "old" {
		return fmt.Errorf("USB_HOST_CLOSE_JOURNAL_CHANGED")
	}
	original, e := decodeJournal(b)
	if e != nil {
		return e
	}
	absent, e := netconfig.ConfirmSharedHostRemovalAbsentNative(t.Instance)
	if e != nil {
		return e
	}
	nonpresent := false
	if !absent {
		r, present, e := findHost()
		if e != nil || !present || r.InterfaceLuid != t.OriginalLUID {
			return fmt.Errorf("USB_HOST_CLOSE_MAPPING_UNPROVEN")
		}
		id, np, e := netconfig.CaptureSharedHostClosingNative(r.InterfaceIndex, r.InterfaceLuid)
		if e != nil || id != t.Instance {
			return fmt.Errorf("USB_HOST_CLOSE_COMPLETION_PENDING")
		}
		addresses, e := recoveryAddresses(r.InterfaceIndex, r.InterfaceLuid)
		if e != nil {
			return fmt.Errorf("USB_HOST_CLOSE_ADDRESS_QUERY_FAILED")
		}
		local, state, e := rebindClosing(original, r.InterfaceIndex, r.InterfaceLuid, addresses)
		if e != nil {
			return e
		}
		if state == "owned" {
			// A crash between the closing receipt and original-address deletion
			// may leave precisely that row. Re-prove files, full native identity
			// and the complete address set before invoking the existing exact-IP
			// removal. No device/DIF removal is reachable here.
			fresh, e := readRecreateJournal(dir, path)
			if e != nil || !bytes.Equal(fresh, b) {
				return fmt.Errorf("USB_HOST_CLOSE_JOURNAL_CHANGED")
			}
			got, found, e := readRecreateTransactionFile(dir)
			if e != nil || !found || got != t {
				return fmt.Errorf("USB_HOST_RECREATE_TRANSACTION_CHANGED")
			}
			id, freshNP, e := netconfig.CaptureSharedHostClosingNative(r.InterfaceIndex, r.InterfaceLuid)
			if e != nil || id != t.Instance || freshNP != np {
				return fmt.Errorf("USB_HOST_CLOSE_COMPLETION_PENDING")
			}
			addresses, e = recoveryAddresses(local.Index, local.LUID)
			if e != nil {
				return fmt.Errorf("USB_HOST_CLOSE_ADDRESS_QUERY_FAILED")
			}
			check, state, e := rebindClosing(original, local.Index, local.LUID, addresses)
			if e != nil || state != "owned" || len(addresses) != 1 || check != local {
				return fmt.Errorf("USB_HOST_CLOSE_ADDRESS_OWNERSHIP_UNPROVEN")
			}
			if e = remove(local); e != nil {
				return e
			}
		}
		addresses, e = recoveryAddresses(local.Index, local.LUID)
		if e != nil || len(addresses) != 0 {
			return fmt.Errorf("USB_HOST_CLOSE_ADDRESS_NOT_ABSENT")
		}
		if !np {
			return fmt.Errorf("USB_HOST_CLOSE_COMPLETION_PENDING")
		}
		nonpresent = true
	}
	fresh, e := readRecreateJournal(dir, path)
	if e != nil || !bytes.Equal(fresh, b) {
		return fmt.Errorf("USB_HOST_CLOSE_JOURNAL_CHANGED")
	}
	got, found, e := readRecreateTransactionFile(dir)
	if e != nil || !found || got != t {
		return fmt.Errorf("USB_HOST_RECREATE_TRANSACTION_CHANGED")
	}
	// Repeat the complete authoritative observation after file readback.
	if nonpresent {
		r, present, e := findHost()
		if e != nil || !present || r.InterfaceLuid != t.OriginalLUID {
			return fmt.Errorf("USB_HOST_CLOSE_MAPPING_UNPROVEN")
		}
		id, e := netconfig.CaptureSharedHostNonpresentNative(r.InterfaceIndex, r.InterfaceLuid)
		if e != nil || id != t.Instance {
			return fmt.Errorf("USB_HOST_CLOSE_COMPLETION_PENDING")
		}
	} else {
		absent, e = netconfig.ConfirmSharedHostRemovalAbsentNative(t.Instance)
		if e != nil || !absent {
			return fmt.Errorf("USB_HOST_CLOSE_COMPLETION_PENDING")
		}
	}
	if e = clearRecreateTransactionFile(dir, t); e != nil {
		return e
	}
	if nonpresent {
		return errClosedOwnedNonpresent
	}
	return nil
}

// The parent directory is already the application's protected recovery store.
// Reject reparse points, hard links and non-files rather than following a
// journal somewhere else. Inherited administrator/SYSTEM ACLs remain valid.
func readRecreateJournal(dir, path string) ([]byte, error) {
	if !removalDirectoryProtected(dir) {
		return nil, fmt.Errorf("USB_HOST_RECREATE_STORE_UNPROVEN")
	}
	p, e := windows.UTF16PtrFromString(path)
	if e != nil {
		return nil, fmt.Errorf("USB_HOST_RECREATE_JOURNAL_UNREADABLE")
	}
	h, e := windows.CreateFile(p, windows.GENERIC_READ, windows.FILE_SHARE_READ, nil, windows.OPEN_EXISTING, windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if e != nil {
		return nil, fmt.Errorf("USB_HOST_RECREATE_JOURNAL_UNREADABLE")
	}
	var info windows.ByHandleFileInformation
	sd, se := windows.GetSecurityInfo(h, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION|windows.OWNER_SECURITY_INFORMATION)
	if se != nil || !recreateJournalACLMatches(sd) || windows.GetFileInformationByHandle(h, &info) != nil || info.NumberOfLinks != 1 || info.FileAttributes&(windows.FILE_ATTRIBUTE_DIRECTORY|windows.FILE_ATTRIBUTE_REPARSE_POINT) != 0 {
		windows.CloseHandle(h)
		return nil, fmt.Errorf("USB_HOST_RECREATE_JOURNAL_PROTECTION_UNPROVEN")
	}
	f := os.NewFile(uintptr(h), path)
	if f == nil {
		windows.CloseHandle(h)
		return nil, fmt.Errorf("USB_HOST_RECREATE_JOURNAL_UNREADABLE")
	}
	defer f.Close()
	b, e := io.ReadAll(io.LimitReader(f, 2049))
	if e != nil || len(b) > 2048 {
		return nil, fmt.Errorf("USB_HOST_RECREATE_JOURNAL_UNREADABLE")
	}
	if _, e = decodeRecreateJournal(b); e != nil {
		return nil, e
	}
	return b, nil
}

func recordRecreate(phase, problem string, fields map[string]any) {
	live.Lock()
	defer live.Unlock()
	next := map[string]any{"observation_only": true, "phase": phase, "native_call_cancellable": false}
	for k, v := range live.recreate {
		next[k] = v
	}
	next["phase"] = phase
	for k, v := range fields {
		next[k] = v
	}
	if problem != "" {
		next["problem"] = problem
		if next["first_problem"] == nil {
			next["first_problem"] = problem
		}
	}
	live.recreate = next
}

func verifyRecreateMapped(t recreateTransaction, p journal, requireZero bool) error {
	if e := netconfig.VerifySharedHostRecreatedNative(p.Index, p.LUID, t.Instance); e != nil {
		return e
	}
	addresses, e := recoveryAddresses(p.Index, p.LUID)
	if e != nil {
		return fmt.Errorf("USB_HOST_RECREATE_ADDRESS_QUERY_FAILED")
	}
	if requireZero {
		if len(addresses) != 0 {
			return fmt.Errorf("USB_HOST_RECREATE_ADDRESS_NOT_ABSENT")
		}
		return nil
	}
	_, state, e := rebindRecovery(p, p.Index, p.LUID, addresses)
	if e != nil || len(addresses) != 1 || state != "owned" {
		return fmt.Errorf("USB_HOST_RECREATE_ADDRESS_OWNERSHIP_UNPROVEN")
	}
	r := row(p)
	if windows.GetUnicastIpAddressEntry(&r) != nil || r.DadState != 4 || !own(p, r) {
		return fmt.Errorf("USB_HOST_RECREATE_ADDRESS_READBACK_FAILED")
	}
	return nil
}

func prepareOwnedNonpresent(ctx context.Context, dir, dllPath string) (*wintun.Device, journal, *recreateTransaction, error) {
	path := filepath.Join(dir, "usb-host-address.json")
	old, e := readRecreateJournal(dir, path)
	if e != nil {
		return nil, journal{}, nil, e
	}
	p, e := decodeJournal(old)
	if e != nil {
		return nil, journal{}, nil, e
	}
	r, present, e := findHost()
	if e != nil || !present {
		return nil, journal{}, nil, fmt.Errorf("USB_HOST_RECREATE_OLD_MAPPING_UNPROVEN")
	}
	addresses, e := recoveryAddresses(r.InterfaceIndex, r.InterfaceLuid)
	if e != nil {
		return nil, journal{}, nil, e
	}
	if e = validateNonpresentRecoveryOwnership(p, r.InterfaceLuid, len(addresses)); e != nil {
		return nil, journal{}, nil, e
	}
	instance, e := netconfig.CaptureSharedHostNonpresentNative(r.InterfaceIndex, r.InterfaceLuid)
	if e != nil {
		return nil, journal{}, nil, e
	}
	if _, found, e := readRemovalIntentFile(dir); e != nil || found {
		return nil, journal{}, nil, fmt.Errorf("USB_HOST_RECREATE_CONFLICTS_WITH_REMOVAL")
	}
	if _, found, e := readRecreateTransactionFile(dir); e != nil || found {
		return nil, journal{}, nil, fmt.Errorf("USB_HOST_RECREATE_ATTEMPT_PENDING")
	}
	pin, e := netconfig.PinVerifiedWintunNative(dllPath, log.New(os.Stderr, "USB host: ", 0))
	if e != nil {
		return nil, journal{}, nil, e
	}
	defer pin.Close()
	var token [12]byte
	if _, e = rand.Read(token[:]); e != nil {
		return nil, journal{}, nil, fmt.Errorf("USB_HOST_RECREATE_RANDOM_FAILED")
	}
	t := recreateTransaction{Version: 1, OldSHA256: journalDigest(old), OriginalLUID: p.LUID, Instance: instance, Token: hex.EncodeToString(token[:]), Ticks: systemTicks(), State: "attempt"}
	if e = writeRecreateTransactionFile(dir, t, false); e != nil {
		return nil, journal{}, nil, e
	}
	recordRecreate("attempt", "", map[string]any{"call_succeeded": false, "fixed_guid_verified": false, "mapping_verified": false, "address_confirmed": false, "journal_committed": false})
	var observed wintun.OwnedCreateObservation
	// All hash/loading/procedure work happens before this callback. Immediately
	// before the synchronous API call, bind both protected files and repeat the
	// full native unique nonpresent/config-zero/address-zero proof.
	d, e := wintun.CreateOwnedNonpresentHost(dllPath, func() error {
		if e := ctx.Err(); e != nil {
			return e
		}
		fresh, e := readRecreateJournal(dir, path)
		if e != nil || !bytes.Equal(fresh, old) {
			return fmt.Errorf("USB_HOST_RECREATE_JOURNAL_CHANGED")
		}
		got, found, e := readRecreateTransactionFile(dir)
		if e != nil || !found || got != t {
			return fmt.Errorf("USB_HOST_RECREATE_TRANSACTION_CHANGED")
		}
		if _, found, e := readRemovalIntentFile(dir); e != nil || found {
			return fmt.Errorf("USB_HOST_RECREATE_CONFLICTS_WITH_REMOVAL")
		}
		current, present, e := findHost()
		if e != nil || !present || current.InterfaceIndex != r.InterfaceIndex || current.InterfaceLuid != p.LUID {
			return fmt.Errorf("USB_HOST_RECREATE_OLD_MAPPING_UNPROVEN")
		}
		id, e := netconfig.CaptureSharedHostNonpresentNative(current.InterfaceIndex, current.InterfaceLuid)
		if e != nil || id != instance {
			return fmt.Errorf("USB_HOST_RECREATE_OLD_NODE_CHANGED")
		}
		fresh, e = readRecreateJournal(dir, path)
		if e != nil || !bytes.Equal(fresh, old) {
			return fmt.Errorf("USB_HOST_RECREATE_JOURNAL_CHANGED")
		}
		recordRecreate("native_call", "", nil)
		return nil
	}, &observed)
	recordRecreate("native_returned", "", map[string]any{"call_entered": observed.Called, "call_returned": observed.Returned, "call_succeeded": observed.Succeeded, "fixed_guid_verified": observed.FixedGUIDVerified, "returned_index": observed.Index, "returned_luid": observed.LUID})
	if e != nil {
		if !observed.Called {
			// Only this uninterrupted synchronous stack knows that no native
			// call occurred. A persisted attempt after a crash never gains it.
			if ce := clearKnownUncalledTransaction(dir, path, t, old); ce == nil {
				recordRecreate("uncalled", "USB_HOST_RECREATE_PRECALL_REJECTED", map[string]any{"uncalled_transaction_cleared": true})
				return nil, journal{}, nil, fmt.Errorf("USB_HOST_RECREATE_PRECALL_REJECTED")
			}
		}
		recordRecreate("attempt_pending", "USB_HOST_RECREATE_NATIVE_CALL_FAILED", nil)
		return nil, journal{}, nil, fmt.Errorf("USB_HOST_RECREATE_NATIVE_CALL_FAILED")
	}
	ok := false
	defer func() {
		if !ok {
			d.Close()
			recordRecreate("close_pending", "USB_HOST_RECREATE_CLOSE_UNCONFIRMED", nil)
		}
	}()
	if e = ctx.Err(); e != nil {
		recordRecreate("attempt_pending", "USB_HOST_RECREATE_CANCELLED_AFTER_CALL", nil)
		return nil, journal{}, nil, e
	}
	next := journal{Version: 1, GUID: usbaddress.HostGUID, Index: d.Index, LUID: d.LUID, Token: t.Token, Planned: nowStamp()}
	if e = verifyRecreateMapped(t, next, true); e != nil {
		recordRecreate("attempt_pending", "USB_HOST_RECREATE_MAPPING_UNPROVEN", nil)
		return nil, journal{}, nil, e
	}
	fresh, e := readRecreateJournal(dir, path)
	if e != nil || !bytes.Equal(fresh, old) {
		return nil, journal{}, nil, fmt.Errorf("USB_HOST_RECREATE_JOURNAL_CHANGED")
	}
	t.State = "mapped"
	t.Next = next
	if e = writeRecreateTransactionFile(dir, t, true); e != nil {
		return nil, journal{}, nil, e
	}
	if e = verifyRecreateMapped(t, next, true); e != nil {
		return nil, journal{}, nil, e
	}
	recordRecreate("mapped", "", map[string]any{"mapping_verified": true, "zero_ipv4_verified": true})
	ok = true
	return d, next, &t, nil
}

func clearKnownUncalledTransaction(dir, path string, t recreateTransaction, b []byte) error {
	if t.State != "attempt" {
		return fmt.Errorf("USB_HOST_RECREATE_PHASE_INVALID")
	}
	position, e := recreateJournalPosition(t, b)
	if e != nil || position != "old" {
		return fmt.Errorf("USB_HOST_RECREATE_JOURNAL_CHANGED")
	}
	fresh, e := readRecreateJournal(dir, path)
	if e != nil || !bytes.Equal(fresh, b) {
		return fmt.Errorf("USB_HOST_RECREATE_JOURNAL_CHANGED")
	}
	got, found, e := readRecreateTransactionFile(dir)
	if e != nil || !found || got != t {
		return fmt.Errorf("USB_HOST_RECREATE_TRANSACTION_CHANGED")
	}
	if _, found, e := readRemovalIntentFile(dir); e != nil || found {
		return fmt.Errorf("USB_HOST_RECREATE_CONFLICTS_WITH_REMOVAL")
	}
	r, present, e := findHost()
	if e != nil || !present || r.InterfaceLuid != t.OriginalLUID {
		return fmt.Errorf("USB_HOST_RECREATE_OLD_MAPPING_UNPROVEN")
	}
	id, e := netconfig.CaptureSharedHostNonpresentNative(r.InterfaceIndex, r.InterfaceLuid)
	if e != nil || id != t.Instance {
		return fmt.Errorf("USB_HOST_RECREATE_OLD_NODE_CHANGED")
	}
	fresh, e = readRecreateJournal(dir, path)
	if e != nil || !bytes.Equal(fresh, b) {
		return fmt.Errorf("USB_HOST_RECREATE_JOURNAL_CHANGED")
	}
	return clearRecreateTransactionFile(dir, t)
}

func commitRecreatedAddress(dir, path string, t *recreateTransaction, p journal) error {
	if e := verifyRecreateMapped(*t, p, false); e != nil {
		return e
	}
	b, e := readRecreateJournal(dir, path)
	if e != nil {
		return e
	}
	position, e := recreateJournalPosition(*t, b)
	if e != nil || position != "old" {
		return fmt.Errorf("USB_HOST_RECREATE_JOURNAL_CHANGED")
	}
	next := *t
	next.State = "ready"
	next.Next = p
	if e = writeRecreateTransactionFile(dir, next, true); e != nil {
		return e
	}
	*t = next
	recordRecreate("ready", "", map[string]any{"address_confirmed": true})
	return finishRecreateTransaction(dir, path, *t, b, true)
}

// Unknown outcomes do not authorize another Create. A reset counter and full
// installed/exact-instance/NetIO absence are required; current-time delays or
// a vanished PRESENT node cannot release this fence. Ready alone carries the
// actual successful handle and completed address proof needed to commit.
func finishRecreateTransaction(dir, path string, t recreateTransaction, b []byte, liveCommit bool) error {
	position, e := recreateJournalPosition(t, b)
	if e != nil {
		return e
	}
	nonpresent, absent := false, false
	if t.State != "ready" {
		if e = recreateUnknownRecoveryGate(t, systemTicks()); e != nil {
			return e
		}
		absent, e = netconfig.ConfirmSharedHostRemovalAbsentNative(t.Instance)
		if e != nil || !absent {
			return fmt.Errorf("USB_HOST_RECREATE_ABSENCE_UNCONFIRMED")
		}
		if e = verifyRecreateAbsenceAddresses(t); e != nil {
			return e
		}
	} else {
		r, present, e := findHost()
		if e != nil {
			return fmt.Errorf("USB_HOST_RECREATE_READY_MAPPING_UNPROVEN")
		}
		if !present && !liveCommit {
			absent, e = netconfig.ConfirmSharedHostRemovalAbsentNative(t.Instance)
			if e != nil || !absent {
				return fmt.Errorf("USB_HOST_RECREATE_ABSENCE_UNCONFIRMED")
			}
			if e = verifyRecreateAbsenceAddresses(t); e != nil {
				return e
			}
		} else {
			if !present || r.InterfaceLuid != t.Next.LUID {
				return fmt.Errorf("USB_HOST_RECREATE_READY_MAPPING_UNPROVEN")
			}
			p := t.Next
			p.Index = r.InterfaceIndex
			e = verifyRecreateMapped(t, p, false)
			if e != nil {
				if liveCommit {
					return e
				}
				// Only ready records an actual successful handle AND completed owned
				// address. It may retire to exact nonpresent/zero after a failed Close;
				// attempt and mapped never acquire this authority from observation.
				id, pe := netconfig.CaptureSharedHostNonpresentNative(p.Index, p.LUID)
				if pe != nil || id != t.Instance {
					return e
				}
				nonpresent = true
			}
		}
	}
	fresh, e := readRecreateJournal(dir, path)
	if e != nil || !bytes.Equal(fresh, b) {
		return fmt.Errorf("USB_HOST_RECREATE_JOURNAL_CHANGED")
	}
	got, found, e := readRecreateTransactionFile(dir)
	if e != nil || !found || got != t {
		return fmt.Errorf("USB_HOST_RECREATE_TRANSACTION_CHANGED")
	}
	if t.State == "ready" && position == "old" {
		if e = save(path, t.Next, true); e != nil {
			return e
		}
		fresh, e = readRecreateJournal(dir, path)
		if e != nil {
			return e
		}
		position, e = recreateJournalPosition(t, fresh)
		if e != nil || position != "new" {
			return fmt.Errorf("USB_HOST_RECREATE_COMMIT_UNCONFIRMED")
		}
	}
	// File I/O and the durable journal replacement are not native identity
	// proofs. Repeat the authoritative observation before releasing/transferring
	// the transaction; a changed external node must retain the fence.
	if absent {
		ok, e := netconfig.ConfirmSharedHostRemovalAbsentNative(t.Instance)
		if e != nil || !ok {
			return fmt.Errorf("USB_HOST_RECREATE_ABSENCE_UNCONFIRMED")
		}
		if e = verifyRecreateAbsenceAddresses(t); e != nil {
			return e
		}
	} else if nonpresent {
		r, present, e := findHost()
		if e != nil || !present || r.InterfaceLuid != t.Next.LUID {
			return fmt.Errorf("USB_HOST_RECREATE_READY_MAPPING_UNPROVEN")
		}
		id, e := netconfig.CaptureSharedHostNonpresentNative(r.InterfaceIndex, r.InterfaceLuid)
		if e != nil || id != t.Instance {
			return fmt.Errorf("USB_HOST_RECREATE_READY_MAPPING_UNPROVEN")
		}
	} else {
		r, present, e := findHost()
		if e != nil || !present || r.InterfaceLuid != t.Next.LUID {
			return fmt.Errorf("USB_HOST_RECREATE_READY_MAPPING_UNPROVEN")
		}
		p := t.Next
		p.Index = r.InterfaceIndex
		if e = verifyRecreateMapped(t, p, false); e != nil {
			return e
		}
	}
	if t.State == "ready" && !liveCommit && !nonpresent && !absent {
		// Replay has no live created handle. A failed Close may still be PRESENT.
		// Preserve the newly committed receipt, turn only this ready transaction
		// into an exact closing obligation, and never fall into ordinary DIF.
		closing := t
		closing.State = "closing"
		closing.OldSHA256 = journalDigest(fresh)
		closing.OriginalLUID = t.Next.LUID
		closing.Next = journal{}
		if e = writeRecreateTransactionFile(dir, closing, true); e != nil {
			return e
		}
		return finishClosingTransaction(dir, path, closing, fresh)
	}
	if e = clearRecreateTransactionFile(dir, t); e != nil {
		return e
	}
	if t.State == "ready" {
		recordRecreate("committed", "", map[string]any{"journal_committed": true})
	}
	if nonpresent {
		return errClosedOwnedNonpresent
	}
	return nil
}

// DAD precedes address creation/ready commit. Its owner proof therefore binds
// the protected OLD completed journal and the exact NEW mapped transaction,
// plus the actual still-held returned creator and fresh native zero-IP target.
// It grants no crash/replay settlement and never replaces the old journal.
func verifyRecreatedDADOwner(ctx context.Context, dir, path string, p journal, d *wintun.Device, expected recreateTransaction, instance string) (result error) {
	defer func() {
		problem := ""
		if result != nil {
			problem = "USB_HOST_OWNED_DAD_RECREATE_OWNER_UNPROVEN"
		}
		recordRecreate("mapped_dad_owner", problem, map[string]any{"dad_owner_verified": result == nil})
	}()
	if ctx == nil || ctx.Err() != nil {
		return fmt.Errorf("USB_HOST_OWNED_DAD_RECREATE_CONTEXT_INVALID")
	}
	old, e := readRecreateJournal(dir, path)
	if e != nil {
		return e
	}
	got, found, e := readRecreateTransactionFile(dir)
	if e != nil || !found || got != expected {
		return fmt.Errorf("USB_HOST_OWNED_DAD_RECREATE_TRANSACTION_CHANGED")
	}
	if _, found, e := readRemovalIntentFile(dir); e != nil || found {
		return fmt.Errorf("USB_HOST_RECREATE_CONFLICTS_WITH_REMOVAL")
	}
	if d == nil || !d.FactoryHandleHeld() {
		return fmt.Errorf("USB_HOST_OWNED_DAD_RECREATE_HANDLE_CHANGED")
	}
	handle := recreatedDADHandle{FactoryHeld: d.FactoryHandleHeld(), GUID: d.GUID.String(), Index: d.Index, LUID: d.LUID, Instance: instance}
	if e = validateRecreatedDADOwnership(expected, old, p, handle); e != nil {
		return e
	}
	if e = verifyHostConfigScope(hostScope(p)); e != nil {
		return e
	}
	if e = verifyRecreateMapped(expected, p, true); e != nil {
		return e
	}
	// Neither file I/O nor a live handle substitutes for native identity. Recheck
	// all inputs after the first complete proof before allowing the small write.
	fresh, e := readRecreateJournal(dir, path)
	if e != nil || !bytes.Equal(fresh, old) {
		return fmt.Errorf("USB_HOST_OWNED_DAD_RECREATE_JOURNAL_CHANGED")
	}
	got, found, e = readRecreateTransactionFile(dir)
	if e != nil || !found || got != expected {
		return fmt.Errorf("USB_HOST_OWNED_DAD_RECREATE_TRANSACTION_CHANGED")
	}
	if _, found, e := readRemovalIntentFile(dir); e != nil || found {
		return fmt.Errorf("USB_HOST_RECREATE_CONFLICTS_WITH_REMOVAL")
	}
	if ctx.Err() != nil || !d.FactoryHandleHeld() || d.GUID.String() != handle.GUID || d.Index != handle.Index || d.LUID != handle.LUID {
		return fmt.Errorf("USB_HOST_OWNED_DAD_RECREATE_HANDLE_CHANGED")
	}
	if e = validateRecreatedDADOwnership(got, fresh, p, handle); e != nil {
		return e
	}
	if e = verifyHostConfigScope(hostScope(p)); e != nil {
		return e
	}
	return verifyRecreateMapped(got, p, true)
}

func verifyRecreateAbsenceAddresses(t recreateTransaction) error {
	return verifyRecreateAbsentAddressReads(t, func(luid uint64) (int, error) {
		addresses, e := recoveryAddresses(0, luid)
		return len(addresses), e
	})
}
