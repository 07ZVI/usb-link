//go:build windows && amd64

// Package usbhost owns the one Windows service address. USB interfaces keep
// their own routes; their scoped weak-host flags are journaled separately.
package usbhost

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"golang.org/x/sys/windows"
	"log"
	"os"
	"path/filepath"
	"strings"
	"suhang/usbnet/internal/platform/windows/interfaceconfig"
	"suhang/usbnet/internal/platform/windows/netconfig"
	"suhang/usbnet/internal/transport/usbaddress"
	"suhang/usbnet/internal/transport/wintun"
	"sync"
	"time"
	"unsafe"
)

var live struct {
	sync.Mutex
	p                journal
	problem          string
	recovery         map[string]any
	identityReadback map[string]any
	recreate         map[string]any
	ownedDAD         interfaceconfig.Observation
}

// Retain the operation lease through the non-cancellable official native call
// and through exact-handle Close. Recover must never race an in-flight create.
var hostOperationMu sync.Mutex

func nowStamp() int64 {
	var f windows.Filetime
	windows.GetSystemTimeAsFileTime(&f)
	return int64(uint64(f.HighDateTime)<<32 | uint64(f.LowDateTime))
}
func row(p journal) windows.MibUnicastIpAddressRow {
	r := windows.MibUnicastIpAddressRow{}
	windows.NewLazySystemDLL("iphlpapi.dll").NewProc("InitializeUnicastIpAddressEntry").Call(uintptr(unsafe.Pointer(&r)))
	r.InterfaceLuid = p.LUID
	r.InterfaceIndex = p.Index
	v := (*windows.RawSockaddrInet4)(unsafe.Pointer(&r.Address))
	v.Family = windows.AF_INET
	v.Addr = [4]byte{10, 6, 9, 1}
	r.PrefixOrigin = 1
	r.SuffixOrigin = 1
	r.OnLinkPrefixLength = 32
	r.SkipAsSource = 0
	r.ValidLifetime = 3600
	r.PreferredLifetime = 3600
	return r
}
func stamp(r windows.MibUnicastIpAddressRow) int64 {
	return int64(uint64(r.CreationTimeStamp.HighDateTime)<<32 | uint64(r.CreationTimeStamp.LowDateTime))
}
func own(p journal, r windows.MibUnicastIpAddressRow) bool {
	return r.InterfaceLuid == p.LUID && r.InterfaceIndex == p.Index && r.OnLinkPrefixLength == 32 && r.PrefixOrigin == 1 && r.SuffixOrigin == 1 && hostOwnedLifetime(p, r.ValidLifetime, r.PreferredLifetime, r.SkipAsSource != 0) && (p.Created != 0 && stamp(r) == p.Created || p.Created == 0 && stamp(r) >= p.Planned && stamp(r)-p.Planned <= 150000000)
}
func checkInterface(p journal) error {
	r := windows.MibIfRow2{InterfaceLuid: p.LUID}
	if e := windows.GetIfEntry2Ex(windows.MibIfEntryNormal, &r); e != nil {
		return e
	}
	if r.InterfaceIndex != p.Index || r.Type != 53 || !strings.EqualFold(r.InterfaceGuid.String(), usbaddress.HostGUID) || windows.UTF16ToString(r.Alias[:]) != usbaddress.HostName {
		return fmt.Errorf("USB_HOST_INTERFACE_CHANGED")
	}
	return nil
}
func remove(p journal) error {
	if e := checkInterface(p); e != nil {
		return e
	}
	r := row(p)
	e := windows.GetUnicastIpAddressEntry(&r)
	if e == windows.ERROR_NOT_FOUND || e == windows.ERROR_FILE_NOT_FOUND {
		return nil
	}
	if e != nil {
		return e
	}
	if !own(p, r) {
		return fmt.Errorf("USB_HOST_ADDRESS_OWNERSHIP_CHANGED")
	}
	rc, _, _ := windows.NewLazySystemDLL("iphlpapi.dll").NewProc("DeleteUnicastIpAddressEntry").Call(uintptr(unsafe.Pointer(&r)))
	if rc != 0 {
		return fmt.Errorf("USB_HOST_DELETE_%d", rc)
	}
	r = row(p)
	e = windows.GetUnicastIpAddressEntry(&r)
	if e != windows.ERROR_NOT_FOUND && e != windows.ERROR_FILE_NOT_FOUND {
		return fmt.Errorf("USB_HOST_ABSENCE_UNCONFIRMED")
	}
	return nil
}
func save(path string, p journal, replace bool) error {
	b, _ := json.Marshal(p)
	file := path
	if replace {
		file = path + ".new"
	}
	f, e := os.OpenFile(file, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if e != nil {
		return e
	}
	_, e = f.Write(b)
	if e == nil {
		e = f.Sync()
	}
	ce := f.Close()
	if e != nil || ce != nil {
		return fmt.Errorf("USB_HOST_JOURNAL_WRITE_FAILED")
	}
	if replace {
		e = windows.MoveFileEx(windows.StringToUTF16Ptr(file), windows.StringToUTF16Ptr(path), windows.MOVEFILE_REPLACE_EXISTING|windows.MOVEFILE_WRITE_THROUGH)
	}
	if e != nil {
		return e
	}
	got, e := os.ReadFile(path)
	if e != nil || !bytes.Equal(got, b) {
		return fmt.Errorf("USB_HOST_JOURNAL_READBACK_FAILED")
	}
	return nil
}
func findHost() (windows.MibIfRow2, bool, error) {
	var table *windows.MibIfTable2
	if e := windows.GetIfTable2Ex(windows.MibIfEntryNormal, &table); e != nil {
		return windows.MibIfRow2{}, false, e
	}
	if table == nil {
		return windows.MibIfRow2{}, false, fmt.Errorf("USB_HOST_INTERFACE_TABLE_INVALID")
	}
	defer windows.FreeMibTable(unsafe.Pointer(table))
	if table.NumEntries > 65536 {
		return windows.MibIfRow2{}, false, fmt.Errorf("USB_HOST_INTERFACE_TABLE_INVALID")
	}
	var found windows.MibIfRow2
	var candidates []hostIdentity
	for _, r := range unsafe.Slice(&table.Table[0], int(table.NumEntries)) {
		if strings.EqualFold(r.InterfaceGuid.String(), usbaddress.HostGUID) || windows.UTF16ToString(r.Alias[:]) == usbaddress.HostName {
			candidates = append(candidates, hostIdentity{GUID: r.InterfaceGuid.String(), Alias: windows.UTF16ToString(r.Alias[:]), Type: r.Type, Index: r.InterfaceIndex, LUID: r.InterfaceLuid})
			found = r
		}
	}
	return found, len(candidates) != 0, validateHostCandidates(candidates)
}

func recoveryAddresses(index uint32, luid uint64) ([]recoveryAddress, error) {
	var table *windows.MibUnicastIpAddressTable
	if e := windows.GetUnicastIpAddressTable(windows.AF_INET, &table); e != nil {
		return nil, e
	}
	if table == nil {
		return nil, fmt.Errorf("USB_HOST_ADDRESS_TABLE_INVALID")
	}
	defer windows.FreeMibTable(unsafe.Pointer(table))
	if table.NumEntries > 65536 {
		return nil, fmt.Errorf("USB_HOST_ADDRESS_TABLE_INVALID")
	}
	var addresses []recoveryAddress
	for _, r := range unsafe.Slice(&table.Table[0], int(table.NumEntries)) {
		if !recoveryAddressMatches(index, luid, r.InterfaceIndex, r.InterfaceLuid) {
			continue
		}
		v := (*windows.RawSockaddrInet4)(unsafe.Pointer(&r.Address))
		if v.Family != windows.AF_INET {
			return nil, fmt.Errorf("USB_HOST_ADDRESS_TABLE_INVALID")
		}
		addresses = append(addresses, recoveryAddress{Index: r.InterfaceIndex, LUID: r.InterfaceLuid, Address: v.Addr, Prefix: r.OnLinkPrefixLength, PrefixOrigin: r.PrefixOrigin, SuffixOrigin: r.SuffixOrigin, ValidLifetime: r.ValidLifetime, PreferredLifetime: r.PreferredLifetime, Created: stamp(r)})
	}
	return addresses, nil
}
func Recover(dir string) error {
	hostOperationMu.Lock()
	defer hostOperationMu.Unlock()
	e := recoverUnlocked(dir)
	if e == errClosedOwnedNonpresent || e == errOwnedPersistentOpen || e == errPersistentFactoryCreate {
		return nil
	}
	return e
}
func recoverUnlocked(dir string) error {
	path := filepath.Join(dir, "usb-host-address.json")
	b, e := readHostDiagnosticJournal(path)
	intent, intentPresent, intentErr := readRemovalIntentFile(dir)
	if intentErr != nil {
		return intentErr
	}
	transaction, transactionPresent, te := readRecreateTransactionFile(dir)
	if te != nil {
		return te
	}
	factory, factoryPresent, fe := readPersistentFactory(dir)
	if fe != nil {
		return fe
	}
	if factoryPresent {
		if intentPresent || transactionPresent {
			return fmt.Errorf("USB_HOST_FACTORY_LEGACY_INTENT_CONFLICT")
		}
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		return recoverPersistentHostFactory(ctx, dir, factory)
	}
	if intentPresent && transactionPresent {
		return fmt.Errorf("USB_HOST_RECREATE_CONFLICTS_WITH_REMOVAL")
	}
	if intentPresent {
		if e != nil && !os.IsNotExist(e) {
			return fmt.Errorf("USB_HOST_JOURNAL_UNREADABLE")
		}
		return finishRemoval(dir, path, intent, b, e == nil)
	}
	if transactionPresent {
		if e != nil {
			return fmt.Errorf("USB_HOST_RECREATE_JOURNAL_UNREADABLE")
		}
		if transaction.State == "closing" {
			e = finishClosingTransaction(dir, path, transaction, b)
		} else {
			e = finishRecreateTransaction(dir, path, transaction, b, false)
		}
		if e != nil {
			return e
		}
		b, e = readHostDiagnosticJournal(path)
	}
	if os.IsNotExist(e) {
		return nil
	}
	if e != nil || len(b) > 2048 {
		return fmt.Errorf("USB_HOST_JOURNAL_UNREADABLE")
	}
	p, e := decodeJournal(b)
	if e != nil {
		return e
	}
	ownedPersistent, pe := interfaceconfig.HasPersistentObligation(dir, hostScope(p))
	if pe != nil {
		return pe
	}
	r, present, e := findHost()
	if e != nil {
		return e
	}
	if !present {
		if p.Version == 2 || ownedPersistent {
			return fmt.Errorf("USB_HOST_PERSISTENT_ADAPTER_ABSENT")
		}
		absent, err := netconfig.ConfirmSharedHostAbsentNative()
		if err != nil || !absent {
			return fmt.Errorf("USB_HOST_ADAPTER_ABSENCE_UNCONFIRMED")
		}
		return os.Remove(path)
	}
	if p.Created == 0 {
		return fmt.Errorf("USB_HOST_INCOMPLETE_CREATION_PENDING")
	}
	initial := hostIdentity{GUID: r.InterfaceGuid.String(), Alias: windows.UTF16ToString(r.Alias[:]), Type: r.Type, Index: r.InterfaceIndex, LUID: r.InterfaceLuid}
	nonpresent := false
	attempts, e := readRecoveryDriverIdentity(initial, func() (hostIdentity, bool, error) {
		current, present, e := findHost()
		return hostIdentity{GUID: current.InterfaceGuid.String(), Alias: windows.UTF16ToString(current.Alias[:]), Type: current.Type, Index: current.InterfaceIndex, LUID: current.InterfaceLuid}, present, e
	}, func(index uint32) error {
		var err error
		nonpresent, err = netconfig.VerifySharedHostRecoveryIdentityNative(index)
		return err
	}, time.Sleep)
	live.Lock()
	live.identityReadback = map[string]any{"attempts": attempts, "verified": e == nil, "nonpresent": nonpresent}
	if e != nil {
		live.identityReadback["problem"] = "USB_HOST_DRIVER_READBACK_UNCONFIRMED"
	}
	live.Unlock()
	if e != nil {
		return e
	}
	addresses, e := recoveryAddresses(r.InterfaceIndex, r.InterfaceLuid)
	if e != nil {
		return e
	}
	if nonpresent {
		if e = validateNonpresentRecoveryOwnership(p, r.InterfaceLuid, len(addresses)); e != nil {
			return e
		}
		// A retained software-device installation and its NetIO identity are
		// not an orphan-removal obligation. Start may re-enumerate only through
		// a separately durable exact owned creation transaction.
		return errOwnedNonpresentRecreate
	}
	if p.Version == 2 || ownedPersistent {
		if !interfaceconfig.PersistentEnabled() {
			return fmt.Errorf("USB_HOST_PERSISTENT_OPTION_DISABLED")
		}
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		if e = checkpointPersistentHost(ctx, dir, path, b, p, r.InterfaceIndex, r.InterfaceLuid); e != nil {
			return e
		}
		return errOwnedPersistentOpen
	}
	next, state, e := rebindRecovery(p, r.InterfaceIndex, r.InterfaceLuid, addresses)
	live.Lock()
	live.recovery = map[string]any{"previous_index": p.Index, "previous_luid": p.LUID, "current_index": r.InterfaceIndex, "current_luid": r.InterfaceLuid, "mapping_changed": p.Index != r.InterfaceIndex || p.LUID != r.InterfaceLuid, "address_state": state, "ipv4_count": len(addresses), "driver_verified": true}
	live.recovery["original_created_stamp"] = p.Created
	live.recovery["original_planned_stamp"] = p.Planned
	if len(addresses) == 1 {
		live.recovery["current_address_created_stamp"] = addresses[0].Created
	}
	live.Unlock()
	if e != nil {
		return e
	}
	if e = checkInterface(next); e != nil {
		return e
	}
	if e = checkpointMapping(p, next, func(n journal) error { return save(path, n, true) }, func() ([]byte, error) { return readHostDiagnosticJournal(path) }); e != nil {
		return e
	}
	p = next
	if e = remove(p); e != nil {
		return e
	}
	// Bind the original durable journal bytes before the exact native deletion.
	b, e = readHostDiagnosticJournal(path)
	if e != nil {
		return fmt.Errorf("USB_HOST_JOURNAL_UNREADABLE")
	}
	current, err := decodeJournal(b)
	if err != nil || current != p {
		return fmt.Errorf("USB_HOST_REMOVAL_JOURNAL_CHANGED")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	var pending removalIntent
	removeNative := netconfig.RemoveVerifiedSharedHostNative
	result, removeErr := removeNative(ctx, p.Index, p.LUID, func(instance string) error {
		fresh, err := readHostDiagnosticJournal(path)
		if err != nil || !bytes.Equal(fresh, b) {
			return fmt.Errorf("USB_HOST_REMOVAL_JOURNAL_CHANGED")
		}
		pending = removalIntent{Version: 1, JournalSHA256: journalDigest(b), Instance: instance, Ticks: systemTicks(), State: "intent"}
		if err = writeRemovalIntentFile(dir, pending, false); err != nil {
			return err
		}
		fresh, err = readHostDiagnosticJournal(path)
		if err != nil || !bytes.Equal(fresh, b) {
			return fmt.Errorf("USB_HOST_REMOVAL_JOURNAL_CHANGED")
		}
		return nil
	})
	if pending.Ticks == 0 {
		return removeErr
	}
	if removeErr != nil {
		if result.RestartRequired {
			pending.State = "restart_required"
		} else if result.Attempted && !result.FlagsReadable {
			pending.State = "flags_unreadable"
		}
		if e = writeRemovalIntentFile(dir, pending, true); e != nil {
			return e
		}
		return removeErr
	}
	if !result.FlagsReadable || result.RestartRequired || !result.AbsenceVerified {
		return fmt.Errorf("USB_HOST_NATIVE_REMOVAL_INCOMPLETE")
	}
	pending.State = "complete"
	if e = writeRemovalIntentFile(dir, pending, true); e != nil {
		return e
	}
	return finishRemoval(dir, path, pending, b, true)
}
func Start(ctx context.Context, dir, dllPath string) (func() error, error) {
	hostOperationMu.Lock()
	defer hostOperationMu.Unlock()
	if e := ctx.Err(); e != nil {
		return nil, e
	}
	recoveryErr := recoverUnlocked(dir)
	if recoveryErr == errClosedOwnedNonpresent {
		recoveryErr = errOwnedNonpresentRecreate
	}
	if recoveryErr != nil && recoveryErr != errOwnedNonpresentRecreate && recoveryErr != errOwnedPersistentOpen && recoveryErr != errPersistentFactoryCreate {
		return nil, recoveryErr
	}
	if e := ctx.Err(); e != nil {
		return nil, e
	}
	if requested, e := interfaceconfig.PersistentRestoreRequested(dir); e != nil {
		return nil, e
	} else if requested {
		return nil, fmt.Errorf("USB_HOST_UNINSTALL_PENDING")
	}
	if _, present, e := findHost(); e != nil {
		return nil, e
	} else if present && recoveryErr != errOwnedNonpresentRecreate && recoveryErr != errOwnedPersistentOpen && recoveryErr != errPersistentFactoryCreate {
		return nil, fmt.Errorf("USB_HOST_UNOWNED_ADAPTER_EXISTS")
	}
	// Retire only fully absent old volatile targets before any official factory.
	if ids, err := interfaceconfig.ReadOwnedDADObligations(dir); err == nil {
		for _, id := range ids {
			if id.Scope.Role == "host" {
				_ = interfaceconfig.RetireOwnedDADAbsent(ctx, dir, id)
			}
		}
	}
	var d *wintun.Device
	var transaction *recreateTransaction
	p := journal{Version: 1, GUID: usbaddress.HostGUID, Planned: nowStamp()}
	path := filepath.Join(dir, "usb-host-address.json")
	if recoveryErr == errPersistentFactoryCreate {
		var e error
		d, p, e = preparePersistentHostFactory(ctx, dir, dllPath)
		if e != nil {
			return nil, e
		}
	} else if recoveryErr == errOwnedPersistentOpen {
		var e error
		d, p, e = openPersistentHost(ctx, dir, dllPath)
		if e != nil {
			return nil, e
		}
	} else if recoveryErr == errOwnedNonpresentRecreate {
		var e error
		d, p, transaction, e = prepareOwnedNonpresent(ctx, dir, dllPath)
		if e != nil {
			return nil, e
		}
	} else {
		var token [12]byte
		if _, e := rand.Read(token[:]); e != nil {
			return nil, e
		}
		p.Token = hex.EncodeToString(token[:])
		if e := save(path, p, false); e != nil {
			return nil, e
		}
		dllPin, e := netconfig.PinVerifiedWintunNative(dllPath, log.New(os.Stderr, "USB host: ", 0))
		if e != nil {
			os.Remove(path)
			return nil, e
		}
		if e := ctx.Err(); e != nil {
			if closeErr := dllPin.Close(); closeErr != nil {
				log.Print("USB_HOST_DLL_PIN_CLOSE_WARNING")
			}
			return nil, e
		}
		d, e = wintun.OpenNamed(dllPath, usbaddress.HostName, usbaddress.HostGUID)
		if closeErr := dllPin.Close(); closeErr != nil {
			log.Print("USB_HOST_DLL_PIN_CLOSE_WARNING")
		}
		if e != nil {
			if _, present, query := findHost(); query == nil && !present {
				os.Remove(path)
			}
			return nil, e
		}
	}
	var e error
	success := false
	defer func() {
		if !success {
			if p.Created > 0 && p.Version != 2 && !interfaceconfig.PersistentEnabled() {
				if _, found, ie := readRecreateTransactionFile(dir); ie == nil && !found {
					_ = closeOwnedHost(dir, p, d)
				}
			}
			d.Close()
			if transaction != nil {
				recordRecreate("close_pending", "USB_HOST_RECREATE_CLOSE_UNCONFIRMED", nil)
			}
		}
	}()
	p.Index = d.Index
	p.LUID = d.LUID
	if transaction == nil && recoveryErr != errPersistentFactoryCreate && recoveryErr != errOwnedPersistentOpen {
		e = save(path, p, true)
	}
	if e != nil {
		return nil, e
	}
	if e = ctx.Err(); e != nil {
		return nil, e
	}
	if e = prepareHostFlags(ctx, p); e != nil {
		return nil, e
	}
	if recoveryErr == errOwnedPersistentOpen {
		if e = restoreReadyHostDADProjection(ctx, dir, p); e != nil {
			return nil, e
		}
	}
	dadScope := hostScope(p)
	if _, e = interfaceconfig.ApplyDADZero(ctx, dir, dadScope, func() error { return verifyHostConfigScope(dadScope) }); e != nil {
		return nil, e
	}
	if interfaceconfig.OwnedDADZeroEnabled() {
		if e = verifyHostConfigScope(dadScope); e != nil {
			return nil, e
		}
		instance, captureError := netconfig.CaptureSharedHostHealthyNative(p.Index, p.LUID)
		observation := interfaceconfig.Observation{Kind: "owned_dad_zero", Code: "USB_OWNED_DAD_SOURCE_UNPROVEN"}
		if captureError == nil {
			owner := func() error {
				if !d.HandleHeld() {
					return fmt.Errorf("USB_HOST_OWNED_DAD_HANDLE_LOST")
				}
				if transaction != nil {
					return verifyRecreatedDADOwner(ctx, dir, path, p, d, *transaction, instance)
				}
				current, err := readHostDiagnosticJournal(path)
				if err != nil {
					return err
				}
				saved, err := decodeJournal(current)
				if err != nil || saved.LUID != p.LUID || saved.Index != p.Index || saved.Token != p.Token {
					return fmt.Errorf("USB_HOST_OWNED_DAD_JOURNAL_CHANGED")
				}
				if err = verifyHostConfigScope(dadScope); err != nil {
					return err
				}
				return netconfig.VerifySharedHostRecreatedNative(p.Index, p.LUID, instance)
			}
			if e = owner(); e != nil {
				return nil, e
			}
			observation, captureError = interfaceconfig.ApplyOwnedDADZero(ctx, dir, interfaceconfig.OwnedDADIdentity{Scope: dadScope, Instance: instance}, owner)
			if e = owner(); e != nil {
				return nil, e
			}
		}
		live.Lock()
		live.ownedDAD = observation
		live.Unlock()
		if captureError != nil {
			log.Printf("USB_HOST_OWNED_DAD_DEGRADED: %s", observation.Code)
		}
	}
	if recoveryErr != errOwnedPersistentOpen && recoveryErr != errPersistentFactoryCreate {
		p.Planned = nowStamp()
		if transaction == nil {
			e = save(path, p, true)
		} else {
			next := *transaction
			next.Next = p
			e = writeRecreateTransactionFile(dir, next, true)
			if e == nil {
				*transaction = next
			}
		}
		if e != nil {
			return nil, e
		}
		if transaction != nil {
			if e = verifyRecreateMapped(*transaction, p, true); e != nil {
				return nil, e
			}
		}
		r := row(p)
		e = windows.GetUnicastIpAddressEntry(&r)
		if e != windows.ERROR_NOT_FOUND && e != windows.ERROR_FILE_NOT_FOUND {
			return nil, fmt.Errorf("USB_HOST_ADDRESS_NOT_ABSENT")
		}
		if e = ctx.Err(); e != nil {
			return nil, e
		}
		rc, _, _ := windows.NewLazySystemDLL("iphlpapi.dll").NewProc("CreateUnicastIpAddressEntry").Call(uintptr(unsafe.Pointer(&r)))
		if rc != 0 {
			return nil, fmt.Errorf("USB_HOST_CREATE_%d", rc)
		}
		for i := 0; i < 50 && ctx.Err() == nil; i++ {
			r = row(p)
			if windows.GetUnicastIpAddressEntry(&r) == nil && r.DadState == 4 {
				p.Created = stamp(r)
				break
			}
			time.Sleep(100 * time.Millisecond)
		}
		if p.Created == 0 {
			return nil, fmt.Errorf("USB_HOST_DAD_UNCONFIRMED")
		}
		if e = ctx.Err(); e != nil {
			return nil, e
		}
		if transaction == nil {
			e = save(path, p, true)
		} else {
			e = commitRecreatedAddress(dir, path, transaction, p)
		}
		if e != nil {
			return nil, e
		}
	}
	if interfaceconfig.PersistentEnabled() && recoveryErr != errOwnedPersistentOpen && recoveryErr != errPersistentFactoryCreate {
		hs := hostScope(p)
		if _, e = interfaceconfig.ApplyPersistentHost(ctx, dir, hs, func() error { return verifyHostConfigScope(hs) }, hostProfileOps(hs)); e != nil {
			return nil, e
		}
		before, be := readHostDiagnosticJournal(path)
		if be != nil {
			return nil, be
		}
		if e = checkpointPersistentHost(ctx, dir, path, before, p, p.Index, p.LUID); e != nil {
			return nil, e
		}
		bytes, e2 := readHostDiagnosticJournal(path)
		if e2 != nil {
			return nil, e2
		}
		p, e2 = decodeJournal(bytes)
		if e2 != nil {
			return nil, e2
		}
	}
	if p.Version == 2 && recoveryErr != errOwnedPersistentOpen && recoveryErr != errPersistentFactoryCreate {
		if e = capturePersistentHostFactory(ctx, dir, p, d); e != nil {
			return nil, e
		}
	}
	live.Lock()
	live.p = p
	live.Unlock()
	done := make(chan struct{})
	stop := make(chan struct{})
	var once sync.Once
	var result error
	go func() {
		defer close(done)
		ticker := time.NewTicker(5 * time.Minute)
		defer ticker.Stop()
		for {
			select {
			case <-stop:
				return
			case <-ticker.C:
				if p.Version == 2 && p.AddressMode == "persistent" {
					continue
				}
				r := row(p)
				if windows.GetUnicastIpAddressEntry(&r) != nil || !own(p, r) {
					SetProblem(fmt.Errorf("USB_HOST_REFRESH_OWNERSHIP_CHANGED"))
					return
				}
				r.ValidLifetime = 3600
				r.PreferredLifetime = 3600
				rc, _, _ := windows.NewLazySystemDLL("iphlpapi.dll").NewProc("SetUnicastIpAddressEntry").Call(uintptr(unsafe.Pointer(&r)))
				if rc != 0 {
					SetProblem(fmt.Errorf("USB_HOST_REFRESH_%d", rc))
					return
				}
			}
		}
	}()
	success = true
	return func() error {
		hostOperationMu.Lock()
		defer hostOperationMu.Unlock()
		once.Do(func() {
			close(stop)
			<-done
			live.Lock()
			live.p = journal{}
			live.Unlock()
			if requested, err := interfaceconfig.OwnedDADRestoreRequested(dir); err != nil {
				result = err
			} else if requested {
				hs := hostScope(p)
				instance, err := netconfig.CaptureSharedHostHealthyNative(hs.Index, hs.LUID)
				if err != nil {
					result = err
				} else {
					result = interfaceconfig.RestoreOwnedDADZero(context.Background(), dir, interfaceconfig.OwnedDADIdentity{Scope: hs, Instance: instance}, func() error {
						if !d.HandleHeld() {
							return fmt.Errorf("USB_HOST_OWNED_DAD_HANDLE_LOST")
						}
						if err := verifyHostConfigScope(hs); err != nil {
							return err
						}
						return netconfig.VerifySharedHostRecreatedNative(hs.Index, hs.LUID, instance)
					})
				}
			}
			if result != nil {
				d.Close()
				return
			}
			if p.Version == 2 {
				result = closePersistentHost(dir, p, d)
			} else {
				hs := hostScope(p)
				result = interfaceconfig.RestoreDADZero(context.Background(), dir, hs, func() error { return verifyHostConfigScope(hs) })
				if result == nil {
					result = closeOwnedHost(dir, p, d)
				} else {
					d.Close()
				}
			}
			if result != nil {
				SetProblem(result)
			}
		})
		return result
	}, nil
}

func Proof() (usbaddress.InterfaceProof, bool) {
	if !sharedHostPublished() {
		return usbaddress.InterfaceProof{}, false
	}
	return PreparedProof()
}

// Only the supervisor preparation callback may use this before publication.
func PreparedProof() (usbaddress.InterfaceProof, bool) {
	live.Lock()
	p := live.p
	live.Unlock()
	if p.Created == 0 || checkInterface(p) != nil {
		return usbaddress.InterfaceProof{}, false
	}
	r := row(p)
	if windows.GetUnicastIpAddressEntry(&r) != nil || r.DadState != 4 || !own(p, r) {
		return usbaddress.InterfaceProof{}, false
	}
	return usbaddress.InterfaceProof{Index: p.Index, GUID: usbaddress.HostGUID, LUID: p.LUID, Role: "host", Created: p.Created, AddressMode: hostProofMode(p)}, true
}

func SetProblem(e error) {
	live.Lock()
	defer live.Unlock()
	live.problem = ""
	if e != nil {
		live.problem = e.Error()
	}
}

// Called after the one Mac bridge has drained and restored its network. The
// remaining native iPad connection keeps its 1500-byte service receive MTU.
func ResetMacMTU(ctx context.Context) error {
	p, ready := Proof()
	if !ready {
		return nil
	}
	return usbaddress.SetHostMTU(ctx, p, 1500)
}
func Details() any {
	p, ready := Proof()
	live.Lock()
	problem := live.problem
	recovery := live.recovery
	identityReadback := live.identityReadback
	recreate := live.recreate
	ownedDAD := live.ownedDAD
	live.Unlock()
	out := map[string]any{"ready": ready, "error": problem, "address": "10.6.9.1", "index": p.Index, "supervisor": SharedHostSupervisorDetails()}
	if recovery != nil {
		out["startup_recovery"] = recovery
	}
	if identityReadback != nil {
		out["startup_driver_identity_readback"] = identityReadback
	}
	if recreate != nil {
		out["startup_recreate"] = recreate
	}
	if ownedDAD.Kind != "" {
		out["owned_dad_zero"] = ownedDAD
	}
	if timings := PersistentHostFactoryTimingsSnapshot(); len(timings) > 0 {
		out["persistent_factory_timings"] = timings
	}
	if ready {
		r := windows.MibIpInterfaceRow{Family: windows.AF_INET, InterfaceLuid: p.LUID}
		if windows.GetIpInterfaceEntry(&r) == nil {
			out["weak_host_send"] = r.WeakHostSend != 0
			out["weak_host_receive"] = r.WeakHostReceive != 0
			out["local_delivery_forwarding"] = r.ForwardingEnabled != 0
			out["mtu"] = r.NlMtu
		}
	}
	return out
}

func prepareHostFlags(ctx context.Context, p journal) error {
	f := windows.MibIpInterfaceRow{Family: windows.AF_INET, InterfaceLuid: p.LUID}
	if e := windows.GetIpInterfaceEntry(&f); e != nil {
		return e
	}
	f.SitePrefixLength = 0
	// Start at the native iPad/baseline MTU. A Mac raises this only after its
	// own nonce-verified roundtrip and IPv4 MTU readback, never speculatively.
	f.NlMtu = 1500
	f.ForwardingEnabled = 1
	f.WeakHostSend = 1
	f.WeakHostReceive = 1
	if e := ctx.Err(); e != nil {
		return e
	}
	rc, _, _ := windows.NewLazySystemDLL("iphlpapi.dll").NewProc("SetIpInterfaceEntry").Call(uintptr(unsafe.Pointer(&f)))
	if rc != 0 {
		return fmt.Errorf("USB_HOST_FLAGS_%d", rc)
	}
	f = windows.MibIpInterfaceRow{Family: windows.AF_INET, InterfaceLuid: p.LUID}
	if windows.GetIpInterfaceEntry(&f) != nil || f.WeakHostSend != 1 || f.WeakHostReceive != 1 || f.ForwardingEnabled != 1 || f.NlMtu != 1500 {
		return fmt.Errorf("USB_HOST_FLAGS_READBACK_FAILED")
	}
	return nil
}
