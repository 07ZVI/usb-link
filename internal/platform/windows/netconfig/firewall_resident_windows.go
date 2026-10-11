//go:build windows && amd64

package netconfig

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"path/filepath"
	"reflect"
	"strings"
	"suhang/usbnet/internal/transport/ipadsession"
	"suhang/usbnet/internal/transport/usbaddress"
	"suhang/usbnet/internal/platform/windows/wincom"
)

// PreparedResidentFirewall is scoped to one fixed role and one live verified
// owner. Fragment has only established PowerShell mutations; Finish always
// audits fresh native readback and never treats a partial script as success.
// Caller retains its ordinary topology/owner lease across the combined batch.
type PreparedResidentFirewall struct {
	dir      string
	ledger   residentLedger
	expected []byte
	fragment string
	verify   func(context.Context) error
	remove   bool
}

func (p *PreparedResidentFirewall) Fragment() string {
	if p == nil {
		return ""
	}
	return p.fragment
}
func (p *PreparedResidentFirewall) Finish(ctx context.Context) (err error) {
	defer func() {
		if p != nil {
			recordResidentOperation(p.ledger.Role, "finish", err)
		}
	}()
	if p == nil || ctx == nil {
		return errors.New("USB_RESIDENT_PLAN_INVALID")
	}
	release, e := usbaddress.ConfigurationLock(ctx)
	if e != nil {
		return e
	}
	defer release()
	if e = p.verify(ctx); e != nil {
		return e
	}
	b, found, e := readResidentLedgerFile(p.dir, p.ledger.Role)
	if e != nil || (!found && p.expected != nil) || (found && !bytes.Equal(b, p.expected)) {
		return errors.New("USB_RESIDENT_LEDGER_CHANGED")
	}
	obs, e := residentReadRules(ctx, p.ledger.Specs, p.verify)
	if e != nil {
		return e
	}
	if p.remove {
		for _, o := range obs {
			if o.Present {
				return errors.New("USB_RESIDENT_RULE_REMAINS")
			}
		}
		if !found {
			return nil
		}
		if e = p.verify(ctx); e != nil {
			return e
		}
		return clearResidentLedgerFile(p.dir, p.ledger.Role, p.expected)
	}
	for i, o := range obs {
		if !o.Present {
			return errors.New("USB_RESIDENT_RULE_MISSING")
		}
		if e = verifyResidentFirewallConstraints(o.Constraints, p.ledger.Specs[i], 1); e != nil {
			return e
		}
	}
	if e = p.verify(ctx); e != nil {
		return e
	}
	if p.ledger.Phase == "complete" && found {
		got, ok, err := readResidentLedgerFile(p.dir, p.ledger.Role)
		if err != nil || !ok || !bytes.Equal(got, p.expected) {
			return errors.New("USB_RESIDENT_LEDGER_CHANGED")
		}
		return nil
	}
	v := p.ledger
	v.Phase = "complete"
	v.Before = obs
	v.Previous = nil
	if e = writeResidentLedgerFile(p.dir, v, p.expected); e != nil {
		return e
	}
	p.ledger = v
	p.expected, _ = json.Marshal(v)
	return p.verify(ctx)
}

func residentReadRules(ctx context.Context, specs []nativeRuleSpec, verify func(context.Context) error) ([]residentRuleObservation, error) {
	var out []residentRuleObservation
	if ctx == nil || verify == nil {
		return nil, errors.New("USB_RESIDENT_OWNER_REQUIRED")
	}
	e := withFirewall(ctx, func(svc *wincom.Dispatch) error {
		for _, s := range specs {
			var first residentRuleObservation
			var fingerprint string
			for i := 0; i < 2; i++ {
				if e := verify(ctx); e != nil {
					return e
				}
				r, e := matchingRule(svc, s.Name)
				if e != nil {
					return e
				}
				o := residentRuleObservation{Present: r != nil}
				if r != nil {
					o.Constraints, e = readFirewallConstraintsMode(r, residentMacAppPathReadScope(specs))
					r.Close()
					if e != nil {
						return e
					}
				}
				h := "ABSENT"
				if o.Present {
					h, e = firewallFingerprint(o.Constraints)
					if e != nil {
						return e
					}
				}
				if i == 0 {
					first = o
					fingerprint = h
				} else if h != fingerprint {
					return errors.New("USB_RESIDENT_CONSTRAINT_CHANGED")
				}
			}
			if e := verify(ctx); e != nil {
				return e
			}
			out = append(out, first)
		}
		return nil
	})
	return out, e
}
func residentVerifier(p usbaddress.InterfaceProof, owner func() error) func(context.Context) error {
	return func(ctx context.Context) error {
		if ctx == nil || owner == nil {
			return errors.New("USB_RESIDENT_OWNER_REQUIRED")
		}
		if e := ctx.Err(); e != nil {
			return e
		}
		if e := owner(); e != nil {
			return e
		}
		if strings.EqualFold(p.GUID, NativeMacGUID) {
			if e := VerifyOwnedWintunRecoveryIdentityNative(ctx, OwnedProfileRecoveryIdentity{Role: "mac", GUID: p.GUID, Index: p.Index, LUID: p.LUID}, owner); e != nil {
				return e
			}
		}
		if strings.EqualFold(p.GUID, usbaddress.HostGUID) {
			if p.Role != "host" || p.Created <= 0 {
				return errors.New("USB_RESIDENT_HOST_PROOF_REQUIRED")
			}
			if e := VerifySharedHostIdentityNative(p.Index); e != nil {
				return e
			}
		}
		_, e := nativeRuleInterface(ctx, p)
		if e != nil {
			return e
		}
		return owner()
	}
}
func prepareResident(ctx context.Context, dir, role string, p usbaddress.InterfaceProof, exe string, owner func() error, legacyProgramOwner ...func(string) error) (result *PreparedResidentFirewall, err error) {
	defer func() { recordResidentOperation(role, "prepare", err) }()
	if ctx == nil || owner == nil {
		return nil, errors.New("USB_RESIDENT_OWNER_REQUIRED")
	}
	release, e := usbaddress.ConfigurationLock(ctx)
	if e != nil {
		return nil, e
	}
	defer release()
	verify := residentVerifier(p, owner)
	if e = verify(ctx); e != nil {
		return nil, e
	}
	alias, e := nativeRuleInterface(ctx, p)
	if e != nil {
		return nil, e
	}
	specs, e := residentSpecs(role, p.GUID, alias, exe)
	if e != nil {
		return nil, e
	}
	b, found, e := readResidentLedgerFile(dir, role)
	if e != nil {
		return nil, e
	}
	var old residentLedger
	if found {
		old, e = decodeResidentLedger(b)
		if e != nil {
			return nil, e
		}
		if old.Role != role || old.GUID != p.GUID || old.Phase == "removing" {
			return nil, errors.New("USB_RESIDENT_LEDGER_SCOPE_CHANGED")
		}
	}
	obs, e := residentReadRules(ctx, specs, verify)
	if e != nil {
		return nil, e
	}
	recognizedLegacy := false
	if !found && len(legacyProgramOwner) != 0 {
		if len(legacyProgramOwner) != 1 || legacyProgramOwner[0] == nil {
			return nil, errors.New("USB_RESIDENT_LEGACY_SOURCE_REQUIRED")
		}
		legacy, e := residentRecognizeLegacySource(specs, obs, role, p.GUID, alias, legacyProgramOwner[0])
		if e != nil {
			return nil, e
		}
		if legacy != nil {
			again, e := residentReadRules(ctx, specs, verify)
			if e != nil {
				return nil, e
			}
			if !reflect.DeepEqual(again, obs) {
				return nil, errors.New("USB_RESIDENT_CONSTRAINT_CHANGED")
			}
			if e = legacyProgramOwner[0](legacy[0].Program); e != nil {
				return nil, e
			}
			old.Specs = legacy
			recognizedLegacy = true
		}
	}
	changed := []int{}
	for i, o := range obs {
		if !o.Present {
			changed = append(changed, i)
			continue
		}
		if verifyResidentFirewallConstraints(o.Constraints, specs[i], 1) == nil {
			continue
		}
		if !found && !recognizedLegacy {
			return nil, errors.New("USB_RESIDENT_UNKNOWN_RULE")
		}
		prior := old.Specs[i]
		if len(old.Previous) != 0 && residentRepairAllowed(o.Constraints, prior) != nil {
			prior = old.Previous[i]
		}
		if e = residentRepairAllowed(o.Constraints, prior); e != nil {
			return nil, e
		}
		changed = append(changed, i)
	}
	if e = verify(ctx); e != nil {
		return nil, e
	}
	plan := &PreparedResidentFirewall{dir: dir, verify: verify, expected: b}
	if found && old.Phase == "complete" && reflect.DeepEqual(old.Specs, specs) && len(changed) == 0 {
		plan.ledger = old
		return plan, nil
	}
	var id [12]byte
	if _, e = rand.Read(id[:]); e != nil {
		return nil, e
	}
	v := residentLedger{Version: 1, Role: role, GUID: p.GUID, Phase: "prepared", ID: hex.EncodeToString(id[:]), Specs: specs, Before: obs}
	if (found || recognizedLegacy) && !reflect.DeepEqual(old.Specs, specs) {
		v.Previous = old.Specs
	}
	if e = writeResidentLedgerFile(dir, v, b); e != nil {
		return nil, e
	}
	plan.ledger = v
	plan.expected, _ = json.Marshal(v)
	if len(changed) != 0 {
		leaf, _ := residentLeaf(role)
		plan.fragment = residentScript(filepath.Join(dir, leaf), plan.expected, v, changed, p.Index)
	}
	return plan, nil
}
func PrepareResidentMacFirewall(ctx context.Context, dir string, p usbaddress.InterfaceProof, owner func() error) (*PreparedResidentFirewall, error) {
	return prepareResident(ctx, dir, "mac", p, "", owner)
}
func PrepareResidentCoreFirewall(ctx context.Context, dir string, p usbaddress.InterfaceProof, peer, exe string, owner func() error, legacyProgramOwner ...func(string) error) (*PreparedResidentFirewall, error) {
	role := "core_mac"
	if peer == "10.6.9.3" {
		role = "core_ipad"
	} else if peer != "10.6.9.2" {
		recordResidentOperation("core_mac", "prepare", errors.New("USB_RESIDENT_SCOPE_INVALID"))
		return nil, errors.New("USB_RESIDENT_SCOPE_INVALID")
	}
	return prepareResident(ctx, dir, role, p, exe, owner, legacyProgramOwner...)
}
func PrepareResidentHostFirewall(ctx context.Context, dir string, p usbaddress.InterfaceProof, exe string, owner func() error, legacyProgramOwner ...func(string) error) (*PreparedResidentFirewall, error) {
	return prepareResident(ctx, dir, "host", p, exe, owner, legacyProgramOwner...)
}
func PrepareResidentIPadFirewall(ctx context.Context, dir string, p ipadsession.Plan, owner func() error) (*PreparedResidentFirewall, error) {
	if !p.Valid() || p.Version < 4 || p.ServerIP != "10.6.9.1" || p.PeerIP() != "10.6.9.3" {
		recordResidentOperation("ipad", "prepare", errors.New("USB_RESIDENT_SCOPE_INVALID"))
		return nil, errors.New("USB_RESIDENT_SCOPE_INVALID")
	}
	return prepareResident(ctx, dir, "ipad", usbaddress.InterfaceProof{GUID: p.GUID, Index: p.Index, LUID: p.LUID}, "", owner)
}

func verifyResident(ctx context.Context, dir, role string, p usbaddress.InterfaceProof, exe string, owner func() error) error {
	if ctx == nil || owner == nil {
		return errors.New("USB_RESIDENT_OWNER_REQUIRED")
	}
	release, e := usbaddress.ConfigurationLock(ctx)
	if e != nil {
		return e
	}
	defer release()
	verify := residentVerifier(p, owner)
	if e = verify(ctx); e != nil {
		return e
	}
	alias, e := nativeRuleInterface(ctx, p)
	if e != nil {
		return e
	}
	specs, e := residentSpecs(role, p.GUID, alias, exe)
	if e != nil {
		return e
	}
	b, found, e := readResidentLedgerFile(dir, role)
	if e != nil {
		return e
	}
	if !found {
		return errors.New("USB_RESIDENT_LEDGER_REQUIRED")
	}
	v, e := decodeResidentLedger(b)
	if e != nil {
		return e
	}
	if v.Phase != "complete" || v.GUID != p.GUID || !reflect.DeepEqual(v.Specs, specs) {
		return errors.New("USB_RESIDENT_LEDGER_SCOPE_CHANGED")
	}
	obs, e := residentReadRules(ctx, specs, verify)
	if e != nil {
		return e
	}
	for i, o := range obs {
		if !o.Present {
			return errors.New("USB_RESIDENT_RULE_MISSING")
		}
		if e = verifyResidentFirewallConstraints(o.Constraints, specs[i], 1); e != nil {
			return e
		}
	}
	if e = verify(ctx); e != nil {
		return e
	}
	got, ok, e := readResidentLedgerFile(dir, role)
	if e != nil || !ok || !bytes.Equal(got, b) {
		return errors.New("USB_RESIDENT_LEDGER_CHANGED")
	}
	return nil
}
func VerifyResidentMacFirewall(ctx context.Context, dir string, p usbaddress.InterfaceProof, owner func() error) error {
	return verifyResident(ctx, dir, "mac", p, "", owner)
}
func VerifyResidentCoreFirewall(ctx context.Context, dir string, p usbaddress.InterfaceProof, peer, exe string, owner func() error) error {
	role := "core_mac"
	if peer == "10.6.9.3" {
		role = "core_ipad"
	} else if peer != "10.6.9.2" {
		return errors.New("USB_RESIDENT_SCOPE_INVALID")
	}
	return verifyResident(ctx, dir, role, p, exe, owner)
}

// Explicit uninstall authority comes from the caller's stopped installed-core
// lease. An absent adapter is not re-created or adopted for firewall cleanup.
func PrepareResidentFirewallUninstall(ctx context.Context, dir string, owner func() error) ([]ResidentPermissionPlan, error) {
	if ctx == nil || owner == nil {
		return nil, errors.New("USB_RESIDENT_OWNER_REQUIRED")
	}
	release, e := usbaddress.ConfigurationLock(ctx)
	if e != nil {
		return nil, e
	}
	defer release()
	verify := func(ctx context.Context) error {
		if e := ctx.Err(); e != nil {
			return e
		}
		return owner()
	}
	var out []ResidentPermissionPlan
	for _, role := range []string{"host", "mac", "ipad", "core_mac", "core_ipad"} {
		if e = verify(ctx); e != nil {
			return nil, e
		}
		b, found, e := readResidentLedgerFile(dir, role)
		if e != nil {
			return nil, e
		}
		if !found {
			continue
		}
		v, e := decodeResidentLedger(b)
		if e != nil {
			return nil, e
		}
		obs, e := residentReadRules(ctx, v.Specs, verify)
		if e != nil {
			return nil, e
		}
		changed := []int{}
		for i, o := range obs {
			if !o.Present {
				continue
			}
			if residentRepairAllowed(o.Constraints, v.Specs[i]) != nil {
				if len(v.Previous) == 0 || residentRepairAllowed(o.Constraints, v.Previous[i]) != nil {
					return nil, errors.New("USB_RESIDENT_FOREIGN_SCOPE")
				}
			}
			changed = append(changed, i)
		}
		v.Phase = "removing"
		v.Before = obs
		if e = writeResidentLedgerFile(dir, v, b); e != nil {
			return nil, e
		}
		newB, _ := json.Marshal(v)
		leaf, _ := residentLeaf(role)
		p := &PreparedResidentFirewall{dir: dir, ledger: v, expected: newB, verify: verify, remove: true}
		if len(changed) != 0 {
			p.fragment = residentScript(filepath.Join(dir, leaf), newB, v, changed, 0)
		}
		out = append(out, p)
	}
	return out, nil
}
