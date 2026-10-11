package netconfig

import (
	"errors"
	"strings"
	"suhang/usbnet/internal/transport/usbaddress"
)

// OwnedProfileRecoveryIdentity selects only an exact owned Wintun interface.
// It does not contain an address, Ready flag or firewall permission. Callers
// must additionally validate their protected original-value obligation in the
// mandatory callback. An iPad instance requires a separate native driver gate.
type OwnedProfileRecoveryIdentity struct {
	Role, GUID string
	Index      uint32
	LUID       uint64
}

func validateProfileRecoveryScope(p OwnedProfileRecoveryIdentity) error {
	if p.Index == 0 || p.LUID == 0 {
		return errors.New("USB_NATIVE_PROFILE_RECOVERY_SCOPE_INVALID")
	}
	switch p.Role {
	case "host":
		if !strings.EqualFold(p.GUID, usbaddress.HostGUID) {
			return errors.New("USB_NATIVE_PROFILE_RECOVERY_SCOPE_INVALID")
		}
	case "mac":
		if !strings.EqualFold(p.GUID, "{A4611646-E050-4D25-B83E-633A5598F302}") {
			return errors.New("USB_NATIVE_PROFILE_RECOVERY_SCOPE_INVALID")
		}
	default:
		return errors.New("USB_NATIVE_PROFILE_RECOVERY_SCOPE_INVALID")
	}
	return nil
}
func validateProfileRecoveryMapping(p OwnedProfileRecoveryIdentity, rows []nativeHostInterface) error {
	if e := validateProfileRecoveryScope(p); e != nil {
		return e
	}
	alias := "USB Link"
	if p.Role == "host" {
		alias = usbaddress.HostName
	}
	count := 0
	for _, r := range rows {
		if r.Index == p.Index || r.LUID == p.LUID || strings.EqualFold(r.GUID, p.GUID) || r.Alias == alias {
			count++
			if r.Index != p.Index || r.LUID != p.LUID || !strings.EqualFold(r.GUID, p.GUID) || r.Alias != alias || r.Type != 53 {
				return errors.New("USB_NATIVE_PROFILE_RECOVERY_MAPPING_CHANGED")
			}
		}
	}
	if count != 1 {
		return errors.New("USB_NATIVE_PROFILE_RECOVERY_MAPPING_CHANGED")
	}
	return nil
}

// Both owner and mapping are checked again after the driver's fresh observation.
// No initial or final failure may be used as an authorization snapshot.
func runProfileRecoveryIdentity(owner, mapping, driver, finished func() error) error {
	if e := owner(); e != nil {
		return e
	}
	if e := mapping(); e != nil {
		return e
	}
	if e := driver(); e != nil {
		return e
	}
	if e := mapping(); e != nil {
		return e
	}
	if e := owner(); e != nil {
		return e
	}
	return finished()
}
