package interfaceconfig

import (
	"errors"
	"regexp"
	"strings"
)

// ActiveOwnership is a fresh local observation, not a serialized authorization
// token. Consumers must rerun verification while retaining configuration lease.
type ActiveOwnership struct {
	Scope         Scope
	Created       int64
	ReceiptSHA256 string
	AddressMode   string
}

var shaPattern = regexp.MustCompile(`^[0-9a-f]{64}$`)

// PlanOwnedPersistentRebind accepts only a completed protected ordinary host
// journal supplied by its owner and two identical fresh native observations.
// It writes nothing; the caller must retain its lease and durably verify the
// original journal is unchanged before checkpointing the new Created stamp.
func PlanOwnedPersistentRebind(old Scope, oldCreated int64, first, last ActiveOwnership) (ActiveOwnership, error) {
	if validateScope(old) != nil || old.Role != "host" || old.LUID != last.Scope.LUID || oldCreated <= 0 || first != last || validateScope(last.Scope) != nil || last.Scope.Role != "host" || !strings.EqualFold(old.GUID, last.Scope.GUID) || last.Created <= 0 || !shaPattern.MatchString(last.ReceiptSHA256) {
		return ActiveOwnership{}, errors.New("USB_PERSISTENT_JOURNAL_REBIND_UNPROVEN")
	}
	return last, nil
}

type activeAddress struct {
	Index                                                                     uint32
	LUID                                                                      uint64
	IP                                                                        string
	Prefix, PrefixOrigin, SuffixOrigin, DAD, ValidLifetime, PreferredLifetime uint32
	Skip                                                                      bool
	Created                                                                   int64
}

func acceptPersistentActive(s Scope, addresses []activeAddress, mtu uint32) (activeAddress, error) {
	return acceptActiveMode(s, addresses, mtu, "persistent", 0)
}
func acceptActiveMode(s Scope, addresses []activeAddress, mtu uint32, mode string, created int64) (activeAddress, error) {
	var out activeAddress
	count := 0
	for _, a := range addresses {
		if a.Index == s.Index || a.LUID == s.LUID {
			count++
			if a.Index != s.Index || a.LUID != s.LUID || a.IP != scopeAddress(s) || a.Prefix != 32 || a.PrefixOrigin != 1 || a.SuffixOrigin != 1 || a.DAD != 4 || !activeLifetimeMatches(mode, created, a) || a.Skip != scopeSkip(s) || a.Created <= 0 {
				return out, errors.New("USB_PERSISTENT_ACTIVE_ADDRESS_UNPROVEN")
			}
			out = a
		}
	}
	if count != 1 || (mtu != 1500 && !((mode == "retained_runtime" || mode == "retained_legacy") && s.Role == "mac" && mtu > 1500 && mtu <= 16000)) {
		return out, errors.New("USB_PERSISTENT_ACTIVE_ADDRESS_UNPROVEN")
	}
	return out, nil
}

func activeLifetimeMatches(mode string, created int64, a activeAddress) bool {
	switch mode {
	case "retained_runtime":
		return created > 0 && a.Created == created && a.ValidLifetime == 0xffffffff && a.PreferredLifetime == 0xffffffff
	case "persistent":
		return a.ValidLifetime == 0xffffffff && a.PreferredLifetime == 0xffffffff
	case "legacy", "retained_legacy":
		return created > 0 && a.Created == created && a.ValidLifetime <= 3600 && a.PreferredLifetime <= 3600
	default:
		return false
	}
}
