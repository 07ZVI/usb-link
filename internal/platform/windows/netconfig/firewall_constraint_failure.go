package netconfig

import (
	"errors"
	"strings"
)

const firewallRuleDiagnosticClass = "MSFT_NetFirewallRule"

// ValidFirewallConstraintField accepts only compiled provider property names.
// It never accepts rule names, values, selectors or caller-supplied identities.
func ValidFirewallConstraintField(field string) bool {
	for _, group := range firewallGroups {
		class := group.class
		if class == "" {
			class = firewallRuleDiagnosticClass
		} else if field == class+"/_association" {
			return true
		}
		for _, property := range group.fields {
			if field == class+"/"+property {
				return true
			}
		}
	}
	return field == firewallRuleDiagnosticClass+"/RemoteDynamicKeywordAddresses" || field == "MSFT_NetAddressFilter/RemoteDynamicKeywordAddresses"
}

type firewallConstraintFailure struct {
	field string
	code  string
	cause error
}

func (e *firewallConstraintFailure) Error() string { return e.code }
func (e *firewallConstraintFailure) Unwrap() error { return e.cause }

// Only an actual reader/comparison attaches a location. No permission is
// normalized by this wrapper; the original error and numeric cause survive.
func firewallReadFailure(class, property string, cause error) error {
	if cause == nil {
		return nil
	}
	if class == "" {
		class = firewallRuleDiagnosticClass
	}
	field := class + "/" + property
	if !ValidFirewallConstraintField(field) {
		return errors.New("USB_NATIVE_FIREWALL_CONSTRAINT_UNKNOWN")
	}
	return &firewallConstraintFailure{field: field, code: ResidentFirewallErrorDetails(cause).Code, cause: cause}
}

// Keys are compiled class/property names. This attaches only the actual
// comparison location, without publishing either side's constraint values.
func residentConstraintFailure(key string, cause error) error {
	i := strings.IndexByte(key, '/')
	if i < 0 {
		return errors.New("USB_RESIDENT_CONSTRAINT_INCOMPLETE")
	}
	return firewallReadFailure(key[:i], key[i+1:], cause)
}
