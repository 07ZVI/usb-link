package netconfig

import (
	"errors"
	"regexp"
	"strings"
)

var absenceSuffix = regexp.MustCompile(`^[A-Z0-9]+(-[A-Z0-9]+)*$`)

// This query proves absence only. It never returns an object usable for deletion.
func sessionRuleAbsenceQuery(token string, names []string) (string, error) {
	if !idPattern.MatchString(token) || len(names) == 0 || len(names) > 16 {
		return "", errors.New("USB_NATIVE_SESSION_RULE_SCOPE_INVALID")
	}

	prefix := "Suhang-USB-Phase2-" + token + "-"
	seen := map[string]bool{}
	terms := make([]string, len(names))
	for i, name := range names {
		if len(name) > 160 || !strings.HasPrefix(name, prefix) || !absenceSuffix.MatchString(strings.TrimPrefix(name, prefix)) || seen[name] {
			return "", errors.New("USB_NATIVE_SESSION_RULE_SCOPE_INVALID")
		}
		seen[name] = true
		terms[i] = "InstanceID='" + name + "'"
	}

	return "SELECT * FROM MSFT_NetFirewallRule WHERE " + strings.Join(terms, " OR "), nil
}

func sessionRuleAbsenceCount(count int32, err error) error {
	if err != nil {
		return err
	}
	if count < 0 {
		return errors.New("USB_NATIVE_FIREWALL_ENUMERATION_OR_AMBIGUITY")
	}
	if count != 0 {
		return errors.New("USB_NATIVE_SESSION_RULE_REMAINS")
	}
	return nil
}
