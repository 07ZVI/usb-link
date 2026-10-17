//go:build usblink_local_remote

package netconfig

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strings"
	"suhang/usbnet/internal/transport/usbaddress"
)

const localMaintenanceRule = "USB-Link-Local-Push-Host-v2"
const legacyLocalMaintenanceRule = "USB-Link-Local-Push-Host-v1"

func localMaintenanceRetainDisabledLegacy(name string, first, second int32) bool {
	return name == legacyLocalMaintenanceRule && first == 2 && second == 2
}

func localMaintenanceSpec(executable, alias string) (nativeRuleSpec, error) {
	if !validCoreExecutable(executable) || alias != usbaddress.HostName {
		return nativeRuleSpec{}, errors.New("USB_LOCAL_PUSH_RULE_SCOPE_INVALID")
	}
	hash := sha256.Sum256([]byte(alias))
	return nativeRuleSpec{Name: localMaintenanceRule, Display: "USB Link local USB push", Group: "USB-Link-Local-Push-v2",
		Description: "USB Link local push v2; host=" + usbaddress.HostGUID + "; alias_sha256=" + hex.EncodeToString(hash[:]),
		Program:     executable, Service: "Any", Alias: alias, Local: "10.6.9.1", Remote: "10.6.9.2", Ports: "47775", RemotePorts: "Any", Protocol: 6}, nil
}

// Cleanup can run after USB disconnect. It requires the complete fixed rule,
// including its alias binding, plus an independently verified installed binary.
func localMaintenanceCleanupSpec(got firewallConstraints) (nativeRuleSpec, error) {
	value := func(key string) string {
		v := got[key]
		if len(v) != 1 || !strings.HasPrefix(v[0], "S:") {
			return ""
		}
		return strings.TrimPrefix(v[0], "S:")
	}
	spec, err := localMaintenanceSpec(value("MSFT_NetApplicationFilter/AppPath"), value("MSFT_NetInterfaceFilter/InterfaceAlias"))
	if err != nil {
		return spec, err
	}
	if value("/InstanceID") == legacyLocalMaintenanceRule {
		spec.Name, spec.Group = legacyLocalMaintenanceRule, "USB-Link-Local-Push-v1"
		spec.Description = strings.Replace(spec.Description, "local push v2;", "local push;", 1)
	}
	enabled := int32(1)
	if len(got["/Enabled"]) == 1 && got["/Enabled"][0] == "N:2" {
		enabled = 2
	}
	return spec, verifyFirewallConstraints(got, spec, enabled)
}
