package netconfig

import (
	"fmt"
	"strings"
	"suhang/usbnet/internal/security/securitypolicy"
	"suhang/usbnet/internal/transport/usbaddress"
)

const serviceGroup = "USB-Link-Owned-Services-v1"
const serviceMarker = "USB Link verified core service / v1"

// Fixed names survive upgrades; only this marked group may be refreshed.
// The caller verifies the installed executable before passing its current path.
func CoreServicesRule(guid, peer, executable string) (string, error) {
	if !guidPattern.MatchString(guid) || (peer != "10.6.9.2" && peer != "10.6.9.3") || !validCoreExecutable(executable) {
		return "", fmt.Errorf("invalid core firewall ownership")
	}
	path := strings.ReplaceAll(executable, "'", "''")
	name := "USB-Link-Core-Mac-v1"
	ports := securitypolicy.Ports(securitypolicy.FileAndSpeed, "TCP") + ",47775"
	if peer == "10.6.9.3" {
		name = "USB-Link-Core-iPad-v1"
		ports = securitypolicy.Ports(securitypolicy.FileAndSpeed, "TCP")
	}

	prefix := coreAdapterPrefix(guid)
	rules := []coreRuleSpec{coreSpec(guid, name, path, "TCP", "10.6.9.1", peer, ports, "", ""), smbCoreSpec(guid, peer)}
	if peer == "10.6.9.3" {
		// Lease acquisition exceptions remain scoped to this verified process and
		// exact physical interface; only these two rules use broadcast addresses.
		rules = append(rules, coreSpec(guid, "USB-Link-Core-DHCP-v1", path, "UDP", "Any", "Any", "67", "68", ""), coreSpec(guid, "USB-Link-Core-MDNS-v1", path, "UDP", "Any", "Any", "5353", "", ""))
	}
	return corePermissionScript(prefix, rules, map[int]string{len(rules) - 1: "USB_CORE_PERMISSION_READY"})
}

func coreAdapterPrefix(guid string) string {
	return fmt.Sprintf(`$ErrorActionPreference='Stop';$a=@(Get-NetAdapter -IncludeHidden | Where-Object {[guid]$_.InterfaceGuid -eq [guid]'%s'});if($a.Count -ne 1){throw 'USB interface identity changed'};`, guid)
}
func coreSpec(guid, name, path, protocol, local, peer, ports, remotePort, service string) coreRuleSpec {
	return coreRuleSpec{guid, name, path, protocol, local, peer, ports, remotePort, service}
}
func smbCoreSpec(guid, peer string) coreRuleSpec {
	return coreSpec(guid, "USB-Link-Native-SMB-"+guid+"-"+strings.ReplaceAll(peer, ".", "-"), "System", "TCP", "10.6.9.1", peer, "445", "", "LanmanServer")
}

func RemoveCoreServicesRules() string {
	return fmt.Sprintf(`$ErrorActionPreference='Stop';foreach($n in @('USB-Link-Core-Mac-v1','USB-Link-Core-iPad-v1','USB-Link-Core-DHCP-v1','USB-Link-Core-MDNS-v1','USB-Link-Core-Host-Mac-v1','USB-Link-Core-Host-iPad-v1')){$r=@(Get-NetFirewallRule -PolicyStore PersistentStore -Name $n -ErrorAction SilentlyContinue);if($r.Count -gt 1){throw 'Ambiguous core rule'};if($r.Count -eq 1){if($r[0].Group -ne '%s' -or $r[0].Description -ne '%s'){throw 'Core rule ownership changed'};$r[0]|Remove-NetFirewallRule -ErrorAction Stop}};Write-Output 'USB_CORE_PERMISSION_REMOVED';`, serviceGroup, serviceMarker)
}

// The additional address-owning adapter has only per-peer, verified-process
// service exceptions. Physical interface exceptions remain independently scoped.
func SharedHostServicesRule(executable string) (string, error) {
	// Reuse the public argument validation without registering an unused plan.
	if !validCoreExecutable(executable) {
		return "", fmt.Errorf("invalid core firewall ownership")
	}
	path := strings.ReplaceAll(executable, "'", "''")
	rules := []coreRuleSpec{
		coreSpec(usbaddress.HostGUID, "USB-Link-Core-Host-Mac-v1", path, "TCP", "10.6.9.1", "10.6.9.2", securitypolicy.Ports(securitypolicy.FileAndSpeed, "TCP")+",47775", "", ""),
		smbCoreSpec(usbaddress.HostGUID, "10.6.9.2"),
		coreSpec(usbaddress.HostGUID, "USB-Link-Core-Host-iPad-v1", path, "TCP", "10.6.9.1", "10.6.9.3", securitypolicy.Ports(securitypolicy.FileAndSpeed, "TCP"), "", ""),
		smbCoreSpec(usbaddress.HostGUID, "10.6.9.3"),
	}
	return corePermissionScriptWithRefresh(coreAdapterPrefix(usbaddress.HostGUID), rules, map[int]string{1: "USB_CORE_PERMISSION_READY", 3: "USB_HOST_PERMISSION_READY"}, map[int]string{2: coreAdapterPrefix(usbaddress.HostGUID)})
}

// Windows owns SMB. Its rule retains the exact System/LanmanServer TCP 445 scope.
type NativeSMBServiceScope struct{ GUID, Peer string }

func NativeSMBServicesRule(guid, peer string) (string, error) {
	return NativeSMBServicesRules([]NativeSMBServiceScope{{guid, peer}})
}

// A multiple-scope execution has one ordered local readback transaction. Each
// scope still freshly queries its exact adapter; no metadata is silently dropped.
func NativeSMBServicesRules(scopes []NativeSMBServiceScope) (string, error) {
	if len(scopes) == 0 {
		return "", nil
	}
	if len(scopes) > coreBaselineLimit {
		return "", fmt.Errorf("native SMB scope limit")
	}
	rules := make([]coreRuleSpec, 0, len(scopes))
	refresh := map[int]string{}
	seen := map[string]bool{}
	for i, scope := range scopes {
		if !guidPattern.MatchString(scope.GUID) || (scope.Peer != "10.6.9.2" && scope.Peer != "10.6.9.3") {
			return "", fmt.Errorf("invalid native SMB scope")
		}
		key := strings.ToLower(scope.GUID) + ":" + scope.Peer
		if seen[key] {
			return "", fmt.Errorf("ambiguous native SMB scope")
		}
		seen[key] = true
		rules = append(rules, smbCoreSpec(scope.GUID, scope.Peer))
		if i > 0 {
			refresh[i] = coreAdapterPrefix(scope.GUID)
		}
	}
	return corePermissionScriptWithRefresh(coreAdapterPrefix(scopes[0].GUID), rules, nil, refresh)
}

func validCoreExecutable(executable string) bool {
	return len(executable) <= 1024 && len(executable) >= 3 && executable[1] == ':' && executable[2] == '\\' && ((executable[0] >= 'A' && executable[0] <= 'Z') || (executable[0] >= 'a' && executable[0] <= 'z')) && !strings.ContainsAny(executable, "\r\n\x00")
}
