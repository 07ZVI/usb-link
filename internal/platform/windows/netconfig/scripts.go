package netconfig

import (
	"fmt"
	"regexp"
	"strings"
	"suhang/usbnet/internal/security/securitypolicy"
	"suhang/usbnet/internal/transport/usbaddress"
)

var idPattern = regexp.MustCompile(`^[a-f0-9]{24}$`)
var guidPattern = regexp.MustCompile(`^\{[0-9a-fA-F]{8}(-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}\}$`)

// Scripts accepts only native adapter identifiers and a generated ownership token.
func Scripts(index uint32, guid string, mtu int, token string) (setup, cleanup string, err error) {
	if index == 0 || !guidPattern.MatchString(guid) || !idPattern.MatchString(token) || mtu < 576 || mtu > 1500 {
		return "", "", fmt.Errorf("invalid owned-adapter configuration")
	}
	prefix := "Suhang-USB-Phase2-" + token
	check := fmt.Sprintf(`$ErrorActionPreference='Stop'; $a=Get-NetAdapter -IncludeHidden | Where-Object {$_.ifIndex -eq %d}; if(@($a).Count -ne 1 -or [guid]$a.InterfaceGuid -ne [guid]'%s' -or $a.Name -ne 'USB Link'){throw 'Owned adapter identity mismatch'}; `, index, guid)
	setup = check + fmt.Sprintf(`
if(Get-NetRoute -AddressFamily IPv4 -DestinationPrefix '10.77.0.0/24' -ErrorAction SilentlyContinue | Where-Object {$_.InterfaceIndex -ne %d}) {throw 'USB test subnet already used by another interface'};
Set-NetIPInterface -InterfaceIndex %d -AddressFamily IPv4 -Dhcp Disabled -NlMtuBytes %d -InterfaceMetric 5000 -PolicyStore ActiveStore;
New-NetIPAddress -InterfaceIndex %d -IPAddress '10.77.0.2' -PrefixLength 24 -AddressFamily IPv4 -PolicyStore ActiveStore | Out-Null;
$deadline=(Get-Date).AddSeconds(15); do {$ip=Get-NetIPAddress -InterfaceIndex %d -IPAddress '10.77.0.2'; if($ip.AddressState -eq 'Duplicate'){throw 'Duplicate test address'}; if($ip.AddressState -eq 'Preferred'){break}; Start-Sleep -Milliseconds 200} while((Get-Date) -lt $deadline); if($ip.AddressState -ne 'Preferred'){throw 'IPv4 address not ready'};
New-NetFirewallRule -Name '%s-ICMP' -DisplayName 'USB Link ping' -Direction Inbound -Action Allow -Profile Any -InterfaceAlias $a.Name -RemoteAddress '10.77.0.1' -LocalAddress '10.77.0.2' -Protocol ICMPv4 -IcmpType 8 | Out-Null;
New-NetFirewallRule -Name '%s-BENCH' -DisplayName 'USB Link bounded throughput test' -Direction Inbound -Action Allow -Profile Any -InterfaceAlias $a.Name -RemoteAddress '10.77.0.1' -LocalAddress '10.77.0.2' -Protocol TCP -LocalPort %s | Out-Null;
New-NetFirewallRule -Name '%s-SUN-TCP' -DisplayName 'USB Link Sunshine TCP' -Direction Inbound -Action Allow -Profile Any -InterfaceAlias $a.Name -RemoteAddress '10.77.0.1' -LocalAddress '10.77.0.2' -Protocol TCP -LocalPort %s | Out-Null;
New-NetFirewallRule -Name '%s-SUN-UDP' -DisplayName 'USB Link Sunshine UDP' -Direction Inbound -Action Allow -Profile Any -InterfaceAlias $a.Name -RemoteAddress '10.77.0.1' -LocalAddress '10.77.0.2' -Protocol UDP -LocalPort %s | Out-Null;
Get-NetIPConfiguration -InterfaceIndex %d | Format-List;
`, index, index, mtu, index, index, prefix, prefix, securitypolicy.Ports(securitypolicy.NativeBenchmark, "TCP"), prefix, securitypolicy.InboundPorts("mac", "TCP"), prefix, securitypolicy.InboundPorts("mac", "UDP"), index)
	cleanup = firewallCleanup([]string{prefix + "-ICMP", prefix + "-BENCH", prefix + "-SUN-TCP", prefix + "-SUN-UDP"})
	return
}

func PrivateProfileScript(index uint32, guid string) string {
	return fmt.Sprintf(`$ErrorActionPreference='Stop'; $a=Get-NetAdapter -IncludeHidden | Where-Object {$_.ifIndex -eq %d}; if(@($a).Count -ne 1 -or [guid]$a.InterfaceGuid -ne [guid]'%s'){throw 'Owned adapter identity mismatch'}; $p=Get-NetConnectionProfile -InterfaceIndex %d -ErrorAction SilentlyContinue; if($p){$p | Set-NetConnectionProfile -NetworkCategory Private; Write-Output 'Owned USB profile is Private'} else {Write-Output 'No NLA profile yet; interface-scoped rules already apply'}`, index, guid, index)
}

// VerifyCleanup reports missing resources only after successful provider
// queries; it does not remove any adapter or broad-match firewall rules.
func VerifyCleanup(guid, token string) (string, error) {
	if !guidPattern.MatchString(guid) || !idPattern.MatchString(token) {
		return "", fmt.Errorf("invalid cleanup ownership")
	}
	prefix := "Suhang-USB-Phase2-" + token
	return fmt.Sprintf(`$ErrorActionPreference='Stop'; $a=@(Get-NetAdapter -IncludeHidden | Where-Object {[guid]$_.InterfaceGuid -eq [guid]'%s'}); if($a.Count -ne 0){throw 'Owned adapter remains after close'}; $names=@('%s-ICMP','%s-BENCH','%s-SUN-TCP','%s-SUN-UDP'); $r=@(Get-NetFirewallRule | Where-Object {$_.Name -in $names}); if($r.Count -ne 0){throw 'Owned firewall rules remain'}; Write-Output 'OWNED_CLEANUP_VERIFIED';`, guid, prefix, prefix, prefix, prefix), nil
}

// The optional file receiver is confined to the already owned Mac USB adapter.
func FileReceiverRule(guid, token string, add bool) (string, error) {
	if !guidPattern.MatchString(guid) || !idPattern.MatchString(token) {
		return "", fmt.Errorf("invalid file receiver ownership")
	}
	name := "Suhang-USB-Phase2-" + token + "-FILES"
	if !add {
		return firewallCleanup([]string{name}), nil
	}
	return fmt.Sprintf(`$ErrorActionPreference='Stop';$a=@(Get-NetAdapter -IncludeHidden | Where-Object {[guid]$_.InterfaceGuid -eq [guid]'%s' -and $_.Name -ceq 'USB Link'});if($a.Count -ne 1){throw 'Owned USB adapter changed'};%sNew-NetFirewallRule -Name '%s' -DisplayName 'USB Link file receiver' -Direction Inbound -Action Allow -Profile Any -InterfaceAlias $a[0].Name -LocalAddress '10.77.0.2' -RemoteAddress '10.77.0.1' -Protocol TCP -LocalPort %s | Out-Null;`, guid, firewallCleanup([]string{name}), name, securitypolicy.Ports(securitypolicy.FileAndSpeed, "TCP")), nil
}

func profileScript(script string, profile string) (string, error) {
	a, e := usbaddress.Lookup(profile)
	if e != nil {
		return "", e
	}
	return strings.NewReplacer("10.77.0.2", a.Windows, "10.77.0.1", a.Peer, "10.77.0.0/24", a.Subnet).Replace(script), nil
}
func ScriptsForProfile(index uint32, guid string, mtu int, token, profile string) (string, string, error) {
	setup, cleanup, e := Scripts(index, guid, mtu, token)
	if e != nil {
		return "", "", e
	}
	setup, e = profileScript(setup, profile)
	return setup, cleanup, e
}
func FileReceiverRuleForProfile(guid, token string, add bool, profile string) (string, error) {
	s, e := FileReceiverRule(guid, token, add)
	if e != nil {
		return "", e
	}
	return profileScript(s, profile)
}

// A successful enumeration with no matching objects means already clean. A
// provider/permission failure must throw instead of being mistaken for absence.
func firewallCleanup(names []string) string {
	quoted := make([]string, len(names))
	for i, name := range names {
		quoted[i] = "'" + name + "'"
	} // Only validated generated identifiers reach this helper.
	return `$ErrorActionPreference='Stop'; $ownedRuleNames=@(` + strings.Join(quoted, ",") + `);
$ownedRules=@(Get-NetFirewallRule -ErrorAction Stop | Where-Object {$_.Name -in $ownedRuleNames});
if($ownedRules.Count -gt 0){$ownedRules | Remove-NetFirewallRule -ErrorAction Stop};
$remainingRules=@(Get-NetFirewallRule -ErrorAction Stop | Where-Object {$_.Name -in $ownedRuleNames});
if($remainingRules.Count -ne 0){throw 'Owned firewall rules remain after removal'};
Write-Output ('OWNED_FIREWALL_CLEANUP_VERIFIED removed='+$ownedRules.Count); `
}

// SharedProfileScripts creates no competing subnet route. Each isolated USB
// interface owns only Windows /32 and its peer's on-link /32 route.
func SharedProfileScripts(index uint32, guid string, mtu int, token string, proofs []usbaddress.InterfaceProof) (string, string, error) {
	setup, cleanup, e := ScriptsForProfile(index, guid, mtu, token, usbaddress.Unified)
	if e != nil {
		return "", "", e
	}
	check, e := usbaddress.ConflictScript(index, guid, proofs)
	if e != nil {
		return "", "", e
	}
	old := fmt.Sprintf("if(Get-NetRoute -AddressFamily IPv4 -DestinationPrefix '10.6.9.0/24' -ErrorAction SilentlyContinue | Where-Object {$_.InterfaceIndex -ne %d}) {throw 'USB test subnet already used by another interface'};", index)
	setup = strings.ReplaceAll(setup, old, check)
	setup = strings.Replace(setup, "-PrefixLength 24", "-PrefixLength 32", 1)
	needle := "$deadline=(Get-Date).AddSeconds(15);"
	setup = strings.Replace(setup, needle, fmt.Sprintf("New-NetRoute -InterfaceIndex %d -DestinationPrefix '10.6.9.2/32' -NextHop '0.0.0.0' -RouteMetric 5000 -PolicyStore ActiveStore | Out-Null;\n", index)+needle, 1)
	return setup, cleanup, nil
}

func VirtualHostMacScripts(index uint32, guid string, mtu int, token string, proofs []usbaddress.InterfaceProof) (string, string, error) {
	hasHost := false
	for _, p := range proofs {
		if p.Role == "host" && p.Created > 0 {
			hasHost = true
		}
	}
	if !hasHost {
		return "", "", fmt.Errorf("shared host address unproven")
	}
	setup, cleanup, e := SharedProfileScripts(index, guid, mtu, token, proofs)
	if e != nil {
		return "", "", e
	}
	setup = strings.Replace(setup, "New-NetIPAddress -InterfaceIndex", "Set-NetIPInterface -InterfaceIndex "+fmt.Sprint(index)+" -AddressFamily IPv4 -WeakHostSend Enabled -WeakHostReceive Enabled -Forwarding Enabled -PolicyStore ActiveStore;\nNew-NetIPAddress -InterfaceIndex", 1)
	setup = strings.Replace(setup, "-IPAddress '10.6.9.1' -PrefixLength 32", "-IPAddress '10.6.9.253' -SkipAsSource $true -PrefixLength 32", 1)
	setup = strings.Replace(setup, "$ip=Get-NetIPAddress -InterfaceIndex "+fmt.Sprint(index)+" -IPAddress '10.6.9.1'", "$ip=Get-NetIPAddress -InterfaceIndex "+fmt.Sprint(index)+" -IPAddress '10.6.9.253'", 1)
	setup += " $flags=Get-NetIPInterface -InterfaceIndex " + fmt.Sprint(index) + " -AddressFamily IPv4 -PolicyStore ActiveStore; if($flags.WeakHostSend -ne 'Enabled' -or $flags.WeakHostReceive -ne 'Enabled' -or $flags.Forwarding -ne 'Enabled'){throw 'USB local delivery flags changed'}; Write-Output 'USB_LOCAL_DELIVERY_FLAGS_VERIFIED';"
	return setup, cleanup, nil
}
