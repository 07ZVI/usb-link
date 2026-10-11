package netconfig

import "fmt"

// Only the nonce-verified trial may call this. Initial network setup continues
// to enforce MTU 1500. This changes no address, route, DNS or firewall policy.
// NlMtuBytes is a cmdlet parameter; the returned MSFT_NetIPInterface property
// is NlMtu. Read the provider property rather than an absent parameter alias.
func VerifiedMTUScript(index uint32, guid string, mtu int) (string, error) {
	if index == 0 || !guidPattern.MatchString(guid) || (mtu != 1500 && mtu != 9000 && mtu != 16000) {
		return "", fmt.Errorf("invalid verified MTU")
	}
	return fmt.Sprintf(`$ErrorActionPreference='Stop';$a=@(Get-NetAdapter -IncludeHidden -ErrorAction Stop | Where-Object {$_.ifIndex -eq %d -and [guid]$_.InterfaceGuid -eq [guid]'%s' -and $_.Name -ceq 'USB Link'});if($a.Count -ne 1){throw 'Owned adapter identity mismatch'};Set-NetIPInterface -InterfaceIndex %d -AddressFamily IPv4 -NlMtuBytes %d -PolicyStore ActiveStore -ErrorAction Stop;$i=@(Get-NetIPInterface -InterfaceIndex %d -AddressFamily IPv4 -PolicyStore ActiveStore -ErrorAction Stop);if($i.Count -ne 1 -or $i[0].NlMtu -ne %d){throw ('MTU readback mismatch count='+$i.Count+' actual='+($i | ForEach-Object {$_.NlMtu}))};Write-Output 'VERIFIED_IP_MTU=%d';`, index, guid, index, mtu, index, mtu, mtu), nil
}
