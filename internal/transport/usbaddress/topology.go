package usbaddress

import (
	"fmt"
	"regexp"
	"strings"
)

// InterfaceProof comes only from currently attached, authorized gateway links.
// A bridge receives the bounded snapshot in its administrator-owned runtime.
type InterfaceProof struct {
	Index       uint32 `json:"index"`
	GUID        string `json:"guid"`
	LUID        uint64 `json:"luid"`
	Role        string `json:"role,omitempty"`
	Created     int64  `json:"address_created,omitempty"`
	AddressMode string `json:"address_mode,omitempty"`
}

const HostGUID = "{C839CF3F-7F98-4CB3-891B-36E4FC772969}"
const HostName = "USB Link Host"

var topologyGUID = regexp.MustCompile(`(?i)^\{[0-9a-f]{8}(-[0-9a-f]{4}){3}-[0-9a-f]{12}\}$`)

func ConflictScript(index uint32, guid string, proofs []InterfaceProof) (string, error) {
	if index == 0 || !topologyGUID.MatchString(guid) || len(proofs) > 4 {
		return "", fmt.Errorf("invalid USB topology")
	}
	allowed := []string{}
	for _, p := range proofs {
		if p.Index == 0 || p.LUID == 0 || (p.Role != "" && p.Role != "host") || (p.Role == "host" && (p.Created <= 0 || !strings.EqualFold(p.GUID, HostGUID))) || (p.Role == "" && (!topologyGUID.MatchString(p.GUID) || p.AddressMode != "")) || (p.AddressMode != "" && p.AddressMode != "persistent") {
			return "", fmt.Errorf("invalid USB interface proof")
		}
		allowed = append(allowed, fmt.Sprintf("@{Index=%d;GUID='%s';Role='%s'}", p.Index, p.GUID, p.Role))
	}
	return fmt.Sprintf(`$ErrorActionPreference='Stop';
$owned=@(%s);$ownedIndices=@();foreach($p in $owned){$a=@(Get-NetAdapter -IncludeHidden | Where-Object {$_.ifIndex -eq $p.Index -and [guid]$_.InterfaceGuid -eq [guid]$p.GUID});if($a.Count -eq 1){$ownedIndices+= $p.Index}};
$a=@(Get-NetAdapter -IncludeHidden | Where-Object {$_.ifIndex -eq %d -and [guid]$_.InterfaceGuid -eq [guid]'%s'});if($a.Count -ne 1){throw 'USB adapter identity changed'};
function V4Num([string]$s){$b=[net.ipaddress]::Parse($s).GetAddressBytes();if($b.Length -ne 4){throw 'Expected IPv4'};return ([uint64]$b[0]*16777216+[uint64]$b[1]*65536+[uint64]$b[2]*256+[uint64]$b[3])};
$base=V4Num '10.6.9.0';$end=$base+255;
foreach($r in @(Get-NetRoute -AddressFamily IPv4 -PolicyStore ActiveStore)){$parts=$r.DestinationPrefix.Split('/');$bits=[int]$parts[1];if($bits -eq 0){continue};$n=V4Num $parts[0];$last=$n+[uint64][math]::Pow(2,32-$bits)-1;if($base -le $last -and $end -ge $n){if($r.InterfaceIndex -notin $ownedIndices -or $r.DestinationPrefix -notin @('10.6.9.1/32','10.6.9.2/32','10.6.9.3/32','10.6.9.253/32','10.6.9.254/32') -or $r.NextHop -ne '0.0.0.0'){throw 'USB subnet conflicts with an existing route'}}};
foreach($ip in @(Get-NetIPAddress -AddressFamily IPv4)){$n=V4Num $ip.IPAddress;if($n -ge $base -and $n -le $end){if($ip.InterfaceIndex -notin $ownedIndices -or $ip.IPAddress -notin @('10.6.9.1','10.6.9.253','10.6.9.254') -or $ip.PrefixLength -ne 32){throw 'USB subnet conflicts with an existing address'}}};
`, strings.Join(allowed, ","), index, guid), nil
}
