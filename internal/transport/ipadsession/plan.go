package ipadsession

import (
	"fmt"
	"hash/crc32"
	"net"
	"regexp"
	"strings"
	"suhang/usbnet/internal/security/securitypolicy"
)

var guidPattern = regexp.MustCompile(`(?i)^\{[0-9a-f]{8}(-[0-9a-f]{4}){3}-[0-9a-f]{12}\}$`)
var tokenPattern = regexp.MustCompile(`^[a-f0-9]{24}$`)
var persistentSHA256Pattern = regexp.MustCompile(`^[a-f0-9]{64}$`)

type Plan struct {
	Version          int        `json:"version"`
	GUID             string     `json:"adapter_guid"`
	LUID             uint64     `json:"adapter_luid"`
	Index            uint32     `json:"adapter_index"`
	ServerIP         string     `json:"server_ip"`
	Token            string     `json:"ownership_token"`
	HostFlags        *HostFlags `json:"host_flags,omitempty"`
	CreatedAt        int64      `json:"address_creation_timestamp,omitempty"`
	PlannedAt        int64      `json:"address_creation_intent_timestamp"`
	AddressMode      string     `json:"address_mode,omitempty"`
	PersistentSHA256 string     `json:"persistent_original_sha256,omitempty"`
}

func (p Plan) Valid() bool {
	ip := net.ParseIP(p.ServerIP).To4()
	validAddress := (p.Version == 1 && ip != nil && ip[0] == 10 && ip[1] == 77 && ip[2] > 0 && ip[2] < 255 && ip[3] == 1) || (p.Version == 2 && p.ServerIP == "10.6.9.1") || (p.Version == 3 && p.ServerIP == "10.6.10.1") || (p.Version == 4 && p.ServerIP == "10.6.9.1") || (p.Version == 5 && p.ServerIP == "10.6.9.1" && p.HostFlags != nil)
	if p.Version == 6 {
		validAddress = p.ServerIP == "10.6.9.1" && p.HostFlags != nil && p.CreatedAt > 0 && (p.AddressMode == "legacy" || p.AddressMode == "persistent") && persistentSHA256Pattern.MatchString(p.PersistentSHA256)
	} else if p.AddressMode != "" || p.PersistentSHA256 != "" {
		return false
	}
	return validAddress && guidPattern.MatchString(p.GUID) && p.GUID != "{00000000-0000-0000-0000-000000000000}" && p.LUID != 0 && p.Index != 0 && tokenPattern.MatchString(p.Token) && p.PlannedAt > 0 && p.CreatedAt >= 0
}
func (p Plan) PeerIP() string {
	ip := net.ParseIP(p.ServerIP).To4()
	if ip == nil {
		return ""
	}
	ip[3] = 2
	if p.Version >= 4 {
		ip[3] = 3
	}
	return ip.String()
}
func (p Plan) Prefix() string { return "Suhang-iPad-App-" + p.Token }
func (p Plan) Marker() string { return p.Prefix() + "/" + strings.ToLower(p.GUID) + "/" + p.ServerIP }
func (p Plan) CheckScript() string {
	return fmt.Sprintf(`$ErrorActionPreference='Stop'; $a=@(Get-NetAdapter -IncludeHidden | Where-Object {$_.ifIndex -eq %d -and [guid]$_.InterfaceGuid -eq [guid]'%s'}); if($a.Count -ne 1){throw 'USB adapter identity changed'}; $a=$a[0]; `, p.Index, p.GUID)
}
func (p Plan) FirewallSetup() (string, error) {
	if !p.Valid() {
		return "", fmt.Errorf("invalid plan")
	}
	prefix, marker, peer := p.Prefix(), p.Marker(), p.PeerIP()
	s := p.CheckScript() + fmt.Sprintf(`
$names=@('%s-DHCP','%s-MDNS','%s-TCP','%s-UDP');
foreach($n in $names){if(Get-NetFirewallRule -PolicyStore PersistentStore -Name $n -ErrorAction SilentlyContinue){throw 'Rule name already exists'}};
New-NetFirewallRule -PolicyStore PersistentStore -Name $names[0] -DisplayName 'Suhang iPad USB DHCP trial' -Group '%s' -Description '%s' -Direction Inbound -Action Allow -Enabled True -Profile Any -InterfaceAlias $a.Name -Protocol UDP -LocalPort %s -RemotePort 68 | Out-Null;
New-NetFirewallRule -PolicyStore PersistentStore -Name $names[1] -DisplayName 'Suhang iPad USB discovery trial' -Group '%s' -Description '%s' -Direction Inbound -Action Allow -Enabled True -Profile Any -InterfaceAlias $a.Name -Protocol UDP -LocalPort %s | Out-Null;
New-NetFirewallRule -PolicyStore PersistentStore -Name $names[2] -DisplayName 'Suhang iPad USB application TCP trial' -Group '%s' -Description '%s' -Direction Inbound -Action Allow -Enabled True -Profile Any -InterfaceAlias $a.Name -LocalAddress '%s' -RemoteAddress '%s' -Protocol TCP -LocalPort %s | Out-Null;
New-NetFirewallRule -PolicyStore PersistentStore -Name $names[3] -DisplayName 'Suhang iPad USB Sunshine UDP trial' -Group '%s' -Description '%s' -Direction Inbound -Action Allow -Enabled True -Profile Any -InterfaceAlias $a.Name -LocalAddress '%s' -RemoteAddress '%s' -Protocol UDP -LocalPort %s | Out-Null;
Write-Output 'OWNED_FIREWALL_READY';`, prefix, prefix, prefix, prefix, prefix, marker, securitypolicy.Ports(securitypolicy.AddressAssignment, "UDP"), prefix, marker, securitypolicy.Ports(securitypolicy.Discovery, "UDP"), prefix, marker, p.ServerIP, peer, securitypolicy.InboundPorts("ipad", "TCP"), prefix, marker, p.ServerIP, peer, securitypolicy.InboundPorts("ipad", "UDP"))
	return s, nil
}
func (p Plan) FirewallCleanup() (string, error) {
	if !p.Valid() {
		return "", fmt.Errorf("invalid plan")
	}
	prefix := p.Prefix()
	return fmt.Sprintf(`$ErrorActionPreference='Stop'; $names=@('%s-DHCP','%s-MDNS','%s-TCP','%s-UDP'); $all=@(Get-NetFirewallRule -PolicyStore PersistentStore); foreach($n in $names){$r=@($all|Where-Object {$_.Name -eq $n});if($r.Count -gt 1){throw 'Ambiguous owned rule'};if($r.Count -eq 1){if($r[0].Group -ne '%s' -or $r[0].Description -ne '%s'){throw 'Rule ownership changed'}; $r[0]|Remove-NetFirewallRule -ErrorAction Stop}}; $left=@(Get-NetFirewallRule -PolicyStore PersistentStore | Where-Object {$_.Name -in $names});if($left.Count -ne 0){throw 'Owned rules remain'};Write-Output 'OWNED_FIREWALL_REMOVED';`, prefix, prefix, prefix, prefix, prefix, p.Marker()), nil
}
func SubnetScript(index uint32, guid string, start byte) (string, error) {
	if index == 0 || !guidPattern.MatchString(guid) || start == 0 || start == 255 {
		return "", fmt.Errorf("invalid subnet request")
	}
	p := Plan{Index: index, GUID: guid}
	return p.CheckScript() + `
function V4Num([string]$s){$b=[net.ipaddress]::Parse($s).GetAddressBytes();if($b.Length -ne 4){throw 'Expected IPv4'};return ([uint64]$b[0]*16777216+[uint64]$b[1]*65536+[uint64]$b[2]*256+[uint64]$b[3])};
$ranges=@();foreach($r in @(Get-NetRoute -AddressFamily IPv4 -PolicyStore ActiveStore)){ $parts=$r.DestinationPrefix.Split('/');$bits=[int]$parts[1];if($bits -eq 0){continue};$base=V4Num $parts[0];$size=[uint64][math]::Pow(2,32-$bits);$ranges+=,@($base,($base+$size-1))};
foreach($ip in @(Get-NetIPAddress -AddressFamily IPv4)){ $n=V4Num $ip.IPAddress;$ranges+=,@($n,$n)};
` + `$base=V4Num '10.6.9.0';$end=$base+255;foreach($r in $ranges){if($base -le $r[1] -and $end -ge $r[0]){throw 'USB subnet conflicts with an existing address or route'}};Write-Output '10.6.9.1';`, nil
}

func ParseChosenSubnet(s string) string {
	s = strings.TrimSpace(s)
	if s != "10.6.9.1" && s != "10.6.10.1" {
		return ""
	}
	return s
}

func (p Plan) AddressLifetime() uint32 {
	if p.Version == 6 && p.AddressMode == "persistent" {
		return ^uint32(0)
	}
	if p.Version == 1 {
		return 1800
	}
	return 3600
}

// Separate subnet and source-bound listeners prevent ambiguous dual routes.
func ConcurrentSubnetScript(index uint32, guid string, start byte) (string, error) {
	script, e := SubnetScript(index, guid, start)
	if e != nil {
		return "", e
	}
	script = strings.ReplaceAll(script, "10.6.9.0", "10.6.10.0")
	return strings.ReplaceAll(script, "10.6.9.1", "10.6.10.1"), nil
}

func (p Plan) AddressPrefix() uint8 {
	if p.Version >= 4 {
		return 32
	}
	return 24
}
func (p Plan) RouteMetric() uint32 { return 5000 + (crc32.ChecksumIEEE([]byte(p.Token)) & 0xffffff) }

type HostFlags struct {
	Send    bool `json:"send"`
	Receive bool `json:"receive"`
	Forward bool `json:"forward,omitempty"`
}

func (p Plan) LocalAddress() string {
	if p.Version == 5 || p.Version == 6 {
		return "10.6.9.254"
	}
	return p.ServerIP
}
