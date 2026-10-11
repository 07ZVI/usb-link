package connectioninstall

import (
	"fmt"
	"regexp"
	"strings"
)

const measurementRule = "Suhang-USB-Latency-Mac-v1"
const measurementGroup = "Suhang-USB-Latency-v1"

var measurementGUID = regexp.MustCompile(`^\{?[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\}?$`)

// Only a fixed port, program, interface and USB peer are authorized. The
// description identifies the request so an old timeout cannot erase a new rule.
func measurementFirewallScript(enabled bool, guid, id, exe string) (string, error) {
	if id != "" && !measurementNonce.MatchString(id) {
		return "", fmt.Errorf("invalid measurement id")
	}
	if enabled && (!measurementGUID.MatchString(guid) || id == "" || exe == "" || strings.ContainsAny(exe, "\x00\r\n")) {
		return "", fmt.Errorf("invalid UDP measurement identity")
	}
	s := `$r=@(Get-NetFirewallRule -Name '` + measurementRule + `' -ErrorAction SilentlyContinue);if(@($r|Where-Object {$_.Group -cne '` + measurementGroup + `'}).Count){throw 'Measurement rule ownership changed'};`
	if !enabled && id != "" {
		s += `$r=@($r|Where-Object {$_.Description -ceq '` + id + `'});`
	}
	s += `$r|Remove-NetFirewallRule -ErrorAction Stop;`
	if enabled {
		s += `$a=@(Get-NetAdapter -IncludeHidden|Where-Object {[guid]$_.InterfaceGuid -eq [guid]'` + guid + `' -and $_.Name -ceq 'USB Link'});if($a.Count -ne 1){throw 'USB adapter identity changed'};New-NetFirewallRule -Name '` + measurementRule + `' -DisplayName 'USB Link temporary authenticated UDP latency' -Group '` + measurementGroup + `' -Description '` + id + `' -Direction Inbound -Action Allow -Protocol UDP -LocalPort 10691 -RemoteAddress '10.6.9.2' -LocalAddress '10.6.9.1' -InterfaceAlias $a[0].Name -Profile Any -Program '` + strings.ReplaceAll(exe, "'", "''") + `' -ErrorAction Stop|Out-Null;`
	}
	return s, nil
}

const measurementICMPRule = "Suhang-USB-Latency-ICMP-Mac-v1"

func measurementICMPFirewallScript(enabled bool, guid, id string) (string, error) {
	if id != "" && !measurementNonce.MatchString(id) {
		return "", fmt.Errorf("invalid measurement id")
	}
	if enabled && (!measurementGUID.MatchString(guid) || id == "") {
		return "", fmt.Errorf("invalid ICMP measurement identity")
	}
	s := `$r=@(Get-NetFirewallRule -Name '` + measurementICMPRule + `' -ErrorAction SilentlyContinue);if(@($r|Where-Object {$_.Group -cne '` + measurementGroup + `'}).Count){throw 'Measurement rule ownership changed'};`
	if !enabled && id != "" {
		s += `$r=@($r|Where-Object {$_.Description -ceq '` + id + `'});`
	}
	s += `$r|Remove-NetFirewallRule -ErrorAction Stop;`
	if enabled {
		s += `$a=@(Get-NetAdapter -IncludeHidden|Where-Object {[guid]$_.InterfaceGuid -eq [guid]'` + guid + `' -and $_.Name -ceq 'USB Link'});if($a.Count -ne 1){throw 'USB adapter identity changed'};New-NetFirewallRule -Name '` + measurementICMPRule + `' -DisplayName 'USB Link temporary USB ICMP echo' -Group '` + measurementGroup + `' -Description '` + id + `' -Direction Inbound -Action Allow -Protocol ICMPv4 -IcmpType 8 -RemoteAddress '10.6.9.2' -LocalAddress '10.6.9.1' -InterfaceAlias $a[0].Name -Profile Any -ErrorAction Stop|Out-Null;`
	}
	return s, nil
}
