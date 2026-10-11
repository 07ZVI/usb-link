package netconfig

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
)

func residentQuote(s string) string { return "'" + strings.ReplaceAll(s, "'", "''") + "'" }

func residentArray(s string) string {
	parts := strings.Split(s, ",")
	for i := range parts {
		parts[i] = residentQuote(parts[i])
	}
	return "@(" + strings.Join(parts, ",") + ")"
}

// The mutation body uses the established NetSecurity cmdlets. CIM is strictly
// read-only here and pins every observed field before a precise named removal.
// No marker-only delete, native COM setter, prefix sweep or speculative repair.
const residentPSProbe = `
function USB-ResidentSnapshot($r){
 $map=@{};$classes=@('','MSFT_NetApplicationFilter','MSFT_NetAddressFilter','MSFT_NetProtocolPortFilter','MSFT_NetInterfaceFilter','MSFT_NetInterfaceTypeFilter','MSFT_NetServiceFilter','MSFT_NetNetworkLayerSecurityFilter');
 $fields=@(@('InstanceID','RuleGroup','Description','DisplayName','ElementName','PackageFamilyName','PolicyAppId','Enabled','Direction','Action','Profiles','Platforms','EdgeTraversalPolicy','LooseSourceMapping','LocalOnlyMapping','Owner'),@('AppPath','Package'),@('LocalAddress','RemoteAddress'),@('Protocol','LocalPort','RemotePort','IcmpType','DynamicTransport'),@('InterfaceAlias'),@('InterfaceType'),@('ServiceName'),@('Authentication','Encryption','OverrideBlockRules','LocalUsers','RemoteUsers','RemoteMachines'));
 $addr=$null;
 for($i=0;$i -lt $classes.Count;$i++){$d=$r;if($i -gt 0){$a=@(Get-CimAssociatedInstance -InputObject $r -ResultClassName $classes[$i] -ErrorAction Stop);if($a.Count -ne 1){throw 'USB_RESIDENT_FILTER_UNPROVEN'};$d=$a[0]};if($i -eq 2){$addr=$d};foreach($f in $fields[$i]){$p=$d.CimInstanceProperties[$f];if($null -eq $p){throw 'USB_RESIDENT_FIELD_UNKNOWN'};$map[$classes[$i]+'/'+$f]=@(USB-ResidentValue $p.Value $f)}};
 $rp=$r.CimInstanceProperties['RemoteDynamicKeywordAddresses'];$ap=$addr.CimInstanceProperties['RemoteDynamicKeywordAddresses'];if(($null -eq $rp) -eq ($null -eq $ap)){throw 'USB_RESIDENT_DYNAMIC_UNKNOWN'};if($null -ne $rp){$map['/dynamic_source']=@('S:RULE');$map['/RemoteDynamicKeywordAddresses']=@(USB-ResidentValue $rp.Value 'RemoteDynamicKeywordAddresses')}else{$map['/dynamic_source']=@('S:ADDRESS');$map['/RemoteDynamicKeywordAddresses']=@(USB-ResidentValue $ap.Value 'RemoteDynamicKeywordAddresses')};return $map
}
function USB-ResidentValue($v,[string]$f){
 if($null -eq $v){return 'NULL'};
 if($f -eq 'Protocol'){if($v -isnot [string]){throw 'USB_RESIDENT_TYPE_UNKNOWN'};$n=switch($v){'TCP'{6};'UDP'{17};'ICMPv4'{1};'ICMPv6'{58};default{[byte]::Parse($v)}};return 'N:'+([string]$n)};
 if($f -in @('LooseSourceMapping','LocalOnlyMapping','OverrideBlockRules')){if($v -isnot [bool]){throw 'USB_RESIDENT_TYPE_UNKNOWN'};return 'B:'+([string]$v).ToLowerInvariant()};
 if($f -in @('Enabled','Direction','Action','Profiles','EdgeTraversalPolicy','DynamicTransport','InterfaceType','Authentication','Encryption')){if($v -isnot [byte] -and $v -isnot [uint16] -and $v -isnot [uint32] -and $v -isnot [int16] -and $v -isnot [int32]){throw 'USB_RESIDENT_TYPE_UNKNOWN'};return 'N:'+([string][uint32]$v)};
 if($f -in @('Platforms','LocalAddress','RemoteAddress','LocalPort','RemotePort','IcmpType','InterfaceAlias','RemoteDynamicKeywordAddresses')){if($v -isnot [array]){throw 'USB_RESIDENT_TYPE_UNKNOWN'};$a=@();foreach($x in $v){if($x -isnot [string] -or $x.Length -gt 1024 -or $x.Contains([char]0)){throw 'USB_RESIDENT_TYPE_UNKNOWN'};$a+=,('S:'+$x)};[array]::Sort($a,[StringComparer]::Ordinal);return $a};
 if($v -isnot [string] -or $v.Length -gt 1024 -or $v.Contains([char]0)){throw 'USB_RESIDENT_TYPE_UNKNOWN'};return 'S:'+$v
}
function USB-ResidentCompare($a,$b){$props=@($b.PSObject.Properties);if($a.Count -ne $props.Count){throw 'USB_RESIDENT_CONSTRAINT_CHANGED'};foreach($p in $props){if(-not $a.ContainsKey($p.Name)){throw 'USB_RESIDENT_CONSTRAINT_CHANGED'};$x=@($a[$p.Name]);$y=@($p.Value);if($x.Count -ne $y.Count){throw 'USB_RESIDENT_CONSTRAINT_CHANGED'};for($j=0;$j -lt $x.Count;$j++){if(-not [string]::Equals($x[$j],$y[$j],[StringComparison]::Ordinal)){throw 'USB_RESIDENT_CONSTRAINT_CHANGED'}}}}
function USB-ResidentRule([string]$n){$a=@(Get-CimInstance -Namespace root/standardcimv2 -ClassName MSFT_NetFirewallRule -Filter ("InstanceID='"+$n.Replace("'","''")+"'") -ErrorAction Stop);if($a.Count -gt 1){throw 'USB_RESIDENT_AMBIGUOUS'};if($a.Count -eq 0){return $null};return $a[0]}
function USB-ResidentPin([string]$p,[string]$sha){$item=Get-Item -LiteralPath $p -Force -ErrorAction Stop;if($item.Attributes -band [IO.FileAttributes]::ReparsePoint){throw 'USB_RESIDENT_STORE_UNPROVEN'};$acl=Get-Acl -LiteralPath $p -ErrorAction Stop;if(-not $acl.AreAccessRulesProtected){throw 'USB_RESIDENT_STORE_UNPROVEN'};$owner=$acl.GetOwner([Security.Principal.SecurityIdentifier]).Value;if($owner -notin @('S-1-5-18','S-1-5-32-544')){throw 'USB_RESIDENT_STORE_UNPROVEN'};$rs=@($acl.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier]));if($rs.Count -ne 2){throw 'USB_RESIDENT_STORE_UNPROVEN'};$ids=@();foreach($x in $rs){if($x.AccessControlType -ne 'Allow' -or $x.IsInherited -or $x.InheritanceFlags -ne 'None' -or $x.PropagationFlags -ne 'None' -or [int]$x.FileSystemRights -ne 2032127){throw 'USB_RESIDENT_STORE_UNPROVEN'};$ids+=$x.IdentityReference.Value};if(('S-1-5-18' -notin $ids) -or ('S-1-5-32-544' -notin $ids)){throw 'USB_RESIDENT_STORE_UNPROVEN'};$h=[IO.File]::Open($p,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read);try{$alg=[Security.Cryptography.SHA256]::Create();try{$got=([BitConverter]::ToString($alg.ComputeHash($h))).Replace('-','').ToLowerInvariant()}finally{$alg.Dispose()};if($got -cne $sha){throw 'USB_RESIDENT_LEDGER_CHANGED'};return $h}catch{$h.Dispose();throw}}
`

func residentGuard(s nativeRuleSpec, b residentRuleObservation, index int) string {
	n := residentQuote(s.Name)
	out := "$r=USB-ResidentRule " + n + ";"
	if !b.Present {
		return out + "if($null -ne $r){throw 'USB_RESIDENT_RULE_APPEARED'};"
	}
	out += fmt.Sprintf("$want=$residentReceipt.Before[%d].Constraints;if($null -eq $r){throw 'USB_RESIDENT_RULE_DISAPPEARED'};USB-ResidentCompare (USB-ResidentSnapshot $r) $want;", index)
	out += "$r=USB-ResidentRule " + n + ";if($null -eq $r){throw 'USB_RESIDENT_RULE_DISAPPEARED'};USB-ResidentCompare (USB-ResidentSnapshot $r) $want;"
	return out
}

func residentNew(s nativeRuleSpec) string {
	out := "New-NetFirewallRule -PolicyStore PersistentStore -Name " + residentQuote(s.Name) + " -DisplayName " + residentQuote(s.Display) + " -Group " + residentQuote(s.Group) + " -Description " + residentQuote(s.Description) + " -Direction Inbound -Action Allow -Enabled True -Profile Any -InterfaceAlias " + residentQuote(s.Alias) + " -LocalAddress " + residentArray(s.Local) + " -RemoteAddress " + residentArray(s.Remote) + " -Program " + residentQuote(s.Program) + " -Service " + residentQuote(s.Service)
	if s.Protocol == 1 {
		out += " -Protocol ICMPv4 -IcmpType 8"
	} else {
		protocol := "TCP"
		if s.Protocol == 17 {
			protocol = "UDP"
		}
		out += " -Protocol " + protocol + " -LocalPort " + residentArray(s.Ports) + " -RemotePort " + residentArray(s.RemotePorts)
	}
	return out + " -ErrorAction Stop|Out-Null;"
}
func residentScript(path string, b []byte, v residentLedger, changed []int, index uint32) string {
	sha := sha256.Sum256(b)
	s := "$ErrorActionPreference='Stop';" + residentPSProbe + "$pin=USB-ResidentPin " + residentQuote(path) + " " + residentQuote(hex.EncodeToString(sha[:])) + ";try{$pin.Position=0;$reader=[IO.StreamReader]::new($pin,[Text.Encoding]::UTF8,$true,1024,$true);try{$residentReceipt=($reader.ReadToEnd()|ConvertFrom-Json)}finally{$reader.Dispose()};"
	if index != 0 {
		s += fmt.Sprintf("$nic=@(Get-NetAdapter -IncludeHidden|Where-Object {[guid]$_.InterfaceGuid -eq [guid]%s -and $_.ifIndex -eq %d -and $_.Name -ceq %s});if($nic.Count -ne 1){throw 'USB_RESIDENT_INTERFACE_CHANGED'};", residentQuote(v.GUID), index, residentQuote(v.Specs[0].Alias))
	}
	// Validate the complete intended batch before its first mutation.
	for _, i := range changed {
		s += residentGuard(v.Specs[i], v.Before[i], i)
	}
	sort.Ints(changed)
	for _, i := range changed {
		s += residentGuard(v.Specs[i], v.Before[i], i)
		if v.Before[i].Present {
			s += "$fr=@(Get-NetFirewallRule -PolicyStore PersistentStore -Name " + residentQuote(v.Specs[i].Name) + " -ErrorAction Stop);if($fr.Count -ne 1){throw 'USB_RESIDENT_AMBIGUOUS'};$fr[0]|Remove-NetFirewallRule -ErrorAction Stop;"
		}
		if v.Phase != "removing" {
			s += residentNew(v.Specs[i])
		}
	}
	return s + "}finally{$pin.Dispose()};"
}
