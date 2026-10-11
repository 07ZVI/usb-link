package netconfig

import "strings"

// ResidentMacAnchorProjectionScript has no inputs and only queries the five
// fixed rules and their exact associations. Literal ICMP 8/* shape recognition
// is diagnostic, not an equivalence proof or a relaxation of any validator.
func ResidentMacAnchorProjectionScript() string {
	var data strings.Builder
	data.WriteString("$plans=@(\n")
	for i, s := range residentMacCompiledSpecs() {
		if i != 0 {
			data.WriteString(",\n")
		}
		data.WriteString("@{name=" + residentQuote(s.Name) + ";fields=@(\n")
		want := expectedFirewallConstraints(s, 1)
		for j, key := range residentAnchors {
			if j != 0 {
				data.WriteString(",\n")
			}
			class, field, _ := strings.Cut(key, "/")
			public := field
			switch field {
			case "InstanceID":
				public = "Name"
			case "RuleGroup":
				public = "Group"
			case "AppPath":
				public = "Program"
			case "ServiceName":
				public = "Service"
			}
			diagnosticClass := class
			if diagnosticClass == "" {
				diagnosticClass = firewallRuleDiagnosticClass
			}
			parts := want[key]
			for k := range parts {
				parts[k] = residentQuote(parts[k])
			}
			data.WriteString("@{field=" + residentQuote(diagnosticClass+"/"+field) + ";class=" + residentQuote(class) + ";property=" + residentQuote(field) + ";public=" + residentQuote(public) + ";expected=@(" + strings.Join(parts, ",") + ")}")
		}
		data.WriteString("\n)}")
	}
	data.WriteString("\n)\n")
	return "$ErrorActionPreference='Stop';$ProgressPreference='SilentlyContinue'\n" + data.String() + residentMacAnchorProjectionBody
}

const residentMacAnchorProjectionBody = `
function AnchorShape($present,$v,[string]$field,$want){
 $o=[ordered]@{kind='missing';is_exact_expected=$false;is_known_8_any_code=$false}
 if(-not $present){return $o};if($null -eq $v){$o.kind='null';return $o}
 $parts=@();if($v -is [string]){$o.kind='string';$parts=@('S:'+$v)}
 elseif($v -is [array]){$o.kind='string_array';foreach($x in $v){if($x -isnot [string]){$o.kind='other';return $o};$parts+=,('S:'+$x)};[array]::Sort($parts,[StringComparer]::Ordinal)}
 elseif($field -eq 'Protocol' -and $v -is [uint16] -and $v -le 255){$o.kind='unsigned_integer';$parts=@('N:'+([string]$v))}
 else{$o.kind='other';return $o}
 if($field -eq 'Protocol' -and $v -is [string]){$n=switch($v){'ICMPv4'{1};'TCP'{6};'UDP'{17};'ICMPv6'{58};default{$null}};if($null -ne $n){$parts=@('N:'+([string]$n))}elseif($v -match '^(0|[1-9][0-9]{0,2})$' -and [int]$v -le 255){$parts=@('N:'+([string][int]$v))}}
 $equal=($parts.Count -eq $want.Count);if($equal){for($k=0;$k -lt $parts.Count;$k++){if(-not [string]::Equals($parts[$k],$want[$k],[StringComparison]::Ordinal)){$equal=$false;break}}};$o.is_exact_expected=$equal
 if($field -eq 'IcmpType' -and $want.Count -eq 1 -and $want[0] -ceq 'S:8' -and $o.kind -eq 'string_array' -and $parts.Count -eq 1 -and ($parts[0] -ceq 'S:8' -or $parts[0] -ceq 'S:8:*')){$o.is_known_8_any_code=$true}
 return $o
}
function PublicAnchorFilter([string]$class,$r){
 switch($class){
 'MSFT_NetApplicationFilter'{return @(Get-NetFirewallApplicationFilter -AssociatedNetFirewallRule $r -ErrorAction Stop -WarningAction SilentlyContinue)}
 'MSFT_NetServiceFilter'{return @(Get-NetFirewallServiceFilter -AssociatedNetFirewallRule $r -ErrorAction Stop -WarningAction SilentlyContinue)}
 'MSFT_NetInterfaceFilter'{return @(Get-NetFirewallInterfaceFilter -AssociatedNetFirewallRule $r -ErrorAction Stop -WarningAction SilentlyContinue)}
 'MSFT_NetAddressFilter'{return @(Get-NetFirewallAddressFilter -AssociatedNetFirewallRule $r -ErrorAction Stop -WarningAction SilentlyContinue)}
 'MSFT_NetProtocolPortFilter'{return @(Get-NetFirewallPortFilter -AssociatedNetFirewallRule $r -ErrorAction Stop -WarningAction SilentlyContinue)}
 default{throw 'FIXED_CLASS_UNKNOWN'}
 }
}
$out=@()
for($i=0;$i -lt 5;$i++){
 $plan=$plans[$i];$n=$plan.name;$row=[ordered]@{selector_index=$i;status='unavailable';public_rule_count=0;cim_rule_count=0;fields=@()}
 try{
  $pr=@(Get-NetFirewallRule -PolicyStore PersistentStore -Name $n -ErrorAction SilentlyContinue -WarningAction SilentlyContinue)
  $cr=@(Get-CimInstance -Namespace root/standardcimv2 -ClassName MSFT_NetFirewallRule -Filter "InstanceID='$n'" -ErrorAction Stop)
  $row.public_rule_count=[Math]::Min(2,$pr.Count);$row.cim_rule_count=[Math]::Min(2,$cr.Count)
  if($pr.Count -eq 0 -and $cr.Count -eq 0){$row.status='rule_absent'}
  elseif($pr.Count -ne 1 -or $cr.Count -ne 1 -or -not [string]::Equals($pr[0].Name,$n,[StringComparison]::Ordinal) -or -not [string]::Equals($cr[0].InstanceID,$n,[StringComparison]::Ordinal)){$row.status='rule_not_unique'}
  else{
   $public=@{' '=$pr};$native=@{' '=$cr};$row.status='observed'
   foreach($class in @('MSFT_NetApplicationFilter','MSFT_NetServiceFilter','MSFT_NetInterfaceFilter','MSFT_NetAddressFilter','MSFT_NetProtocolPortFilter')){
    $public[$class]=@(PublicAnchorFilter $class $pr[0]);$native[$class]=@(Get-CimAssociatedInstance -InputObject $cr[0] -ResultClassName $class -ErrorAction Stop)
    if($public[$class].Count -ne 1 -or $native[$class].Count -ne 1){$row.status='filter_not_unique'}
   }
   foreach($def in $plan.fields){
    $class=$def.class;if($class -eq ''){$class=' '};$pa=$public[$class];$ca=$native[$class]
    $ps=[ordered]@{kind='unread';is_exact_expected=$false;is_known_8_any_code=$false};$cs=[ordered]@{kind='unread';is_exact_expected=$false;is_known_8_any_code=$false}
    if($pa.Count -eq 1){$prop=$pa[0].PSObject.Properties[$def.public];$ps=AnchorShape ($null -ne $prop) $(if($null -ne $prop){$prop.Value}else{$null}) $def.property $def.expected}
    if($ca.Count -eq 1){$prop=$ca[0].CimInstanceProperties[$def.property];$cs=AnchorShape ($null -ne $prop) $(if($null -ne $prop){$prop.Value}else{$null}) $def.property $def.expected}
    $row.fields+=([pscustomobject][ordered]@{field=$def.field;public_count=[Math]::Min(2,$pa.Count);cim_count=[Math]::Min(2,$ca.Count);public_kind=$ps.kind;cim_kind=$cs.kind;public_is_exact_expected=$ps.is_exact_expected;cim_is_exact_expected=$cs.is_exact_expected;public_is_known_8_any_code=$ps.is_known_8_any_code;cim_is_known_8_any_code=$cs.is_known_8_any_code})
   }
  }
 }catch{$row.status='unavailable';$row.fields=@()}
 $out+=([pscustomobject]$row)
}
$json=ConvertTo-Json -InputObject ([ordered]@{schema=1;read_only=$true;rows=$out}) -Depth 5 -Compress
if($json.Length -le 32768){Write-Output ('USB_MAC_ANCHOR_PROJECTION '+$json)}
else{Write-Output 'USB_MAC_ANCHOR_PROJECTION {"schema":1,"read_only":true,"rows":[],"status":"bounded_output_rejected"}'}
`
