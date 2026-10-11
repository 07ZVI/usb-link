package netconfig

import "strings"

// The input is exclusively residentSpecs(core_ipad) built after fresh owner
// proof. No RPC or caller supplies names, expected fields or arbitrary scripts.
func ipadAddressPublicScript(specs []nativeRuleSpec) string {
	if len(specs) != 4 {
		return ""
	}
	var b strings.Builder
	b.WriteString(`$ErrorActionPreference='Stop';$ProgressPreference='SilentlyContinue';$specs=@(`)
	for i, s := range specs {
		if i != 0 {
			b.WriteString(",")
		}
		b.WriteString("@{n=" + residentQuote(s.Name) + ";l=" + residentQuote(s.Local) + ";r=" + residentQuote(s.Remote) + ";p=" + residentQuote(s.Program) + ";a=" + residentQuote(s.Alias) + ";g=" + residentQuote(s.Group) + ";d=" + residentQuote(s.Description) + "}")
	}
	b.WriteString(`)
function Unread {return [ordered]@{status='unavailable';rule_count=0;filter_count=0;markers_match=$false;program_match=$false;interface_match=$false;local=[ordered]@{kind='unread';count=0;is_any=$false;expected_exact=$false};remote=[ordered]@{kind='unread';count=0;is_any=$false;expected_exact=$false}}}
function Shape($prop,[string]$expected){
 $o=[ordered]@{kind='missing';count=0;is_any=$false;expected_exact=$false}
 if($null -eq $prop){return $o};$v=$prop.Value
 if($null -eq $v){$o.kind='null';return $o}
 if($v -is [string]){$o.kind='string';$a=@($v)}elseif($v -is [array]){$o.kind='array';$a=@($v)}else{$o.kind='other';return $o}
 if($a.Count -gt 64){$o.kind='other';return $o}
 foreach($x in $a){if($x -isnot [string] -or $x.Length -gt 1024 -or $x.Contains([char]0)){$o.kind='other';return $o}}
 $o.count=$a.Count;$o.is_any=($a.Count -eq 1 -and [string]::Equals($a[0],'Any',[StringComparison]::OrdinalIgnoreCase));$want=@($expected.Split(','));[array]::Sort($a,[StringComparer]::Ordinal);[array]::Sort($want,[StringComparer]::Ordinal);$same=($a.Count -eq $want.Count);if($same){for($j=0;$j -lt $a.Count;$j++){if(-not [string]::Equals($a[$j],$want[$j],[StringComparison]::Ordinal)){$same=$false}}};$o.expected_exact=$same;return $o
}
$rows=@()
for($i=0;$i -lt 4;$i++){
 $s=$specs[$i];$p=Unread
 try{
  $rs=@(Get-NetFirewallRule -PolicyStore PersistentStore -Name $s.n -ErrorAction SilentlyContinue -WarningAction SilentlyContinue);$p.rule_count=[Math]::Min(2,$rs.Count)
  if($rs.Count -eq 0){$p.status='rule_absent'}elseif($rs.Count -ne 1 -or -not [string]::Equals($rs[0].Name,$s.n,[StringComparison]::Ordinal)){$p.status='rule_not_unique'}else{
   $p.markers_match=([string]::Equals($rs[0].Group,$s.g,[StringComparison]::Ordinal) -and [string]::Equals($rs[0].Description,$s.d,[StringComparison]::Ordinal))
   $ap=@(Get-NetFirewallApplicationFilter -AssociatedNetFirewallRule $rs[0] -ErrorAction Stop);if($ap.Count -eq 1){$p.program_match=[string]::Equals($ap[0].Program,$s.p,[StringComparison]::OrdinalIgnoreCase)}
   $ip=@(Get-NetFirewallInterfaceFilter -AssociatedNetFirewallRule $rs[0] -ErrorAction Stop);if($ip.Count -eq 1){$ia=@($ip[0].InterfaceAlias);$p.interface_match=($ia.Count -eq 1 -and [string]::Equals($ia[0],$s.a,[StringComparison]::Ordinal))}
   $af=@(Get-NetFirewallAddressFilter -AssociatedNetFirewallRule $rs[0] -ErrorAction Stop);$p.filter_count=[Math]::Min(2,$af.Count)
   if($af.Count -ne 1){$p.status='filter_not_unique'}else{$p.status='observed';$lp=$af[0].PSObject.Properties['LocalAddress'];$rp=$af[0].PSObject.Properties['RemoteAddress'];$p.local=Shape $lp $s.l;$p.remote=Shape $rp $s.r}
  }
 }catch{$p=Unread}
 $rows+=([pscustomobject]@{selector_index=$i;public=$p;native=(Unread)})
}
$result=[ordered]@{duration_ms=0;schema=1;read_only=$true;scope='FIXED_CORE_IPAD_ADDRESS_OBSERVATION_NOT_OWNERSHIP_OR_NULL_COMPATIBILITY';status='observed';rows=$rows}
$json=ConvertTo-Json -InputObject $result -Depth 7 -Compress;if($json.Length -gt 8192){throw 'IPAD_ADDRESS_PROJECTION_LIMIT'};Write-Output ('USB_IPAD_ADDRESS_PROJECTION '+$json)
`)
	return b.String()
}
