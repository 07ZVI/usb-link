package netconfig

// ResidentMacNullProjectionScript is a fixed, read-only diagnostic. It compares
// provider AppPath with NetSecurity's public Program projection without emitting
// either value. Its observations never authorize Ready, repair or default Any.
func ResidentMacNullProjectionScript() string {
	return `$ErrorActionPreference='Stop';$ProgressPreference='SilentlyContinue'
$names=@('USB-Link-Resident-Mac-ICMP-v1','USB-Link-Resident-Mac-BENCH-v1','USB-Link-Resident-Mac-SUN-TCP-v1','USB-Link-Resident-Mac-SUN-UDP-v1','USB-Link-Resident-Mac-FILES-v1')
function Shape($present,$value){
  if(-not $present){return @('missing',$false)}
  if($null -eq $value){return @('null',$false)}
  if($value -is [string]){return @('string',[string]::Equals($value,'Any',[StringComparison]::OrdinalIgnoreCase))}
  return @('other',$false)
}
$out=@()
for($i=0;$i -lt 5;$i++){
  $n=$names[$i]
  $row=[ordered]@{selector_index=$i;status='unavailable';phase='public_rule';public_rule_count=0;public_filter_count=0;cim_rule_count=0;cim_filter_count=0;public_program_kind='unread';public_program_is_any=$false;cim_app_path_kind='unread';cim_app_path_is_any=$false}
  try{
    $rules=@(Get-NetFirewallRule -Name $n -ErrorAction SilentlyContinue -WarningAction SilentlyContinue)
    $row.public_rule_count=[Math]::Min(2,$rules.Count)
    if($rules.Count -eq 0){$row.status='rule_absent'}
    elseif($rules.Count -ne 1 -or -not [string]::Equals($rules[0].Name,$n,[StringComparison]::Ordinal)){$row.status='rule_not_unique'}
    else{
      $row.phase='public_filter'
      $pf=@(Get-NetFirewallApplicationFilter -AssociatedNetFirewallRule $rules[0] -ErrorAction Stop -WarningAction SilentlyContinue)
      $row.public_filter_count=[Math]::Min(2,$pf.Count)
      if($pf.Count -ne 1){$row.status='filter_not_unique'}
      else{
        $prop=$pf[0].PSObject.Properties['Program']
        $shape=Shape ($null -ne $prop) $(if($null -ne $prop){$prop.Value}else{$null})
        $row.public_program_kind=$shape[0];$row.public_program_is_any=$shape[1]
        $row.phase='cim_rule'
        $cr=@(Get-CimInstance -Namespace root/standardcimv2 -ClassName MSFT_NetFirewallRule -Filter "InstanceID='$n'" -ErrorAction Stop)
        $row.cim_rule_count=[Math]::Min(2,$cr.Count)
        if($cr.Count -ne 1 -or -not [string]::Equals($cr[0].InstanceID,$n,[StringComparison]::Ordinal)){$row.status='rule_not_unique'}
        else{
          $row.phase='cim_filter'
          $cf=@(Get-CimAssociatedInstance -InputObject $cr[0] -ResultClassName MSFT_NetApplicationFilter -ErrorAction Stop)
          $row.cim_filter_count=[Math]::Min(2,$cf.Count)
          if($cf.Count -ne 1){$row.status='filter_not_unique'}
          else{
            $prop=$cf[0].CimInstanceProperties['AppPath']
            $shape=Shape ($null -ne $prop) $(if($null -ne $prop){$prop.Value}else{$null})
            $row.cim_app_path_kind=$shape[0];$row.cim_app_path_is_any=$shape[1]
            $row.status='observed'
          }
        }
      }
    }
  }catch{$row.status='unavailable'}
  $out+=([pscustomobject]$row)
}
$result=[ordered]@{schema=1;read_only=$true;rows=$out}
$json=ConvertTo-Json -InputObject $result -Depth 4 -Compress
if($json.Length -le 4096){Write-Output ('USB_MAC_NULL_PROJECTION '+$json)}
else{Write-Output 'USB_MAC_NULL_PROJECTION {"schema":1,"read_only":true,"rows":[],"status":"bounded_output_rejected"}'}
`
}
