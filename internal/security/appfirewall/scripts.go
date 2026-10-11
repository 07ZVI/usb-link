package appfirewall

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
)

// Only a validated structured rule is embedded, as base64 JSON. Paths and
// destination strings never become executable PowerShell source.
func Script(c Change) (string, error) {
	if !c.Rule.Valid() || (c.Operation != "upsert" && c.Operation != "delete") {
		return "", fmt.Errorf("FIREWALL_CHANGE_INVALID")
	}
	b, _ := json.Marshal(c)
	return `$ErrorActionPreference='Stop';[Console]::OutputEncoding=New-Object System.Text.UTF8Encoding($false);
$c=ConvertFrom-Json ([Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('` + base64.StdEncoding.EncodeToString(b) + `')));$v=$c.rule;
$name='USB-Link-App-'+$v.id;$group='USB-Link-Application-Firewall-v1';$marker=$group+'/'+$v.id+'/'+$v.application.sha256;
$rules=@(Get-NetFirewallRule -PolicyStore PersistentStore -ErrorAction Stop | Where-Object {$_.Name -ceq $name});if($rules.Count -gt 1){throw 'FIREWALL_RULE_AMBIGUOUS'};
if($rules.Count -eq 1){$old=$rules[0];$apps=@($old|Get-NetFirewallApplicationFilter -ErrorAction Stop);if($old.Group -cne $group -or $old.Description -cne $marker -or $apps.Count -ne 1 -or $apps[0].Program -ine $v.application.path){throw 'FIREWALL_RULE_OWNERSHIP_CHANGED'}};
if($c.operation -ceq 'delete'){
 if($rules.Count -eq 1){$rules[0]|Remove-NetFirewallRule -ErrorAction Stop};if(@(Get-NetFirewallRule -PolicyStore PersistentStore -ErrorAction Stop|Where-Object {$_.Name -ceq $name}).Count){throw 'FIREWALL_RULE_REMAINS'};'APP_FIREWALL_RULE_REMOVED';exit 0
};
if((Get-Service BFE -ErrorAction Stop).Status -ne 'Running' -or (Get-Service MpsSvc -ErrorAction Stop).Status -ne 'Running'){throw 'FIREWALL_PROVIDER_UNAVAILABLE'};
$profiles=@(Get-NetFirewallProfile -PolicyStore ActiveStore -ErrorAction Stop);if($profiles.Count -ne 3 -or @($profiles|Where-Object {[string]$_.Enabled -ine 'True'}).Count -or @($profiles.Name|Sort-Object -Unique).Count -ne 3){throw 'FIREWALL_PROFILE_DISABLED'};
if((Get-FileHash -LiteralPath $v.application.path -Algorithm SHA256 -ErrorAction Stop).Hash -ine $v.application.sha256){throw 'FIREWALL_APPLICATION_CHANGED'};
$params=@{Action=$v.action;Direction=$v.direction;Enabled='True';Profile='Any';Protocol=$v.protocol;RemoteAddress=$v.remote;LocalPort='Any';RemotePort='Any'};
if($v.port -gt 0){if($v.direction -ceq 'outbound'){$params.RemotePort=[string]$v.port}else{$params.LocalPort=[string]$v.port}};
if($rules.Count -eq 1){$rules[0]|Set-NetFirewallRule @params -ErrorAction Stop}else{New-NetFirewallRule -PolicyStore PersistentStore -Name $name -DisplayName ('USB Link · '+[IO.Path]::GetFileName($v.application.path)) -Group $group -Description $marker -Program $v.application.path @params -ErrorAction Stop|Out-Null};
$persistentSet=@(Get-NetFirewallRule -PolicyStore PersistentStore -ErrorAction Stop);$effectiveSet=@(Get-NetFirewallRule -PolicyStore ActiveStore -ErrorAction Stop);
` + ruleReadBack + `;'APP_FIREWALL_RULE_APPLIED';`, nil
}

// Shared verification is also used by the read-only refresh. Saved receipts
// alone never establish that a rule still exists in the system.
const ruleReadBack = `$written=@($persistentSet|Where-Object {$_.Name -ceq $name});$effective=@($effectiveSet|Where-Object {$_.Name -ceq $name});
if($written.Count -ne 1 -or $effective.Count -ne 1){throw 'FIREWALL_RULE_NOT_EFFECTIVE'};
foreach($r in @($written[0],$effective[0])){
 $apps=@($r|Get-NetFirewallApplicationFilter -ErrorAction Stop);$addresses=@($r|Get-NetFirewallAddressFilter -ErrorAction Stop);$ports=@($r|Get-NetFirewallPortFilter -ErrorAction Stop);
 if($r.Group -cne $group -or $r.Description -cne $marker -or [string]$r.Action -ine $v.action -or [string]$r.Direction -ine $v.direction -or [string]$r.Enabled -ine 'True' -or [string]$r.Profile -ine 'Any' -or $apps.Count -ne 1 -or $apps[0].Program -ine $v.application.path -or $addresses.Count -ne 1 -or ($addresses[0].RemoteAddress -join ',') -ine $v.remote -or $ports.Count -ne 1){throw 'FIREWALL_RULE_READBACK_MISMATCH'};
 $protocol=[string]$ports[0].Protocol;$expected=@{any='Any';tcp='TCP';udp='UDP'}[$v.protocol];$number=@{any='256';tcp='6';udp='17'}[$v.protocol];if($protocol -ine $expected -and $protocol -cne $number){throw 'FIREWALL_RULE_PROTOCOL_MISMATCH'};
 if(($ports[0].LocalPort -join ',') -ine $params.LocalPort -or ($ports[0].RemotePort -join ',') -ine $params.RemotePort){throw 'FIREWALL_RULE_PORT_MISMATCH'}
}`

func AuditScript(rules []Rule) (string, error) {
	if len(rules) > 256 {
		return "", fmt.Errorf("FIREWALL_RULE_LIMIT")
	}
	for _, r := range rules {
		if !r.Valid() {
			return "", fmt.Errorf("FIREWALL_RULE_INVALID")
		}
	}
	b, _ := json.Marshal(rules)
	return `$ErrorActionPreference='Stop';[Console]::OutputEncoding=New-Object System.Text.UTF8Encoding($false);
$items=ConvertFrom-Json ([Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('` + base64.StdEncoding.EncodeToString(b) + `')));$group='USB-Link-Application-Firewall-v1';
$profiles=@(Get-NetFirewallProfile -PolicyStore ActiveStore -ErrorAction Stop);$provider=((Get-Service BFE).Status -eq 'Running' -and (Get-Service MpsSvc).Status -eq 'Running' -and $profiles.Count -eq 3 -and @($profiles|Where-Object {[string]$_.Enabled -ine 'True'}).Count -eq 0 -and @($profiles.Name|Sort-Object -Unique).Count -eq 3);
$persistentSet=@(Get-NetFirewallRule -PolicyStore PersistentStore -ErrorAction Stop);$effectiveSet=@(Get-NetFirewallRule -PolicyStore ActiveStore -ErrorAction Stop);
$results=@(foreach($v in $items){$name='USB-Link-App-'+$v.id;$marker=$group+'/'+$v.id+'/'+$v.application.sha256;$params=@{LocalPort='Any';RemotePort='Any'};if($v.port -gt 0){if($v.direction -ceq 'outbound'){$params.RemotePort=[string]$v.port}else{$params.LocalPort=[string]$v.port}};
try {if(-not $provider){throw 'FIREWALL_PROVIDER_UNAVAILABLE'};` + ruleReadBack + `;[pscustomobject]@{id=$v.id;state='applied';error=''}}catch{[pscustomobject]@{id=$v.id;state='error';error=$_.Exception.Message}}});ConvertTo-Json -InputObject $results -Depth 4 -Compress;`, nil
}
