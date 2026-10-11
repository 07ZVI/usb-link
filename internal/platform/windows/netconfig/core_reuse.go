package netconfig

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
)

const coreBaselineLimit = 64
const coreMetadataPrefix = "USB_CORE_META:"

type coreRuleSpec struct {
	GUID, Name, Program, Protocol, Local, Peer, Ports, RemotePort, Service string
}

func (r coreRuleSpec) key() string {
	b, _ := json.Marshal(struct {
		Rule                                                                   coreRuleSpec
		Group, Marker, DisplayName, Direction, Action, Enabled, Profile, Store string
	}{r, serviceGroup, serviceMarker, "USB Link USB services", "Inbound", "Allow", "True", "Any", "PersistentStore"})
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

type corePending struct {
	nonce, script string
	rules         []coreRuleSpec
	baseline      []string
	expected      []string
}
type coreBaselineState struct {
	sync.Mutex
	baselines map[string]string
	order     []string
	pending   []corePending
	stats     CorePermissionReadbackSummary
}

var coreBaselines = coreBaselineState{baselines: map[string]string{}}

// CorePermissionReadbackSummary contains counters, never rule contents. They
// describe completed local executions and cache bookkeeping; none authorize a
// connection. Failed native execution before readback has no classified rows.
type CorePermissionReadbackSummary struct {
	CacheEntries       int    `json:"cache_entries"`
	PendingPlans       int    `json:"pending_plans"`
	CreatedBaselines   uint64 `json:"created_baselines"`
	ReusedRules        uint64 `json:"reused_rules"`
	CreatedRules       uint64 `json:"created_rules"`
	MissingBaseline    uint64 `json:"missing_baseline"`
	UnknownFields      uint64 `json:"unknown_fields"`
	ChangedConstraints uint64 `json:"changed_constraints"`
	MetadataRejected   uint64 `json:"metadata_rejected"`
	BaselinesEvicted   uint64 `json:"baselines_evicted"`
	PlansEvicted       uint64 `json:"plans_evicted"`
}

func CorePermissionReadbackStats() CorePermissionReadbackSummary {
	coreBaselines.Lock()
	defer coreBaselines.Unlock()
	v := coreBaselines.stats
	v.CacheEntries = len(coreBaselines.baselines)
	v.PendingPlans = len(coreBaselines.pending)
	return v
}

func corePermissionScript(prefix string, specs []coreRuleSpec, markers map[int]string) (string, error) {
	return corePermissionScriptWithRefresh(prefix, specs, markers, nil)
}
func corePermissionScriptWithRefresh(prefix string, specs []coreRuleSpec, markers, refresh map[int]string) (string, error) {
	if len(specs) == 0 || len(specs) > coreBaselineLimit {
		return "", fmt.Errorf("core rule plan limit")
	}
	var nonceBytes [16]byte
	if _, err := rand.Read(nonceBytes[:]); err != nil {
		return "", fmt.Errorf("core readback correlation unavailable")
	}
	nonce := hex.EncodeToString(nonceBytes[:])
	coreBaselines.Lock()
	hashes := make([]string, len(specs))
	for i, r := range specs {
		hashes[i] = coreBaselines.baselines[r.key()]
	}
	coreBaselines.Unlock()
	s := prefix + coreSnapshotProbe
	expected := []string{}
	for i, r := range specs {
		s += refresh[i]
		s += coreRuleWithBaseline(r, hashes[i], nonce, i)
		if marker := markers[i]; marker != "" {
			s += "Write-Output '" + marker + "';"
			expected = append(expected, marker)
		}
	}
	p := corePending{nonce: nonce, script: s, rules: append([]coreRuleSpec(nil), specs...), baseline: append([]string(nil), hashes...), expected: expected}
	coreBaselines.Lock()
	if len(coreBaselines.pending) == coreBaselineLimit {
		coreBaselines.stats.PlansEvicted++
		coreBaselines.pending = coreBaselines.pending[1:]
	}
	coreBaselines.pending = append(coreBaselines.pending, p)
	coreBaselines.Unlock()
	return s, nil
}

// CompleteCorePermissionReadback is called only by the local executor after its
// successful exit, bounded stdout read, and original completion predicate. It
// correlates the exact generated body (or its exact batch suffix), never a nonce
// copied into an unrelated script. No disk state or pre-existing rule is trusted
// as a first baseline. Metadata is stripped before the old ready checks run.
func CompleteCorePermissionReadback(script, output string, ready func(string) bool) (cleanOutput string, readbackError error) {
	coreBaselines.Lock()
	defer coreBaselines.Unlock()
	defer func() {
		if readbackError != nil {
			coreBaselines.stats.MetadataRejected++
		}
	}()
	var p *corePending
	for i := range coreBaselines.pending {
		candidate := &coreBaselines.pending[i]
		if script == candidate.script || strings.HasSuffix(script, "\n"+candidate.script) {
			copy := *candidate
			p = &copy
			coreBaselines.pending = append(coreBaselines.pending[:i], coreBaselines.pending[i+1:]...)
			break
		}
	}
	if p == nil {
		if strings.Contains(output, coreMetadataPrefix) {
			return "", fmt.Errorf("unowned core readback")
		}
		return output, nil
	}
	if len(output) > 4096 {
		return "", fmt.Errorf("core readback output limit")
	}
	type result struct{ state, complete, hash, reason string }
	results := make(map[int]result)
	clean := []string{}
	for _, line := range strings.Split(strings.ReplaceAll(strings.TrimSpace(output), "\r\n", "\n"), "\n") {
		if !strings.HasPrefix(line, coreMetadataPrefix) {
			if strings.Contains(line, coreMetadataPrefix) {
				return "", fmt.Errorf("invalid core readback framing")
			}
			clean = append(clean, line)
			continue
		}
		parts := strings.Split(line, ":")
		if len(parts) != 7 || parts[1] != p.nonce {
			return "", fmt.Errorf("invalid core readback association")
		}
		index := -1
		for i := range p.rules {
			if parts[2] == fmt.Sprint(i) {
				index = i
				break
			}
		}
		if index < 0 {
			return "", fmt.Errorf("invalid core readback index")
		}
		if _, ok := results[index]; ok {
			return "", fmt.Errorf("duplicate core readback")
		}
		if parts[3] != "CREATED" && parts[3] != "REUSED" {
			return "", fmt.Errorf("invalid core readback origin")
		}
		if parts[4] != "COMPLETE" && parts[4] != "INCOMPLETE" {
			return "", fmt.Errorf("invalid core readback completeness")
		}
		decoded, e := hex.DecodeString(parts[5])
		if e != nil || len(decoded) != 32 || strings.ToLower(parts[5]) != parts[5] {
			return "", fmt.Errorf("invalid core readback fingerprint")
		}
		if parts[6] != "MATCHED" && parts[6] != "NO_BASELINE" && parts[6] != "FIELDS_UNKNOWN" && parts[6] != "CONSTRAINT_CHANGED" && parts[6] != "RULE_ABSENT" {
			return "", fmt.Errorf("invalid core readback reason")
		}
		if (parts[3] == "REUSED") != (parts[6] == "MATCHED") {
			return "", fmt.Errorf("invalid core readback origin reason")
		}
		results[index] = result{parts[3], parts[4], parts[5], parts[6]}
	}
	sanitized := strings.Join(clean, "\n")
	if len(results) != len(p.rules) || ready == nil || !ready(sanitized) {
		return "", fmt.Errorf("incomplete core permission execution")
	}
	for _, marker := range p.expected {
		count := 0
		for _, line := range clean {
			if line == marker {
				count++
			}
		}
		if count != 1 {
			return "", fmt.Errorf("core completion marker changed")
		}
	}
	// Commit all fingerprints atomically. Unknown fields in any rule leave all
	// previous baselines unchanged. A REUSED row cannot invent a new baseline.
	complete := true
	for i, r := range p.rules {
		result := results[i]
		if result.complete != "COMPLETE" {
			complete = false
		}
		if result.state == "REUSED" && (result.complete != "COMPLETE" || p.baseline[i] == "" || p.baseline[i] != result.hash || coreBaselines.baselines[r.key()] != result.hash) {
			return "", fmt.Errorf("core reuse baseline changed")
		}
	}
	for _, v := range results {
		if v.state == "CREATED" {
			coreBaselines.stats.CreatedRules++
		} else {
			coreBaselines.stats.ReusedRules++
		}
		if v.reason == "NO_BASELINE" {
			coreBaselines.stats.MissingBaseline++
		}
		if v.reason == "FIELDS_UNKNOWN" || v.complete != "COMPLETE" {
			coreBaselines.stats.UnknownFields++
		}
		if v.reason == "CONSTRAINT_CHANGED" {
			coreBaselines.stats.ChangedConstraints++
		}
	}
	if !complete {
		return sanitized, nil
	}

	for i, r := range p.rules {
		if results[i].state != "CREATED" {
			continue
		}
		key := r.key()
		if _, found := coreBaselines.baselines[key]; !found {
			if len(coreBaselines.order) == coreBaselineLimit {
				coreBaselines.stats.BaselinesEvicted++
				delete(coreBaselines.baselines, coreBaselines.order[0])
				coreBaselines.order = coreBaselines.order[1:]
			}
			coreBaselines.order = append(coreBaselines.order, key)
		}
		coreBaselines.baselines[key] = results[i].hash
		coreBaselines.stats.CreatedBaselines++
	}
	return sanitized, nil
}

const coreSnapshotProbe = `
function USB-CoreSnapshot($r) {
 try {
  $app=@($r|Get-NetFirewallApplicationFilter -ErrorAction Stop);$addr=@($r|Get-NetFirewallAddressFilter -ErrorAction Stop);$port=@($r|Get-NetFirewallPortFilter -ErrorAction Stop);$iface=@($r|Get-NetFirewallInterfaceFilter -ErrorAction Stop);$kind=@($r|Get-NetFirewallInterfaceTypeFilter -ErrorAction Stop);$svc=@($r|Get-NetFirewallServiceFilter -ErrorAction Stop);$sec=@($r|Get-NetFirewallSecurityFilter -ErrorAction Stop)
  foreach($f in @($app,$addr,$port,$iface,$kind,$svc,$sec)){if($f.Count -ne 1){return @{Complete=$false;Hash=('0'*64)}}}
  foreach($check in @(@($r,'Enabled',@('True','False','1','2')),@($r,'Direction',@('Inbound','Outbound','1','2')),@($r,'Action',@('Allow','Block','AllowBypass','2','3','4')),@($r,'EdgeTraversalPolicy',@('Block','Allow','DeferToUser','DeferToApp','0','1','2','3')),@($port[0],'DynamicTarget',@('Any','ProximityApps','ProximitySharing','WifiDirectPrinting','WifiDirectDisplay','WifiDirectDevices','0','1','2','4','8','16')),@($kind[0],'InterfaceType',@('Any','Wired','Wireless','RemoteAccess','1','2','4','7')),@($sec[0],'Authentication',@('NotRequired','Required','NoEncap','NoEncapsulation','0','1','2')),@($sec[0],'Encryption',@('NotRequired','Required','Dynamic','0','1','2')))) {
   $v=$check[0].PSObject.Properties[$check[1]];if($null -eq $v -or $null -eq $v.Value -or @($v.Value).Count -ne 1 -or [string]$v.Value -cnotin $check[2]){return @{Complete=$false;Hash=('0'*64)}}
  }
  if($r.LooseSourceMapping -isnot [bool] -or $r.LocalOnlyMapping -isnot [bool] -or $sec[0].OverrideBlockRules -isnot [bool]){return @{Complete=$false;Hash=('0'*64)}}
  $dynamicRule=$r.PSObject.Properties['RemoteDynamicKeywordAddresses'];$dynamicAddress=$addr[0].PSObject.Properties['RemoteDynamicKeywordAddresses'];if(($null -eq $dynamicRule) -eq ($null -eq $dynamicAddress)){return @{Complete=$false;Hash=('0'*64)}};$dynamic=if($null -ne $dynamicRule){$r}else{$addr[0]}
  $objects=@($r,$app[0],$addr[0],$port[0],$iface[0],$kind[0],$svc[0],$sec[0],$dynamic)
  $fields=@(@('Name','Group','Description','DisplayName','Enabled','Direction','Action','Profile','Platform','EdgeTraversalPolicy','LooseSourceMapping','LocalOnlyMapping','Owner'),@('Program','Package'),@('LocalAddress','RemoteAddress'),@('Protocol','LocalPort','RemotePort','DynamicTarget'),@('InterfaceAlias'),@('InterfaceType'),@('Service'),@('Authentication','Encryption','OverrideBlockRules','LocalUser','RemoteUser','RemoteMachine'),@('RemoteDynamicKeywordAddresses'))
  $snapshot=New-Object 'System.Collections.Generic.List[object]';$snapshot.Add(@('dynamic_source',$(if($null -ne $dynamicRule){'RULE'}else{'ADDRESS'})))
  for($i=0;$i -lt $objects.Count;$i++){
   foreach($field in $fields[$i]){
    $property=$objects[$i].PSObject.Properties[$field];if($null -eq $property){return @{Complete=$false;Hash=('0'*64)}}
    $value=$property.Value;if($null -eq $value -and $field -notin @('Platform','Owner','Package','RemoteDynamicKeywordAddresses','LocalUser','RemoteUser','RemoteMachine')){return @{Complete=$false;Hash=('0'*64)}};if(@($value).Count -gt 64){return @{Complete=$false;Hash=('0'*64)}};$items=New-Object 'System.Collections.Generic.List[string]'
    if($null -eq $value){$items.Add('NULL')}else{foreach($v in @($value)){if($null -eq $v){$items.Add('NULL');continue};if($v -is [string]){$items.Add('S:'+ $v)}elseif($v -is [bool]){$items.Add('B:'+ $v.ToString())}elseif($v.GetType().IsEnum){$items.Add('E:'+ $v.GetType().FullName+':'+$v.ToString())}elseif($v -is [byte] -or $v -is [uint16] -or $v -is [uint32] -or $v -is [int16] -or $v -is [int32]){$items.Add('N:'+ $v.ToString([Globalization.CultureInfo]::InvariantCulture))}else{return @{Complete=$false;Hash=('0'*64)}}}}
    $snapshot.Add(@($i,$field,@($items.ToArray()|Sort-Object -CaseSensitive)))
   }
  }
  # TCP/UDP have no applicable ICMP type constraint. All other rule/filter
  # constraints, including security defaults, are fingerprinted as actually read.
  $data=[Text.Encoding]::UTF8.GetBytes((ConvertTo-Json -InputObject $snapshot.ToArray() -Depth 8 -Compress));$sha=[Security.Cryptography.SHA256]::Create();try{$hash=([BitConverter]::ToString($sha.ComputeHash($data))).Replace('-','').ToLowerInvariant()}finally{$sha.Dispose()}
  return @{Complete=$true;Hash=$hash;App=$app[0];Address=$addr[0];Port=$port[0];Interface=$iface[0];Service=$svc[0]}
 } catch {return @{Complete=$false;Hash=('0'*64)}}
}
`

func coreRuleWithBaseline(r coreRuleSpec, baseline, nonce string, index int) string {
	extra := ""
	if r.RemotePort != "" {
		extra += " -RemotePort " + r.RemotePort
	}
	if r.Service != "" {
		extra += " -Service '" + r.Service + "'"
	}
	serviceCheck := ""
	if r.Service != "" {
		serviceCheck = "$svc=$r[0]|Get-NetFirewallServiceFilter;if($svc.Service -ne '" + r.Service + "'){throw 'SMB service scope changed'};"
	}
	ports := "'" + strings.ReplaceAll(r.Ports, ",", "','") + "'"
	return fmt.Sprintf(`
$r=@(Get-NetFirewallRule -PolicyStore PersistentStore -Name '%s' -ErrorAction SilentlyContinue);if($r.Count -gt 1){throw 'Ambiguous core rule'};$reuse=$false;$reason=if('%s' -eq ''){'NO_BASELINE'}else{'RULE_ABSENT'};if($r.Count -eq 1){if($r[0].Group -ne '%s' -or $r[0].Description -ne '%s'){throw 'Core rule ownership changed'};if('%s' -ne ''){$before=USB-CoreSnapshot $r[0];$reuse=($before.Complete -and $before.Hash -ceq '%s');$reason=if($reuse){'MATCHED'}elseif(!$before.Complete){'FIELDS_UNKNOWN'}else{'CONSTRAINT_CHANGED'}}};
$origin='REUSED';if(!$reuse){if($r.Count -eq 1){$r[0]|Remove-NetFirewallRule -ErrorAction Stop};New-NetFirewallRule -PolicyStore PersistentStore -Name '%s' -DisplayName 'USB Link USB services' -Group '%s' -Description '%s' -Direction Inbound -Action Allow -Enabled True -Profile Any -InterfaceAlias $a[0].Name -Program '%s' -LocalAddress '%s' -RemoteAddress '%s' -Protocol %s -LocalPort %s%s | Out-Null;$origin='CREATED'};
$r=@(Get-NetFirewallRule -PolicyStore PersistentStore -Name '%s' -ErrorAction Stop);if($r.Count -ne 1 -or $r[0].Group -ne '%s' -or $r[0].Description -ne '%s'){throw 'Core firewall readback ownership mismatch'};
$final=USB-CoreSnapshot $r[0];if($final.Complete -and ($r[0].Name -cne '%s' -or $r[0].DisplayName -cne 'USB Link USB services' -or [string]$r[0].Profile -cnotin @('Any','0'))){$final.Complete=$false;$final.Hash=('0'*64)};if($final.Complete){$app=$final.App;$addr=$final.Address;$port=$final.Port;$iface=$final.Interface}else{$app=$r[0]|Get-NetFirewallApplicationFilter;$addr=$r[0]|Get-NetFirewallAddressFilter;$port=$r[0]|Get-NetFirewallPortFilter;$iface=$r[0]|Get-NetFirewallInterfaceFilter};%s
if($r[0].Enabled -ne 'True' -or $r[0].Action -ne 'Allow' -or $r[0].Direction -ne 'Inbound' -or $app.Program -ne '%s' -or @($addr.LocalAddress).Count -ne 1 -or $addr.LocalAddress -ne '%s' -or @($addr.RemoteAddress).Count -ne 1 -or $addr.RemoteAddress -ne '%s' -or $port.Protocol -notin @('%s','%s') -or @(Compare-Object -ReferenceObject @(%s) -DifferenceObject @($port.LocalPort)).Count -ne 0 -or @($iface.InterfaceAlias).Count -ne 1 -or $iface.InterfaceAlias -ne $a[0].Name){throw 'Core firewall readback mismatch'};
if($reuse -and (!$final.Complete -or $final.Hash -cne '%s')){throw 'Core reuse fresh readback changed'};
$complete=if($final.Complete){'COMPLETE'}else{'INCOMPLETE'};Write-Output ('USB_CORE_META:%s:%d:'+ $origin+':'+$complete+':'+$final.Hash+':'+$reason);
`, r.Name, baseline, serviceGroup, serviceMarker, baseline, baseline, r.Name, serviceGroup, serviceMarker, r.Program, r.Local, r.Peer, r.Protocol, r.Ports, extra, r.Name, serviceGroup, serviceMarker, r.Name, serviceCheck, r.Program, r.Local, r.Peer, r.Protocol, map[string]string{"TCP": "6", "UDP": "17"}[r.Protocol], ports, baseline, nonce, index)
}
