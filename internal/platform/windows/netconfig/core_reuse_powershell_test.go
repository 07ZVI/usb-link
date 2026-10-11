package netconfig

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// These cmdlets model documented filter cardinality and explicitly supplied
// fixture values. They are not a claim about Windows provider defaults.
const coreFirewallFixture = `
$global:rules=@{};$global:removed=0;$global:created=0;$global:filterReads=0;$global:duplicate=$false;$global:filterFault=''
function Get-NetAdapter {[CmdletBinding()]param([switch]$IncludeHidden);[pscustomobject]@{InterfaceGuid='{A4611646-E050-4D25-B83E-633A5598F302}';Name='USB Link'};[pscustomobject]@{InterfaceGuid='{B4611646-E050-4D25-B83E-633A5598F302}';Name='USB Link second'};[pscustomobject]@{InterfaceGuid='{C839CF3F-7F98-4CB3-891B-36E4FC772969}';Name='USB Link Host'}}
function Get-NetFirewallRule {[CmdletBinding()]param($PolicyStore,$Name);if($PolicyStore -and $PolicyStore -ne 'PersistentStore'){throw 'wrong store'};if($global:rules.ContainsKey($Name)){$global:rules[$Name];if($global:duplicate){$global:rules[$Name]}}}
function New-NetFirewallRule {[CmdletBinding()]param($PolicyStore,$Name,$DisplayName,$Group,$Description,$Direction,$Action,$Enabled,$Profile,$InterfaceAlias,$Program,$LocalAddress,$RemoteAddress,$Protocol,[string[]]$LocalPort,$RemotePort,$Service)
 if(!$RemotePort){$RemotePort='Any'};if(!$Service){$Service='Any'};$global:created++
 $global:rules[$Name]=[pscustomobject]@{Name=$Name;Group=$Group;Description=$Description;DisplayName=$DisplayName;Direction=$Direction;Action=$Action;Enabled=$Enabled;Profile=$Profile;Platform=@();EdgeTraversalPolicy='Block';LooseSourceMapping=$false;LocalOnlyMapping=$false;Owner='';Generation=$global:created;
 App=[pscustomobject]@{Program=$Program;Package=''};
 Address=[pscustomobject]@{LocalAddress=@($LocalAddress);RemoteAddress=@($RemoteAddress);RemoteDynamicKeywordAddresses=@()};
 Port=[pscustomobject]@{Protocol=$Protocol;LocalPort=@($LocalPort);RemotePort=@($RemotePort);DynamicTarget='Any';IcmpType=@('Any')};
 Interface=[pscustomobject]@{InterfaceAlias=@($InterfaceAlias)};Kind=[pscustomobject]@{InterfaceType='Any'};
 Svc=[pscustomobject]@{Service=$Service};Security=[pscustomobject]@{Authentication=$(if($global:fixtureAuthentication){$global:fixtureAuthentication}else{'NotRequired'});Encryption='NotRequired';OverrideBlockRules=$false;LocalUser='';RemoteUser='';RemoteMachine=''}}
 if($global:ruleDynamicProjection){$global:rules[$Name]|Add-Member -NotePropertyName 'RemoteDynamicKeywordAddresses' -NotePropertyValue @();$global:rules[$Name].Address.PSObject.Properties.Remove('RemoteDynamicKeywordAddresses')};if($global:missingNewSecurity){$global:rules[$Name].Security.PSObject.Properties.Remove('Authentication')}
 $global:rules[$Name]
}
function Remove-NetFirewallRule {[CmdletBinding()]param([Parameter(ValueFromPipeline=$true)]$InputObject);process{$global:rules.Remove($InputObject.Name);$global:removed++}}
function Get-CoreFixtureFilter($r,$kind){$global:filterReads++;if($r.Generation -eq 1){if($global:filterFault -eq $kind){throw 'fixture unreadable private C:\SECRET SID'};if($global:filterFault -eq ('duplicate-'+$kind)){$r.$kind;$r.$kind;return};if($global:filterFault -eq ('absent-'+$kind)){return}};$r.$kind}
function Get-NetFirewallApplicationFilter {[CmdletBinding()]param([Parameter(ValueFromPipeline=$true)]$InputObject);process{Get-CoreFixtureFilter $InputObject 'App'}}
function Get-NetFirewallAddressFilter {[CmdletBinding()]param([Parameter(ValueFromPipeline=$true)]$InputObject);process{Get-CoreFixtureFilter $InputObject 'Address'}}
function Get-NetFirewallPortFilter {[CmdletBinding()]param([Parameter(ValueFromPipeline=$true)]$InputObject);process{Get-CoreFixtureFilter $InputObject 'Port'}}
function Get-NetFirewallInterfaceFilter {[CmdletBinding()]param([Parameter(ValueFromPipeline=$true)]$InputObject);process{Get-CoreFixtureFilter $InputObject 'Interface'}}
function Get-NetFirewallInterfaceTypeFilter {[CmdletBinding()]param([Parameter(ValueFromPipeline=$true)]$InputObject);process{Get-CoreFixtureFilter $InputObject 'Kind'}}
function Get-NetFirewallServiceFilter {[CmdletBinding()]param([Parameter(ValueFromPipeline=$true)]$InputObject);process{Get-CoreFixtureFilter $InputObject 'Svc'}}
function Get-NetFirewallSecurityFilter {[CmdletBinding()]param([Parameter(ValueFromPipeline=$true)]$InputObject);process{Get-CoreFixtureFilter $InputObject 'Security'}}
`

func runCoreFirewallFixture(t *testing.T, script string) string {
	t.Helper()
	pwsh := os.Getenv("SUHANG_TEST_PWSH")
	if pwsh == "" {
		t.Skip("PowerShell fixture unavailable")
	}
	file := filepath.Join(t.TempDir(), "core.ps1")
	if err := os.WriteFile(file, []byte(coreFirewallFixture+script), 0600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, pwsh, "-NoLogo", "-NoProfile", "-NonInteractive", "-File", file).CombinedOutput()
	if err != nil {
		t.Fatalf("%v %s", err, out)
	}
	return string(out)
}

func resetCoreBaselineFixture(t *testing.T) {
	t.Helper()
	coreBaselines.Lock()
	coreBaselines.baselines = map[string]string{}
	coreBaselines.order = nil
	coreBaselines.pending = nil
	coreBaselines.stats = CorePermissionReadbackSummary{}
	coreBaselines.Unlock()
}
func coreFixturePlan(t *testing.T) string {
	t.Helper()
	s, err := corePermissionScript("$ErrorActionPreference='Stop';$a=@([pscustomobject]@{Name='USB Link'});", []coreRuleSpec{coreSpec("{A4611646-E050-4D25-B83E-633A5598F302}", "USB-Link-Core-Mac-v1", `C:\USB-Link.exe`, "TCP", "10.6.9.1", "10.6.9.2", "445,47775", "", "")}, map[int]string{0: "USB_CORE_PERMISSION_READY"})
	if err != nil {
		t.Fatal(err)
	}
	return s
}
func captureCoreFixture(t *testing.T, script, out string) string {
	t.Helper()
	clean, err := CompleteCorePermissionReadback(script, out, func(v string) bool { return v == "USB_CORE_PERMISSION_READY" })
	if err != nil {
		t.Fatal(err)
	}
	return clean
}
func TestCoreRuleSelfCreatedBaselineAndFreshChanges(t *testing.T) {
	resetCoreBaselineFixture(t)
	seed := coreFixturePlan(t)
	captureCoreFixture(t, seed, runCoreFirewallFixture(t, seed))
	for _, tc := range []struct {
		name, change string
		reused       bool
	}{
		{"identical", "", true},
		{"reordered-ports", `$target.Port.LocalPort=@('47775','445')`, true},
		{"program", `$target.App.Program='C:\other.exe'`, false},
		{"adapter", `$target.Interface.InterfaceAlias=@('Ethernet')`, false},
		{"peer", `$target.Address.RemoteAddress=@('10.6.9.3')`, false},
		{"broad-peer", `$target.Address.RemoteAddress=@('10.6.9.0/24')`, false},
		{"extra-peer", `$target.Address.RemoteAddress=@('10.6.9.2','10.6.9.3')`, false},
		{"local-address", `$target.Address.LocalAddress=@('Any')`, false},
		{"local-port", `$target.Port.LocalPort=@('Any')`, false},
		{"duplicate-port", `$target.Port.LocalPort=@('445','445')`, false},
		{"remote-port", `$target.Port.RemotePort=@('68')`, false},
		{"protocol", `$target.Port.Protocol='UDP'`, false},
		{"direction", `$target.Direction='Outbound'`, false},
		{"action", `$target.Action='AllowBypass'`, false},
		{"disabled", `$target.Enabled='False'`, false},
		{"profile", `$target.Profile='Public'`, false},
		{"platform", `$target.Platform=@('6.1')`, false},
		{"owner", `$target.Owner='S-1-5-21-123'`, false},
		{"displayname", `$target.DisplayName='other'`, false},
		{"edge", `$target.EdgeTraversalPolicy='Allow'`, false},
		{"loose-source", `$target.LooseSourceMapping=$true`, false},
		{"local-only", `$target.LocalOnlyMapping=$true`, false},
		{"nonboolean-mapping", `$target.LocalOnlyMapping='False'`, false},
		{"interface-type", `$target.Kind.InterfaceType='Wireless'`, false},
		{"service", `$target.Svc.Service='OtherService'`, false},
		{"package", `$target.App.Package='S-1-15-2-1'`, false},
		{"dynamic-transport", `$target.Port.DynamicTarget='ProximityApps'`, false},
		{"dynamic-address", `$target.Address.RemoteDynamicKeywordAddresses=@('{12345678-1234-1234-1234-123456789ABC}')`, false},
		{"authentication", `$target.Security.Authentication='Required'`, false},
		{"encryption", `$target.Security.Encryption='Required'`, false},
		{"override", `$target.Security.OverrideBlockRules=$true`, false},
		{"local-user", `$target.Security.LocalUser='D:(A;;CC;;;WD)'`, false},
		{"remote-user", `$target.Security.RemoteUser='D:(A;;CC;;;WD)'`, false},
		{"remote-machine", `$target.Security.RemoteMachine='D:(A;;CC;;;WD)'`, false},
		{"missing-security-property", `$target.Security.PSObject.Properties.Remove('Authentication')`, false},
		{"unknown-null-authentication", `$target.Security.Authentication=$null`, false},
		{"unrecognized-authentication", `$target.Security.Authentication='999'`, false},
		{"missing-rule-property", `$target.PSObject.Properties.Remove('Owner')`, false},
		{"missing-modern-address-property", `$target.Address.PSObject.Properties.Remove('RemoteDynamicKeywordAddresses')`, false},
		{"unreadable-filter", `$global:filterFault='Security'`, false},
		{"duplicate-filter", `$global:filterFault='duplicate-App'`, false},
		{"missing-filter", `$global:filterFault='absent-Svc'`, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			plan := coreFixturePlan(t)
			check := `if($global:created -ne 2 -or $global:removed -ne 1){throw 'not safely refreshed'}`
			if tc.reused {
				check = `if($global:created -ne 1 -or $global:removed -ne 0 -or $global:filterReads -lt 14){throw 'not a fresh full no-op'}`
			}
			out := runCoreFirewallFixture(t, `& {`+seed+`}|Out-Null;$global:filterReads=0;$target=$global:rules['USB-Link-Core-Mac-v1'];`+tc.change+";"+plan+check)
			origin := ":CREATED:"
			if tc.reused {
				origin = ":REUSED:"
			}
			if !strings.Contains(out, origin) || strings.Contains(out, "SECRET") || strings.Contains(out, "S-1-") {
				t.Fatalf("unexpected bounded outcome %s", out)
			}
			captureCoreFixture(t, plan, out)
		})
	}
}

func TestCoreRuleOwnershipAndAmbiguityNeverMutate(t *testing.T) {
	resetCoreBaselineFixture(t)
	seed := coreFixturePlan(t)
	captureCoreFixture(t, seed, runCoreFirewallFixture(t, seed))
	for _, change := range []string{`$global:rules['USB-Link-Core-Mac-v1'].Group='foreign'`, `$global:rules['USB-Link-Core-Mac-v1'].Description='foreign'`, `$global:duplicate=$true`} {
		plan := coreFixturePlan(t)
		out := runCoreFirewallFixture(t, `& {`+seed+`}|Out-Null;`+change+`;try{`+plan+`;throw 'unexpected success'}catch{if($_.Exception.Message -notin @('Core rule ownership changed','Ambiguous core rule')){throw}};if($global:created -ne 1 -or $global:removed -ne 0){throw 'unowned mutation'};Write-Output 'PROTECTED'`)
		if !strings.Contains(out, "PROTECTED") {
			t.Fatal(out)
		}
	}
}

func TestCoreBaselineDoesNotGuessCreationDefaults(t *testing.T) {
	resetCoreBaselineFixture(t)
	seed := coreFixturePlan(t)
	fixture := seed // original New parameters remain untouched
	prefix := `$global:fixtureAuthentication='Required';`
	out := runCoreFirewallFixture(t, prefix+fixture)
	captureCoreFixture(t, seed, out)
	plan := coreFixturePlan(t)
	out = runCoreFirewallFixture(t, prefix+`& {`+seed+`}|Out-Null;`+plan+`if($global:created -ne 1 -or $global:removed -ne 0){throw 'default was guessed'}`)
	if !strings.Contains(out, ":REUSED:") {
		t.Fatal(out)
	}
	captureCoreFixture(t, plan, out)
}

func TestCoreRulesFirstMissingBaselineAlwaysRefreshesExisting(t *testing.T) {
	resetCoreBaselineFixture(t)
	seed := coreFixturePlan(t)
	plan := coreFixturePlan(t)
	out := runCoreFirewallFixture(t, `& {`+seed+`}|Out-Null;`+plan+`if($global:created -ne 2 -or $global:removed -ne 1){throw 'existing rule became first baseline'}`)
	if !strings.Contains(out, ":CREATED:") {
		t.Fatal(out)
	}
	captureCoreFixture(t, plan, out)
}

func TestCoreBaselineRuleDynamicProjectionAndIncompleteCreation(t *testing.T) {
	for _, tc := range []struct {
		name, prefix string
		complete     bool
	}{
		{"rule-projection", `$global:ruleDynamicProjection=$true;`, true},
		{"unknown-creation-field", `$global:missingNewSecurity=$true;`, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			resetCoreBaselineFixture(t)
			seed := coreFixturePlan(t)
			captureCoreFixture(t, seed, runCoreFirewallFixture(t, tc.prefix+seed))
			plan := coreFixturePlan(t)
			counts := `if($global:created -ne 2 -or $global:removed -ne 1){throw 'unknown fields reused'}`
			if tc.complete {
				counts = `if($global:created -ne 1 -or $global:removed -ne 0){throw 'actual rule projection ignored'}`
			}
			out := runCoreFirewallFixture(t, tc.prefix+`& {`+seed+`}|Out-Null;`+plan+counts)
			captureCoreFixture(t, plan, out)
			stats := CorePermissionReadbackStats()
			if tc.complete {
				if stats.ReusedRules != 1 || stats.CreatedBaselines != 1 {
					t.Fatal(stats)
				}
			} else if stats.UnknownFields != 2 || stats.CacheEntries != 0 {
				t.Fatal(stats)
			}
		})
	}
}

func TestNativeSMBMultipleScopesOneStrictReadbackTransaction(t *testing.T) {
	resetCoreBaselineFixture(t)
	scopes := []NativeSMBServiceScope{{"{A4611646-E050-4D25-B83E-633A5598F302}", "10.6.9.2"}, {"{B4611646-E050-4D25-B83E-633A5598F302}", "10.6.9.3"}}
	seed, e := NativeSMBServicesRules(scopes)
	if e != nil {
		t.Fatal(e)
	}
	out := runCoreFirewallFixture(t, seed+`Write-Output 'SUHANG_NETWORK_SCRIPT_OK'`)
	if _, e = CompleteCorePermissionReadback(seed, out, func(v string) bool { return v == "SUHANG_NETWORK_SCRIPT_OK" }); e != nil {
		t.Fatal(e)
	}
	plan, e := NativeSMBServicesRules(scopes)
	if e != nil {
		t.Fatal(e)
	}
	out = runCoreFirewallFixture(t, `& {`+seed+`}|Out-Null;`+plan+`if($global:created -ne 2 -or $global:removed -ne 0){throw 'multiple scopes did not reuse'};Write-Output 'SUHANG_NETWORK_SCRIPT_OK'`)
	if _, e = CompleteCorePermissionReadback(plan, out, func(v string) bool { return v == "SUHANG_NETWORK_SCRIPT_OK" }); e != nil {
		t.Fatal(e)
	}
	stats := CorePermissionReadbackStats()
	if stats.ReusedRules != 2 || stats.CreatedBaselines != 2 {
		t.Fatal(stats)
	}
}

func TestSharedHostCompositePlanRetainsPhysicalRuleExclusion(t *testing.T) {
	resetCoreBaselineFixture(t)
	seed, e := SharedHostServicesRule(`C:\USB-Link.exe`)
	if e != nil {
		t.Fatal(e)
	}
	if strings.Count(seed, "Get-NetAdapter") != 2 || strings.Contains(seed, "USB-Link-Core-DHCP-v1") || strings.Contains(seed, "USB-Link-Core-MDNS-v1") {
		t.Fatal("host scopes changed")
	}
	out := runCoreFirewallFixture(t, seed)
	want := "USB_CORE_PERMISSION_READY\nUSB_HOST_PERMISSION_READY"
	if _, e = CompleteCorePermissionReadback(seed, out, func(v string) bool { return v == want }); e != nil {
		t.Fatal(e)
	}
	plan, e := SharedHostServicesRule(`C:\USB-Link.exe`)
	if e != nil {
		t.Fatal(e)
	}
	out = runCoreFirewallFixture(t, `& {`+seed+`}|Out-Null;`+plan+`if($global:created -ne 4 -or $global:removed -ne 0){throw 'host plan not a no-op'}`)
	if _, e = CompleteCorePermissionReadback(plan, out, func(v string) bool { return v == want }); e != nil {
		t.Fatal(e)
	}
}

func TestNativeSMBCompositeActualOutputRejectsMetadataFaultsAtomically(t *testing.T) {
	scopes := []NativeSMBServiceScope{{"{A4611646-E050-4D25-B83E-633A5598F302}", "10.6.9.2"}, {"{B4611646-E050-4D25-B83E-633A5598F302}", "10.6.9.3"}}
	for _, fault := range []string{"missing-second", "duplicate-first", "wrong-second-nonce"} {
		t.Run(fault, func(t *testing.T) {
			resetCoreBaselineFixture(t)
			plan, e := NativeSMBServicesRules(scopes)
			if e != nil {
				t.Fatal(e)
			}
			out := runCoreFirewallFixture(t, plan+`Write-Output 'SUHANG_NETWORK_SCRIPT_OK'`)
			lines := strings.Split(strings.TrimSpace(out), "\n")
			if len(lines) != 3 {
				t.Fatal(out)
			}
			switch fault {
			case "missing-second":
				lines = append(lines[:1], lines[2:]...)
			case "duplicate-first":
				lines = append([]string{lines[0]}, lines...)
			case "wrong-second-nonce":
				parts := strings.Split(lines[1], ":")
				parts[1] = strings.Repeat("0", 32)
				lines[1] = strings.Join(parts, ":")
			}
			if _, e = CompleteCorePermissionReadback(plan, strings.Join(lines, "\n"), func(v string) bool { return v == "SUHANG_NETWORK_SCRIPT_OK" }); e == nil {
				t.Fatal("composite metadata fault accepted")
			}
			stats := CorePermissionReadbackStats()
			if stats.CacheEntries != 0 || stats.CreatedBaselines != 0 || stats.MetadataRejected != 1 {
				t.Fatal("partial composite captured", stats)
			}
		})
	}
}
