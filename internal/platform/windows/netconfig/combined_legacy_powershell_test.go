package netconfig

import (
	"strings"
	"testing"
)

// The fixture models explicit legacy cmdlet constraints, not Windows defaults.
// Enumerating without Name is used by the FILES exact-token cleanup; core reads
// still require their exact PersistentStore name and bounded filter readback.
const combinedLegacyRuleEnumeration = `
function Get-NetFirewallRule {
 [CmdletBinding()]param($PolicyStore,$Name)
 if($PolicyStore -and $PolicyStore -ne 'PersistentStore'){throw 'wrong store'}
 if(!$Name){foreach($r in $global:rules.Values){$r};return}
 if($global:rules.ContainsKey($Name)){$global:rules[$Name];if($global:duplicate){$global:rules[$Name]}}
}
`

func TestCombinedLegacyPowerShellFragmentsDoNotPolluteScopedCoreReadback(t *testing.T) {
	resetCoreBaselineFixture(t)
	script, err := LegacyMacServiceScript("{A4611646-E050-4D25-B83E-633A5598F302}", "0123456789abcdef01234567", `C:\USB-Link.exe`)
	if err != nil {
		t.Fatal(err)
	}
	// Seed conflicting variable values; each original fragment must re-query
	// its own exact adapter and generated names rather than inherit these values.
	seed := `$a=@([pscustomobject]@{Name='unrelated'});$ownedRuleNames=@('unrelated');$ownedRules=@();$r='unrelated';`
	check := `
if($global:created -ne 3 -or $global:rules.Count -ne 3){throw 'wrong combined rule count'}
$f=$global:rules['Suhang-USB-Phase2-0123456789abcdef01234567-FILES']
$c=$global:rules['USB-Link-Core-Mac-v1']
if($f.Interface.InterfaceAlias[0] -cne 'USB Link' -or $c.Interface.InterfaceAlias[0] -cne 'USB Link'){throw 'adapter variable leaked'}
if($f.Address.LocalAddress[0] -cne '10.6.9.1' -or $f.Address.RemoteAddress[0] -cne '10.6.9.2'){throw 'file scope changed'}
if($c.App.Program -cne 'C:\USB-Link.exe' -or $c.Address.RemoteAddress[0] -cne '10.6.9.2'){throw 'core source/peer changed'}
Write-Output 'COMBINED_FIXTURE_SCOPE_VERIFIED';
`
	output := runCoreFirewallFixture(t, combinedLegacyRuleEnumeration+seed+script+check)
	clean, err := CompleteCorePermissionReadback(script, output, func(v string) bool {
		return strings.HasSuffix(strings.TrimSpace(v), "USB_CORE_PERMISSION_READY\nCOMBINED_FIXTURE_SCOPE_VERIFIED")
	})
	if err != nil || !strings.Contains(clean, "COMBINED_FIXTURE_SCOPE_VERIFIED") {
		t.Fatal("polluted/partial readback admitted or valid original batch rejected", clean, err)
	}
}
