package netconfig

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
	"testing"
)

// Executes production scripts with substitute cmdlets: no native firewall or
// network operation is performed. Windows provider integration is separate.
func TestPowerShellFirewallRecovery(t *testing.T) {
	pwsh := os.Getenv("SUHANG_TEST_PWSH")
	if pwsh == "" {
		t.Skip("set SUHANG_TEST_PWSH for script execution with fixture cmdlets")
	}
	guid, token := "{A4611646-E050-4D25-B83E-633A5598F302}", "0123456789abcdef01234567"
	_, cleanup, e := Scripts(1, guid, 1500, token)
	if e != nil {
		t.Fatal(e)
	}
	files, e := FileReceiverRule(guid, token, false)
	if e != nil {
		t.Fatal(e)
	}
	for _, tc := range []struct {
		name, mode string
		owned      []string
		failure    string
	}{
		{name: "already-clean"},
		{name: "partially-clean", owned: []string{"ICMP", "FILES"}},
		{name: "all-owned-rules", owned: []string{"ICMP", "BENCH", "SUN-TCP", "SUN-UDP", "FILES"}},
		{name: "provider-failure", mode: "query-fail", failure: "fixture provider unavailable"},
		{name: "delete-denied", mode: "remove-fail", owned: []string{"ICMP"}, failure: "fixture access denied"},
		{name: "delete-not-effective", mode: "remove-noop", owned: []string{"ICMP"}, failure: "Owned firewall rules remain"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			names := []string{"'Unrelated-Application-Rule'"}
			for _, suffix := range tc.owned {
				names = append(names, "'Suhang-USB-Phase2-"+token+"-"+suffix+"'")
			}
			fixture := fmt.Sprintf(`$global:rules=@(%s);$global:removed=0;$global:mode='%s';
function Get-NetFirewallRule {
 [CmdletBinding()] param([string]$Name)
 if($global:mode -eq 'query-fail'){throw 'fixture provider unavailable'}
 $found=@($global:rules | Where-Object { !$PSBoundParameters.ContainsKey('Name') -or $_ -eq $Name });
 if($PSBoundParameters.ContainsKey('Name') -and $found.Count -eq 0){$PSCmdlet.WriteError([System.Management.Automation.ErrorRecord]::new([Exception]::new('fixture no matching rule'),'RULE_NOT_FOUND',[System.Management.Automation.ErrorCategory]::ObjectNotFound,$Name));return};
 foreach($n in $found){[pscustomobject]@{Name=$n}}
}
function Remove-NetFirewallRule {
 [CmdletBinding()] param([Parameter(ValueFromPipeline=$true)]$InputObject)
 process {
 if($global:mode -eq 'remove-fail'){throw 'fixture access denied'};
 if($global:mode -eq 'remove-noop'){return};
 if($InputObject.Name -eq 'Unrelated-Application-Rule'){throw 'UNRELATED RULE REMOVED'};
 $global:rules=@($global:rules | Where-Object {$_ -ne $InputObject.Name});$global:removed++;
 }
}
`, strings.Join(names, ","), tc.mode)
			checks := fmt.Sprintf(`
if($global:rules.Count -ne 1 -or $global:rules[0] -ne 'Unrelated-Application-Rule'){throw 'fixture final rule set mismatch'};
if($global:removed -ne %d){throw 'fixture removal count mismatch'};
`, len(tc.owned))
			cmd := exec.Command(pwsh, "-NoProfile", "-NonInteractive", "-Command", fixture+diagnosticScript(files+cleanup+checks))
			output, err := cmd.CombinedOutput()
			text := string(output)
			if tc.failure != "" {
				if err == nil || !strings.Contains(text, tc.failure) || strings.Contains(text, "SUHANG_NETWORK_SCRIPT_OK") {
					t.Fatalf("failure was masked: %v %s", err, text)
				}
			} else if err != nil || !strings.Contains(text, "SUHANG_NETWORK_SCRIPT_OK") {
				t.Fatalf("clean state did not succeed: %v %s", err, text)
			}
		})
	}
}

// Reproduce the original silent nonzero exit with cmdlet-style missing-item
// errors. PowerShell 7 is a language fixture, not Windows NetSecurity proof.
func TestPowerShellLegacyMissingRulesReproduction(t *testing.T) {
	pwsh := os.Getenv("SUHANG_TEST_PWSH")
	if pwsh == "" {
		t.Skip("set SUHANG_TEST_PWSH for script fixture")
	}
	fixture := `function Get-NetFirewallRule { [CmdletBinding()] param([string]$Name); $PSCmdlet.WriteError([System.Management.Automation.ErrorRecord]::new([Exception]::new('fixture rule absent'),'RULE_NOT_FOUND',[System.Management.Automation.ErrorCategory]::ObjectNotFound,$Name)) }; function Remove-NetFirewallRule { [CmdletBinding()] param([Parameter(ValueFromPipeline=$true)]$InputObject); process {} }; `
	legacy := `$ErrorActionPreference='Stop'; foreach($n in @('ICMP','BENCH','SUN-TCP','SUN-UDP')) {Get-NetFirewallRule -Name $n -ErrorAction SilentlyContinue | Remove-NetFirewallRule -ErrorAction Stop};`
	output, err := exec.Command(pwsh, "-NoProfile", "-NonInteractive", "-Command", fixture+legacy).CombinedOutput()
	exit, ok := err.(*exec.ExitError)
	if !ok || exit.ExitCode() != 1 || strings.TrimSpace(string(output)) != "" {
		t.Fatalf("old failure not reproduced: %v %s", err, output)
	}
}
