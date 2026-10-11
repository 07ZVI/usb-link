package appfirewall

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
)

// Executes the production language/control flow with fixture cmdlets. This is
// not proof of the Windows NetSecurity provider or actual packet interception.
const firewallFixture = `
$global:owned=@();$global:foreign=[pscustomobject]@{Name='Other-Application';Group='Foreign'};
function Get-NetFirewallRule { [CmdletBinding()]param($PolicyStore);if($mode -eq 'query-failure'){throw 'QUERY_FAILED'};if($PolicyStore -eq 'ActiveStore' -and $mode -eq 'not-effective'){return $global:foreign};@($global:foreign)+@($global:owned) }
function Get-NetFirewallApplicationFilter { [CmdletBinding()]param([Parameter(ValueFromPipeline=$true)]$InputObject);process{[pscustomobject]@{Program=$InputObject.Program}} }
function Get-NetFirewallAddressFilter { [CmdletBinding()]param([Parameter(ValueFromPipeline=$true)]$InputObject);process{[pscustomobject]@{RemoteAddress=$InputObject.RemoteAddress}} }
function Get-NetFirewallPortFilter { [CmdletBinding()]param([Parameter(ValueFromPipeline=$true)]$InputObject);process{[pscustomobject]@{Protocol=$InputObject.Protocol;LocalPort=$InputObject.LocalPort;RemotePort=$InputObject.RemotePort}} }
function Get-Service { [CmdletBinding()]param([Parameter(Position=0)]$Name);[pscustomobject]@{Status=$(if($mode -eq 'stopped-service'){'Stopped'}else{'Running'})} }
function Get-NetFirewallProfile { [CmdletBinding()]param($PolicyStore);foreach($n in @('Domain','Private','Public')){[pscustomobject]@{Name=$n;Enabled=$(if($mode -eq 'disabled-profile'){'False'}else{'True'})}} }
function Get-FileHash { [CmdletBinding()]param($LiteralPath,$Algorithm);if($LiteralPath -cne $expected.application.path){throw 'PATH_CHANGED'};[pscustomobject]@{Hash=$(if($mode -eq 'changed-hash'){'bad'}else{$expected.application.sha256})} }
function New-NetFirewallRule { [CmdletBinding()]param($PolicyStore,$Name,$DisplayName,$Group,$Description,$Program,$Action,$Direction,$Enabled,$Profile,$Protocol,$RemoteAddress,$LocalPort,$RemotePort);
 if($mode -eq 'write-denied'){throw 'WRITE_DENIED'};if($mode -eq 'port-mismatch'){$RemotePort='22'};if($mode -eq 'protocol-mismatch'){$Protocol='ICMPv4'};if($mode -eq 'numeric-protocol'){$Protocol='6'};
 $global:owned=@([pscustomobject]@{Name=$Name;Group=$Group;Description=$Description;Program=$Program;Action=$Action;Direction=$Direction;Enabled=$Enabled;Profile=$Profile;Protocol=$Protocol;RemoteAddress=$RemoteAddress;LocalPort=$LocalPort;RemotePort=$RemotePort}) }
function Set-NetFirewallRule { [CmdletBinding()]param([Parameter(ValueFromPipeline=$true)]$InputObject,$Action,$Direction,$Enabled,$Profile,$Protocol,$RemoteAddress,$LocalPort,$RemotePort);process{
 if($InputObject.Name -eq 'Other-Application'){throw 'FOREIGN_UPDATED'};$InputObject.Action=$Action;$InputObject.Direction=$Direction;$InputObject.Enabled=$Enabled;$InputObject.Profile=$Profile;$InputObject.Protocol=$Protocol;$InputObject.RemoteAddress=$RemoteAddress;$InputObject.LocalPort=$LocalPort;$InputObject.RemotePort=$RemotePort} }
function Remove-NetFirewallRule { [CmdletBinding()]param([Parameter(ValueFromPipeline=$true)]$InputObject);process{if($InputObject.Name -eq 'Other-Application'){throw 'FOREIGN_REMOVED'};if($mode -eq 'delete-noop'){return};$global:owned=@()} }
`

func fixture(t *testing.T, pwsh, mode, op, script string, r Rule) string {
	t.Helper()
	raw, _ := json.Marshal(r)
	pre := fmt.Sprintf("$mode='%s';$expected=ConvertFrom-Json ([Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('%s')));", mode, base64.StdEncoding.EncodeToString(raw))
	if op == "update" || op == "delete" || op == "audit" || mode == "foreign-owner" {
		pre += `$global:owned=@([pscustomobject]@{Name=('USB-Link-App-'+$expected.id);Group='USB-Link-Application-Firewall-v1';Description=('USB-Link-Application-Firewall-v1/'+$expected.id+'/'+$expected.application.sha256);Program=$expected.application.path;Action=$expected.action;Direction=$expected.direction;Enabled='True';Profile='Any';Protocol=$expected.protocol;RemoteAddress=$expected.remote;LocalPort='Any';RemotePort=([string]$expected.port)});`
		if mode == "foreign-owner" {
			pre += `$global:owned[0].Group='Foreign';`
		}
		if mode == "audit-missing" {
			pre += `$global:owned=@();`
		}
	}
	if op == "update" {
		pre += `$global:owned[0].Action='allow';`
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	body := firewallFixture + pre + `try{& {` + script + `};if($global:foreign.Group -cne 'Foreign'){throw 'FOREIGN_CHANGED'}}catch{[Console]::Error.WriteLine($_.Exception.Message);exit 17}`
	b, err := exec.CommandContext(ctx, pwsh, "-NoProfile", "-NonInteractive", "-Command", body).CombinedOutput()
	if ctx.Err() != nil {
		t.Fatal("fixture timeout")
	}
	if err != nil && !strings.Contains(string(b), "FAILED") && !strings.Contains(string(b), "FIREWALL_") && !strings.Contains(string(b), "DENIED") {
		t.Fatalf("unexpected fixture error: %v %s", err, b)
	}
	return strings.TrimSpace(string(b))
}

func TestPowerShellApplicationRules(t *testing.T) {
	pwsh := os.Getenv("USBLINK_TEST_PWSH")
	if pwsh == "" {
		t.Skip("PowerShell fixture host not configured")
	}
	for _, tc := range []struct{ name, mode, op, want string }{
		{"create", "", "upsert", "APP_FIREWALL_RULE_APPLIED"}, {"numeric-protocol", "numeric-protocol", "upsert", "APP_FIREWALL_RULE_APPLIED"},
		{"edit", "", "update", "APP_FIREWALL_RULE_APPLIED"}, {"remove", "", "delete", "APP_FIREWALL_RULE_REMOVED"}, {"already-removed", "", "delete-absent", "APP_FIREWALL_RULE_REMOVED"},
		{"foreign-owner", "foreign-owner", "upsert", "FIREWALL_RULE_OWNERSHIP_CHANGED"}, {"query-failure", "query-failure", "upsert", "QUERY_FAILED"},
		{"provider-stopped", "stopped-service", "upsert", "FIREWALL_PROVIDER_UNAVAILABLE"}, {"disabled-profile-string", "disabled-profile", "upsert", "FIREWALL_PROFILE_DISABLED"},
		{"changed-file", "changed-hash", "upsert", "FIREWALL_APPLICATION_CHANGED"}, {"write-denied", "write-denied", "upsert", "WRITE_DENIED"},
		{"not-effective", "not-effective", "upsert", "FIREWALL_RULE_NOT_EFFECTIVE"}, {"port-mismatch", "port-mismatch", "upsert", "FIREWALL_RULE_PORT_MISMATCH"},
		{"protocol-mismatch", "protocol-mismatch", "upsert", "FIREWALL_RULE_PROTOCOL_MISMATCH"}, {"delete-noop", "delete-noop", "delete", "FIREWALL_RULE_REMAINS"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := sampleRule()
			op := "upsert"
			if strings.HasPrefix(tc.op, "delete") {
				op = "delete"
			}
			script, err := Script(Change{Operation: op, Rule: r})
			if err != nil {
				t.Fatal(err)
			}
			out := fixture(t, pwsh, tc.mode, tc.op, script, r)
			if !strings.Contains(out, tc.want) {
				t.Fatal(out, "wanted", tc.want)
			}
			if tc.want != "APP_FIREWALL_RULE_APPLIED" && tc.want != "APP_FIREWALL_RULE_REMOVED" && strings.Contains(out, "APP_FIREWALL_RULE_") {
				t.Fatal("failure returned success", out)
			}
		})
	}
}
func TestPowerShellLiteralProgramPath(t *testing.T) {
	pwsh := os.Getenv("USBLINK_TEST_PWSH")
	if pwsh == "" {
		t.Skip("PowerShell fixture host not configured")
	}
	r := sampleRule()
	r.Application.Path = `C:\Program Files\x';throw 'INJECTED';$(bad).exe`
	s, err := Script(Change{Operation: "upsert", Rule: r})
	if err != nil {
		t.Fatal(err)
	}
	if out := fixture(t, pwsh, "", "upsert", s, r); out != "APP_FIREWALL_RULE_APPLIED" {
		t.Fatal(out)
	}
}
func TestPowerShellReadOnlyAuditDetectsExternalChange(t *testing.T) {
	pwsh := os.Getenv("USBLINK_TEST_PWSH")
	if pwsh == "" {
		t.Skip("PowerShell fixture host not configured")
	}
	for _, mode := range []string{"", "audit-missing", "disabled-profile", "foreign-owner"} {
		t.Run(mode, func(t *testing.T) {
			r := sampleRule()
			s, err := AuditScript([]Rule{r})
			if err != nil {
				t.Fatal(err)
			}
			out := fixture(t, pwsh, mode, "audit", s, r)
			var result []struct {
				State string `json:"state"`
				Error string `json:"error"`
			}
			if json.Unmarshal([]byte(out), &result) != nil || len(result) != 1 {
				t.Fatal(out)
			}
			if mode == "" && result[0].State != "applied" || mode != "" && (result[0].State != "error" || result[0].Error == "") {
				t.Fatal(out)
			}
		})
	}
}
