package connectioninstall

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// Runs the production script with only the external scheduler/filesystem
// providers replaced. These fixtures never query or mutate real Windows tasks.
// Without an existing PowerShell runtime, the test reports its runtime boundary.
func TestStartupRegistrationAdversarialProviderFixtures(t *testing.T) {
	pwsh := os.Getenv("USBLINK_TEST_PWSH")
	if pwsh == "" && runtime.GOOS == "windows" {
		pwsh = filepath.Join(os.Getenv("SystemRoot"), "System32", "WindowsPowerShell", "v1.0", "powershell.exe")
	}
	if pwsh == "" {
		t.Skip("existing PowerShell runtime unavailable; no native registration proof")
	}
	for _, tc := range []struct {
		name      string
		calls     string
		operation string
		failed    bool
	}{
		{"create", "1,2", "READBACK", false}, {"update", "1,4", "READBACK", false},
		{"validate_fail", "1", "VALIDATE_XML", true}, {"foreign_initial", "", "QUERY", true},
		{"foreign_prewrite", "1", "PREWRITE", true}, {"deleted_before_update", "1,4", "UPDATE", true},
		{"create_collision", "1,2", "CREATE", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// PowerShell resolves 8.3 short names; the fixture paths must already be long.
			dir, err := filepath.EvalSymlinks(t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			root := filepath.Join(dir, "product")
			exe := filepath.Join(root, "0.8.91", BinaryName)
			calls := filepath.Join(dir, "provider-calls.txt")
			providerScript := strings.Replace(startupTaskScript, "New-Object -ComObject 'Schedule.Service'", "$testScheduler", 1)
			if runtime.GOOS != "windows" {
				// SecurityIdentifier is a Windows provider too. Portable PS fixtures
				// exercise orchestration only, never claim native SID translation.
				start := strings.Index(providerScript, "function Exact-Sid(")
				end := strings.Index(providerScript[start:], "\n") + start
				providerScript = providerScript[:start] + `function Exact-Sid($value){if($value -cne $env:SUHANG_SID){throw 'STARTUP_PRINCIPAL_CHANGED'};return $value}` + providerScript[end:]
			}
			body := startupProviderFixture + "\n" + providerScript
			script := filepath.Join(dir, "fixture.ps1")
			if err := os.WriteFile(script, []byte(body), 0600); err != nil {
				t.Fatal(err)
			}
			c := exec.Command(pwsh, "-NoProfile", "-NonInteractive", "-File", script)
			c.Env = append(os.Environ(), "SUHANG_FIXTURE_CASE="+tc.name, "SUHANG_FIXTURE_CALLS="+calls, "SUHANG_TASK_NAME=USB-Link-fixture", "SUHANG_LEGACY_TASK_NAME=Suhang-iPad-USB-fixture", "SUHANG_SID=S-1-5-21-1-2-3-1001", "SUHANG_PRODUCT="+ProductID, "SUHANG_EXE="+exe, "SUHANG_ROOT="+root, "SUHANG_LEGACY_ROOT="+filepath.Join(dir, "legacy"), "SUHANG_STARTUP_MODE=ON", "SUHANG_TASK_XML=<Task>fixture</Task>")
			output, runErr := c.CombinedOutput()
			v, parseErr := parseStartupTaskObservation(output, runErr != nil)
			if tc.failed != (runErr != nil) || tc.failed != (parseErr != nil) || v.Operation != tc.operation {
				t.Fatalf("failure/operation mismatch: %+v run=%v parse=%v output=%s", v, runErr, parseErr, output)
			}
			b, err := os.ReadFile(calls)
			if err != nil && !os.IsNotExist(err) {
				t.Fatal(err)
			}
			if strings.TrimSpace(string(b)) != tc.calls {
				t.Fatalf("unexpected scheduler calls: %q", b)
			}
			if tc.name == "validate_fail" || tc.name == "deleted_before_update" || tc.name == "create_collision" {
				if v.InnerNativeError != 2147942405 || v.InnerExceptionKind != "COM" {
					t.Fatalf("native COM code lost behind wrapper: %+v", v)
				}
			}
			var raw map[string]any
			if json.Unmarshal(output, &raw) != nil {
				t.Fatal("non-JSON provider output")
			}
		})
	}
}

const startupProviderFixture = `$global:testQueries=0;$global:testTask=$null
$testHash='aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'
function New-FixtureTask($foreign){
 [pscustomobject]@{TaskName=$env:SUHANG_TASK_NAME;TaskPath='\';Description=$(if($foreign){'foreign'}else{$env:SUHANG_PRODUCT});Principal=[pscustomobject]@{UserId=$env:SUHANG_SID;LogonType='Interactive';RunLevel='Highest'};Actions=@([pscustomobject]@{Execute=$env:SUHANG_EXE;Arguments='--resident';WorkingDirectory=''});Triggers=@([pscustomobject]@{CimClass=[pscustomobject]@{CimClassName='MSFT_TaskLogonTrigger'};UserId=$env:SUHANG_SID;Delay='PT5S';Enabled=$true});Settings=[pscustomobject]@{Enabled=$true};State='Ready'}
}
if($env:SUHANG_FIXTURE_CASE -in @('update','deleted_before_update')){$global:testTask=New-FixtureTask $false}
if($env:SUHANG_FIXTURE_CASE -eq 'foreign_initial'){$global:testTask=New-FixtureTask $true}
function Get-ScheduledTask { [CmdletBinding()]param();$global:testQueries++;if($env:SUHANG_FIXTURE_CASE -eq 'foreign_prewrite' -and $global:testQueries -ge 2){$global:testTask=New-FixtureTask $true};if($null -ne $global:testTask){$global:testTask} }
function Get-Item { [CmdletBinding()]param($LiteralPath,[switch]$Force);[pscustomobject]@{Attributes=0} }
function Get-Content { [CmdletBinding()]param($LiteralPath,[switch]$Raw);@{product=$env:SUHANG_PRODUCT;version='0.8.91';sha256=$testHash}|ConvertTo-Json -Compress }
function Get-FileHash { [CmdletBinding()]param($LiteralPath,$Algorithm);[pscustomobject]@{Hash=$testHash} }
function Unregister-ScheduledTask { [CmdletBinding()]param([Parameter(ValueFromPipeline=$true)]$InputObject);throw 'unexpected fixture delete' }
$testFolder=[pscustomobject]@{}
$testFolder|Add-Member ScriptMethod RegisterTask {
 param($name,$xml,$flags,$sid,$password,$logon,$sddl)
 if($name -cne $env:SUHANG_TASK_NAME -or $xml -cne $env:SUHANG_TASK_XML -or $sid -cne $env:SUHANG_SID -or $null -ne $password -or $logon -ne 3 -or $null -ne $sddl){throw 'changed registration contract'}
 $old='';if([IO.File]::Exists($env:SUHANG_FIXTURE_CALLS)){$old=[IO.File]::ReadAllText($env:SUHANG_FIXTURE_CALLS)}
 if($old -ne ''){$old+=','};[IO.File]::WriteAllText($env:SUHANG_FIXTURE_CALLS,$old+[string]$flags)
 if($flags -notin @(1,2,4)){throw 'unsafe flags'}
 if(($flags -eq 1 -and $env:SUHANG_FIXTURE_CASE -eq 'validate_fail') -or ($flags -eq 4 -and $env:SUHANG_FIXTURE_CASE -eq 'deleted_before_update') -or ($flags -eq 2 -and $env:SUHANG_FIXTURE_CASE -eq 'create_collision')){throw [Runtime.InteropServices.COMException]::new('fixture error must not be exported',-2147024891)}
 if($flags -ne 1){$global:testTask=New-FixtureTask $false}
 return $null
}
$testScheduler=[pscustomobject]@{}
$testScheduler|Add-Member ScriptMethod Connect {param();return $null}
$testScheduler|Add-Member ScriptMethod GetFolder {param($path);if($path -cne '\'){throw 'changed root folder'};return $testFolder}
`

func TestStartupScriptRegistrationContract(t *testing.T) {
	validate := strings.Index(startupTaskScript, "$env:SUHANG_TASK_XML,1,$env:SUHANG_SID,$null,3,$null")
	fresh := strings.Index(startupTaskScript, "$operation='PREWRITE';$prewrite=@(Product-Tasks)")
	create := strings.Index(startupTaskScript, "$operation='CREATE';$flags=2")
	update := strings.Index(startupTaskScript, "$operation='UPDATE';$flags=4")
	register := strings.Index(startupTaskScript, "$env:SUHANG_TASK_XML,$flags,$env:SUHANG_SID,$null,3,$null")
	if validate < 0 || fresh < validate || create < fresh || update < create || register < update {
		t.Fatal("registration call/ownership order changed")
	}
	for _, unsafe := range []string{"Register-ScheduledTask", "$flags=6", "-Force -ErrorAction Stop|Out-Null", "FullyQualifiedErrorId", "ErrorDetails.Message"} {
		if strings.Contains(startupTaskScript, unsafe) {
			t.Fatalf("unexpected broad registration or error output: %s", unsafe)
		}
	}
	if !strings.Contains(startupTaskScript, "$depth -lt 4") || !strings.Contains(startupTaskScript, "if($code -cnotin $allowed)") {
		t.Fatal("unbounded or raw exception output")
	}
}
