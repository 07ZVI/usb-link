package netconfig

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestCombinedRecoveryProviderFailuresAndForeignResources(t *testing.T) {
	pwsh := os.Getenv("USBLINK_TEST_PWSH")
	if pwsh == "" {
		t.Skip("PowerShell fixture host not configured")
	}
	script, e := FullRecovery("{A4611646-E050-4D25-B83E-633A5598F302}", "0123456789abcdef01234567")
	if e != nil {
		t.Fatal(e)
	}
	for _, mode := range []string{"rules", "clean", "provider-failure", "foreign-adapter"} {
		t.Run(mode, func(t *testing.T) {
			pre := `$ErrorActionPreference='Stop';$script:mode='` + mode + `';$script:rules=@('unrelated');if($script:mode -eq 'rules'){$script:rules+=@('ICMP','BENCH','SUN-TCP','SUN-UDP','FILES')|ForEach-Object {'Suhang-USB-Phase2-0123456789abcdef01234567-'+$_}};
function Get-NetFirewallRule {param($ErrorAction) if($script:mode -eq 'provider-failure'){throw 'provider unavailable'};$script:rules|ForEach-Object {[pscustomobject]@{Name=$_}}};
function Remove-NetFirewallRule {param([Parameter(ValueFromPipeline=$true)]$InputObject) process {$script:rules=@($script:rules|Where-Object {$_ -cne $InputObject.Name})}};
function Get-NetAdapter {param([switch]$IncludeHidden) if($script:mode -eq 'foreign-adapter'){[pscustomobject]@{InterfaceGuid='{A4611646-E050-4D25-B83E-633A5598F302}';Name='Foreign';PnPDeviceID='unowned'}}};
`
			post := `;if($script:rules.Count -ne 1 -or $script:rules[0] -cne 'unrelated'){throw 'unrelated rule changed'}; 'FIXTURE_PASS'`
			p := filepath.Join(t.TempDir(), "fixture.ps1")
			if e = os.WriteFile(p, []byte(pre+script+post), 0600); e != nil {
				t.Fatal(e)
			}
			b, err := exec.Command(pwsh, "-NoProfile", "-NonInteractive", "-File", p).CombinedOutput()
			if mode == "rules" || mode == "clean" {
				if err != nil || !strings.Contains(string(b), "FIXTURE_PASS") {
					t.Fatalf("%v %s", err, b)
				}
			} else {
				if err == nil {
					t.Fatal("unsafe recovery succeeded")
				}
				expected := "provider unavailable"
				if mode == "foreign-adapter" {
					expected = "Owned adapter name changed"
				}
				if !strings.Contains(string(b), expected) {
					t.Fatalf("wrong failure %s", b)
				}
			}
		})
	}
}
