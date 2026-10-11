package netconfig

import (
	"strings"
	"testing"
)

func TestOnlyOwnedAdapterAndScopedRules(t *testing.T) {
	setup, cleanup, err := Scripts(17, "{A4611646-E050-4D25-B83E-633A5598F302}", 1500, "0123456789abcdef01234567")
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range []string{"InterfaceIndex 17", "InterfaceGuid", "-RemoteAddress '10.77.0.1'", "-LocalAddress '10.77.0.2'", "-InterfaceAlias $a.Name", "-PolicyStore ActiveStore"} {
		if !strings.Contains(setup, s) {
			t.Fatal("missing scope", s)
		}
	}
	for _, s := range []string{"DefaultGateway", "Set-DnsClient", "Disable-NetFirewall", "-ExecutionPolicy", "Set-NetFirewallProfile"} {
		if strings.Contains(setup, s) {
			t.Fatal("unrelated change", s)
		}
	}
	if strings.Contains(cleanup, "*") || strings.Contains(cleanup, "Remove-NetAdapter") {
		t.Fatal("broad cleanup")
	}
	for _, suffix := range []string{"ICMP", "BENCH", "SUN-TCP", "SUN-UDP"} {
		if !strings.Contains(cleanup, "0123456789abcdef01234567-"+suffix) {
			t.Fatal("missing cleanup")
		}
	}
}
func TestRejectScriptInjectionAndInvalidMTU(t *testing.T) {
	for _, args := range []struct {
		i  uint32
		g  string
		m  int
		id string
	}{{0, "{A4611646-E050-4D25-B83E-633A5598F302}", 1500, "0123456789abcdef01234567"}, {1, "'; Remove-Item", 1500, "0123456789abcdef01234567"}, {1, "{A4611646-E050-4D25-B83E-633A5598F302}", 1501, "0123456789abcdef01234567"}, {1, "{A4611646-E050-4D25-B83E-633A5598F302}", 1500, "'*'"}} {
		if _, _, err := Scripts(args.i, args.g, args.m, args.id); err == nil {
			t.Fatal("invalid script args accepted")
		}
	}
}

func TestCleanupVerificationRejectsUnownedIdentifiers(t *testing.T) {
	guid := "{A4611646-E050-4D25-B83E-633A5598F302}"
	token := "0123456789abcdef01234567"
	if _, err := VerifyCleanup(guid, token); err != nil {
		t.Fatal(err)
	}
	for _, pair := range [][2]string{{guid, "*"}, {guid, "'; Remove-Item"}, {"wrong", token}} {
		if _, err := VerifyCleanup(pair[0], pair[1]); err == nil {
			t.Fatal("accepted unknown or injected ownership")
		}
	}
}

func TestFileReceiverIsConfinedToOwnedUSBAndExactRule(t *testing.T) {
	guid, token := "{A4611646-E050-4D25-B83E-633A5598F302}", "0123456789abcdef01234567"
	add, e := FileReceiverRule(guid, token, true)
	if e != nil {
		t.Fatal(e)
	}
	for _, scope := range []string{guid, "-InterfaceAlias $a[0].Name", "-LocalAddress '10.77.0.2'", "-RemoteAddress '10.77.0.1'", "-Protocol TCP -LocalPort 10690", "-FILES"} {
		if !strings.Contains(add, scope) {
			t.Fatal("missing file rule scope", scope)
		}
	}
	// A listener retry must repair the exact receipt-owned rule left by its
	// previous attempt. Validate the adapter before any rule mutation.
	if strings.Contains(add, "File rule already exists") || strings.Index(add, "Owned USB adapter changed") > strings.Index(add, "Remove-NetFirewallRule") || !strings.Contains(add, "Owned firewall rules remain after removal") {
		t.Fatal("rule retries are not safe/idempotent")
	}
	remove, e := FileReceiverRule(guid, token, false)
	if e != nil || strings.Contains(remove, "*") || strings.Contains(remove, "Remove-NetAdapter") || !strings.Contains(remove, token+"-FILES") {
		t.Fatal("broad file cleanup")
	}
	for _, args := range [][2]string{{guid, "*"}, {"'; Remove-Item", token}} {
		if _, e := FileReceiverRule(args[0], args[1], true); e == nil {
			t.Fatal("invalid file ownership accepted")
		}
	}
}

func TestUnifiedMacWindowsPeerAndFirewallUseActualAddresses(t *testing.T) {
	guid, token := "{A4611646-E050-4D25-B83E-633A5598F302}", "0123456789abcdef01234567"
	setup, _, e := ScriptsForProfile(17, guid, 1500, token, "unified")
	if e != nil || strings.Contains(setup, "10.77.") {
		t.Fatal("legacy route in unified configuration")
	}
	for _, s := range []string{"'10.6.9.0/24'", "-IPAddress '10.6.9.1'", "-LocalAddress '10.6.9.1'", "-RemoteAddress '10.6.9.2'"} {
		if !strings.Contains(setup, s) {
			t.Fatal("profile mismatch", s)
		}
	}
	files, e := FileReceiverRuleForProfile(guid, token, true, "unified")
	if e != nil || strings.Contains(files, "10.77.") || !strings.Contains(files, "-LocalAddress '10.6.9.1' -RemoteAddress '10.6.9.2'") {
		t.Fatal("file rule address mismatch")
	}
	if _, _, e = ScriptsForProfile(17, guid, 1500, token, "bad"); e == nil {
		t.Fatal("unknown profile accepted")
	}
}

func TestRecoveryRemovalRequiresExactJournalAndDriverIdentity(t *testing.T) {
	guid, token := "{A4611646-E050-4D25-B83E-633A5598F302}", "0123456789abcdef01234567"
	s, e := RecoverAdapter(guid, token)
	if e != nil {
		t.Fatal(e)
	}
	for _, required := range []string{guid, "Name -cne 'Suhang USB'", "Service -ine 'Wintun'", "ClassGuid", "/remove-device $id", "$LASTEXITCODE -ne 0", "Owned adapter remains after removal"} {
		if !strings.Contains(s, required) {
			t.Fatal("missing guard", required)
		}
	}
	for _, forbidden := range []string{"/delete-driver", "/force", "/subtree", "/reboot", "Remove-Item", "-like"} {
		if strings.Contains(s, forbidden) {
			t.Fatal("broad removal", forbidden)
		}
	}
	for _, args := range [][2]string{{"*", token}, {guid, "*"}, {"'; exit", token}} {
		if _, e := RecoverAdapter(args[0], args[1]); e == nil {
			t.Fatal("invalid ownership accepted", args)
		}
	}
}
