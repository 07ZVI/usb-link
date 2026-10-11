package netconfig

import (
	"fmt"
	"strings"
	"testing"
)

func fixturePending(t *testing.T, specs []coreRuleSpec) (string, corePending) {
	t.Helper()
	s, e := corePermissionScript("$a=@([pscustomobject]@{Name='USB Link'});", specs, map[int]string{len(specs) - 1: "USB_CORE_PERMISSION_READY"})
	if e != nil {
		t.Fatal(e)
	}
	coreBaselines.Lock()
	p := coreBaselines.pending[len(coreBaselines.pending)-1]
	coreBaselines.Unlock()
	return s, p
}
func fixtureMetadata(p corePending, origin, complete, hash string) string {
	lines := []string{}
	for i := range p.rules {
		lines = append(lines, fmt.Sprintf("USB_CORE_META:%s:%d:%s:%s:%s:%s", p.nonce, i, origin, complete, hash, map[string]string{"CREATED": "NO_BASELINE", "REUSED": "MATCHED"}[origin]))
	}
	return strings.Join(append(lines, "USB_CORE_PERMISSION_READY"), "\n")
}
func TestCoreBaselineProtocolRejectsPartialAndForgedResults(t *testing.T) {
	r := coreSpec("{A4611646-E050-4D25-B83E-633A5598F302}", "USB-Link-Core-Mac-v1", `C:\USB-Link.exe`, "TCP", "10.6.9.1", "10.6.9.2", "445", "", "")
	hash := strings.Repeat("a", 64)
	for _, tc := range []struct {
		name   string
		change func(corePending, string, string) (string, string)
		ready  bool
	}{
		{"wrong-nonce", func(p corePending, s, o string) (string, string) {
			return s, strings.ReplaceAll(o, p.nonce, strings.Repeat("0", 32))
		}, true},
		{"copied-nonce-in-unrelated-script", func(p corePending, s, o string) (string, string) { return "# nonce=" + p.nonce, o }, true},
		{"duplicate-row", func(p corePending, s, o string) (string, string) { return s, strings.Split(o, "\n")[0] + "\n" + o }, true},
		{"unknown-index", func(p corePending, s, o string) (string, string) { return s, strings.Replace(o, ":0:", ":1:", 1) }, true},
		{"unknown-origin", func(p corePending, s, o string) (string, string) {
			return s, strings.Replace(o, ":CREATED:", ":EXISTING:", 1)
		}, true},
		{"truncated-hash", func(p corePending, s, o string) (string, string) { return s, strings.Replace(o, hash, hash[:63], 1) }, true},
		{"invalid-hash", func(p corePending, s, o string) (string, string) {
			return s, strings.Replace(o, hash, strings.Repeat("g", 64), 1)
		}, true},
		{"unknown-completeness", func(p corePending, s, o string) (string, string) {
			return s, strings.Replace(o, ":COMPLETE:", ":UNKNOWN:", 1)
		}, true},
		{"unknown-metadata", func(p corePending, s, o string) (string, string) { return s, "USB_CORE_META:unrecognized\n" + o }, true},
		{"embedded-metadata", func(p corePending, s, o string) (string, string) { return s, "prefix-" + o }, true},
		{"missing-metadata", func(p corePending, s, o string) (string, string) { return s, "USB_CORE_PERMISSION_READY" }, true},
		{"partial-ready", func(p corePending, s, o string) (string, string) {
			return s, strings.ReplaceAll(o, "USB_CORE_PERMISSION_READY", "OWNED_FIREWALL_READY")
		}, true},
		{"duplicate-ready", func(p corePending, s, o string) (string, string) { return s, o + "\nUSB_CORE_PERMISSION_READY" }, true},
		{"failed-whole-execution", func(p corePending, s, o string) (string, string) { return s, o }, false},
		{"invented-reuse-before-creation", func(p corePending, s, o string) (string, string) {
			return s, strings.Replace(o, ":CREATED:", ":REUSED:", 1)
		}, true},
		{"oversized-output", func(p corePending, s, o string) (string, string) { return s, o + strings.Repeat(" ", 4096) }, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			resetCoreBaselineFixture(t)
			s, p := fixturePending(t, []coreRuleSpec{r})
			s, o := tc.change(p, s, fixtureMetadata(p, "CREATED", "COMPLETE", hash))
			if _, e := CompleteCorePermissionReadback(s, o, func(string) bool { return tc.ready }); e == nil {
				t.Fatal("unsafe transcript accepted")
			}
			coreBaselines.Lock()
			n := len(coreBaselines.baselines)
			coreBaselines.Unlock()
			if n != 0 {
				t.Fatal("failed transcript captured baseline")
			}
			if CorePermissionReadbackStats().MetadataRejected != 1 {
				t.Fatal("rejection not counted")
			}
		})
	}
}
func TestCoreBaselineCaptureAtomicAndBounded(t *testing.T) {
	resetCoreBaselineFixture(t)
	r := coreSpec("{A4611646-E050-4D25-B83E-633A5598F302}", "USB-Link-Core-Mac-v1", `C:\USB-Link.exe`, "TCP", "10.6.9.1", "10.6.9.2", "445", "", "")
	second := r
	second.Name = "second"
	s, p := fixturePending(t, []coreRuleSpec{r, second})
	output := fixtureMetadata(p, "CREATED", "COMPLETE", strings.Repeat("b", 64))
	output = strings.Replace(output, ":1:CREATED:COMPLETE:", ":1:CREATED:INCOMPLETE:", 1)
	clean, e := CompleteCorePermissionReadback(s, output, func(v string) bool { return v == "USB_CORE_PERMISSION_READY" })
	if e != nil || clean != "USB_CORE_PERMISSION_READY" || len(coreBaselines.baselines) != 0 {
		t.Fatal("partial fingerprint transaction captured", e)
	}
	for i := 0; i < coreBaselineLimit+10; i++ {
		r.Name = fmt.Sprint(i)
		s, p = fixturePending(t, []coreRuleSpec{r})
		_, e = CompleteCorePermissionReadback(s, fixtureMetadata(p, "CREATED", "COMPLETE", strings.Repeat("b", 64)), func(v string) bool { return v == "USB_CORE_PERMISSION_READY" })
		if e != nil {
			t.Fatal(e)
		}
	}
	if len(coreBaselines.baselines) != coreBaselineLimit || len(coreBaselines.order) != coreBaselineLimit {
		t.Fatal("baseline bound")
	}
	for i := 0; i < coreBaselineLimit+10; i++ {
		r.Name = fmt.Sprint(i)
		fixturePending(t, []coreRuleSpec{r})
	}
	if len(coreBaselines.pending) != coreBaselineLimit {
		t.Fatal("unexecuted plans not evicted")
	}
}
func TestCoreBaselineKeyIncludesAllExplicitScopes(t *testing.T) {
	r := coreSpec("{A4611646-E050-4D25-B83E-633A5598F302}", "USB-Link-Core-Mac-v1", `C:\USB-Link.exe`, "TCP", "10.6.9.1", "10.6.9.2", "445", "", "")
	changes := []func(*coreRuleSpec){func(v *coreRuleSpec) { v.GUID = "other" }, func(v *coreRuleSpec) { v.Name = "other" }, func(v *coreRuleSpec) { v.Program = "other" }, func(v *coreRuleSpec) { v.Protocol = "UDP" }, func(v *coreRuleSpec) { v.Local = "Any" }, func(v *coreRuleSpec) { v.Peer = "10.6.9.3" }, func(v *coreRuleSpec) { v.Ports = "67" }, func(v *coreRuleSpec) { v.RemotePort = "68" }, func(v *coreRuleSpec) { v.Service = "other" }}
	for i, change := range changes {
		next := r
		change(&next)
		if next.key() == r.key() {
			t.Fatal("scope missing from key", i)
		}
	}
}

func TestCorePermissionReadbackStatsAreReadOnlyAndBounded(t *testing.T) {
	resetCoreBaselineFixture(t)
	r := coreSpec("{A4611646-E050-4D25-B83E-633A5598F302}", "USB-Link-Core-Mac-v1", `C:\USB-Link.exe`, "TCP", "10.6.9.1", "10.6.9.2", "445", "", "")
	s, p := fixturePending(t, []coreRuleSpec{r})
	_, e := CompleteCorePermissionReadback(s, fixtureMetadata(p, "CREATED", "COMPLETE", strings.Repeat("b", 64)), func(v string) bool { return v == "USB_CORE_PERMISSION_READY" })
	if e != nil {
		t.Fatal(e)
	}
	stats := CorePermissionReadbackStats()
	if stats.CacheEntries != 1 || stats.PendingPlans != 0 || stats.CreatedBaselines != 1 || stats.CreatedRules != 1 || stats.MissingBaseline != 1 || stats.ReusedRules != 0 {
		t.Fatal(stats)
	}
	s, p = fixturePending(t, []coreRuleSpec{r})
	_, e = CompleteCorePermissionReadback(s, fixtureMetadata(p, "REUSED", "COMPLETE", strings.Repeat("b", 64)), func(v string) bool { return v == "USB_CORE_PERMISSION_READY" })
	if e != nil {
		t.Fatal(e)
	}
	next := CorePermissionReadbackStats()
	if next.ReusedRules != 1 || next.CreatedBaselines != 1 || next != CorePermissionReadbackStats() {
		t.Fatal("read changed counters", next)
	}
}

func TestCoreBatchReadbackPreservesExactOriginalReadyContract(t *testing.T) {
	resetCoreBaselineFixture(t)
	r := coreSpec("{A4611646-E050-4D25-B83E-633A5598F302}", "USB-Link-Core-Mac-v1", `C:\USB-Link.exe`, "TCP", "10.6.9.1", "10.6.9.2", "445", "", "")
	s, p := fixturePending(t, []coreRuleSpec{r})
	o := "OWNED_FIREWALL_READY\n" + fixtureMetadata(p, "CREATED", "COMPLETE", strings.Repeat("c", 64))
	clean, e := CompleteCorePermissionReadback("Write-Output 'OWNED_FIREWALL_READY';\n"+s, o, func(v string) bool { return v == "OWNED_FIREWALL_READY\nUSB_CORE_PERMISSION_READY" })
	if e != nil || clean != "OWNED_FIREWALL_READY\nUSB_CORE_PERMISSION_READY" {
		t.Fatal(clean, e)
	}
	// Successful observation is one-use, and a copied completed transcript is not
	// admitted after its exact plan was consumed.
	if _, e = CompleteCorePermissionReadback(s, o, func(string) bool { return true }); e == nil {
		t.Fatal("replayed successful observation accepted")
	}
}
