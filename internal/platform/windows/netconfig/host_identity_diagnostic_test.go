package netconfig

import (
	"encoding/json"
	"strings"
	"testing"
)

const validHostDiagnostic = `{"phase":"pnp_identity","hresult":0,"adapter_count":1,"guid_matches":true,"alias_matches":true,"index_matches":true,"instance_nonempty":true,"instance_wildcard_free":true,"pnp_count":1,"service_wintun":false,"class_net":true}`

func TestHostIdentityDiagnosticRetainsUnknownAndMismatch(t *testing.T) {
	for _, raw := range []string{
		`{"phase":"adapter_query","hresult":-2147024891,"adapter_count":null,"guid_matches":null,"alias_matches":null,"index_matches":null,"instance_nonempty":null,"instance_wildcard_free":null,"pnp_count":null,"service_wintun":null,"class_net":null}`,
		validHostDiagnostic,
	} {
		d, e := decodeHostIdentityDiagnostic([]byte(raw))
		if e != nil {
			t.Fatal(e)
		}
		if d.Phase == "adapter_query" && d.ServiceWintun != nil {
			t.Fatal("failed provider invented identity")
		}
		if d.Phase == "pnp_identity" && (d.ServiceWintun == nil || *d.ServiceWintun) {
			t.Fatal("mismatch masked")
		}
	}
}

func TestHostIdentityDiagnosticRejectsRawAndUnboundedOutput(t *testing.T) {
	for _, raw := range []string{
		`{"phase":"pnp_identity","hresult":0}`,
		strings.TrimSuffix(validHostDiagnostic, "}") + `,"pnp_instance":"SECRET"}`,
		strings.TrimSuffix(validHostDiagnostic, "}") + `,"query_error":"SECRET PATH"}`,
		strings.TrimSuffix(validHostDiagnostic, "}") + `,"phase":"adapter_query"}`,
		strings.Replace(validHostDiagnostic, `"pnp_identity"`, `"SECRET"`, 1),
		strings.Replace(validHostDiagnostic, `"adapter_count":1`, `"adapter_count":65537`, 1),
		strings.Replace(validHostDiagnostic, `"hresult":0`, `"hresult":2147483648`, 1),
		validHostDiagnostic + ` {}`,
		strings.Repeat("x", 4097),
	} {
		if _, e := decodeHostIdentityDiagnostic([]byte(raw)); e == nil {
			t.Fatalf("accepted %s", raw[:min(len(raw), 100)])
		}
	}
}

func TestHostIdentityDiagnosticFixedReadonlyQueries(t *testing.T) {
	s := sharedHostIdentityDiagnosticScript(28)
	for _, required := range []string{"Get-NetAdapter -IncludeHidden", "Get-CimInstance -ClassName Win32_PnPEntity", "$_.DeviceID -ieq $id", "$p[0].Service -ieq 'Wintun'", "4d36e972-e325-11ce-bfc1-08002be10318", "[uint32]$a[0].ifIndex -eq 28", "$_.Exception.HResult"} {
		if !strings.Contains(s, required) {
			t.Fatal(required)
		}
	}
	for _, forbidden := range []string{"Set-", "Remove-", "New-Net", "Enable-", "Disable-", "Restart-", "Exception.Message", "Write-Output $id"} {
		if strings.Contains(s, forbidden) {
			t.Fatal(forbidden)
		}
	}
	d, e := decodeHostIdentityDiagnostic([]byte(`{"phase":"adapter_query","hresult":0,"adapter_count":null,"guid_matches":null,"alias_matches":null,"index_matches":null,"instance_nonempty":null,"instance_wildcard_free":null,"pnp_count":null,"service_wintun":null,"class_net":null}`))
	if e != nil {
		t.Fatal(e)
	}
	b, _ := json.Marshal(d)
	if strings.Contains(string(b), "pnp_instance") {
		t.Fatal("raw identity exported")
	}
}
