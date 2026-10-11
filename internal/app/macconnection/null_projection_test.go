package macconnection

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"log"
	"strings"
	"suhang/usbnet/internal/platform/windows/netconfig"
	"testing"
)

func nullProjectionFixture() *netconfig.MacNullProjection {
	v := &netconfig.MacNullProjection{Schema: 1, ReadOnly: true}
	for i := 0; i < 5; i++ {
		v.Rows = append(v.Rows, netconfig.MacNullProjectionRow{SelectorIndex: i, Status: "unavailable", Phase: "public_rule", PublicProgramKind: "unread", CIMAppPathKind: "unread"})
	}
	return v
}
func TestMacNullProjectionRequiresActualFirstFailureBinding(t *testing.T) {
	epoch := beginNativeFailureAttempt()
	defer beginNativeFailureAttempt()
	b := nativeChildBinding{pid: 17, creation: 5, nonce: strings.Repeat("a", 24)}
	v := nullProjectionFixture()
	if recordMacNullProjection(epoch, b, v) {
		t.Fatal("unbound accepted")
	}
	if !bindNativeFailureChild(epoch, b) {
		t.Fatal("bind failed")
	}
	if recordMacNullProjection(epoch, b, v) {
		t.Fatal("without original first failure")
	}
	f := netconfig.NativeStepDiagnostic{Schema: 1, Operation: "mac_resident_mac_plan", Code: "MAC_RESIDENT_MAC_PLAN_FAILED", CauseCode: "USB_NATIVE_FIREWALL_CONSTRAINT_NULL", CauseField: "MSFT_NetApplicationFilter/AppPath"}
	if !recordNativeFailure(epoch, b, f) {
		t.Fatal("failure lost")
	}
	foreign := b
	foreign.creation++
	if recordMacNullProjection(epoch, foreign, v) {
		t.Fatal("PID reuse accepted")
	}
	if !recordMacNullProjection(epoch, b, v) || recordMacNullProjection(epoch, b, v) {
		t.Fatal("first-only projection lost")
	}
	v.Rows[0].Status = "observed"
	d := NativeStartupFailureDetails()
	got := d["firewall_null_projection"].(*netconfig.MacNullProjection)
	if got.Rows[0].Status != "unavailable" || d["cause_field"] != f.CauseField {
		t.Fatal(d)
	}
	got.Rows[0].Status = "observed"
	if NativeStartupFailureDetails()["firewall_null_projection"].(*netconfig.MacNullProjection).Rows[0].Status != "unavailable" {
		t.Fatal("snapshot aliases")
	}
	beginNativeFailureAttempt()
	if recordMacNullProjection(epoch, b, v) {
		t.Fatal("stale accepted")
	}
}
func TestMacNullProjectionRequiresExactOwnedRunnerLogPrefix(t *testing.T) {
	b, _ := json.Marshal(nullProjectionFixture())
	prefix := "2026/10/09 12:34:56.123456 owned network configuration: " + netconfig.MacNullProjectionPrefix
	if _, e := parseMacNullProjectionLine(prefix + string(b)); e != nil {
		t.Fatal(e)
	}
	for _, bad := range []string{netconfig.MacNullProjectionPrefix + string(b), "2026/10/09 12:34:56.123456 error=" + netconfig.MacNullProjectionPrefix + string(b), prefix + string(b) + "{}"} {
		if _, e := parseMacNullProjectionLine(bad); e == nil {
			t.Fatal("embedded marker accepted")
		}
	}
}

func TestMacNullProjectionProductionRunnerMultilineFraming(t *testing.T) {
	b, _ := json.Marshal(nullProjectionFixture())
	// CombinedOutput's actual wrapper layout, passed through the same production
	// logger function RunContext calls. Scanner must reject the raw second line
	// and accept the re-emitted dated DTO, not a fabricated dated JSON fixture.
	output := []byte("SUHANG_NETWORK_SCRIPT_BEGIN\r\n" + netconfig.MacNullProjectionPrefix + string(b) + "\r\nSUHANG_NETWORK_SCRIPT_OK\r\n")
	cases := []struct {
		name, script string
		output       []byte
		err          error
		want         int
	}{
		{"actual-success", netconfig.ResidentMacNullProjectionScript(), output, nil, 1},
		{"foreign-script", "Write-Output other", output, nil, 0},
		{"process-failed", netconfig.ResidentMacNullProjectionScript(), output, errors.New("failed"), 0},
		{"extra-json", netconfig.ResidentMacNullProjectionScript(), bytes.Replace(output, b, append(append([]byte(nil), b...), []byte("{}")...), 1), nil, 0},
		{"provider-warning", netconfig.ResidentMacNullProjectionScript(), append([]byte("warning\n"), output...), nil, 0},
		{"no-completion", netconfig.ResidentMacNullProjectionScript(), bytes.Replace(output, []byte("SUHANG_NETWORK_SCRIPT_OK"), []byte("FAILED"), 1), nil, 0},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			var logged bytes.Buffer
			logger := log.New(&logged, "", log.Ldate|log.Ltime|log.Lmicroseconds)
			netconfig.LogNetworkScriptOutput(c.script, c.output, c.err, logger)
			scanner := bufio.NewScanner(&logged)
			accepted := 0
			for scanner.Scan() {
				if _, e := parseMacNullProjectionLine(scanner.Text()); e == nil {
					accepted++
				}
			}
			if accepted != c.want {
				t.Fatalf("accepted=%d want=%d", accepted, c.want)
			}
		})
	}
	prefix := "2026/10/09 12:34:56.123456 owned network configuration: " + netconfig.MacNullProjectionPrefix
	if _, e := parseMacNullProjectionLine(prefix + string(b) + " error=<nil>"); e != nil {
		t.Fatal(e)
	}
	for _, tail := range []string{" error=failed", " {}", " error=<nil> extra"} {
		if _, e := parseMacNullProjectionLine(prefix + string(b) + tail); e == nil {
			t.Fatal("unknown trailing accepted")
		}
	}
}
func TestMacDiagnosticTimingPreservesBoundFailureAndCannotOverwrite(t *testing.T) {
	epoch := beginNativeFailureAttempt()
	defer beginNativeFailureAttempt()
	binding := nativeChildBinding{pid: 17, creation: 9, nonce: strings.Repeat("a", 24)}
	row := netconfig.BridgeNetworkScriptTiming{Operation: "diagnostic", Count: 1, DurationMS: 10002, Success: false}
	if recordMacDiagnosticTiming(epoch, binding, row) {
		t.Fatal("unbound timing accepted")
	}
	bindNativeFailureChild(epoch, binding)
	if recordMacDiagnosticTiming(epoch, binding, row) {
		t.Fatal("without failure")
	}
	f := netconfig.NativeStepDiagnostic{Schema: 1, Operation: "mac_resident_mac_plan", Code: "MAC_RESIDENT_MAC_PLAN_FAILED", CauseCode: "USB_NATIVE_FIREWALL_CONSTRAINT_NULL"}
	if !recordNativeFailure(epoch, binding, f) || !recordMacDiagnosticTiming(epoch, binding, row) {
		t.Fatal("actual evidence lost")
	}
	if got := NativeStartupFailureDetails()["diagnostic_script_timing"]; got != row {
		t.Fatal(got)
	}
	row.Success = true
	if recordMacDiagnosticTiming(epoch, binding, row) {
		t.Fatal("later changed result")
	}
	foreign := binding
	foreign.creation++
	if recordMacDiagnosticTiming(epoch, foreign, row) {
		t.Fatal("PID reuse accepted")
	}
	next := beginNativeFailureAttempt()
	if recordMacDiagnosticTiming(epoch, binding, row) {
		t.Fatal("old timing accepted")
	}
	clearNativeFailure(next)
}
