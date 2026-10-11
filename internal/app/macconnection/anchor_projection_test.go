package macconnection

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"log"
	"path/filepath"
	"strings"
	"suhang/usbnet/internal/diagnostics/logfile"
	"suhang/usbnet/internal/platform/windows/netconfig"
	"testing"
)

func anchorProjectionFixture(t *testing.T) (*netconfig.MacAnchorProjection, []byte) {
	t.Helper()
	fields := []string{"MSFT_NetFirewallRule/InstanceID", "MSFT_NetFirewallRule/RuleGroup", "MSFT_NetFirewallRule/Description", "MSFT_NetApplicationFilter/AppPath", "MSFT_NetServiceFilter/ServiceName", "MSFT_NetInterfaceFilter/InterfaceAlias", "MSFT_NetAddressFilter/LocalAddress", "MSFT_NetAddressFilter/RemoteAddress", "MSFT_NetProtocolPortFilter/Protocol", "MSFT_NetProtocolPortFilter/LocalPort", "MSFT_NetProtocolPortFilter/RemotePort", "MSFT_NetProtocolPortFilter/IcmpType"}
	rows := []any{}
	for i := 0; i < 5; i++ {
		fs := []any{}
		for _, f := range fields {
			fs = append(fs, map[string]any{"field": f, "public_count": 1, "cim_count": 1, "public_kind": "string", "cim_kind": "string", "public_is_exact_expected": false, "cim_is_exact_expected": false, "public_is_known_8_any_code": false, "cim_is_known_8_any_code": false})
		}
		rows = append(rows, map[string]any{"selector_index": i, "status": "observed", "public_rule_count": 1, "cim_rule_count": 1, "fields": fs})
	}
	b, e := json.Marshal(map[string]any{"schema": 1, "read_only": true, "rows": rows})
	if e != nil {
		t.Fatal(e)
	}
	v, e := netconfig.DecodeMacAnchorProjection(b)
	if e != nil {
		t.Fatal(e)
	}
	return v, b
}
func TestMacAnchorProjectionRequiresBoundOriginalForeignScope(t *testing.T) {
	epoch := beginNativeFailureAttempt()
	defer beginNativeFailureAttempt()
	binding := nativeChildBinding{pid: 17, creation: 19, nonce: strings.Repeat("a", 24)}
	v, _ := anchorProjectionFixture(t)
	if recordMacAnchorProjection(epoch, binding, v) {
		t.Fatal("unbound accepted")
	}
	bindNativeFailureChild(epoch, binding)
	if recordMacAnchorProjection(epoch, binding, v) {
		t.Fatal("no original failure")
	}
	wrong := netconfig.NativeStepDiagnostic{Schema: 1, Operation: "mac_resident_mac_plan", Code: "MAC_RESIDENT_MAC_PLAN_FAILED", CauseCode: "USB_NATIVE_FIREWALL_CONSTRAINT_NULL"}
	recordNativeFailure(epoch, binding, wrong)
	if recordMacAnchorProjection(epoch, binding, v) {
		t.Fatal("different cause accepted")
	}
	epoch = beginNativeFailureAttempt()
	bindNativeFailureChild(epoch, binding)
	f := netconfig.NativeStepDiagnostic{Schema: 1, Operation: "mac_resident_mac_plan", Code: "MAC_RESIDENT_MAC_PLAN_FAILED", CauseCode: "USB_RESIDENT_FOREIGN_SCOPE", CauseField: "MSFT_NetProtocolPortFilter/IcmpType"}
	if !recordNativeFailure(epoch, binding, f) {
		t.Fatal("first lost")
	}
	foreign := binding
	foreign.creation++
	if recordMacAnchorProjection(epoch, foreign, v) {
		t.Fatal("PID reuse accepted")
	}
	if !recordMacAnchorProjection(epoch, binding, v) || recordMacAnchorProjection(epoch, binding, v) {
		t.Fatal("first-only projection lost")
	}
	v.ReadOnly = false
	d := NativeStartupFailureDetails()
	got := d["firewall_anchor_projection"].(*netconfig.MacAnchorProjection)
	if !got.ReadOnly || d["cause_field"] != f.CauseField {
		t.Fatal("store aliased or first changed")
	}
	got.ReadOnly = false
	if !NativeStartupFailureDetails()["firewall_anchor_projection"].(*netconfig.MacAnchorProjection).ReadOnly {
		t.Fatal("snapshot alias")
	}
	row := netconfig.BridgeNetworkScriptTiming{Operation: "diagnostic", Count: 1, DurationMS: 120, Success: true}
	if !recordMacDiagnosticTiming(epoch, binding, row) || NativeStartupFailureDetails()["diagnostic_script_timing"] != row {
		t.Fatal("bound diagnostic timing lost")
	}
	beginNativeFailureAttempt()
	if recordMacAnchorProjection(epoch, binding, v) {
		t.Fatal("stale attempt accepted")
	}
}
func TestMacAnchorProjectionProductionRunnerFraming(t *testing.T) {
	_, b := anchorProjectionFixture(t)
	output := []byte("SUHANG_NETWORK_SCRIPT_BEGIN\r\n" + netconfig.MacAnchorProjectionPrefix + string(b) + "\r\nSUHANG_NETWORK_SCRIPT_OK\r\n")
	cases := []struct {
		name, script string
		output       []byte
		err          error
		want         int
	}{
		{"success", netconfig.ResidentMacAnchorProjectionScript(), output, nil, 1},
		{"wrong-fixed-script", netconfig.ResidentMacNullProjectionScript(), output, nil, 0},
		{"process-failed", netconfig.ResidentMacAnchorProjectionScript(), output, errors.New("failed"), 0},
		{"extra-json", netconfig.ResidentMacAnchorProjectionScript(), bytes.Replace(output, b, append(append([]byte(nil), b...), []byte("{}")...), 1), nil, 0},
		{"provider-warning", netconfig.ResidentMacAnchorProjectionScript(), append([]byte("warning\n"), output...), nil, 0},
		{"no-completion", netconfig.ResidentMacAnchorProjectionScript(), bytes.Replace(output, []byte("SUHANG_NETWORK_SCRIPT_OK"), []byte("FAILED"), 1), nil, 0},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			var logged bytes.Buffer
			netconfig.LogNetworkScriptOutput(c.script, c.output, c.err, log.New(&logged, "", log.Ldate|log.Ltime|log.Lmicroseconds))
			s := bufio.NewScanner(&logged)
			s.Buffer(make([]byte, 4096), 65536)
			accepted := 0
			for s.Scan() {
				if _, e := parseMacAnchorProjectionLine(s.Text()); e == nil {
					accepted++
				}
			}
			if accepted != c.want || s.Err() != nil {
				t.Fatal(accepted, c.want, s.Err())
			}
		})
	}
	prefix := "2026/10/09 12:34:56.123456 " + netconfig.MacAnchorProjectionPrefix
	for _, bad := range []string{netconfig.MacAnchorProjectionPrefix + string(b), "2026/10/09 12:34:56.123456 error=" + netconfig.MacAnchorProjectionPrefix + string(b), prefix + string(b) + "{}", prefix + string(b) + " error=<nil>"} {
		if _, e := parseMacAnchorProjectionLine(bad); e == nil {
			t.Fatal("bare/embedded/trailing accepted")
		}
	}
}

func TestMacAnchorProjectionProductionPipeAtMaximumRawByteBound(t *testing.T) {
	_, compact := anchorProjectionFixture(t)
	if len(compact) > netconfig.MacAnchorProjectionByteLimit {
		t.Fatal("fixture exceeds fixed bound")
	}
	// Exact maximum admitted raw JSON, including legal whitespace. Production
	// re-emission remains compact; both raw and dated lines traverse the actual
	// MultiWriter/logfile/io.Pipe/Scanner transport used for a bound child.
	payload := append(append([]byte(nil), compact...), bytes.Repeat([]byte(" "), netconfig.MacAnchorProjectionByteLimit-len(compact))...)
	output := []byte("SUHANG_NETWORK_SCRIPT_BEGIN\r\n" + netconfig.MacAnchorProjectionPrefix + string(payload) + "\r\nSUHANG_NETWORK_SCRIPT_OK\r\n")
	f, e := logfile.Open(filepath.Join(t.TempDir(), "installer.log"), 1<<20)
	if e != nil {
		t.Fatal(e)
	}
	defer f.Close()
	pipeR, pipeW := io.Pipe()
	defer pipeR.Close()
	type result struct {
		accepted, max int
		err           error
	}
	done := make(chan result, 1)
	go func() {
		s := bufio.NewScanner(pipeR)
		s.Buffer(make([]byte, 4096), 65536)
		var r result
		for s.Scan() {
			line := s.Text()
			if len(line) > r.max {
				r.max = len(line)
			}
			if _, e := parseMacAnchorProjectionLine(line); e == nil {
				r.accepted++
			}
		}
		r.err = s.Err()
		done <- r
	}()
	netconfig.LogNetworkScriptOutput(netconfig.ResidentMacAnchorProjectionScript(), output, nil, log.New(io.MultiWriter(f, pipeW), "", log.Ldate|log.Ltime|log.Lmicroseconds))
	if e := pipeW.Close(); e != nil {
		t.Fatal(e)
	}
	r := <-done
	if r.err != nil || r.accepted != 1 || r.max >= 65536 || r.max < netconfig.MacAnchorProjectionByteLimit {
		t.Fatal(r)
	}
}
