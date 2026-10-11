package ipadncm

import (
	"bytes"
	"encoding/json"
	"strings"
	"suhang/usbnet/internal/security/appfirewall"
	"suhang/usbnet/internal/security/securitypolicy"
	"testing"
	"time"
)

func TestDesktopUIResultRetainedUntilMatchingAck(t *testing.T) {
	var c desktopUIResultCache
	now := time.Now()
	id := strings.Repeat("a", 32)
	c.put("security", id, "security-refresh", map[string]any{"event": "security", "rules": []any{}}, now)
	first := c.get("security", id, now)
	if len(first) == 0 || !bytes.Equal(first, c.get("security", id, now)) {
		t.Fatal("read consumed correlated result")
	}
	first[0] = 'x'
	if c.get("security", id, now)[0] != '{' {
		t.Fatal("returned alias to stored reply")
	}
	c.ack("gateway", id)
	if c.get("security", id, now) == nil {
		t.Fatal("different panel acknowledgement consumed reply")
	}
	c.ack("security", id)
	if c.get("security", id, now) != nil {
		t.Fatal("matching acknowledgement did not consume reply")
	}
	c.put("security", id, "security-refresh", struct{}{}, now)
	if c.get("security", id, now.Add(2*time.Minute+time.Second)) != nil {
		t.Fatal("expired reply retained")
	}
}
func TestDesktopUIResultOversizeHasCorrelatedError(t *testing.T) {
	var c desktopUIResultCache
	now := time.Now()
	id := strings.Repeat("a", 32)
	c.put("security", id, "security-refresh", strings.Repeat("x", desktopUIResultLimit+1), now)
	var r map[string]any
	json.Unmarshal(c.get("security", id, now), &r)
	if r["event"] != "security" || r["request_id"] != id || r["problem"] != "UI_RESULT_TOO_LARGE" {
		t.Fatal(r)
	}
	for i := 0; i < 40; i++ {
		c.put("gateway", strings.Repeat("x", i+1), "gateway-refresh", struct{}{}, now.Add(time.Duration(i)*time.Second))
	}
	if len(c.rows) > 32 {
		t.Fatal("reply cache unbounded")
	}
}
func TestSecurityUIMessageFitsLocalPipeWithBusyHost(t *testing.T) {
	connections := make([]appfirewall.Connection, 1024)
	for i := range connections {
		connections[i].Path = "C:\\" + strings.Repeat("程序", 400) + ".exe"
	}
	rules := []appfirewall.Rule{{ID: strings.Repeat("a", 32), Application: appfirewall.Identity{Path: "C:\\Example.exe"}}}
	devices := make([]securitypolicy.DeviceRecord, 256)
	m := securityUIMessage("security-refresh", strings.Repeat("a", 32), rules, connections, devices, "", "")
	b, _ := json.Marshal(m)
	if len(b) > desktopUIResultLimit || m["truncated"] != true || m["connections_total"] != 1024 || m["usb_devices_total"] != 256 || len(m["rules"].([]appfirewall.Rule)) != 1 {
		t.Fatal("busy host must fit while retaining complete rules and reporting observed totals")
	}
	if len(m["connections"].([]appfirewall.Connection)) >= 200 {
		t.Fatal("serialized byte budget was ignored")
	}
	// The displayed limit must not mutate the authoritative observations.
	if len(connections) != 1024 || len(devices) != 256 {
		t.Fatal("observer state altered")
	}
}
