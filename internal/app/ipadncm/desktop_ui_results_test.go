package ipadncm

import (
	"bytes"
	"context"
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

func TestDesktopSlowReadDoesNotBlockOtherReplies(t *testing.T) {
	var c desktopUIResultCache
	release, finished := make(chan struct{}), make(chan struct{})
	defer close(release)
	id := strings.Repeat("a", 32)
	if _, accepted := c.startRead(context.Background(), "share-folders", id, "share-folders-refresh", func() any {
		close(finished)
		<-release
		return map[string]any{"event": "share-folders", "request_id": id}
	}); !accepted {
		t.Fatal("first read rejected")
	}
	select {
	case <-finished:
	case <-time.After(time.Second):
		t.Fatal("read did not start")
	}
	// A duplicate request must not create another worker, while a different ID
	// gets a bounded busy result rather than an unbounded queue of filesystem I/O.
	unexpected := func() any { panic("duplicate worker") }
	if _, accepted := c.startRead(context.Background(), "share-folders", id, "share-folders-refresh", unexpected); !accepted {
		t.Fatal("same request not coalesced")
	}
	if _, accepted := c.startRead(context.Background(), "share-folders", strings.Repeat("b", 32), "share-folders-refresh", unexpected); accepted {
		t.Fatal("concurrent read accepted")
	}
	c.put("gateway", id, "gateway-refresh", map[string]any{"event": "gateway"}, time.Now())
	if c.get("gateway", id, time.Now()) == nil {
		t.Fatal("unrelated reply blocked by filesystem read")
	}
	if c.get("share-folders", id, time.Now()) != nil {
		t.Fatal("unfinished read published")
	}
}

func TestDesktopAsyncReadCompletionAndCancellation(t *testing.T) {
	for _, cancelled := range []bool{false, true} {
		var c desktopUIResultCache
		ctx, cancel := context.WithCancel(context.Background())
		release := make(chan struct{})
		id := strings.Repeat("c", 32)
		done, accepted := c.startRead(ctx, "share-folders", id, "share-folders-refresh", func() any {
			<-release
			return map[string]any{"event": "share-folders", "request_id": id, "folders": []any{}}
		})
		if !accepted {
			t.Fatal("read rejected")
		}
		if cancelled {
			cancel()
		}
		close(release)
		select {
		case <-done:
		case <-time.After(time.Second):
			t.Fatal("read did not finish")
		}
		cancel()
		result := c.get("share-folders", id, time.Now())
		if (result == nil) != cancelled {
			t.Fatalf("cancelled=%v reply=%s", cancelled, result)
		}
		if !cancelled {
			c.ack("share-folders", id)
			if c.get("share-folders", id, time.Now()) != nil {
				t.Fatal("ack did not consume async reply")
			}
		}
		if _, accepted := c.startRead(ctx, "share-folders", id, "share-folders-refresh", func() any { panic("cancelled read") }); accepted {
			t.Fatal("cancelled owner started read")
		}
	}
}
