package ipadncm

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"testing"
	"time"

	"howett.net/plist"
)

func testMuxServer(t *testing.T, handler func(net.Listener) error) string {
	t.Helper()
	l, e := net.Listen("tcp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	done := make(chan error, 1)
	go func() { done <- handler(l) }()
	t.Cleanup(func() {
		l.Close()
		select {
		case e := <-done:
			if e != nil {
				t.Error(e)
			}
		case <-time.After(time.Second):
			t.Error("test server did not close")
		}
	})
	return l.Addr().String()
}
func acceptTest(l net.Listener) (net.Conn, error) {
	c, e := l.Accept()
	if e == nil {
		c.SetDeadline(time.Now().Add(10 * time.Second))
	}
	return c, e
}
func expectRequest(c net.Conn, name string) (map[string]any, error) {
	m, e := receiveMux(c, false)
	if e == nil && m["MessageType"] != name {
		e = fmt.Errorf("unexpected request: %v", m["MessageType"])
	}
	return m, e
}
func testIdentityExchange(l net.Listener) error {
	c, e := acceptTest(l)
	if e != nil {
		return e
	}
	defer c.Close()
	m, e := expectRequest(c, "Connect")
	if e != nil {
		return e
	}
	if m["DeviceID"] != uint64(7) || m["PortNumber"] != uint64(0x7ef2) {
		return fmt.Errorf("wrong Connect target")
	}
	if e = sendMux(c, map[string]any{"MessageType": "Result", "Number": uint64(0)}); e != nil {
		return e
	}
	for i, key := range []string{"ProductType", "ProductVersion"} {
		h := make([]byte, 4)
		if _, e = io.ReadFull(c, h); e != nil {
			return e
		}
		n := binary.BigEndian.Uint32(h)
		if n > 4096 {
			return fmt.Errorf("oversized metadata request")
		}
		b := make([]byte, n)
		if _, e = io.ReadFull(c, b); e != nil {
			return e
		}
		var request map[string]any
		if _, e = plist.Unmarshal(b, &request); e != nil {
			return e
		}
		if request["Request"] != "GetValue" || request["Key"] != key {
			return fmt.Errorf("unexpected device request")
		}
		b, e = plist.Marshal(map[string]any{"Value": []string{"iPad13,16", "27.0.1"}[i]}, plist.XMLFormat)
		if e != nil {
			return e
		}
		binary.BigEndian.PutUint32(h, uint32(len(b)))
		if e = writeAll(c, h); e != nil {
			return e
		}
		if e = writeAll(c, b); e != nil {
			return e
		}
	}
	return nil
}
func TestMuxListUsesDeviceIDInProperties(t *testing.T) {
	address := testMuxServer(t, func(l net.Listener) error {
		c, e := acceptTest(l)
		if e != nil {
			return e
		}
		_, e = expectRequest(c, "ListDevices")
		if e != nil {
			c.Close()
			return e
		}
		e = sendMux(c, map[string]any{"DeviceList": []any{map[string]any{"Properties": map[string]any{"DeviceID": uint64(7), "ConnectionType": "USB"}}}})
		c.Close()
		if e != nil {
			return e
		}
		return testIdentityExchange(l)
	})
	var d MuxDiagnostic
	model, version, code := queryModel(context.Background(), address, &d)
	if model != "iPad13,16" || version != "27.0.1" || code != "" || !d.ListArrayPresent || d.USBEntries != 1 || d.ListenAttempted {
		t.Fatalf("%s %s %s %+v", model, version, code, d)
	}
}
func TestMuxUnsupportedListFallsBackToReadOnlyListen(t *testing.T) {
	address := testMuxServer(t, func(l net.Listener) error {
		c, e := acceptTest(l)
		if e != nil {
			return e
		}
		_, e = expectRequest(c, "ListDevices")
		if e != nil {
			c.Close()
			return e
		}
		e = sendMux(c, map[string]any{"MessageType": "Result", "Number": uint64(1)})
		c.Close()
		if e != nil {
			return e
		}
		c, e = acceptTest(l)
		if e != nil {
			return e
		}
		defer c.Close()
		_, e = expectRequest(c, "Listen")
		if e != nil {
			return e
		}
		if e = sendMux(c, map[string]any{"MessageType": "Result", "Number": uint64(0)}); e != nil {
			return e
		}
		for _, m := range []map[string]any{
			{"MessageType": "Attached", "Properties": map[string]any{"DeviceID": uint64(8), "ConnectionType": "USB"}},
			{"MessageType": "Detached", "DeviceID": uint64(8)},
			{"MessageType": "Attached", "Properties": map[string]any{"DeviceID": uint64(7), "ConnectionType": "USB"}},
		} {
			if e = sendMux(c, m); e != nil {
				return e
			}
		}
		return testIdentityExchange(l)
	})
	var d MuxDiagnostic
	model, _, code := queryModel(context.Background(), address, &d)
	if model != "iPad13,16" || code != "" || !d.ListenAccepted || d.USBEntries != 1 || d.ListResult == nil || *d.ListResult != 1 {
		t.Fatalf("%s %s %+v", model, code, d)
	}
}
func TestMuxRefusesAmbiguousOrNetworkOnlyDevices(t *testing.T) {
	for _, types := range [][]string{{"USB", "USB"}, {"Network"}, {"USB", "Unknown"}} {
		t.Run(fmt.Sprint(types), func(t *testing.T) {
			address := testMuxServer(t, func(l net.Listener) error {
				c, e := acceptTest(l)
				if e != nil {
					return e
				}
				defer c.Close()
				_, e = expectRequest(c, "ListDevices")
				if e != nil {
					return e
				}
				var devices []any
				for i, kind := range types {
					devices = append(devices, map[string]any{"Properties": map[string]any{"DeviceID": uint64(i + 1), "ConnectionType": kind}})
				}
				return sendMux(c, map[string]any{"DeviceList": devices})
			})
			var d MuxDiagnostic
			model, _, code := queryModel(context.Background(), address, &d)
			if model != "" || code != "NEED_ONE_USB_APPLE_COMMUNICATION_DEVICE" {
				t.Fatalf("%s %s", model, code)
			}
		})
	}
}
func TestMuxRejectsOversizedAndPartialFrames(t *testing.T) {
	for _, partial := range []bool{false, true} {
		a, b := net.Pipe()
		done := make(chan struct{})
		go func() {
			defer close(done)
			defer b.Close()
			h := make([]byte, 16)
			binary.LittleEndian.PutUint32(h, 700000)
			if partial {
				h = h[:8]
			}
			writeAll(b, h)
		}()
		if _, e := receiveMux(a, false); e == nil {
			t.Error("accepted invalid frame")
		}
		a.Close()
		<-done
	}
}

func TestEmptyListWaitsForDelayedUSBDiscovery(t *testing.T) {
	address := testMuxServer(t, func(l net.Listener) error {
		c, e := acceptTest(l)
		if e != nil {
			return e
		}
		if _, e = expectRequest(c, "ListDevices"); e != nil {
			c.Close()
			return e
		}
		e = sendMux(c, map[string]any{"DeviceList": []any{}})
		c.Close()
		if e != nil {
			return e
		}
		c, e = acceptTest(l)
		if e != nil {
			return e
		}
		defer c.Close()
		if _, e = expectRequest(c, "Listen"); e != nil {
			return e
		}
		if e = sendMux(c, map[string]any{"MessageType": "Result", "Number": uint64(0)}); e != nil {
			return e
		}
		time.Sleep(30 * time.Millisecond)
		if e = sendMux(c, map[string]any{"MessageType": "Attached", "Properties": map[string]any{"DeviceID": uint64(7), "ConnectionType": "USB"}}); e != nil {
			return e
		}
		return testIdentityExchange(l)
	})
	var d MuxDiagnostic
	model, _, code := queryModelWithEmptyWait(context.Background(), address, &d, 150*time.Millisecond)
	if model != "iPad13,16" || code != "" || !d.EmptyListWait || !d.ListenAccepted || d.ListenWindowMS != 150 || d.USBEntries != 1 || d.TrustState != "UNKNOWN_NOT_AUTHENTICATED" {
		t.Fatal(model, code, d)
	}
}
func TestEmptyListenIsNotATrustFailure(t *testing.T) {
	address := testMuxServer(t, func(l net.Listener) error {
		c, e := acceptTest(l)
		if e != nil {
			return e
		}
		if _, e = expectRequest(c, "ListDevices"); e != nil {
			c.Close()
			return e
		}
		e = sendMux(c, map[string]any{"DeviceList": []any{}})
		c.Close()
		if e != nil {
			return e
		}
		c, e = acceptTest(l)
		if e != nil {
			return e
		}
		defer c.Close()
		if _, e = expectRequest(c, "Listen"); e != nil {
			return e
		}
		if e = sendMux(c, map[string]any{"MessageType": "Result", "Number": uint64(0)}); e != nil {
			return e
		}
		var b [1]byte
		_, e = c.Read(b[:])
		if e == io.EOF {
			return nil
		}
		return e
	})
	var d MuxDiagnostic
	model, _, code := queryModelWithEmptyWait(context.Background(), address, &d, 50*time.Millisecond)
	if model != "" || code != "APPLE_USB_DEVICE_NOT_READY" || d.TrustState != "UNKNOWN_NO_USB_COMMUNICATION_DEVICE" || !d.ListenAccepted {
		t.Fatal(model, code, d)
	}
}
func TestCancelClosesReadOnlyListen(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	address := testMuxServer(t, func(l net.Listener) error {
		c, e := acceptTest(l)
		if e != nil {
			return e
		}
		if _, e = expectRequest(c, "ListDevices"); e != nil {
			c.Close()
			return e
		}
		e = sendMux(c, map[string]any{"DeviceList": []any{}})
		c.Close()
		if e != nil {
			return e
		}
		c, e = acceptTest(l)
		if e != nil {
			return e
		}
		defer c.Close()
		if _, e = expectRequest(c, "Listen"); e != nil {
			return e
		}
		if e = sendMux(c, map[string]any{"MessageType": "Result", "Number": uint64(0)}); e != nil {
			return e
		}
		time.Sleep(30 * time.Millisecond)
		cancel()
		var b [1]byte
		_, e = c.Read(b[:])
		if e == io.EOF {
			return nil
		}
		return e
	})
	var d MuxDiagnostic
	started := time.Now()
	_, _, code := queryModel(ctx, address, &d)
	if code != "APPLE_USB_QUERY_CANCELLED_OR_TIMED_OUT" || time.Since(started) > time.Second {
		t.Fatal(code, time.Since(started))
	}
}
func TestMetadataTrustErrorClassificationDoesNotExportRawErrors(t *testing.T) {
	for _, tc := range []struct{ code, kind, state string }{
		{"PairingDialogResponsePending", "PAIRING_RESPONSE_PENDING", "DEVICE_REPORTS_PAIRING_PENDING"},
		{"PasswordProtected", "DEVICE_LOCKED", "DEVICE_REPORTS_LOCKED"},
		{"UserDeniedPairing", "PAIRING_DENIED", "DEVICE_REPORTS_PAIRING_DENIED"},
		{"secret arbitrary native response", "OTHER_DEVICE_ERROR", "UNKNOWN_NOT_AUTHENTICATED"},
	} {
		kind, state := classifyMetadataDeviceError(tc.code)
		if kind != tc.kind || state != tc.state {
			t.Fatal(kind, state)
		}
	}
}
