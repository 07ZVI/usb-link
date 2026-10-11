package bench

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"suhang/usbnet/internal/diagnostics/rawusb"
	"testing"
)

func TestRawCapturesOnlyRegisteredRunnerAndFixedBounds(t *testing.T) {
	nonce := "0123456789abcdef0123456789abcdef"
	for _, q := range []struct {
		k string
		n int
	}{{"RAWIN", 0}, {"RAWOUT", 16}, {"RAWCLOSEDCPU", 1}, {"RAWOUTTRACE", 6}, {"RAWINTRACE", 0}, {"RAWUDPEXEC", 10}} {
		if ValidatePerformance(q.k, q.n, nonce) == nil {
			t.Fatal(q)
		}
	}
	for _, kind := range []string{"RAWOUT", "RAWIN", "RAWCLOSED", "RAWINCPU", "RAWOUTCPU"} {
		if e := ValidatePerformance(kind, 5, nonce); e != nil {
			t.Fatal(e)
		}
	}
	SetRawRunner(nil)
	var b bytes.Buffer
	if e := handlePerformance(context.Background(), &b, []string{PerfProtocol, "RAWIN", "5", nonce}); e == nil || b.Len() != 0 {
		t.Fatal("unregistered raw capture accepted")
	}
	SetRawRunner(func(ctx context.Context, kind string, seconds int, n string, ready func(int) error) (rawusb.Result, error) {
		if seconds != 5 || n != nonce {
			t.Fatal("forwarded incorrect request")
		}
		if e := ready(8000); e != nil {
			return rawusb.Result{}, e
		}
		return rawusb.Result{Kind: kind, Nonce: n, IPLength: 8000, Seconds: 5}, nil
	})
	defer SetRawRunner(nil)
	if e := handlePerformance(context.Background(), &b, []string{PerfProtocol, "RAWIN", "5", nonce}); e != nil {
		t.Fatal(e)
	}
	var got rawusb.Capture
	data := b.Bytes()
	prefix := fmt.Sprintf("READY %s 8000\n", nonce)
	if !bytes.HasPrefix(data, []byte(prefix)) {
		t.Fatal("no readiness")
	}
	data = data[len(prefix):]
	i := bytes.IndexByte(data, '\n')
	if i < 0 {
		t.Fatal("no DONE")
	}
	if e := json.Unmarshal(data[i+1:], &got); e != nil || got.Raw.Nonce != nonce || got.Raw.Seconds != 5 || len(got.Profile) != 0 {
		t.Fatal(e, got.Raw)
	}
}
