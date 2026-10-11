package updater

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
)

type statusRoundTrip func(*http.Request) (*http.Response, error)

func (f statusRoundTrip) RoundTrip(q *http.Request) (*http.Response, error) { return f(q) }
func TestReadUSBStatusFallbackOnlyOnTransportFailure(t *testing.T) {
	calls := 0
	normal := &http.Client{Transport: statusRoundTrip(func(q *http.Request) (*http.Response, error) {
		calls++
		if q.Method != "GET" || q.URL.Path != "/v1/status" || q.Header.Get("Authorization") != "Bearer scoped" {
			t.Fatal("status request scope changed")
		}
		return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(`{"version":"normal"}`))}, nil
	})}
	primary := &http.Client{Transport: statusRoundTrip(func(*http.Request) (*http.Response, error) { return nil, errors.New("raw endpoint gone") })}
	b, e := readUSBStatus(context.Background(), primary, normal, "https://10.6.9.1:47775/v1/status", "scoped")
	if e != nil || !strings.Contains(string(b), "normal") || calls != 1 {
		t.Fatalf("fallback %q %v %d", b, e, calls)
	}
	primary.Transport = statusRoundTrip(func(*http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: 401, Body: io.NopCloser(strings.NewReader("refused"))}, nil
	})
	if _, e = readUSBStatus(context.Background(), primary, normal, "https://10.6.9.1:47775/v1/status", "scoped"); e == nil || calls != 1 {
		t.Fatal("HTTP rejection incorrectly retried")
	}
}
