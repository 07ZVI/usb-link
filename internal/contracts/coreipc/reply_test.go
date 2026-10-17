package coreipc

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

func TestCompletionRequiresSuccessfulWriteAndAcknowledgement(t *testing.T) {
	err := errors.New("transport failed")
	for _, tt := range []struct {
		name        string
		write, read error
		ack         byte
		want        int
	}{
		{"write failure", err, nil, 1, 0}, {"no acknowledgement", nil, err, 0, 0}, {"invalid acknowledgement", nil, nil, 2, 0}, {"zero acknowledgement", nil, nil, 0, 0}, {"acknowledged", nil, nil, 1, 1},
	} {
		t.Run(tt.name, func(t *testing.T) {
			called := 0
			completeReply(Response{AfterAcknowledged: func() { called++ }}, tt.write, tt.read, tt.ack)
			if called != tt.want {
				t.Fatalf("called %d", called)
			}
		})
	}
}
func TestCompletionCallbackNeverCrossesProtocol(t *testing.T) {
	r := Response{Version: 1, ID: "11111111111111111111111111111111", AfterAcknowledged: func() { t.Fatal("serialization invoked callback") }}
	b, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(b), "After") {
		t.Fatal("callback serialized")
	}
	if _, err := ParseResponse(b, r.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := ParseResponse([]byte(`{"version":1,"id":"11111111111111111111111111111111","AfterAcknowledged":true}`), r.ID); err == nil {
		t.Fatal("caller can inject callback")
	}
}
