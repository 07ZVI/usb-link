package macconnection

import (
	"encoding/json"
	"strings"
	"testing"
	"unicode/utf8"
)

func TestServiceEvidenceBoundsWithoutChangingManagerState(t *testing.T) {
	path := strings.Repeat("界\\", 1000)
	rows := []map[string]any{}
	for i := 0; i < 8; i++ {
		rows = append(rows, map[string]any{"path": path, "core": true})
	}
	input := map[string]any{"permitted_applications": rows, "pending_applications": rows, "recent_drops": rows, "pending_requests": 8}
	bounded := boundedGatewayEvidence(input)
	b, e := json.Marshal(map[string]any{"gateway": bounded, "parent": boundedServiceText(path), "bridge": boundedServiceText(path)})
	if e != nil || len(b) > 8192 {
		t.Fatalf("raw record exceeds bound: %d %v", len(b), e)
	}
	if !utf8.Valid(b) || !utf8.ValidString(boundedServiceText(strings.Repeat("界", 300))) {
		t.Fatal("invalid UTF8")
	}
	if input["permitted_applications"].([]map[string]any)[0]["path"] != path || len(rows) != 8 {
		t.Fatal("manager snapshot was mutated")
	}
	x := bounded.(map[string]any)
	if x["permitted_applications_log_truncated"] != true || len(x["permitted_applications"].([]map[string]any)) != 2 || x["pending_requests"] != 8 {
		t.Fatal("truncation/count missing")
	}
}
