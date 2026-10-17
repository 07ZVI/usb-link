package ipadncm

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestDesktopDiagnosticProjectionKeepsCaptureModeAndSourceAccounting(t *testing.T) {
	b, err := json.Marshal(desktopExperimentControl(map[string]any{"capture_mode": "scalar_projection", "provider_coverage": "partial", "recent": []string{"PRIVATE_BODY"}}))
	if err != nil || !strings.Contains(string(b), `"capture_mode":"scalar_projection"`) || strings.Contains(string(b), "PRIVATE_BODY") {
		t.Fatal("projection scope lost or event data duplicated", string(b), err)
	}
	b, err = json.Marshal(desktopUSBTraceSummary(map[string]any{
		"callbacks_received": 6, "session_metadata_callbacks": 6, "session_header_callbacks": 6,
		"received": 0, "accepted": 0, "schema_rejected": 0,
		"received_semantics": "known_usb_provider_callbacks_not_requests", "rejected_headers": []string{"PRIVATE_HEADER_DETAIL"},
	}))
	if err != nil || !strings.Contains(string(b), `"session_metadata_callbacks":6`) || !strings.Contains(string(b), `"received":0`) || strings.Contains(string(b), "PRIVATE_HEADER_DETAIL") {
		t.Fatal("source categories lost or event samples duplicated", string(b), err)
	}
}
