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
}
