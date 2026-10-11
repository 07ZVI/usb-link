package updater

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestLargeDiagnosticResponseIsComplete(t *testing.T) {
	in := `{"history":"` + strings.Repeat("a", 70000) + `","version":"0.8.108"}`
	b, err := readControlResponse(strings.NewReader(in))
	if err != nil || string(b) != in || !json.Valid(b) {
		t.Fatal("large bounded diagnostic was truncated", err)
	}
}

func TestOversizedDiagnosticRejectedWithoutPartialData(t *testing.T) {
	b, err := readControlResponse(strings.NewReader(strings.Repeat("a", controlResponseLimit+1)))
	if err == nil || b != nil {
		t.Fatal("oversized response accepted as partial evidence")
	}
}
