//go:build windows && amd64

package ipadncm

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

// Synthetic receipt only. A cancelled run must return before opening SCM.
func TestLocalTrustTrialCancelledBeforeSCMRequiresAbsentReceipt(t *testing.T) {
	for _, kind := range []string{"absent", "receipt", "invalid", "directory"} {
		t.Run(kind, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, "amds-diagnostic.json")
			switch kind {
			case "receipt":
				if err := os.WriteFile(path, []byte(`{"version":1,"original_state":4,"original_start_type":2}`), 0600); err != nil {
					t.Fatal(err)
				}
			case "invalid":
				if err := os.WriteFile(path, []byte(`broken`), 0600); err != nil {
					t.Fatal(err)
				}
			case "directory":
				if err := os.Mkdir(path, 0700); err != nil {
					t.Fatal(err)
				}
			}
			ctx, cancel := context.WithCancel(context.Background())
			cancel()
			r := runAMDSModeDiagnostic(ctx, "test", "stopped", dir, "")
			if r.Error != "DIAGNOSTIC_CANCELLED_BEFORE_CHANGE" || r.Before != 0 || r.During != 0 || r.After != 0 || r.Mode != nil || r.Restored {
				t.Fatalf("unexpected service activity: %+v", r)
			}
			if r.CancelledBeforeChange != (kind == "absent") || r.NoServiceChangeNoReceipt != (kind == "absent") {
				t.Fatalf("kind=%s result=%+v", kind, r)
			}
		})
	}
}
