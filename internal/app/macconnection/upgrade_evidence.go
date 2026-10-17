package macconnection

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"suhang/usbnet/internal/diagnostics/logfile"
	"time"
)

type connectionEvidenceLogState struct {
	body    string
	written time.Time
}

// Keep this row independent of the larger bridge evidence and retry failures.
// Refresh at most every 30 seconds so tail readers can recover after an upgrade
// disconnect. The caller uses its existing five-second loop, with no device IO.
func appendChangedConnectionEvidence(dir string, evidence any, previous *connectionEvidenceLogState, now time.Time) error {
	body, err := json.Marshal(evidence)
	if err != nil || string(body) == previous.body && now.Sub(previous.written) < 30*time.Second {
		return err
	}
	if err = appendUpgradeEvidence(dir, body); err != nil {
		return err
	}
	*previous = connectionEvidenceLogState{body: string(body), written: now}
	return nil
}

func appendUpgradeEvidence(dir string, body []byte) error {
	if len(body) > 8192 {
		return fmt.Errorf("upgrade evidence exceeds bound")
	}
	path := filepath.Join(dir, "service.log")
	if st, e := os.Lstat(path); e == nil {
		if !st.Mode().IsRegular() {
			return fmt.Errorf("upgrade evidence path redirected")
		}
	} else if !os.IsNotExist(e) {
		return e
	}
	f, e := logfile.Open(path, 128*1024)
	if e != nil {
		return e
	}
	defer f.Close()
	if _, e = fmt.Fprintf(f, "\nUSB_LINK_UPGRADE_EVIDENCE %s\n", body); e != nil {
		return e
	}
	return f.Sync()
}
