package macconnection

import (
	"fmt"
	"os"
	"path/filepath"
	"suhang/usbnet/internal/diagnostics/logfile"
)

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
