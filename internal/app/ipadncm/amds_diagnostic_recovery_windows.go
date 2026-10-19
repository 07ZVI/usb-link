//go:build windows && amd64

package ipadncm

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"
)

// The AMDS mode diagnostic itself no longer exists. A release that ran it may
// have been interrupted with the Apple Mobile Device Service in a temporary
// state and a protected receipt on disk; this recovery core replays that
// receipt, and the service helpers are shared with the AMDS hold.
var amdsDiagnosticMu sync.Mutex

func diagnosticServiceState(ctx context.Context, s *mgr.Service, wanted svc.State) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}
	status, e := s.Query()
	if e != nil {
		return e
	}
	if status.State == wanted {
		return nil
	}
	if wanted == svc.Running {
		e = s.Start()
	} else {
		_, e = s.Control(svc.Stop)
	}
	if e != nil {
		return e
	}
	ticker := time.NewTicker(50 * time.Millisecond)
	defer ticker.Stop()
	for {
		status, e = s.Query()
		if e != nil {
			return e
		}
		if status.State == wanted {
			return nil
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("service wait: %w", ctx.Err())
		case <-ticker.C:
		}
	}
}

type amdsDiagnosticJournal struct {
	Version   int    `json:"version"`
	State     uint32 `json:"original_state"`
	StartType uint32 `json:"original_start_type"`
}

// The protected receipt is also replayed at the next launch after a crash.
// Startup type is read back, never overwritten.
func RecoverAMDSModeDiagnostic(dir string) error {
	path := filepath.Join(dir, "amds-diagnostic.json")
	p, e := readAMDSDiagnosticReceipt(path)
	if os.IsNotExist(e) {
		return nil
	}
	if e != nil || len(p) > 1024 {
		return fmt.Errorf("AMDS receipt unavailable")
	}
	var j amdsDiagnosticJournal
	dec := json.NewDecoder(strings.NewReader(string(p)))
	dec.DisallowUnknownFields()
	if dec.Decode(&j) != nil || j.Version != 1 || (j.State != uint32(svc.Running) && j.State != uint32(svc.Stopped)) || j.StartType > 4 {
		return fmt.Errorf("AMDS receipt invalid")
	}
	var trailing any
	if dec.Decode(&trailing) != io.EOF {
		return fmt.Errorf("AMDS receipt trailing data")
	}
	m, e := mgr.Connect()
	if e != nil {
		return e
	}
	defer m.Disconnect()
	s, e := m.OpenService("Apple Mobile Device Service")
	if e != nil {
		return e
	}
	defer s.Close()
	cfg, e := s.Config()
	if e != nil || cfg.StartType != j.StartType {
		return fmt.Errorf("AMDS startup configuration changed")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if e := diagnosticServiceState(ctx, s, svc.State(j.State)); e != nil {
		return e
	}
	status, e := s.Query()
	if e != nil || uint32(status.State) != j.State {
		return fmt.Errorf("AMDS restoration not verified")
	}
	return os.Remove(path)
}

func readAMDSDiagnosticReceipt(path string) ([]byte, error) {
	p, e := windows.UTF16PtrFromString(path)
	if e != nil {
		return nil, e
	}
	h, e := windows.CreateFile(p, windows.GENERIC_READ, windows.FILE_SHARE_READ, nil, windows.OPEN_EXISTING, windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if e != nil {
		return nil, e
	}
	var info windows.ByHandleFileInformation
	if e := windows.GetFileInformationByHandle(h, &info); e != nil || info.FileAttributes&(windows.FILE_ATTRIBUTE_REPARSE_POINT|windows.FILE_ATTRIBUTE_DIRECTORY) != 0 {
		windows.CloseHandle(h)
		return nil, fmt.Errorf("unsafe AMDS receipt")
	}
	f := os.NewFile(uintptr(h), path)
	if f == nil {
		windows.CloseHandle(h)
		return nil, fmt.Errorf("AMDS receipt handle unavailable")
	}
	defer f.Close()
	return io.ReadAll(io.LimitReader(f, 1025))
}
