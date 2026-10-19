package ipadncm

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"time"

	"suhang/usbnet/internal/contracts/coreipc"
)

// The login UI talks to the core over a local pipe. When that fails, the
// specific cause is kept here (UI side) and handed to the core with the next
// successful snapshot request, so exported diagnostics describe the outage
// even though the failure happened while the core could not be reached.

const uiIPCRecentLimit = 12
const uiIPCDetailLimit = 120

type UIIPCFailure struct {
	UTC       string `json:"utc"`
	LastUTC   string `json:"last_utc,omitempty"`
	Operation string `json:"operation"`
	Code      string `json:"code"`
	Win32     uint32 `json:"win32,omitempty"`
	Detail    string `json:"detail,omitempty"`
	Count     int    `json:"count"`
}

type UIIPCReport struct {
	Failures        uint64         `json:"failures"`
	Recoveries      uint64         `json:"recoveries"`
	LastOKUTC       string         `json:"last_ok_utc,omitempty"`
	OutageSinceUTC  string         `json:"outage_since_utc,omitempty"`
	LongestOutageMS int64          `json:"longest_outage_ms"`
	CoreRestarts    uint64         `json:"core_restart_attempts"`
	LastRestartUTC  string         `json:"last_restart_utc,omitempty"`
	LastRestart     string         `json:"last_restart_result,omitempty"`
	ForcedExits     uint64         `json:"forced_ui_exits"`
	Recent          []UIIPCFailure `json:"recent,omitempty"`
}

var coreLink struct {
	sync.Mutex
	report      UIIPCReport
	outageStart time.Time
	consecutive int
	revision    uint64
	delivered   uint64
}

func utcNow() string { return time.Now().UTC().Format(time.RFC3339Nano) }

func boundedASCII(s string, n int) string {
	var b strings.Builder
	for _, r := range s {
		if b.Len() >= n {
			break
		}
		if r >= 0x20 && r < 0x7f {
			b.WriteRune(r)
		} else {
			b.WriteByte('?')
		}
	}
	return b.String()
}

// CoreLinkErrorCode is the specific, display-safe cause of a failed core call.
func CoreLinkErrorCode(err error) (code string, win32 uint32, detail string) {
	if err == nil {
		return "CORE_DESKTOP_RESPONSE_INVALID", 0, ""
	}
	if c, w, d, transport := coreipc.ErrorDetail(err); transport {
		return c, w, d
	}
	switch {
	case errors.Is(err, context.DeadlineExceeded):
		return "CORE_UI_READ_TIMEOUT", 0, ""
	case errors.Is(err, context.Canceled):
		return "CORE_UI_READ_CANCELED", 0, ""
	}
	text := err.Error()
	if i := strings.IndexAny(text, ": "); i > 0 {
		text = text[:i]
	}
	if strings.HasPrefix(text, "CORE_") && coreipc.CodeShaped(text) {
		return text, 0, ""
	}
	return "CORE_UI_READ_FAILED", 0, ""
}

// RecordCoreLinkFailure notes one failed UI-to-core call and returns how long
// the core has now been unreachable and how many calls failed in a row.
func RecordCoreLinkFailure(operation string, err error) (time.Duration, int) {
	code, win32, detail := CoreLinkErrorCode(err)
	now := time.Now()
	coreLink.Lock()
	defer coreLink.Unlock()
	if coreLink.consecutive == 0 {
		coreLink.outageStart = now
		coreLink.report.OutageSinceUTC = now.UTC().Format(time.RFC3339Nano)
	}
	coreLink.consecutive++
	r := &coreLink.report
	r.Failures++
	coreLink.revision++
	if n := len(r.Recent); n > 0 {
		last := &r.Recent[n-1]
		if last.Operation == operation && last.Code == code && last.Win32 == win32 {
			last.Count++
			last.LastUTC = now.UTC().Format(time.RFC3339Nano)
			return now.Sub(coreLink.outageStart), coreLink.consecutive
		}
	}
	if len(r.Recent) == uiIPCRecentLimit {
		copy(r.Recent, r.Recent[1:])
		r.Recent = r.Recent[:uiIPCRecentLimit-1]
	}
	r.Recent = append(r.Recent, UIIPCFailure{UTC: now.UTC().Format(time.RFC3339Nano), Operation: operation, Code: code, Win32: win32, Detail: boundedASCII(detail, uiIPCDetailLimit), Count: 1})
	return now.Sub(coreLink.outageStart), coreLink.consecutive
}

func RecordCoreLinkSuccess() {
	now := time.Now()
	coreLink.Lock()
	defer coreLink.Unlock()
	r := &coreLink.report
	if coreLink.consecutive > 0 {
		if d := now.Sub(coreLink.outageStart).Milliseconds(); d > r.LongestOutageMS {
			r.LongestOutageMS = d
		}
		r.Recoveries++
		r.OutageSinceUTC = ""
		coreLink.consecutive = 0
		coreLink.revision++
	}
	r.LastOKUTC = now.UTC().Format(time.RFC3339Nano)
}

// CoreLinkOutage reports the current continuous outage (zero when healthy).
func CoreLinkOutage() (time.Duration, int) {
	coreLink.Lock()
	defer coreLink.Unlock()
	if coreLink.consecutive == 0 {
		return 0, 0
	}
	return time.Since(coreLink.outageStart), coreLink.consecutive
}

func RecordCoreRestartAttempt(result string) {
	coreLink.Lock()
	defer coreLink.Unlock()
	r := &coreLink.report
	r.CoreRestarts++
	r.LastRestartUTC = utcNow()
	r.LastRestart = boundedASCII(result, uiIPCDetailLimit)
	coreLink.revision++
}

func RecordForcedUIExit() {
	coreLink.Lock()
	defer coreLink.Unlock()
	coreLink.report.ForcedExits++
	coreLink.revision++
}

// TakeCoreLinkReport returns the report to attach to the next snapshot request
// when anything changed since the last delivery. confirm marks it delivered.
func TakeCoreLinkReport() (report *UIIPCReport, confirm func()) {
	coreLink.Lock()
	defer coreLink.Unlock()
	if coreLink.report.Failures == 0 || coreLink.revision == coreLink.delivered {
		return nil, func() {}
	}
	out := coreLink.report
	out.Recent = append([]UIIPCFailure(nil), coreLink.report.Recent...)
	revision := coreLink.revision
	return &out, func() {
		coreLink.Lock()
		if coreLink.delivered < revision {
			coreLink.delivered = revision
		}
		coreLink.Unlock()
	}
}

// The core stores only the latest sanitized report. It is diagnostics; it
// never selects an action, a device or an authority.
var uiReported struct {
	sync.Mutex
	report   *UIIPCReport
	received string
}

func SanitizeUIIPCReport(in UIIPCReport) UIIPCReport {
	out := in
	for _, p := range []*string{&out.LastOKUTC, &out.OutageSinceUTC, &out.LastRestartUTC} {
		if _, err := time.Parse(time.RFC3339Nano, *p); err != nil {
			*p = ""
		}
	}
	out.LastRestart = boundedASCII(out.LastRestart, uiIPCDetailLimit)
	if len(out.Recent) > uiIPCRecentLimit {
		out.Recent = out.Recent[len(out.Recent)-uiIPCRecentLimit:]
	}
	out.Recent = append([]UIIPCFailure(nil), out.Recent...)
	for i := range out.Recent {
		f := &out.Recent[i]
		if !coreipc.CodeShaped(f.Code) {
			f.Code = "INVALID_CODE"
		}
		switch f.Operation {
		case "read", "register", "action", "restart":
		default:
			f.Operation = "unknown"
		}
		f.Detail = boundedASCII(f.Detail, uiIPCDetailLimit)
		for _, p := range []*string{&f.UTC, &f.LastUTC} {
			if _, err := time.Parse(time.RFC3339Nano, *p); err != nil {
				*p = ""
			}
		}
		if f.Count < 1 {
			f.Count = 1
		}
	}
	return out
}

func NoteUIIPCReport(in UIIPCReport) {
	clean := SanitizeUIIPCReport(in)
	uiReported.Lock()
	uiReported.report = &clean
	uiReported.received = utcNow()
	uiReported.Unlock()
}

// Evidence rows are limited to 8 KiB by the log writer; a row over the limit
// would be dropped whole, so detail shrinks before the row can be lost.
const coreIPCEvidenceLimit = 6500

type coreIPCEvidence struct {
	Server      coreipc.ServerReport `json:"core_pipe"`
	UIReported  *UIIPCReport         `json:"ui_reported,omitempty"`
	UIReceived  string               `json:"ui_report_received_utc,omitempty"`
	SnapshotCap int                  `json:"snapshot_budget_bytes"`
}

func shrinkCoreIPCEvidence(e coreIPCEvidence) coreIPCEvidence {
	size := func() int { b, _ := json.Marshal(e); return len(b) }
	for _, step := range []func(){
		func() {
			for i := range e.Server.Recent {
				e.Server.Recent[i].Detail = boundedASCII(e.Server.Recent[i].Detail, 160)
			}
		},
		func() {
			if n := len(e.Server.Recent); n > 6 {
				e.Server.Recent = e.Server.Recent[n-6:]
			}
			if e.UIReported != nil {
				if n := len(e.UIReported.Recent); n > 6 {
					e.UIReported.Recent = e.UIReported.Recent[n-6:]
				}
			}
		},
		func() {
			for i := range e.Server.Recent {
				e.Server.Recent[i].Detail = ""
			}
			e.Server.ByCode = nil
		},
	} {
		if size() <= coreIPCEvidenceLimit {
			break
		}
		step()
	}
	return e
}

// CoreIPCDiagnostics joins both sides of the pipe: failures the core saw while
// serving, and failures the UI saw while calling, delivered after recovery.
func CoreIPCDiagnostics() any {
	uiReported.Lock()
	var report *UIIPCReport
	if uiReported.report != nil {
		copied := *uiReported.report
		copied.Recent = append([]UIIPCFailure(nil), uiReported.report.Recent...)
		report = &copied
	}
	received := uiReported.received
	uiReported.Unlock()
	return shrinkCoreIPCEvidence(coreIPCEvidence{coreipc.ServerReportSnapshot(), report, received, coreipc.MaxMessage - 256})
}
