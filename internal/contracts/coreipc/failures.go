package coreipc

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"syscall"
	"time"
)

// CallError keeps the transport stage and native error number of a failed
// local call. It carries no request or response content, only fixed codes.
type CallError struct {
	Stage  string
	Code   string
	Win32  uint32
	Detail string
	Err    error
}

func (e *CallError) Error() string {
	text := e.Code
	if e.Win32 != 0 {
		text += fmt.Sprintf(": win32=%d", e.Win32)
	}
	if e.Detail != "" {
		text += ": " + e.Detail
	}
	return text
}
func (e *CallError) Unwrap() error { return e.Err }

// IPCCode is the compact, display-safe cause code (upper case, digits, _).
func (e *CallError) IPCCode() string {
	if e.Win32 != 0 && e.Code != "CORE_IPC_PIPE_ABSENT" {
		return fmt.Sprintf("%s_WIN32_%d", e.Code, e.Win32)
	}
	return e.Code
}

// ErrorDetail separates a transport failure from a reply the core chose to
// send. Only the former is a transport error.
func ErrorDetail(err error) (code string, win32 uint32, detail string, transport bool) {
	var ce *CallError
	if errors.As(err, &ce) {
		return ce.IPCCode(), ce.Win32, ce.Detail, true
	}
	return "", 0, "", false
}

// CodeShaped reports whether s is a stable code rather than free text.
func CodeShaped(s string) bool {
	if len(s) < 3 || len(s) > 80 {
		return false
	}
	for _, c := range s {
		if !(c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_') {
			return false
		}
	}
	return true
}

// codeOf extracts a leading stable code from "CODE: free text" errors.
func codeOf(err error) string {
	if err == nil {
		return ""
	}
	s := err.Error()
	for i, c := range s {
		if c == ':' || c == ' ' {
			s = s[:i]
			break
		}
	}
	if CodeShaped(s) {
		return s
	}
	return ""
}

func errno(err error) uint32 {
	var n syscall.Errno
	if errors.As(err, &n) {
		return uint32(n)
	}
	return 0
}

const (
	errFileNotFound = 2
	errPathNotFound = 3
	errAccessDenied = 5
)

// wrapCall classifies a failed client step. Deadlines keep the stage so a
// busy pipe, a silent core and a stalled write remain distinguishable.
func wrapCall(stage string, err error) error {
	if err == nil {
		return nil
	}
	var existing *CallError
	if errors.As(err, &existing) {
		return err
	}
	upper := map[string]string{"connect": "CONNECT", "busy": "BUSY", "verify": "VERIFY", "write": "WRITE", "read": "READ", "ack": "ACK"}[stage]
	if upper == "" {
		upper = "CALL"
	}
	ce := &CallError{Stage: stage, Err: err}
	switch {
	case errors.Is(err, context.DeadlineExceeded):
		ce.Code = "CORE_IPC_" + upper + "_TIMEOUT"
	case errors.Is(err, context.Canceled):
		ce.Code = "CORE_IPC_" + upper + "_CANCELED"
	default:
		ce.Win32 = errno(err)
		switch {
		case stage == "connect" && (ce.Win32 == errFileNotFound || ce.Win32 == errPathNotFound):
			ce.Code = "CORE_IPC_PIPE_ABSENT"
		case stage == "connect" && ce.Win32 == errAccessDenied:
			ce.Code = "CORE_IPC_PIPE_ACCESS_DENIED"
		case stage == "verify":
			ce.Code = "CORE_IPC_SERVER_REJECTED"
			ce.Detail = codeOf(err)
		case codeOf(err) != "" && ce.Win32 == 0:
			ce.Code = codeOf(err)
		default:
			ce.Code = "CORE_IPC_" + upper + "_FAILED"
		}
	}
	return ce
}

// ServerFailure is one request the core pipe could not complete. Detail is a
// bounded code or panic summary; request payloads are never recorded.
type ServerFailure struct {
	UTC       string `json:"utc"`
	Stage     string `json:"stage"`
	Code      string `json:"code"`
	Win32     uint32 `json:"win32,omitempty"`
	Method    string `json:"method,omitempty"`
	PeerPID   uint32 `json:"peer_pid,omitempty"`
	ElapsedMS int64  `json:"elapsed_ms"`
	Detail    string `json:"detail,omitempty"`
	Count     int    `json:"count,omitempty"`
}

type ServerReport struct {
	Served           uint64            `json:"-"` // changes every poll; kept out of evidence rows
	Failed           uint64            `json:"failed"`
	HandlerPanics    uint64            `json:"handler_panics"`
	HandlerAbandoned uint64            `json:"handler_abandoned"`
	ListenerRetries  uint64            `json:"listener_retries"`
	MaxHandlerMS     int64             `json:"max_handler_ms"`
	ByCode           map[string]uint64 `json:"by_code,omitempty"`
	Recent           []ServerFailure   `json:"recent,omitempty"`
}

const serverFailureLimit = 16
const serverCodeLimit = 24

var server struct {
	sync.Mutex
	report ServerReport
}

func boundedText(s string, n int) string {
	if len(s) <= n {
		return s
	}
	cut := n
	for cut > 0 && s[cut]&0xC0 == 0x80 {
		cut--
	}
	return s[:cut]
}

func recordServed(elapsed time.Duration) {
	server.Lock()
	server.report.Served++
	if ms := elapsed.Milliseconds(); ms > server.report.MaxHandlerMS {
		server.report.MaxHandlerMS = ms
	}
	server.Unlock()
}

func recordServerFailure(f ServerFailure) {
	if !CodeShaped(f.Code) {
		f.Code = "CORE_IPC_UNCLASSIFIED"
	}
	f.Detail = boundedText(f.Detail, 600)
	f.UTC = time.Now().UTC().Format(time.RFC3339Nano)
	server.Lock()
	defer server.Unlock()
	r := &server.report
	r.Failed++
	switch f.Stage {
	case "handler_panic":
		r.HandlerPanics++
	case "handler_timeout":
		r.HandlerAbandoned++
	}
	if r.ByCode == nil {
		r.ByCode = map[string]uint64{}
	}
	if _, ok := r.ByCode[f.Code]; ok || len(r.ByCode) < serverCodeLimit {
		r.ByCode[f.Code]++
	}
	if n := len(r.Recent); n > 0 {
		last := &r.Recent[n-1]
		if last.Stage == f.Stage && last.Code == f.Code && last.Win32 == f.Win32 && last.Method == f.Method {
			if last.Count == 0 {
				last.Count = 1
			}
			last.Count++
			last.UTC = f.UTC
			return
		}
	}
	if len(r.Recent) == serverFailureLimit {
		copy(r.Recent, r.Recent[1:])
		r.Recent = r.Recent[:serverFailureLimit-1]
	}
	r.Recent = append(r.Recent, f)
}

func recordListenerRetry() {
	server.Lock()
	server.report.ListenerRetries++
	server.Unlock()
}

// ServerReportSnapshot is a copy that is safe to encode into diagnostics.
func ServerReportSnapshot() ServerReport {
	server.Lock()
	defer server.Unlock()
	out := server.report
	out.Recent = append([]ServerFailure(nil), server.report.Recent...)
	out.ByCode = make(map[string]uint64, len(server.report.ByCode))
	for k, v := range server.report.ByCode {
		out.ByCode[k] = v
	}
	return out
}
