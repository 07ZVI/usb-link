package coreipc

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestCallErrorKeepsStageAndNativeNumber(t *testing.T) {
	for name, tc := range map[string]struct {
		stage string
		err   error
		code  string
		win32 uint32
	}{
		"absent":     {"connect", syscall.Errno(2), "CORE_IPC_PIPE_ABSENT", 2},
		"denied":     {"connect", syscall.Errno(5), "CORE_IPC_PIPE_ACCESS_DENIED_WIN32_5", 5},
		"broken":     {"read", syscall.Errno(109), "CORE_IPC_READ_FAILED_WIN32_109", 109},
		"busy":       {"busy", context.DeadlineExceeded, "CORE_IPC_BUSY_TIMEOUT", 0},
		"silent":     {"read", fmt.Errorf("wrapped: %w", context.DeadlineExceeded), "CORE_IPC_READ_TIMEOUT", 0},
		"frame":      {"read", fmt.Errorf("CORE_IPC_FRAME_INVALID"), "CORE_IPC_FRAME_INVALID", 0},
		"rejected":   {"verify", fmt.Errorf("CORE_SERVICE_PID_CHANGED"), "CORE_IPC_SERVER_REJECTED", 0},
		"ack":        {"ack", syscall.Errno(232), "CORE_IPC_ACK_FAILED_WIN32_232", 232},
		"cancelled":  {"write", context.Canceled, "CORE_IPC_WRITE_CANCELED", 0},
		"unexpected": {"write", errors.New("free text with a private path"), "CORE_IPC_WRITE_FAILED", 0},
	} {
		t.Run(name, func(t *testing.T) {
			err := wrapCall(tc.stage, tc.err)
			code, win32, detail, transport := ErrorDetail(err)
			if !transport || code != tc.code || win32 != tc.win32 || !CodeShaped(code) {
				t.Fatalf("%q %d %q %v", code, win32, detail, transport)
			}
			if !errors.Is(err, tc.err) {
				t.Fatal("cause not preserved")
			}
		})
	}
	if _, _, detail, _ := ErrorDetail(wrapCall("verify", fmt.Errorf("CORE_SERVICE_PID_CHANGED"))); detail != "CORE_SERVICE_PID_CHANGED" {
		t.Fatal(detail)
	}
	if _, _, _, transport := ErrorDetail(errors.New("CORE_INITIALIZING")); transport {
		t.Fatal("a reply from the core is not a transport failure")
	}
}

func TestServerFailureLogIsBoundedAndCoalesced(t *testing.T) {
	server.Lock()
	server.report = ServerReport{}
	server.Unlock()
	for i := 0; i < 5; i++ {
		recordServerFailure(ServerFailure{Stage: "read_request", Code: "CORE_IPC_SERVER_READ_REQUEST_FAILED", Win32: 109, ElapsedMS: 15000})
	}
	if r := ServerReportSnapshot(); len(r.Recent) != 1 || r.Recent[0].Count != 5 {
		t.Fatalf("%+v", r.Recent)
	}
	for i := 0; i < 100; i++ {
		recordServerFailure(ServerFailure{Stage: "handler_error", Code: fmt.Sprintf("CORE_TEST_%d", i), Method: "snapshot", Detail: strings.Repeat("x", 5000)})
	}
	recordServerFailure(ServerFailure{Stage: "handler_panic", Code: "not a code"})
	recordServed(3 * time.Second)
	r := ServerReportSnapshot()
	if r.Failed != 106 || r.HandlerPanics != 1 || r.Served != 1 || r.MaxHandlerMS != 3000 {
		t.Fatalf("%+v", r)
	}
	if len(r.Recent) != serverFailureLimit || len(r.ByCode) > serverCodeLimit {
		t.Fatal(len(r.Recent), len(r.ByCode))
	}
	for _, f := range r.Recent {
		if len(f.Detail) > 600 || !CodeShaped(f.Code) {
			t.Fatal(f)
		}
	}
	if r.Recent[len(r.Recent)-1].Code != "CORE_IPC_UNCLASSIFIED" {
		t.Fatal(r.Recent[len(r.Recent)-1])
	}
}
