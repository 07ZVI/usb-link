package ipadncm

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"syscall"
	"testing"

	"suhang/usbnet/internal/contracts/coreipc"
)

func resetCoreLink() {
	coreLink.Lock()
	coreLink.report, coreLink.consecutive, coreLink.revision, coreLink.delivered = UIIPCReport{}, 0, 0, 0
	coreLink.Unlock()
}

func TestReadErrorCodeKeepsSpecificCauseWithoutRawText(t *testing.T) {
	for name, tc := range map[string]struct {
		err  error
		want string
	}{
		"core_answer":   {errors.New("CORE_EXIT_IN_PROGRESS"), "CORE_EXIT_IN_PROGRESS"},
		"snapshot":      {errors.New("CORE_SNAPSHOT_LIMIT"), "CORE_SNAPSHOT_LIMIT"},
		"handler_panic": {errors.New("CORE_HANDLER_PANIC"), "CORE_HANDLER_PANIC"},
		"timeout":       {fmt.Errorf("x: %w", context.DeadlineExceeded), "CORE_UI_READ_TIMEOUT"},
		"cancelled":     {context.Canceled, "CORE_UI_READ_CANCELED"},
		"absent":        {&coreipc.CallError{Stage: "connect", Code: "CORE_IPC_PIPE_ABSENT", Win32: 2}, "CORE_IPC_PIPE_ABSENT"},
		"broken":        {&coreipc.CallError{Stage: "read", Code: "CORE_IPC_READ_FAILED", Win32: uint32(syscall.Errno(109))}, "CORE_IPC_READ_FAILED_WIN32_109"},
		"free_text":     {errors.New("open C:\\Users\\name\\secret: denied"), "CORE_UI_READ_FAILED"},
		"not_core":      {errors.New("ACCESS_DENIED"), "CORE_UI_READ_FAILED"},
	} {
		t.Run(name, func(t *testing.T) {
			if got := desktopReadErrorCode(tc.err); got != tc.want {
				t.Fatal(got)
			}
		})
	}
}

func TestCoreLinkTracksOutageAndDeliversReportOnce(t *testing.T) {
	resetCoreLink()
	if r, _ := TakeCoreLinkReport(); r != nil {
		t.Fatal("report before any failure")
	}
	absent := &coreipc.CallError{Stage: "connect", Code: "CORE_IPC_PIPE_ABSENT", Win32: 2}
	for i := 0; i < 5; i++ {
		RecordCoreLinkFailure("read", absent)
	}
	outage, count := CoreLinkOutage()
	if count != 5 || outage < 0 {
		t.Fatal(outage, count)
	}
	RecordCoreRestartAttempt("started")
	report, confirm := TakeCoreLinkReport()
	if report == nil || report.Failures != 5 || len(report.Recent) != 1 || report.Recent[0].Count != 5 || report.CoreRestarts != 1 || report.OutageSinceUTC == "" {
		t.Fatalf("%+v", report)
	}
	if again, _ := TakeCoreLinkReport(); again == nil {
		t.Fatal("report must repeat until delivery is confirmed")
	}
	confirm()
	if again, _ := TakeCoreLinkReport(); again != nil {
		t.Fatal("delivered report repeated")
	}
	RecordCoreLinkSuccess()
	if _, count := CoreLinkOutage(); count != 0 {
		t.Fatal("outage not cleared")
	}
	report, _ = TakeCoreLinkReport()
	if report == nil || report.Recoveries != 1 || report.OutageSinceUTC != "" || report.LastOKUTC == "" {
		t.Fatalf("recovery not reported: %+v", report)
	}
}

func TestCoreLinkLogStaysBounded(t *testing.T) {
	resetCoreLink()
	for i := 0; i < 500; i++ {
		RecordCoreLinkFailure("read", fmt.Errorf("CORE_TEST_%d", i))
	}
	report, _ := TakeCoreLinkReport()
	b, _ := json.Marshal(report)
	if len(report.Recent) != uiIPCRecentLimit || len(b) > 4096 {
		t.Fatal(len(report.Recent), len(b))
	}
}

func TestCoreSanitizesUIReportedFailures(t *testing.T) {
	in := UIIPCReport{Failures: 3, LastRestart: "ok\x00\x1b[31m" + strings.Repeat("x", 500), LastOKUTC: "yesterday"}
	for i := 0; i < 40; i++ {
		in.Recent = append(in.Recent, UIIPCFailure{UTC: "2026-10-19T10:00:00Z", Operation: "format c:", Code: "not a code with spaces", Detail: strings.Repeat("é", 400), Count: -4})
	}
	out := SanitizeUIIPCReport(in)
	if len(out.Recent) != uiIPCRecentLimit || len(out.LastRestart) > uiIPCDetailLimit || out.LastOKUTC != "" || strings.ContainsAny(out.LastRestart, "\x00\x1b") {
		t.Fatalf("%+v", out)
	}
	for _, f := range out.Recent {
		if f.Operation != "unknown" || f.Code != "INVALID_CODE" || len(f.Detail) > uiIPCDetailLimit || f.Count != 1 || f.LastUTC != "" {
			t.Fatalf("%+v", f)
		}
	}
	NoteUIIPCReport(in)
	b, err := json.Marshal(CoreIPCDiagnostics())
	if err != nil || len(b) > coreIPCEvidenceLimit+1500 {
		t.Fatal(len(b), err)
	}
}

func TestOversizeSnapshotIsTrimmedNotDropped(t *testing.T) {
	display, _ := json.Marshal(map[string]any{
		"desktop":     map[string]any{"event": "status", "detail": strings.Repeat("诊断 ", 3000), "keep": "version"},
		"connections": map[string]any{"Mac": map[string]any{"status": "MAC_RUNNING", "error": strings.Repeat("e", 30000)}},
		"events":      []any{"queued"},
	})
	trimmed, ok := TrimDisplayForTransport(display, len(display)-20000)
	if !ok || len(trimmed) > 20000 {
		t.Fatal(ok, len(trimmed))
	}
	var got struct {
		Desktop     map[string]any `json:"desktop"`
		Connections map[string]struct {
			Status string `json:"status"`
		} `json:"connections"`
		Events []any `json:"events"`
	}
	if err := json.Unmarshal(trimmed, &got); err != nil || got.Desktop["keep"] != "version" || got.Connections["Mac"].Status != "MAC_RUNNING" || got.Events != nil {
		t.Fatal(err, string(trimmed[:200]))
	}
	if _, ok := TrimDisplayForTransport(display, len(display)); ok {
		t.Fatal("cannot shrink to nothing")
	}
}
