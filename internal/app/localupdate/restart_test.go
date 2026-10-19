//go:build usblink_local_remote

package localupdate

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"

	"suhang/usbnet/internal/app/connectioninstall"
)

func TestSoftwareRestartReadsRealServerDiagnosticProjection(t *testing.T) {
	server := connectioninstall.LocalRestartStatus{
		ID: strings.Repeat("a", 32), Phase: "failed", Error: "LOCAL_RESTART_TASK_FAILED",
		Diagnostic:        connectioninstall.LocalRestartDiagnostic{Operation: "create", Stage: "register", Cause: "NATIVE_FAILURE", NativeKind: "HRESULT", NativeCode: 0x80070005},
		CleanupDiagnostic: connectioninstall.LocalRestartDiagnostic{Operation: "delete", Stage: "absence", Cause: "TASK_DELETE_UNCONFIRMED"},
		TaskInspection:    &connectioninstall.LocalRestartTaskInspection{Exists: true, ReadComplete: true, NameMatches: true, PathMatches: true, Enabled: true, State: 3, TaskMismatch: 1 << 12, PrincipalUserForm: "other", PrincipalResolutionChecked: true, PrincipalSIDMatches: true},
	}
	data, err := json.Marshal(server)
	if err != nil {
		t.Fatal(err)
	}
	got, err := decodeSoftwareRestart(data)
	if err != nil || got.Diagnostic == nil || got.Diagnostic.NativeCode != 0x80070005 || got.CleanupDiagnostic == nil || got.CleanupDiagnostic.Cause != "TASK_DELETE_UNCONFIRMED" || got.TaskInspection == nil || !got.TaskInspection.PrincipalSIDMatches {
		t.Fatalf("real server diagnostic contract rejected: %s %v", data, err)
	}
	for name, change := range map[string]func(*connectioninstall.LocalRestartStatus){
		"arbitrary stage":       func(s *connectioninstall.LocalRestartStatus) { s.Diagnostic.Stage = "C:/private/path" },
		"arbitrary cause":       func(s *connectioninstall.LocalRestartStatus) { s.Diagnostic.Cause = "raw exception" },
		"unbounded mask":        func(s *connectioninstall.LocalRestartStatus) { s.Diagnostic.TaskMismatch = 1 << 16 },
		"missing native code":   func(s *connectioninstall.LocalRestartStatus) { s.Diagnostic.NativeCode = 0 },
		"arbitrary native type": func(s *connectioninstall.LocalRestartStatus) { s.Diagnostic.NativeKind = "raw" },
		"unknown state": func(s *connectioninstall.LocalRestartStatus) {
			copy := *s.TaskInspection
			copy.State = 5
			s.TaskInspection = &copy
		},
		"raw account": func(s *connectioninstall.LocalRestartStatus) {
			copy := *s.TaskInspection
			copy.PrincipalUserForm = "DOMAIN/private-user"
			s.TaskInspection = &copy
		},
	} {
		t.Run(name, func(t *testing.T) {
			x := server
			change(&x)
			data, _ := json.Marshal(x)
			if _, err := decodeSoftwareRestart(data); err == nil {
				t.Fatal("unbounded diagnostic accepted")
			}
		})
	}
	data, _ = json.Marshal(server)
	withXML := strings.Replace(string(data), `"task_inspection":{`, `"task_inspection":{"xml":"must-not-pass",`, 1)
	if _, err := decodeSoftwareRestart([]byte(withXML)); err == nil {
		t.Fatal("raw task material accepted")
	}
}

type restartRoundTrip func(*http.Request) (*http.Response, error)

func (f restartRoundTrip) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestSoftwareRestartCrossesRealClientAllowlistWithAuthentication(t *testing.T) {
	calls := 0
	token := strings.Repeat("b", 64)
	c := &client{token: token, http: &http.Client{Transport: restartRoundTrip(func(r *http.Request) (*http.Response, error) {
		calls++
		if r.URL.String() != endpoint+"/v1/restart" || r.Header.Get("Authorization") != "Bearer "+token {
			t.Fatal("restart changed fixed authenticated destination")
		}
		data := []byte(`{"phase":"idle"}`)
		if r.Method == "POST" {
			var body map[string]string
			if json.NewDecoder(r.Body).Decode(&body) != nil || len(body) != 1 || !validID(body["id"]) {
				t.Fatal("invalid restart request body")
			}
			data, _ = json.Marshal(softwareRestartStatus{ID: body["id"], Phase: "prepared"})
		} else if r.Method != "GET" {
			t.Fatal("unsupported method reached transport")
		}
		return &http.Response{StatusCode: http.StatusOK, Header: make(http.Header), Body: io.NopCloser(bytes.NewReader(data))}, nil
	})}}
	if err := requestSoftwareRestart(context.Background(), c.request, io.Discard); err != nil {
		t.Fatal(err)
	}
	if err := readSoftwareRestart(context.Background(), c.request, io.Discard); err != nil {
		t.Fatal(err)
	}
	for _, route := range [][2]string{{"DELETE", "/v1/restart"}, {"PUT", "/v1/restart"}, {"POST", "/v1/restart/"}, {"POST", "/v1/restart?command=x"}, {"GET", "//foreign/restart"}, {"GET", "/v1/restart/status"}} {
		if _, err := c.request(context.Background(), route[0], route[1], nil, "", 0); err == nil {
			t.Fatal("restart widened the route allowlist")
		}
	}
	if calls != 2 {
		t.Fatal("rejected route reached transport")
	}
}

func TestSoftwareRestartUsesOneFixedRequestAndDoesNotClaimCompletion(t *testing.T) {
	calls := 0
	var out bytes.Buffer
	request := func(_ context.Context, method, path string, body io.Reader, manifest string, size int64) ([]byte, error) {
		calls++
		var payload map[string]string
		if method != "POST" || path != "/v1/restart" || manifest != "" || size != 0 || json.NewDecoder(body).Decode(&payload) != nil || len(payload) != 1 || !validID(payload["id"]) {
			t.Fatal("restart escaped its fixed request contract")
		}
		return json.Marshal(softwareRestartStatus{ID: payload["id"], Phase: "prepared"})
	}
	if err := requestSoftwareRestart(context.Background(), request, &out); err != nil || calls != 1 || !strings.Contains(out.String(), "request only") || !strings.Contains(out.String(), "restart-status") {
		t.Fatalf("request acknowledgement changed: calls=%d out=%q err=%v", calls, out.String(), err)
	}
	out.Reset()
	lost := errors.New("connection closed")
	request = func(context.Context, string, string, io.Reader, string, int64) ([]byte, error) {
		calls++
		return nil, lost
	}
	if err := requestSoftwareRestart(context.Background(), request, &out); !errors.Is(err, lost) || calls != 2 || out.Len() != 0 {
		t.Fatal("lost acknowledgement retried a mutation or reported success")
	}
}

func TestSoftwareRestartRejectsWrongOrPrematureAcknowledgement(t *testing.T) {
	for _, phase := range []string{"completed", "running", "idle", "prepared"} {
		t.Run(phase, func(t *testing.T) {
			request := func(context.Context, string, string, io.Reader, string, int64) ([]byte, error) {
				return json.Marshal(softwareRestartStatus{ID: strings.Repeat("1", 32), Phase: phase, CoreReadable: phase == "completed", LoginRequested: phase == "completed"})
			}
			if err := requestSoftwareRestart(context.Background(), request, io.Discard); err == nil {
				t.Fatal("unbound or premature response accepted")
			}
		})
	}
}

func TestSoftwareRestartStatusNeedsNewCoreEvidence(t *testing.T) {
	id := strings.Repeat("1", 32)
	for _, s := range []softwareRestartStatus{
		{Phase: "idle"}, {ID: id, Phase: "prepared"}, {ID: id, Phase: "running"}, {ID: id, Phase: "ready"},
		{ID: id, Phase: "starting", CoreReadable: true}, {ID: id, Phase: "completed", CoreReadable: true, LoginRequested: true},
		{ID: id, Phase: "failed", Error: "LOCAL_RESTART_RECOVERY_PENDING"},
	} {
		data, _ := json.Marshal(s)
		if _, err := decodeSoftwareRestart(data); err != nil {
			t.Fatalf("valid bounded progress rejected: %+v %v", s, err)
		}
	}
	for _, data := range []string{
		`{"phase":"completed","id":"` + id + `"}`,
		`{"phase":"completed","id":"` + id + `","core_readable":true}`,
		`{"phase":"prepared","id":"` + id + `","core_readable":true}`,
		`{"phase":"starting","id":"` + id + `","login_requested":true}`,
		`{"phase":"idle","id":"` + id + `"}`,
		`{"phase":"running","id":"BAD"}`,
		`{"phase":"failed","id":"` + id + `","error":"C:/private/path"}`,
		`{"phase":"failed","id":"` + id + `"}`,
		`{"phase":"idle","command":"arbitrary"}`,
		`{"phase":"idle"} {"phase":"idle"}`,
		strings.Repeat(" ", 4097),
	} {
		if _, err := decodeSoftwareRestart([]byte(data)); err == nil {
			t.Fatal("unsupported or unconfirmed status accepted")
		}
	}
}

func TestSoftwareRestartStatusUsesFixedReadOnlyRoute(t *testing.T) {
	var out bytes.Buffer
	request := func(_ context.Context, method, path string, body io.Reader, manifest string, size int64) ([]byte, error) {
		if method != "GET" || path != "/v1/restart" || body != nil || manifest != "" || size != 0 {
			t.Fatal("status query mutated or changed destination")
		}
		return []byte(`{"phase":"idle"}`), nil
	}
	if err := readSoftwareRestart(context.Background(), request, &out); err != nil || out.String() != "{\"phase\":\"idle\"}\n" {
		t.Fatalf("invalid status output: %q %v", out.String(), err)
	}
}

func TestSoftwareRestartFlagsRejectMixedModesBeforeFileOrNetworkAccess(t *testing.T) {
	for _, flags := range [][]string{
		{"--restart", "--status"}, {"--restart", "--restart-status"}, {"--restart=false"},
		{"--restart", "--exe", "unreadable"}, {"--restart-status", "--stage-only"},
		{"--restart", "--sign-key", "must-not-open"}, {"--restart", "--init-key", "must-not-create"},
		{"--restart-status", "--version", "1.0.0"},
	} {
		if err := run(flags, io.Discard); err == nil || !strings.Contains(err.Error(), "choose restart or restart-status") {
			t.Fatalf("mixed restart flags reached file or network access: %q %v", flags, err)
		}
	}
}
