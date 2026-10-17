//go:build usblink_local_remote

package localupdate

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
)

type restartRequest func(context.Context, string, string, io.Reader, string, int64) ([]byte, error)

type softwareRestartStatus struct {
	ID                string                         `json:"id,omitempty"`
	Phase             string                         `json:"phase"`
	Error             string                         `json:"error,omitempty"`
	CoreReadable      bool                           `json:"core_readable,omitempty"`
	LoginRequested    bool                           `json:"login_requested,omitempty"`
	Diagnostic        *softwareRestartDiagnostic     `json:"diagnostic,omitempty"`
	CleanupDiagnostic *softwareRestartDiagnostic     `json:"cleanup_diagnostic,omitempty"`
	TaskInspection    *softwareRestartTaskInspection `json:"task_inspection,omitempty"`
}

type softwareRestartDiagnostic struct {
	Operation    string `json:"operation"`
	Stage        string `json:"stage"`
	Cause        string `json:"cause"`
	NativeKind   string `json:"native_kind"`
	NativeCode   uint32 `json:"native_code"`
	TaskMismatch uint32 `json:"task_mismatch"`
}

func restartDiagnosticChoice(value string, choices ...string) bool {
	for _, choice := range choices {
		if value == choice {
			return true
		}
	}
	return false
}

func validSoftwareRestartDiagnostic(d *softwareRestartDiagnostic) bool {
	if d == nil || *d == (softwareRestartDiagnostic{}) {
		return true
	}
	return restartDiagnosticChoice(d.Operation, "create", "verify", "run", "delete", "prepare", "helper", "inspect") &&
		restartDiagnosticChoice(d.Stage, "apartment", "activate", "connect", "folder", "enumerate", "count", "item", "name", "query_name", "query_path", "query_xml", "xml_validate", "hash", "enabled", "register", "run", "delete", "absence", "receipt_save", "pre_submit", "helper", "query_enabled", "query_state") &&
		restartDiagnosticChoice(d.Cause, "NATIVE_FAILURE", "TASK_XML_MISMATCH", "TASK_QUERY_FAILED", "TASK_CHANGED", "TASK_DISABLED", "TASK_AMBIGUOUS", "TASK_EXISTS", "TASK_MISSING", "TASK_DELETE_UNCONFIRMED", "TASK_OPERATION_INVALID", "OPERATION_FAILED") &&
		(d.NativeKind == "" && d.NativeCode == 0 || restartDiagnosticChoice(d.NativeKind, "HRESULT", "WIN32") && d.NativeCode != 0) && d.TaskMismatch <= 0xffff
}

type softwareRestartTaskInspection struct {
	Exists                     bool                       `json:"exists"`
	ReadComplete               bool                       `json:"read_complete"`
	NameMatches                bool                       `json:"name_matches"`
	PathMatches                bool                       `json:"path_matches"`
	Enabled                    bool                       `json:"enabled"`
	State                      uint32                     `json:"state"`
	ReceiptHashPresent         bool                       `json:"receipt_hash_present"`
	HashMatches                bool                       `json:"hash_matches"`
	TaskMismatch               uint32                     `json:"task_mismatch"`
	PrincipalUserForm          string                     `json:"principal_user_form"`
	PrincipalResolutionChecked bool                       `json:"principal_resolution_checked"`
	PrincipalSIDMatches        bool                       `json:"principal_sid_matches"`
	Diagnostic                 *softwareRestartDiagnostic `json:"diagnostic,omitempty"`
}

func validSoftwareRestartTaskInspection(s *softwareRestartTaskInspection) bool {
	return s == nil || s.State <= 4 && s.TaskMismatch <= 0xffff && restartDiagnosticChoice(s.PrincipalUserForm, "", "unreadable", "empty", "sid", "other") && validSoftwareRestartDiagnostic(s.Diagnostic)
}

func decodeSoftwareRestart(data []byte) (softwareRestartStatus, error) {
	var s softwareRestartStatus
	d := json.NewDecoder(bytes.NewReader(data))
	d.DisallowUnknownFields()
	if len(data) > 4096 || d.Decode(&s) != nil || d.Decode(new(any)) != io.EOF {
		return s, fmt.Errorf("invalid software restart status")
	}
	if !validSoftwareRestartDiagnostic(s.Diagnostic) || !validSoftwareRestartDiagnostic(s.CleanupDiagnostic) || !validSoftwareRestartTaskInspection(s.TaskInspection) {
		return s, fmt.Errorf("invalid software restart diagnostic summary")
	}
	if s.Phase == "idle" {
		if s.ID == "" && s.Error == "" && !s.CoreReadable && !s.LoginRequested && s.Diagnostic == nil && s.CleanupDiagnostic == nil && s.TaskInspection == nil {
			return s, nil
		}
		return s, fmt.Errorf("invalid idle software restart status")
	}
	if !validID(s.ID) || len(s.Error) > 128 {
		return s, fmt.Errorf("invalid software restart identity")
	}
	for _, c := range s.Error {
		if !(c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_') {
			return s, fmt.Errorf("invalid software restart error code")
		}
	}
	switch s.Phase {
	case "prepared", "running", "ready":
		if s.Error == "" && !s.CoreReadable && !s.LoginRequested {
			return s, nil
		}
	case "starting":
		if s.Error == "" && (!s.LoginRequested || s.CoreReadable) {
			return s, nil
		}
	case "completed":
		if s.Error == "" && s.CoreReadable && s.LoginRequested {
			return s, nil
		}
	case "failed":
		if s.Error != "" {
			return s, nil
		}
	}
	return s, fmt.Errorf("unconfirmed software restart state")
}

func requestSoftwareRestart(ctx context.Context, request restartRequest, out io.Writer) error {
	var nonce [16]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return err
	}
	id := hex.EncodeToString(nonce[:])
	body, _ := json.Marshal(map[string]string{"id": id})
	data, err := request(ctx, "POST", "/v1/restart", bytes.NewReader(body), "", 0)
	if err != nil {
		// The server may already have admitted this ID. Never retry a mutation
		// automatically when the connection disappears during shutdown.
		return fmt.Errorf("software restart %s acknowledgement unavailable; read restart-status before retrying: %w", id, err)
	}
	s, err := decodeSoftwareRestart(data)
	if err != nil || s.ID != id || s.Phase != "prepared" {
		return fmt.Errorf("software restart acknowledgement not confirmed; read restart-status")
	}
	_, err = fmt.Fprintln(out, "Software restart requested:", id, "This acknowledges the request only. Rediscover USB and read restart-status to confirm the new core is readable; login_requested does not prove a visible window.")
	return err
}

func readSoftwareRestart(ctx context.Context, request restartRequest, out io.Writer) error {
	data, err := request(ctx, "GET", "/v1/restart", nil, "", 0)
	if err != nil {
		return err
	}
	s, err := decodeSoftwareRestart(data)
	if err != nil {
		return err
	}
	data, err = json.Marshal(s)
	if err != nil {
		return err
	}
	_, err = fmt.Fprintln(out, string(data))
	return err
}
