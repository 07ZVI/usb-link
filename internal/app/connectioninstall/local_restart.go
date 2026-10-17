//go:build usblink_local_remote

package connectioninstall

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
)

const LocalRestartArgument = "--local-remote-restart"
const localRestartFile = "local-restart-v1.json"

type LocalRestartStatus struct {
	CleanupDiagnostic LocalRestartDiagnostic      `json:"cleanup_diagnostic,omitzero"`
	TaskInspection    *LocalRestartTaskInspection `json:"task_inspection,omitempty"`
	Diagnostic        LocalRestartDiagnostic      `json:"diagnostic,omitzero"`
	ID                string                      `json:"id,omitempty"`
	Phase             string                      `json:"phase"`
	Error             string                      `json:"error,omitempty"`
	CoreReadable      bool                        `json:"core_readable,omitempty"`
	LoginRequested    bool                        `json:"login_requested,omitempty"`
}
type localRestartJob struct {
	CleanupDiagnostic LocalRestartDiagnostic `json:"cleanup_diagnostic,omitzero"`
	Diagnostic        LocalRestartDiagnostic `json:"diagnostic,omitzero"`
	Schema            int                    `json:"schema"`
	ID                string                 `json:"id"`
	Binding           CoreServiceBinding     `json:"binding"`
	Session           uint32                 `json:"session"`
	CorePID           uint32                 `json:"core_pid"`
	CoreCreation      uint64                 `json:"core_creation"`
	HelperPID         uint32                 `json:"helper_pid"`
	HelperCreation    uint64                 `json:"helper_creation"`
	TaskSHA           string                 `json:"task_sha256"`
	Admitted          bool                   `json:"admitted"`
	CoreReadable      bool                   `json:"core_readable"`
	LoginRequested    bool                   `json:"login_requested"`
	Consent           localRestartConsent    `json:"consent"`
	Phase             string                 `json:"phase"`
	Error             string                 `json:"error"`
}
type localRestartConsent struct {
	Revision  uint64 `json:"revision"`
	TokenHash string `json:"token_hash"`
}

func restartTerminal(p string) bool { return p == "completed" || p == "failed" }
func (j localRestartJob) valid() bool {
	if !restartDiagnosticValid(j.CleanupDiagnostic) || !restartDiagnosticValid(j.Diagnostic) || j.Schema != 1 || !localArchiveHex(j.ID, 32) || !validPreparedUserSID(j.Binding.OwnerSID) || j.Binding.Executable == "" || j.Binding.Version != 1 || j.Binding.Product != ProductID || !localArchiveHex(j.Binding.SHA256, 64) || j.Session == 0 || j.Session == 0xffffffff || j.CorePID == 0 || j.CoreCreation == 0 || j.Consent.Revision == 0 || !localArchiveHex(j.Consent.TokenHash, 64) {
		return false
	}
	if (j.HelperPID == 0) != (j.HelperCreation == 0) || (j.TaskSHA != "" && !localArchiveHex(j.TaskSHA, 64)) || !restartErrorValid(j.Error) || j.Phase != "failed" && j.Error != "" || j.Phase == "completed" && (!j.Admitted || !j.CoreReadable || !j.LoginRequested) {
		return false
	}
	switch j.Phase {
	case "prepared":
		return j.HelperPID == 0 && j.HelperCreation == 0 && !j.Admitted && !j.CoreReadable && !j.LoginRequested
	case "running":
		return j.HelperPID != 0 && j.HelperCreation != 0 && localArchiveHex(j.TaskSHA, 64) && !j.CoreReadable && !j.LoginRequested
	case "ready":
		return j.HelperPID != 0 && j.HelperCreation != 0 && localArchiveHex(j.TaskSHA, 64) && j.Admitted && !j.CoreReadable && !j.LoginRequested
	case "starting", "completed":
		return j.HelperPID != 0 && j.HelperCreation != 0 && localArchiveHex(j.TaskSHA, 64) && j.Admitted && (!j.LoginRequested || j.CoreReadable)
	case "failed":
		return j.Error != ""
	}
	return false
}
func decodeRestartJob(b []byte) (j localRestartJob, e error) {
	if len(b) > 8192 {
		return j, errors.New("LOCAL_RESTART_RECEIPT_INVALID")
	}
	fields := []string{"schema", "id", "binding", "session", "core_pid", "core_creation", "helper_pid", "helper_creation", "task_sha256", "admitted", "core_readable", "login_requested", "consent", "phase", "error"}
	var diagnosticField map[string]json.RawMessage
	if json.Unmarshal(b, &diagnosticField) != nil {
		return j, errors.New("LOCAL_RESTART_RECEIPT_INVALID")
	}
	for _, name := range []string{"diagnostic", "cleanup_diagnostic"} {
		if raw, ok := diagnosticField[name]; ok {
			fields = append(fields, name)
			if !coreExactFields(raw, []string{"operation", "stage", "cause", "native_kind", "native_code", "task_mismatch"}) {
				return j, errors.New("LOCAL_RESTART_RECEIPT_INVALID")
			}
		}
	}
	if !coreExactFields(b, fields) {
		return j, errors.New("LOCAL_RESTART_RECEIPT_INVALID")
	}
	var nested map[string]json.RawMessage
	if json.Unmarshal(b, &nested) != nil {
		return j, errors.New("LOCAL_RESTART_RECEIPT_INVALID")
	}
	if _, err := parseCoreBinding(nested["binding"]); err != nil || !coreExactFields(nested["consent"], []string{"revision", "token_hash"}) {
		return j, errors.New("LOCAL_RESTART_RECEIPT_INVALID")
	}
	d := json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	if len(b) > 8192 || d.Decode(&j) != nil || d.Decode(new(any)) != io.EOF || !j.valid() {
		return j, errors.New("LOCAL_RESTART_RECEIPT_INVALID")
	}
	return j, nil
}
func restartTaskName(id string) string { return "USB-Link-Restart-" + id }
func restartTaskXML(j localRestartJob) string {
	return `<?xml version="1.0"?><Task version="1.2" xmlns="` + taskNamespace + `"><RegistrationInfo><Description>` + ProductID + `:restart:` + j.ID + `</Description></RegistrationInfo><Triggers/><Principals><Principal id="Owner"><UserId>` + escape(j.Binding.OwnerSID) + `</UserId><LogonType>InteractiveToken</LogonType><RunLevel>HighestAvailable</RunLevel></Principal></Principals><Settings><MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy><DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries><StopIfGoingOnBatteries>false</StopIfGoingOnBatteries><AllowHardTerminate>false</AllowHardTerminate><AllowStartOnDemand>true</AllowStartOnDemand><ExecutionTimeLimit>PT0S</ExecutionTimeLimit><Enabled>true</Enabled></Settings><Actions Context="Owner"><Exec><Command>` + escape(j.Binding.Executable) + `</Command><Arguments>` + LocalRestartArgument + ` ` + j.ID + `</Arguments></Exec></Actions></Task>`
}
func validateRestartTask(text string, j localRestartJob) error {
	if mask := restartTaskMismatch(text, j); mask != 0 {
		return restartTaskMismatchError(mask)
	}
	return nil
}

func restartTaskHash(s string) string { h := sha256.Sum256([]byte(s)); return hex.EncodeToString(h[:]) }
func restartErrorValid(s string) bool {
	switch s {
	case "", "LOCAL_RESTART_PRECONDITION_FAILED", "LOCAL_RESTART_TASK_FAILED", "LOCAL_RESTART_TASK_CLEANUP_FAILED", "LOCAL_RESTART_HELPER_FAILED", "LOCAL_RESTART_REVOKED", "LOCAL_RESTART_EXIT_FAILED", "LOCAL_RESTART_EXIT_TIMEOUT", "LOCAL_RESTART_SOURCE_CHANGED", "LOCAL_RESTART_START_FAILED", "LOCAL_RESTART_CORE_UNCONFIRMED", "LOCAL_RESTART_LOGIN_FAILED":
		return true
	}
	return false
}
func (j localRestartJob) status() LocalRestartStatus {
	return LocalRestartStatus{CleanupDiagnostic: j.CleanupDiagnostic, Diagnostic: j.Diagnostic, ID: j.ID, Phase: j.Phase, Error: j.Error, CoreReadable: j.CoreReadable, LoginRequested: j.LoginRequested}
}

func restartCoreSnapshotReadable(data []byte, expectedVersion string) bool {
	var s struct {
		Version string `json:"version"`
		Display struct {
			Desktop struct {
				Event   string `json:"event"`
				Version string `json:"version"`
				Exit    struct {
					Phase string `json:"phase"`
				} `json:"program_exit"`
			} `json:"desktop"`
		} `json:"display"`
	}
	return len(data) <= 65536 && json.Unmarshal(data, &s) == nil && expectedVersion != "" && s.Version == expectedVersion && s.Display.Desktop.Event == "status" && s.Display.Desktop.Version == s.Version && s.Display.Desktop.Exit.Phase == "idle"
}

// Only a proved dead claimed helper can be reconciled automatically. An
// unclaimed task is revoked explicitly by a new request under the claim lock.
func restartAbandoned(j localRestartJob, exited, known bool) bool {
	return !restartTerminal(j.Phase) && j.Phase != "prepared" && j.HelperPID != 0 && exited && known
}
func restartPreparedSupersedable(j localRestartJob) bool {
	return j.Phase == "prepared" && j.HelperPID == 0 && j.HelperCreation == 0 && !j.Admitted
}

func restartAdmissionMatches(j localRestartJob, id, sid string, session, pid uint32, creation uint64, corePID uint32) bool {
	return j.valid() && j.ID == id && j.Phase == "running" && !j.Admitted && j.Binding.OwnerSID == sid && j.Session == session && j.HelperPID == pid && j.HelperCreation == creation && j.CorePID == corePID
}

func restartAdmissionReceipt(before, after localRestartJob) bool {
	before.Admitted = true
	return after == before
}
