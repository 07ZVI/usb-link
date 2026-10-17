//go:build usblink_local_remote

package connectioninstall

import (
	"encoding/xml"
	"errors"
	"io"
	"strings"
	"syscall"
)

// Only fixed stages, failed predicates and numeric native statuses are public.
// Task XML, account names, paths and exception text remain private.
type LocalRestartDiagnostic struct {
	Operation    string `json:"operation"`
	Stage        string `json:"stage"`
	Cause        string `json:"cause"`
	NativeKind   string `json:"native_kind"`
	NativeCode   uint32 `json:"native_code"`
	TaskMismatch uint32 `json:"task_mismatch"`
}

func restartDiagnosticValid(d LocalRestartDiagnostic) bool {
	if d == (LocalRestartDiagnostic{}) {
		return true
	}
	switch d.Operation {
	case "create", "verify", "run", "delete", "prepare", "helper", "inspect":
	default:
		return false
	}
	switch d.Stage {
	case "apartment", "activate", "connect", "folder", "enumerate", "count", "item", "name", "query_name", "query_path", "query_xml", "xml_validate", "hash", "enabled", "register", "run", "delete", "absence", "receipt_save", "pre_submit", "helper", "query_enabled", "query_state":
	default:
		return false
	}
	switch d.Cause {
	case "NATIVE_FAILURE", "TASK_XML_MISMATCH", "TASK_QUERY_FAILED", "TASK_CHANGED", "TASK_DISABLED", "TASK_AMBIGUOUS", "TASK_EXISTS", "TASK_MISSING", "TASK_DELETE_UNCONFIRMED", "TASK_OPERATION_INVALID", "OPERATION_FAILED":
	default:
		return false
	}
	return (d.NativeKind == "" && d.NativeCode == 0 || (d.NativeKind == "HRESULT" || d.NativeKind == "WIN32") && d.NativeCode != 0) && d.TaskMismatch & ^uint32(0xffff) == 0
}

type restartTaskFailure struct {
	diagnostic LocalRestartDiagnostic
	err        error
}

func (e *restartTaskFailure) Error() string { return "LOCAL_RESTART_TASK_NATIVE_FAILED" }
func (e *restartTaskFailure) Unwrap() error { return e.err }

type restartTaskMismatchError uint32

func (e restartTaskMismatchError) Error() string { return "LOCAL_RESTART_TASK_CHANGED" }
func restartDiagnostic(operation, stage string, err error) LocalRestartDiagnostic {
	var failure *restartTaskFailure
	if errors.As(err, &failure) {
		return failure.diagnostic
	}
	d := LocalRestartDiagnostic{Operation: operation, Stage: stage, Cause: "OPERATION_FAILED"}
	var mismatch restartTaskMismatchError
	if errors.As(err, &mismatch) {
		d.Cause = "TASK_XML_MISMATCH"
		d.TaskMismatch = uint32(mismatch)
	}
	var hr interface{ NativeHRESULT() uint32 }
	var errno syscall.Errno
	if errors.As(err, &hr) && hr.NativeHRESULT() != 0 {
		d.Cause = "NATIVE_FAILURE"
		d.NativeKind = "HRESULT"
		d.NativeCode = hr.NativeHRESULT()
	} else if errors.As(err, &errno) && errno != 0 {
		d.Cause = "NATIVE_FAILURE"
		d.NativeKind = "WIN32"
		d.NativeCode = uint32(errno)
	} else if err != nil && d.Cause == "OPERATION_FAILED" {
		switch err.Error() {
		case "LOCAL_RESTART_TASK_QUERY_FAILED":
			d.Cause = "TASK_QUERY_FAILED"
		case "LOCAL_RESTART_TASK_CHANGED":
			d.Cause = "TASK_CHANGED"
		case "LOCAL_RESTART_TASK_DISABLED":
			d.Cause = "TASK_DISABLED"
		case "LOCAL_RESTART_TASK_AMBIGUOUS":
			d.Cause = "TASK_AMBIGUOUS"
		case "LOCAL_RESTART_TASK_EXISTS":
			d.Cause = "TASK_EXISTS"
		case "LOCAL_RESTART_TASK_MISSING":
			d.Cause = "TASK_MISSING"
		case "LOCAL_RESTART_TASK_DELETE_UNCONFIRMED":
			d.Cause = "TASK_DELETE_UNCONFIRMED"
		case "LOCAL_RESTART_TASK_OPERATION_INVALID":
			d.Cause = "TASK_OPERATION_INVALID"
		}
	}
	if !restartDiagnosticValid(d) {
		return LocalRestartDiagnostic{Operation: "helper", Stage: "helper", Cause: "OPERATION_FAILED"}
	}
	return d
}

// Bits 0..7: receipt, XML envelope, uniqueness/namespace, settings shape,
// definition, principal, action, unknown principal/action field. Bits 8..14:
// instances, battery start/stop, hard terminate, demand, limit, enabled. Bit 15
// identifies the principal UserId mismatch before exact SID normalization.
func restartTaskMismatch(text string, j localRestartJob) uint32 {
	if !j.valid() {
		return 1
	}
	if len(text) > 65536 || strings.Contains(text, "<!") {
		return 2
	}
	if !nativeTaskXMLUnique(text) {
		return 4
	}
	mask := restartTaskPolicyMismatch(text)
	var d nativeStartupDefinition
	dec := nativeTaskDecoder(text)
	if dec.Decode(&d) != nil || dec.Decode(new(any)) != io.EOF || d.XMLName != (xml.Name{Space: taskNamespace, Local: "Task"}) || d.Registration.Description != ProductID+":restart:"+j.ID || len(d.Triggers.Items) != 0 || len(d.Principals.Items) != 1 || len(d.Actions.Items) != 1 || d.Actions.Context != "Owner" || !nativeTaskEnabled(d.Settings.Enabled) {
		return mask | 16
	}
	p := d.Principals.Items[0]
	a := d.Actions.Items[0]
	if p.ID != "Owner" || p.UserID != j.Binding.OwnerSID || p.LogonType != "InteractiveToken" || p.RunLevel != "HighestAvailable" {
		mask |= 32
	}
	if p.UserID != j.Binding.OwnerSID {
		mask |= 1 << 15
	}
	if a.XMLName != (xml.Name{Space: taskNamespace, Local: "Exec"}) || !strings.EqualFold(a.Command, j.Binding.Executable) || a.Arguments != LocalRestartArgument+" "+j.ID || a.WorkingDirectory != "" {
		mask |= 64
	}
	return mask
}
func restartTaskPolicyMismatch(text string) uint32 {
	d := nativeTaskDecoder(text)
	stack := []string{}
	values := map[string]string{}
	seen := map[string]bool{}
	var mask uint32
	names := []string{"MultipleInstancesPolicy", "DisallowStartIfOnBatteries", "StopIfGoingOnBatteries", "AllowHardTerminate", "AllowStartOnDemand", "ExecutionTimeLimit", "Enabled"}
	expected := []string{"IgnoreNew", "false", "false", "false", "true", "PT0S", "true"}
	for {
		t, e := d.Token()
		if e == io.EOF {
			break
		}
		if e != nil {
			return mask | 8
		}
		switch v := t.(type) {
		case xml.StartElement:
			stack = append(stack, v.Name.Local)
			path := strings.Join(stack, "/")
			if seen[path] {
				return mask | 8
			}
			seen[path] = true
			if strings.HasPrefix(path, "Task/Principals/Principal/") && path != "Task/Principals/Principal/UserId" && path != "Task/Principals/Principal/LogonType" && path != "Task/Principals/Principal/RunLevel" {
				mask |= 128
			}
			if strings.HasPrefix(path, "Task/Actions/Exec/") && path != "Task/Actions/Exec/Command" && path != "Task/Actions/Exec/Arguments" {
				mask |= 128
			}
		case xml.CharData:
			if len(stack) == 3 && stack[0] == "Task" && stack[1] == "Settings" {
				values[stack[2]] += string(v)
			}
		case xml.EndElement:
			if len(stack) == 0 {
				return mask | 8
			}
			stack = stack[:len(stack)-1]
		}
	}
	for i, name := range names {
		value := strings.Trim(values[name], " \t\r\n")
		// Task Scheduler may omit these schema-default true settings on readback.
		// An explicit empty value is not an absent element. The false policies
		// must remain explicit, since their schema defaults are true.
		if !seen["Task/Settings/"+name] && (name == "AllowStartOnDemand" || name == "Enabled") {
			value = "true"
		}
		if expected[i] == "true" && value == "1" {
			value = "true"
		} else if expected[i] == "false" && value == "0" {
			value = "false"
		}
		if value != expected[i] {
			mask |= uint32(1) << (8 + i)
		}
	}
	return mask
}

type LocalRestartTaskInspection struct {
	PrincipalResolutionChecked bool                   `json:"principal_resolution_checked"`
	PrincipalSIDMatches        bool                   `json:"principal_sid_matches"`
	Exists                     bool                   `json:"exists"`
	ReadComplete               bool                   `json:"read_complete"`
	NameMatches                bool                   `json:"name_matches"`
	PathMatches                bool                   `json:"path_matches"`
	Enabled                    bool                   `json:"enabled"`
	State                      int32                  `json:"state"`
	ReceiptHashPresent         bool                   `json:"receipt_hash_present"`
	HashMatches                bool                   `json:"hash_matches"`
	TaskMismatch               uint32                 `json:"task_mismatch"`
	PrincipalUserForm          string                 `json:"principal_user_form"`
	Diagnostic                 LocalRestartDiagnostic `json:"diagnostic,omitzero"`
}

func restartPrincipalUserForm(text string) string {
	var d nativeStartupDefinition
	dec := nativeTaskDecoder(text)
	if len(text) > 65536 || strings.Contains(text, "<!") || dec.Decode(&d) != nil || len(d.Principals.Items) != 1 {
		return "unreadable"
	}
	user := d.Principals.Items[0].UserID
	if user == "" {
		return "empty"
	}
	if validPreparedUserSID(user) {
		return "sid"
	}
	return "other"
}
func restartRetainUnverified(j localRestartJob) bool {
	return j.Phase == "failed" && j.TaskSHA == "" && !j.Admitted && j.HelperPID == 0 && j.HelperCreation == 0
}

func restartResolvedTaskMismatch(text string, j localRestartJob, resolve func(string) (string, error)) (mask uint32, checked, matched bool) {
	mask = restartTaskMismatch(text, j)
	// Never resolve arbitrary values from an invalid envelope/definition.
	if mask&(1|2|4|16) != 0 {
		return mask, false, false
	}
	var d nativeStartupDefinition
	dec := nativeTaskDecoder(text)
	if dec.Decode(&d) != nil || len(d.Principals.Items) != 1 {
		return mask, false, false
	}
	p := d.Principals.Items[0]
	if p.UserID == j.Binding.OwnerSID {
		return mask, true, true
	}
	if len(p.UserID) == 0 || len(p.UserID) > 256 || resolve == nil {
		return mask, false, false
	}
	sid, e := resolve(p.UserID)
	if e != nil {
		return mask, false, false
	}
	checked = true
	matched = sid == j.Binding.OwnerSID
	if matched {
		mask &^= 1 << 15
		if p.ID == "Owner" && p.LogonType == "InteractiveToken" && p.RunLevel == "HighestAvailable" {
			mask &^= 32
		}
	}
	return mask, checked, matched
}

func retainRestartReceipt(j localRestartJob, read func() (localRestartJob, bool, error), count func() (int, error), write func(localRestartJob) error) error {
	if !j.valid() || !restartRetainUnverified(j) {
		return errors.New("LOCAL_RESTART_RETENTION_UNCONFIRMED")
	}
	old, present, e := read()
	if e != nil {
		return e
	}
	if present {
		if old != j {
			return errors.New("LOCAL_RESTART_RETENTION_CHANGED")
		}
		return nil
	}
	n, e := count()
	if e != nil {
		return e
	}
	if n < 0 || n >= 16 {
		return errors.New("LOCAL_RESTART_RETENTION_LIMIT")
	}
	if e = write(j); e != nil {
		return e
	}
	old, present, e = read()
	if e != nil || !present || old != j {
		return errors.New("LOCAL_RESTART_RETENTION_UNCONFIRMED")
	}
	return nil
}
