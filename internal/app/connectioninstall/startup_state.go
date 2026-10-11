package connectioninstall

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync"
)

type StartupTaskObservation struct {
	Available          bool   `json:"available"`
	Enabled            bool   `json:"enabled"`
	TaskCount          int    `json:"task_count"`
	Code               string `json:"code"`
	Phase              string `json:"phase"`
	NativeError        uint32 `json:"native_error"`
	DurationMS         int64  `json:"duration_ms"`
	Operation          string `json:"operation,omitempty"`
	ExceptionKind      string `json:"exception_kind,omitempty"`
	InnerExceptionKind string `json:"inner_exception_kind,omitempty"`
	InnerNativeError   uint32 `json:"inner_native_error,omitempty"`
	ExceptionDepth     int    `json:"exception_depth,omitempty"`
	CIMNativeError     uint32 `json:"cim_native_error,omitempty"`
	CIMStatus          uint32 `json:"cim_status,omitempty"`
}

var startupTaskObservation struct {
	sync.Mutex
	value StartupTaskObservation
}

func LastStartupTaskObservation() StartupTaskObservation {
	startupTaskObservation.Lock()
	defer startupTaskObservation.Unlock()
	return startupTaskObservation.value
}

func recordStartupTaskObservation(v StartupTaskObservation) {
	startupTaskObservation.Lock()
	startupTaskObservation.value = v
	startupTaskObservation.Unlock()
}

func parseStartupTaskObservation(b []byte, failed bool) (StartupTaskObservation, error) {
	v := StartupTaskObservation{Code: "STARTUP_OUTPUT_UNCONFIRMED"}
	if len(b) == 0 || len(b) > 4096 || !startupJSONUniqueFields(b) {
		return v, errors.New(v.Code)
	}
	var wire struct {
		Code               string  `json:"code"`
		Phase              string  `json:"phase"`
		NativeError        *uint32 `json:"native_error"`
		TaskCount          *int    `json:"task_count"`
		Enabled            *bool   `json:"enabled"`
		Operation          *string `json:"operation"`
		ExceptionKind      *string `json:"exception_kind"`
		InnerExceptionKind *string `json:"inner_exception_kind"`
		InnerNativeError   *uint32 `json:"inner_native_error"`
		ExceptionDepth     *int    `json:"exception_depth"`
		CIMNativeError     *uint32 `json:"cim_native_error"`
		CIMStatus          *uint32 `json:"cim_status"`
	}
	d := json.NewDecoder(strings.NewReader(strings.TrimSpace(string(b))))
	d.DisallowUnknownFields()
	if d.Decode(&wire) != nil || wire.NativeError == nil || wire.TaskCount == nil || wire.Enabled == nil || *wire.TaskCount < 0 || *wire.TaskCount > 2 || (wire.Phase != "QUERY" && wire.Phase != "REGISTER" && wire.Phase != "REMOVE" && wire.Phase != "READBACK") {
		return v, errors.New(v.Code)
	}
	if d.Decode(new(any)) != io.EOF {
		return v, errors.New(v.Code)
	}
	if wire.Code != "OK" && !startupFailureCode(wire.Code) {
		return v, errors.New(v.Code)
	}
	v = StartupTaskObservation{Available: wire.Code == "OK" && !failed, Enabled: *wire.Enabled, TaskCount: *wire.TaskCount, Code: wire.Code, Phase: wire.Phase, NativeError: *wire.NativeError}
	// Older fixed output remains parseable. New diagnostics are one complete,
	// fixed-enum group; a partial or unbounded string cannot reach UI/status.
	diagnosticPresent := wire.Operation != nil || wire.ExceptionKind != nil || wire.InnerExceptionKind != nil || wire.InnerNativeError != nil || wire.ExceptionDepth != nil || wire.CIMNativeError != nil || wire.CIMStatus != nil
	if diagnosticPresent {
		if wire.Operation == nil || wire.ExceptionKind == nil || wire.InnerExceptionKind == nil || wire.InnerNativeError == nil || wire.ExceptionDepth == nil || wire.CIMNativeError == nil || wire.CIMStatus == nil || !startupOperation(wire.Phase, *wire.Operation) || !startupExceptionKind(*wire.ExceptionKind) || !startupExceptionKind(*wire.InnerExceptionKind) || *wire.ExceptionDepth < 0 || *wire.ExceptionDepth > 4 {
			return StartupTaskObservation{Code: "STARTUP_OUTPUT_UNCONFIRMED"}, errors.New("STARTUP_OUTPUT_UNCONFIRMED")
		}
		if (wire.Code == "OK" && (*wire.ExceptionKind != "NONE" || *wire.InnerExceptionKind != "NONE" || *wire.ExceptionDepth != 0 || *wire.InnerNativeError != 0 || *wire.CIMNativeError != 0 || *wire.CIMStatus != 0)) || (wire.Code != "OK" && (*wire.ExceptionKind == "NONE" || *wire.ExceptionDepth == 0)) || (*wire.ExceptionDepth < 2 && (*wire.InnerExceptionKind != "NONE" || *wire.InnerNativeError != 0)) {
			return StartupTaskObservation{Code: "STARTUP_OUTPUT_UNCONFIRMED"}, errors.New("STARTUP_OUTPUT_UNCONFIRMED")
		}
		v.Operation, v.ExceptionKind, v.InnerExceptionKind = *wire.Operation, *wire.ExceptionKind, *wire.InnerExceptionKind
		v.InnerNativeError, v.ExceptionDepth, v.CIMNativeError, v.CIMStatus = *wire.InnerNativeError, *wire.ExceptionDepth, *wire.CIMNativeError, *wire.CIMStatus
	}
	if !v.Available {
		if v.Code == "OK" {
			v.Code = "STARTUP_PROCESS_FAILED"
		}
		v.Enabled = false
		return v, fmt.Errorf("%s phase=%s operation=%s native=0x%08x inner=0x%08x cim=0x%08x", v.Code, v.Phase, v.Operation, v.NativeError, v.InnerNativeError, v.CIMNativeError)
	}
	if v.NativeError != 0 || (v.TaskCount == 0 && v.Enabled) {
		v.Available = false
		v.Enabled = false
		v.Code = "STARTUP_OUTPUT_UNCONFIRMED"
		return v, errors.New(v.Code)
	}
	return v, nil
}

func startupJSONUniqueFields(b []byte) bool {
	d := json.NewDecoder(strings.NewReader(string(b)))
	first, e := d.Token()
	if e != nil || first != json.Delim('{') {
		return false
	}
	seen := map[string]bool{}
	for d.More() {
		key, e := d.Token()
		if e != nil {
			return false
		}
		name, ok := key.(string)
		if !ok || seen[name] {
			return false
		}
		seen[name] = true
		var raw json.RawMessage
		if d.Decode(&raw) != nil {
			return false
		}
	}
	last, e := d.Token()
	return e == nil && last == json.Delim('}') && d.Decode(new(any)) == io.EOF
}

func startupFailureCode(s string) bool {
	switch s {
	case "STARTUP_PRINCIPAL_CHANGED", "STARTUP_QUERY_UNBOUNDED", "STARTUP_TASK_AMBIGUOUS", "STARTUP_TASK_OWNERSHIP_CHANGED", "STARTUP_TASK_LOGON_TYPE_CHANGED", "STARTUP_TASK_RUN_LEVEL_CHANGED", "STARTUP_TASK_ACTION_CHANGED", "STARTUP_TASK_PATH_CHANGED", "STARTUP_TASK_REPARSE", "STARTUP_TASK_RECEIPT_CHANGED", "STARTUP_TASK_TRIGGER_CHANGED", "STARTUP_TASK_STATE_UNKNOWN", "STARTUP_READBACK_CHANGED", "STARTUP_MODE_INVALID", "STARTUP_QUERY_FAILED", "STARTUP_REGISTER_FAILED", "STARTUP_REMOVE_FAILED", "STARTUP_READBACK_FAILED":
		return true
	}
	return false
}

func startupOperation(phase, operation string) bool {
	switch phase {
	case "QUERY":
		return operation == "QUERY"
	case "REGISTER":
		switch operation {
		case "CONNECT", "ROOT_FOLDER", "VALIDATE_XML", "PREWRITE", "CREATE", "UPDATE":
			return true
		}
	case "REMOVE":
		return operation == "REMOVE"
	case "READBACK":
		return operation == "READBACK"
	}
	return false
}

func startupExceptionKind(s string) bool {
	switch s {
	case "NONE", "COM", "CIM", "RUNTIME", "METHOD_INVOCATION", "CMDLET_INVOCATION", "ACTION_PREFERENCE_STOP", "PARAMETER_BINDING", "ACCESS_DENIED", "XML", "OTHER":
		return true
	}
	return false
}
