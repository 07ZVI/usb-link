package netconfig

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
)

const NativeFailurePrefix = "USB_NATIVE_STEP_FAILURE "

// This bounded message crosses only the verified child's existing stdout pipe.
// It contains no process/device identity, source path, log or authority token.
type NativeStepDiagnostic struct {
	Schema      int    `json:"schema"`
	Operation   string `json:"operation"`
	HRESULT     uint32 `json:"hresult"`
	Code        string `json:"code,omitempty"`
	CauseCode   string `json:"cause_code,omitempty"`
	CauseField  string `json:"cause_field,omitempty"`
	NativeError uint32 `json:"native_error,omitempty"`
}

func NativeStepDiagnosticValid(v NativeStepDiagnostic) bool {
	return v.Schema == 1 && NativeOperationValid(v.Operation) && (v.HRESULT == 0 || int32(v.HRESULT) < 0) && nativeDiagnosticCodeValid(v) && nativeDiagnosticCauseValid(v) && (v.CauseField == "" || (v.CauseCode != "" && ValidFirewallConstraintField(v.CauseField)))
}
func NativeStepFailureMessage(err error) ([]byte, bool) {
	op, hr := NativeStepFailureDetails(err)
	if op == "" {
		return nil, false
	}
	b, e := json.Marshal(NativeStepDiagnostic{Schema: 1, Operation: op, HRESULT: hr})
	return b, e == nil && len(b) <= 512
}
func DecodeNativeStepFailureMessage(data []byte) (NativeStepDiagnostic, error) {
	var out NativeStepDiagnostic
	if len(data) == 0 || len(data) > 512 {
		return out, errors.New("USB_NATIVE_FAILURE_MESSAGE_SIZE")
	}
	d := json.NewDecoder(bytes.NewReader(data))
	token, e := d.Token()
	if e != nil || token != json.Delim('{') {
		return out, errors.New("USB_NATIVE_FAILURE_MESSAGE_OBJECT")
	}
	seen := map[string]bool{}
	for d.More() {
		token, e = d.Token()
		if e != nil {
			return out, e
		}
		name, ok := token.(string)
		if !ok || seen[name] || (name != "schema" && name != "operation" && name != "hresult" && name != "code" && name != "cause_code" && name != "native_error" && name != "cause_field") {
			return out, errors.New("USB_NATIVE_FAILURE_MESSAGE_FIELD")
		}
		seen[name] = true
		var raw json.RawMessage
		if e = d.Decode(&raw); e != nil {
			return out, e
		}
		if bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
			return out, errors.New("USB_NATIVE_FAILURE_MESSAGE_NULL")
		}
	}
	token, e = d.Token()
	if e != nil || token != json.Delim('}') || (!seen["schema"] || !seen["operation"] || !seen["hresult"] || len(seen) < 3 || len(seen) > 7) {
		return out, errors.New("USB_NATIVE_FAILURE_MESSAGE_FIELDS")
	}
	var tail any
	if d.Decode(&tail) != io.EOF {
		return out, errors.New("USB_NATIVE_FAILURE_MESSAGE_TRAILING")
	}
	if e = json.Unmarshal(data, &out); e != nil {
		return NativeStepDiagnostic{}, e
	}
	if !NativeStepDiagnosticValid(out) {
		return NativeStepDiagnostic{}, errors.New("USB_NATIVE_FAILURE_MESSAGE_UNPROVEN")
	}
	return out, nil
}
