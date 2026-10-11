// Package coreipc carries a bounded local-only UI protocol. A request is not
// consent: the core must revalidate the existing action/device scope itself.
package coreipc

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
)

const PipeName = `\\.\pipe\USBLink-Core-3d547ef4-v1`
const MaxMessage = 64 << 10

type Request struct {
	Version int             `json:"version"`
	ID      string          `json:"id"`
	Method  string          `json:"method"`
	Payload json.RawMessage `json:"payload"`
}
type Response struct {
	Version int             `json:"version"`
	ID      string          `json:"id"`
	Payload json.RawMessage `json:"payload,omitempty"`
	Problem string          `json:"problem,omitempty"`
}
type Peer struct {
	PID, Session uint32
	Creation     uint64
	SID          string
	Elevated     bool
}

func validMethod(method string) bool {
	switch method {
	case "snapshot", "consent", "settings", "action", "update-notice-ack":
		return true
	}
	return false
}
func ParseRequest(b []byte) (Request, error) {
	var r Request
	if len(b) > MaxMessage || !exactFields(b, []string{"version", "id", "method", "payload"}) {
		return r, fmt.Errorf("CORE_IPC_REQUEST_INVALID")
	}
	d := json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	if d.Decode(&r) != nil || d.Decode(new(any)) != io.EOF || r.Version != 1 || len(r.ID) != 32 || !hexID(r.ID) || !validMethod(r.Method) || len(r.Payload) == 0 {
		return Request{}, fmt.Errorf("CORE_IPC_REQUEST_INVALID")
	}
	return r, nil
}
func AuthorizePeer(ownerSID string, peer Peer, method string) error {
	if ownerSID == "" || peer.SID != ownerSID || peer.Session == 0 || peer.Session == 0xffffffff || peer.PID == 0 {
		return fmt.Errorf("CORE_IPC_PEER_REJECTED")
	}
	if !validMethod(method) || method != "snapshot" && !peer.Elevated {
		return fmt.Errorf("CORE_IPC_ADMIN_REQUIRED")
	}
	return nil
}
func hexID(s string) bool {
	for _, c := range s {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}
func exactFields(b []byte, fields []string) bool {
	d := json.NewDecoder(bytes.NewReader(b))
	t, e := d.Token()
	if e != nil || t != json.Delim('{') {
		return false
	}
	seen := map[string]bool{}
	for _, k := range fields {
		seen[k] = false
	}
	for d.More() {
		t, e = d.Token()
		k, ok := t.(string)
		v, exists := seen[k]
		if e != nil || !ok || !exists || v {
			return false
		}
		seen[k] = true
		var raw json.RawMessage
		if d.Decode(&raw) != nil {
			return false
		}
	}
	for _, v := range seen {
		if !v {
			return false
		}
	}
	t, e = d.Token()
	return e == nil && t == json.Delim('}') && d.Decode(new(any)) == io.EOF
}

func ParseResponse(b []byte, id string) (Response, error) {
	var r Response
	if len(b) > MaxMessage || !responseFields(b) {
		return r, fmt.Errorf("CORE_IPC_RESPONSE_INVALID")
	}
	d := json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	if d.Decode(&r) != nil || d.Decode(new(any)) != io.EOF || r.Version != 1 || r.ID != id || len(id) != 32 || !hexID(id) {
		return Response{}, fmt.Errorf("CORE_IPC_RESPONSE_INVALID")
	}
	return r, nil
}
func responseFields(b []byte) bool {
	d := json.NewDecoder(bytes.NewReader(b))
	t, e := d.Token()
	if e != nil || t != json.Delim('{') {
		return false
	}
	seen := map[string]bool{"version": false, "id": false, "payload": false, "problem": false}
	for d.More() {
		t, e = d.Token()
		k, ok := t.(string)
		v, known := seen[k]
		if e != nil || !ok || !known || v {
			return false
		}
		seen[k] = true
		var raw json.RawMessage
		if d.Decode(&raw) != nil {
			return false
		}
	}
	if !seen["version"] || !seen["id"] {
		return false
	}
	t, e = d.Token()
	return e == nil && t == json.Delim('}') && d.Decode(new(any)) == io.EOF
}
