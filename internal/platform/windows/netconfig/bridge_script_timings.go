package netconfig

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"math"
)

const BridgeNetworkScriptTimingPrefix = "USB_BRIDGE_NETWORK_SCRIPT "

// This fixed-schema diagnostic is bridge-local; never sum it with overlapping
// core operations or interpret successful script execution as network readiness.
type BridgeNetworkScriptTiming struct {
	Operation  string  `json:"operation"`
	Count      uint64  `json:"count"`
	DurationMS float64 `json:"duration_ms"`
	Success    bool    `json:"success"`
}

func BridgeNetworkScriptOperationValid(name string) bool {
	switch name {
	case "setup", "cleanup", "cleanup_verify", "private_profile", "diagnostic":
		return true
	}
	return false
}

// CopyBridgeNetworkScriptTimings produces a bounded independent diagnostic
// snapshot. Source/child authentication remains the caller's separate duty.
func CopyBridgeNetworkScriptTimings(rows []BridgeNetworkScriptTiming) []BridgeNetworkScriptTiming {
	var out []BridgeNetworkScriptTiming
	for _, row := range rows[:min(len(rows), 16)] {
		if BridgeNetworkScriptOperationValid(row.Operation) && row.Count == 1 && !math.IsNaN(row.DurationMS) && !math.IsInf(row.DurationMS, 0) && row.DurationMS >= 0 && row.DurationMS <= 120000 {
			out = append(out, row)
		}
	}
	return out
}

func DecodeBridgeNetworkScriptTiming(b []byte) (BridgeNetworkScriptTiming, error) {
	var row BridgeNetworkScriptTiming
	if len(b) == 0 || len(b) > 512 {
		return row, errors.New("bridge script timing invalid")
	}
	// Reject duplicate, missing and arbitrary fields, including a missing false
	// success value. Neither paths nor script content enter this channel.
	d := json.NewDecoder(bytes.NewReader(b))
	token, err := d.Token()
	if err != nil || token != json.Delim('{') {
		return row, errors.New("bridge script timing invalid")
	}
	seen := map[string]bool{}
	for d.More() {
		token, err = d.Token()
		key, ok := token.(string)
		if err != nil || !ok || seen[key] || (key != "operation" && key != "count" && key != "duration_ms" && key != "success") {
			return row, errors.New("bridge script timing invalid")
		}
		seen[key] = true
		var value json.RawMessage
		if d.Decode(&value) != nil {
			return row, errors.New("bridge script timing invalid")
		}
		var target any
		switch key {
		case "operation":
			target = &row.Operation
		case "count":
			target = &row.Count
		case "duration_ms":
			target = &row.DurationMS
		case "success":
			target = &row.Success
		}
		if string(value) == "null" || json.Unmarshal(value, target) != nil {
			return row, errors.New("bridge script timing invalid")
		}
	}
	if token, err = d.Token(); err != nil || token != json.Delim('}') || len(seen) != 4 || d.Decode(new(any)) != io.EOF || !BridgeNetworkScriptOperationValid(row.Operation) || row.Count != 1 || math.IsNaN(row.DurationMS) || math.IsInf(row.DurationMS, 0) || row.DurationMS < 0 || row.DurationMS > 120000 {
		return row, errors.New("bridge script timing invalid")
	}
	return row, nil
}
