package netconfig

import (
	"bytes"
	"encoding/json"
	"log"
	"strings"
)

// LogNetworkScriptOutput preserves the existing generic runner log. Only the two exact fixed read-only
// scripts can additionally emit an authenticated one-line typed observation.
// BEGIN/JSON/OK must be the entire successful CombinedOutput, not a marker
// embedded in a provider warning or error. No output authorizes Ready.
func LogNetworkScriptOutput(script string, output []byte, runErr error, l *log.Logger) {
	l.Printf("owned network configuration: %s error=%v", strings.TrimSpace(string(output)), runErr)
	if runErr != nil {
		return
	}
	prefix := ""
	switch script {
	case ResidentMacNullProjectionScript():
		prefix = MacNullProjectionPrefix
	case ResidentMacAnchorProjectionScript():
		prefix = MacAnchorProjectionPrefix
	default:
		return
	}
	lines := bytes.Split(bytes.TrimSpace(output), []byte("\n"))
	if len(lines) != 3 || string(bytes.TrimSuffix(lines[0], []byte("\r"))) != "SUHANG_NETWORK_SCRIPT_BEGIN" || string(bytes.TrimSuffix(lines[2], []byte("\r"))) != "SUHANG_NETWORK_SCRIPT_OK" {
		return
	}
	line := bytes.TrimSuffix(lines[1], []byte("\r"))
	var value any
	switch prefix {
	case MacNullProjectionPrefix:
		if !bytes.HasPrefix(line, []byte(prefix)) {
			return
		}
		v, e := DecodeMacNullProjection(line[len(prefix):])
		if e != nil {
			return
		}
		value = v
	case MacAnchorProjectionPrefix:
		if !bytes.HasPrefix(line, []byte(prefix)) {
			return
		}
		v, e := DecodeMacAnchorProjection(line[len(prefix):])
		if e != nil {
			return
		}
		value = v
	default:
		return
	}
	if b, e := json.Marshal(value); e == nil {
		l.Printf("%s%s", prefix, b)
	}
}
