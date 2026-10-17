package logfile

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

const diagnosticLimit = 256 * 1024
const serviceMarker = "\nBACKGROUND_SERVICE_LOG_BEGIN\n"
const evidencePrefix = "USB_LINK_UPGRADE_EVIDENCE "

type DiagnosticTails struct {
	Installer string
	Bridge    string
	Service   string
}

func diagnosticTail(path string, limit int64, completeLines bool) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return "", err
	}
	truncated := info.Size() > limit
	if truncated {
		if _, err = f.Seek(info.Size()-limit, io.SeekStart); err != nil {
			return "", err
		}
	}
	b, err := io.ReadAll(io.LimitReader(f, limit))
	if err != nil {
		return "", err
	}
	text := string(b)
	if completeLines {
		if truncated {
			if next := strings.IndexByte(text, '\n'); next >= 0 {
				text = text[next+1:]
			} else {
				return "", nil
			}
		}
		// A concurrent writer may not yet have completed its final record.
		if end := strings.LastIndexByte(text, '\n'); end >= 0 {
			text = text[:end+1]
		} else {
			text = ""
		}
	}
	return text, nil
}

// Service evidence is independent of installer.log, which can be absent or rotated.
func ReadDiagnosticTails(dir string) DiagnosticTails {
	installer, err := diagnosticTail(filepath.Join(dir, "installer.log"), 64*1024, false)
	if err != nil {
		installer = err.Error()
	}
	bridge, err := diagnosticTail(filepath.Join(dir, "usbnet-bridge.log"), 64*1024, false)
	if err != nil {
		bridge = err.Error()
	}
	service, _ := diagnosticTail(filepath.Join(dir, "service.log"), 64*1024, true)
	return DiagnosticTails{installer, bridge, service}
}

// Retain each latest independent iPad section when unrelated service logs are large.
func latestDiagnosticEvidence(service string) string {
	latest := map[string]string{}
	for _, line := range strings.Split(service, "\n") {
		if !strings.HasPrefix(line, evidencePrefix) {
			continue
		}
		var row map[string]json.RawMessage
		if json.Unmarshal([]byte(strings.TrimPrefix(line, evidencePrefix)), &row) != nil {
			continue
		}
		for _, key := range []string{"ipad_connection", "ipad_runtime_network", "ipad_trust_timeline", "connection_timing", "photo_isolation"} {
			if _, ok := row[key]; ok {
				latest[key] = line
			}
		}
	}
	var lines []string
	for _, key := range []string{"ipad_connection", "ipad_runtime_network", "ipad_trust_timeline", "connection_timing", "photo_isolation"} {
		if line := latest[key]; line != "" {
			lines = append(lines, line)
		}
	}
	return strings.Join(lines, "\n") + "\n"
}

// Bound the encoded payload, since JSON escaping can expand raw log bytes sixfold.
// Old ordinary log prefixes are expendable before complete recent iPad evidence.
func MarshalDiagnosticSnapshot(fields map[string]any, tails DiagnosticTails) ([]byte, error) {
	snapshot := make(map[string]any, len(fields)+2)
	for key, value := range fields {
		snapshot[key] = value
	}
	truncated := map[string]bool{}
	for {
		installer := tails.Installer
		if tails.Service != "" {
			installer += serviceMarker + tails.Service
		}
		snapshot["logs"] = map[string]string{"installer.log": installer, "ncm-probe.log": tails.Bridge}
		if len(truncated) != 0 {
			snapshot["log_prefixes_omitted_for_transport"] = truncated
		}
		body, err := json.Marshal(snapshot)
		if err != nil || len(body) <= diagnosticLimit {
			return body, err
		}
		switch {
		case len(tails.Installer) > 0:
			tails.Installer = tails.Installer[(len(tails.Installer)+1)/2:]
			truncated["installer.log"] = true
		case len(tails.Bridge) > 0:
			tails.Bridge = tails.Bridge[(len(tails.Bridge)+1)/2:]
			truncated["ncm-probe.log"] = true
		case !truncated["service.log"]:
			tails.Service = latestDiagnosticEvidence(tails.Service)
			truncated["service.log"] = true
		default:
			return nil, fmt.Errorf("diagnostic metadata and latest evidence exceed transport bound")
		}
	}
}
