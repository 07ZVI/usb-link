package ipadncm

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"suhang/usbnet/internal/transport/ipadsession"
)

const localNCMDirectJournalName = "local-ncm-direct-v1.json"
const localNCMDirectJournalLimit = 8192

// 0x45 is retained as observed bytes, not treated as a documented mode ID.
// Restoring this intent requires observing the original initial USB layout on
// the same device, or proving the separately requested ordinary mode-3 layout.
type localNCMDirectJournal struct {
	Schema                      int    `json:"schema"`
	Root                        string `json:"root"`
	Hub                         string `json:"hub"`
	Port                        uint32 `json:"port"`
	SerialSHA256                string `json:"serial_sha256"`
	OriginalConfiguration       byte   `json:"original_configuration"`
	OriginalConfigurationSHA256 string `json:"original_configuration_sha256"`
	OriginalProbe               []byte `json:"original_probe"`
	RequestedMode               int    `json:"requested_mode"`
}

func directDigest(s string) bool {
	b, e := hex.DecodeString(s)
	return e == nil && len(b) == 32 && s == strings.ToLower(s)
}
func (j localNCMDirectJournal) valid() bool {
	return j.Schema == 1 && ipadsession.USBGrant(j.Root, "12AB", "local-direct-recovery").Valid() && len(j.Hub) > 0 && len(j.Hub) <= 1024 && !strings.ContainsAny(j.Hub, "\x00\r\n") && j.Port > 0 && j.Port <= 255 && directDigest(j.SerialSHA256) && directDigest(j.OriginalConfigurationSHA256) && j.OriginalConfiguration == 3 && bytes.Equal(j.OriginalProbe, []byte{3, 3, 3, 0}) && (j.RequestedMode == 5 || j.RequestedMode == 3)
}
func decodeLocalNCMDirectJournal(b []byte) (localNCMDirectJournal, error) {
	var j localNCMDirectJournal
	d := json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	if len(b) > localNCMDirectJournalLimit || d.Decode(&j) != nil || d.Decode(new(any)) != io.EOF || !j.valid() {
		return j, errors.New("DIRECT_RECOVERY_RECORD_INVALID")
	}
	return j, nil
}
func directConfigurationDigest(configs []Configuration, current byte) string {
	var found *Configuration
	for i := range configs {
		if configs[i].Value == current {
			if found != nil {
				return ""
			}
			found = &configs[i]
		}
	}
	if found == nil {
		return ""
	}
	b, e := json.Marshal(found)
	if e != nil {
		return ""
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}
func cloneDirectConfigurations(configs []Configuration) []Configuration {
	if len(configs) == 0 {
		return nil
	}
	b, _ := json.Marshal(configs)
	var out []Configuration
	_ = json.Unmarshal(b, &out)
	return out
}
