package connectioninstall

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strings"
)

func IsExternalSMBID(id string) bool {
	if !strings.HasPrefix(id, "external:") || len(id) != 73 {
		return false
	}
	_, err := hex.DecodeString(id[9:])
	return err == nil
}

// The UI receives a fingerprint of the full observed share, never authority to
// name an arbitrary share. Any changed path/descriptor/marker invalidates it.
func externalSMBID(name, path, remark, descriptor string) string {
	data, _ := json.Marshal([]string{name, path, remark, descriptor})
	sum := sha256.Sum256(data)
	return "external:" + hex.EncodeToString(sum[:])
}
