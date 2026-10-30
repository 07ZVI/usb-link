package connectioninstall

import (
	"encoding/json"
	"fmt"
)

type smbVolumeMove struct {
	OldPath, Path, Identity string
	Published               bool
}

// Match the bounded native SMB state reader; reject before replacing the
// last readable intent. JSON escaping can inflate long pathname values.
func encodeSMBVolumeMoves(moves map[string]smbVolumeMove) ([]byte, error) {
	data, err := json.Marshal(moves)
	if err != nil {
		return nil, err
	}
	if len(moves) > 32 || len(data) > 1<<20 {
		return nil, fmt.Errorf("SMB_VOLUME_JOURNAL_TOO_LARGE")
	}
	return data, nil
}
