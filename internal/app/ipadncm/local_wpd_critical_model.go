//go:build usblink_local_remote

package ipadncm

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
)

// Correlation is system ETW context, never evidence of a particular device.
type wpdCriticalCorrelation struct {
	ThreadID              uint32 `json:"thread_id"`
	ActivityPresent       bool   `json:"activity_present"`
	ActivitySHA256        string `json:"activity_sha256,omitempty"`
	RelatedActivityStatus string `json:"related_activity_status"`
	Attribution           string `json:"attribution"`
}

func wpdCriticalHeaderCorrelation(raw [wpdCriticalHeaderSize]byte) wpdCriticalCorrelation {
	var activity [16]byte
	copy(activity[:], raw[64:80])
	out := wpdCriticalCorrelation{ThreadID: binary.LittleEndian.Uint32(raw[8:12]), ActivityPresent: activity != ([16]byte{}), RelatedActivityStatus: "not_collected", Attribution: "system_unattributed"}
	if out.ActivityPresent {
		sum := sha256.Sum256(activity[:])
		out.ActivitySHA256 = hex.EncodeToString(sum[:])
	}
	return out
}

func wpdCriticalTemplateStage(provider [16]byte, id uint16, version uint8, metadata []byte) string {
	if provider == ([16]byte{}) || len(metadata) < 16 || !bytes.Equal(provider[:], metadata[:16]) {
		return "metadata_provider_mismatch"
	}
	if len(wpdExactMTPCommandField("mtp", id, version, metadata)) != 1 {
		return "strict_manifest_template_mismatch"
	}
	return ""
}

// Fixed scalars distinguish declared record size from the two copied regions.
// No pointer, payload, provider GUID or instance identity is exported.
type wpdRecordShape struct {
	RecordBytes   uint16 `json:"record_bytes"`
	HeaderBytes   uint16 `json:"header_bytes"`
	UserDataBytes uint16 `json:"user_data_bytes"`
	HeaderFlags   uint16 `json:"header_flags"`
	ExtendedCount uint16 `json:"extended_count"`
}

func (item *wpdCriticalItem) recordShape() wpdRecordShape {
	if item.projected {
		return item.shape
	}
	return wpdRecordShape{RecordBytes: binary.LittleEndian.Uint16(item.header[:2]), HeaderBytes: wpdCriticalHeaderSize, UserDataBytes: item.length, HeaderFlags: binary.LittleEndian.Uint16(item.header[4:6])}
}

func (item *wpdCriticalItem) safeCorrelation() wpdCriticalCorrelation {
	if item.projected {
		return item.correlation
	}
	return wpdCriticalHeaderCorrelation(item.header)
}
