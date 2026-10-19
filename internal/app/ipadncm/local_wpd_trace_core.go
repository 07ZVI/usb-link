package ipadncm

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"unicode/utf16"
)

const localWPDTraceJournalFile = "local-wpd-trace-v1.json"

const localWPDTraceETLFile = "local-wpd-trace.etl"

const localWPDTraceJournalLimit = 4096

type localWPDTraceJournal struct {
	Schema   int    `json:"schema"`
	Session  string `json:"session"`
	GUID     string `json:"guid"`
	OwnerSID string `json:"owner_sid"`
	File     string `json:"file"`
	Mode     string `json:"mode,omitempty"`
	Stopped  bool   `json:"stopped"`
}

func decodeLocalWPDTraceJournal(b []byte) (localWPDTraceJournal, error) {
	var j localWPDTraceJournal
	d := json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	if len(b) > localWPDTraceJournalLimit || d.Decode(&j) != nil || d.Decode(new(any)) != io.EOF || !j.valid() {
		return j, errors.New("WPD_TRACE_JOURNAL_INVALID")
	}
	return j, nil
}

type localWPDTraceFailure struct {
	Code      string
	Native    uint32
	Ownership *wpdSessionQueryEvidence
}

func wpdTraceError(code string, native uint32) error {
	return &localWPDTraceFailure{Code: code, Native: native}
}

func wpdCheckSessionQuery(j localWPDTraceJournal, expectedPath string, raw []byte, guidMatch bool, mode, maxFile, nameOffset, fileOffset uint32) wpdSessionQueryEvidence {
	d := wpdSessionQueryEvidence{Schema: j.Schema, Mode: mode, MaxFileMiB: maxFile, NameOffset: nameOffset, FileOffset: fileOffset, BufferSize: uint32(len(raw))}
	if !guidMatch {
		d.Mismatch |= 1
	}
	name, nameOK := wpdQueryString(raw, nameOffset)
	if !nameOK {
		d.Mismatch |= 2
	} else if name != j.Session {
		d.Mismatch |= 4
	}
	file, fileOK := "", true
	if fileOffset != 0 {
		file, fileOK = wpdQueryString(raw, fileOffset)
	}
	if !fileOK {
		d.Mismatch |= 8
	}
	if !j.valid() || !wpdSessionModeOwned(j, mode, maxFile, strings.ToLower(file), strings.ToLower(expectedPath)) {
		d.Mismatch |= 16
	}
	return d
}

// Mismatch bits: 1 GUID, 2 name encoding/range, 4 name identity,
// 8 file encoding/range, 16 mode/size/file identity. No names or paths escape.
type wpdSessionQueryEvidence struct {
	Schema     int    `json:"schema"`
	Mode       uint32 `json:"mode"`
	MaxFileMiB uint32 `json:"max_file_mib"`
	NameOffset uint32 `json:"name_offset"`
	FileOffset uint32 `json:"file_offset"`
	BufferSize uint32 `json:"buffer_bytes"`
	Mismatch   uint32 `json:"mismatch_bits"`
}

// Unlike the display-only UTF16 helper, an invalid output must not turn into
// an apparently empty filename. Only strings outside the native header qualify.
func wpdQueryString(raw []byte, offset uint32) (string, bool) {
	if offset < 120 || offset%2 != 0 || uint64(offset)+2 > uint64(len(raw)) {
		return "", false
	}
	u := make([]uint16, 0, 128)
	for i := int(offset); i+1 < len(raw) && len(u) <= 1023; i += 2 {
		v := binary.LittleEndian.Uint16(raw[i:])
		if v == 0 {
			for n := 0; n < len(u); n++ {
				if u[n] >= 0xd800 && u[n] <= 0xdbff {
					if n+1 >= len(u) || u[n+1] < 0xdc00 || u[n+1] > 0xdfff {
						return "", false
					}
					n++
				} else if u[n] >= 0xdc00 && u[n] <= 0xdfff {
					return "", false
				}
			}
			return string(utf16.Decode(u)), true
		}
		u = append(u, v)
	}
	return "", false
}

func (j localWPDTraceJournal) valid() bool {
	nonce := strings.TrimPrefix(j.Session, "USBLink-WPD-")
	format := j.Schema == 1 && j.Mode == "" && j.File == localWPDTraceETLFile || j.Schema == 2 && j.Mode == "metadata_session" && j.File == ""
	return format && len(nonce) == 32 && strings.Trim(nonce, "0123456789abcdef") == "" && j.Session == "USBLink-WPD-"+nonce &&
		len(j.GUID) == 38 && j.GUID[0] == '{' && j.GUID[37] == '}' && j.GUID[9] == '-' && j.GUID[14] == '-' && j.GUID[19] == '-' && j.GUID[24] == '-' && strings.Trim(j.GUID, "{}-0123456789abcdefABCDEF") == "" &&
		strings.HasPrefix(j.OwnerSID, "S-1-") && len(j.OwnerSID) <= 184 && strings.Trim(j.OwnerSID[4:], "0123456789-") == ""
}
func (e *localWPDTraceFailure) Error() string { return e.Code }

func wpdSessionModeOwned(j localWPDTraceJournal, mode, maxFile uint32, file, expected string) bool {
	if j.Schema == 2 {
		return j.Mode == "metadata_session" && file == "" && maxFile == 0 && wpdMetadataModeOwned(mode)
	}
	return j.Schema == 1 && maxFile == 8 && mode&2 != 0 && file == expected
}

// ETW supplies one hybrid-shutdown policy when none was requested. Accept only
// these exact owned variants; unrelated flags and contradictory policies fail.
func wpdMetadataModeOwned(mode uint32) bool {
	return mode == wpdMetadataBaseMode || mode == wpdMetadataBaseMode|wpdStopOnHybridShutdown || mode == wpdMetadataBaseMode|wpdPersistOnHybridShutdown
}

const (
	wpdMetadataBaseMode        uint32 = 0x10000100
	wpdStopOnHybridShutdown    uint32 = 0x00400000
	wpdPersistOnHybridShutdown uint32 = 0x00800000
)
