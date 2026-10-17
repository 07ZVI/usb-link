//go:build usblink_local_remote

package localupdate

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sort"
)

type archiveEntry struct {
	ID         string `json:"id"`
	Attempt    uint64 `json:"attempt"`
	CreatedUTC string `json:"created_utc"`
	Total      int64  `json:"total"`
	SHA256     string `json:"sha256"`
	Complete   bool   `json:"complete"`
	Truncated  bool   `json:"truncated"`
}
type archiveIndex struct {
	Schema      int             `json:"schema"`
	Entries     []archiveEntry  `json:"entries"`
	Diagnostics json.RawMessage `json:"diagnostics"`
}
type archiveChunk struct {
	ID        string `json:"id"`
	Offset    int64  `json:"offset"`
	Total     int64  `json:"total"`
	SHA256    string `json:"sha256"`
	Data      []byte `json:"data"`
	Complete  bool   `json:"complete"`
	Truncated bool   `json:"truncated"`
}
type archiveTransfer struct {
	Entry    archiveEntry `json:"entry"`
	Bytes    int64        `json:"received_bytes"`
	Verified bool         `json:"transport_verified"`
	Error    string       `json:"error,omitempty"`
}
type archiveCollection struct {
	Schema   int               `json:"schema"`
	Status   string            `json:"transport_status"`
	Archives []archiveTransfer `json:"archives"`
	Error    string            `json:"error,omitempty"`
}

func archiveHex(s string, n int) bool {
	b, e := hex.DecodeString(s)
	return e == nil && len(s) == n && hex.EncodeToString(b) == s
}
func archiveDecode(data []byte, v any) error {
	d := json.NewDecoder(bytes.NewReader(data))
	d.DisallowUnknownFields()
	var extra any
	if d.Decode(v) != nil || d.Decode(&extra) != io.EOF {
		return errors.New("ARCHIVE_RESPONSE_INVALID")
	}
	return nil
}
func (c *client) archiveIndex(ctx context.Context) (archiveIndex, []byte, error) {
	var index archiveIndex
	b, e := c.request(ctx, "GET", "/v1/diagnostics/index", nil, "", 0)
	if e != nil {
		return index, nil, e
	}
	if archiveDecode(b, &index) != nil || index.Schema != 1 || len(index.Entries) > 16 {
		return index, nil, errors.New("ARCHIVE_INDEX_INVALID")
	}
	seen := map[string]bool{}
	for _, entry := range index.Entries {
		if !validID(entry.ID) || !archiveHex(entry.SHA256, 64) || entry.Total < 0 || entry.Total > 4<<20 || seen[entry.ID] {
			return index, nil, errors.New("ARCHIVE_INDEX_INVALID")
		}
		seen[entry.ID] = true
	}
	var state struct {
		CurrentID string `json:"current_id"`
	}
	if json.Unmarshal(index.Diagnostics, &state) != nil || state.CurrentID != "" && !validID(state.CurrentID) {
		return index, nil, errors.New("ARCHIVE_INDEX_INVALID")
	}
	sort.SliceStable(index.Entries, func(i, j int) bool {
		a, b := index.Entries[i], index.Entries[j]
		if a.ID == b.ID {
			return false
		}
		if a.ID == state.CurrentID {
			return true
		}
		if b.ID == state.CurrentID {
			return false
		}
		return a.CreatedUTC > b.CreatedUTC
	})
	return index, b, nil
}
func (c *client) archiveBytes(ctx context.Context, entry archiveEntry) ([]byte, error) {
	data := make([]byte, 0, int(entry.Total))
	for offset := int64(0); offset < entry.Total; {
		length := int64(32768)
		if entry.Total-offset < length {
			length = entry.Total - offset
		}
		request, _ := json.Marshal(struct {
			ID     string `json:"id"`
			Offset int64  `json:"offset"`
			Length int64  `json:"length"`
			SHA    string `json:"expected_sha256"`
		}{entry.ID, offset, length, entry.SHA256})
		b, e := c.request(ctx, "POST", "/v1/diagnostics/chunk", bytes.NewReader(request), "", 0)
		if e != nil {
			return nil, e
		}
		var chunk archiveChunk
		if archiveDecode(b, &chunk) != nil || chunk.ID != entry.ID || chunk.Offset != offset || chunk.Total != entry.Total || chunk.SHA256 != entry.SHA256 || chunk.Complete != entry.Complete || chunk.Truncated != entry.Truncated || int64(len(chunk.Data)) != length {
			return nil, errors.New("ARCHIVE_CHUNK_INVALID")
		}
		data = append(data, chunk.Data...)
		offset += length
	}
	sum := sha256.Sum256(data)
	if hex.EncodeToString(sum[:]) != entry.SHA256 {
		return nil, errors.New("ARCHIVE_SHA256_MISMATCH")
	}
	// Even a transport-valid reply must remain the requested JSONL archive.
	for _, line := range bytes.Split(bytes.TrimSuffix(data, []byte("\n")), []byte("\n")) {
		if len(line) == 0 && len(data) == 0 {
			continue
		}
		var row struct {
			ID     string `json:"id"`
			Schema int    `json:"schema"`
		}
		if len(line) > 256<<10 || json.Unmarshal(line, &row) != nil || row.ID != entry.ID || row.Schema != 1 {
			return nil, errors.New("ARCHIVE_JSONL_INVALID")
		}
	}
	return data, nil
}
func writeArchiveFile(dir, name string, data []byte) error {
	f, e := os.OpenFile(filepath.Join(dir, name), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if e != nil {
		return errors.New("ARCHIVE_OUTPUT_FAILED")
	}
	_, e = f.Write(data)
	closeErr := f.Close()
	if e != nil || closeErr != nil {
		return errors.New("ARCHIVE_OUTPUT_FAILED")
	}
	return nil
}
func archiveFailure(e error) string {
	var response *requestFailure
	if errors.As(e, &response) {
		if response.status == 404 {
			return "unsupported"
		}
		if response.status == 409 {
			return "ARCHIVE_SNAPSHOT_CHANGED"
		}
		if response.status == 403 {
			return "ARCHIVE_AUTHORIZATION_REVOKED"
		}
	}
	for _, code := range []string{"ARCHIVE_RESPONSE_INVALID", "ARCHIVE_INDEX_INVALID", "ARCHIVE_CHUNK_INVALID", "ARCHIVE_SHA256_MISMATCH", "ARCHIVE_JSONL_INVALID", "ARCHIVE_OUTPUT_FAILED"} {
		if e.Error() == code {
			return code
		}
	}
	return "ARCHIVE_TRANSFER_UNAVAILABLE"
}
func collectArchives(ctx context.Context, c *client, outputDir string, output io.Writer) error {
	if e := os.MkdirAll(outputDir, 0700); e != nil {
		return errors.New("ARCHIVE_OUTPUT_FAILED")
	}
	dir, e := os.MkdirTemp(outputDir, "capture-")
	if e != nil {
		return errors.New("ARCHIVE_OUTPUT_FAILED")
	}
	receipt := archiveCollection{Schema: 1, Status: "complete", Archives: []archiveTransfer{}}
	index, raw, e := c.archiveIndex(ctx)
	if e != nil {
		receipt.Status = "failed"
		receipt.Error = archiveFailure(e)
		if receipt.Error == "unsupported" {
			receipt.Status = "unsupported"
		}
	} else {
		if e = writeArchiveFile(dir, "index.json", raw); e != nil {
			return e
		}
		for _, entry := range index.Entries {
			var data []byte
			for retry := 0; retry < 3; retry++ {
				data, e = c.archiveBytes(ctx, entry)
				var response *requestFailure
				if e == nil || entry.Complete || !errors.As(e, &response) || response.status != http.StatusConflict || retry == 2 {
					break
				}
				updated, _, readErr := c.archiveIndex(ctx)
				if readErr != nil {
					e = readErr
					break
				}
				found := false
				for _, next := range updated.Entries {
					if next.ID == entry.ID {
						entry = next
						found = true
						break
					}
				}
				if !found {
					e = errors.New("ARCHIVE_INDEX_INVALID")
					break
				}
			}
			result := archiveTransfer{Entry: entry}
			if e == nil {
				e = writeArchiveFile(dir, entry.ID+".jsonl", data)
			}
			if e == nil {
				result.Bytes = int64(len(data))
				result.Verified = true
				meta, _ := json.MarshalIndent(entry, "", "  ")
				e = writeArchiveFile(dir, entry.ID+".index.json", meta)
			}
			if e != nil {
				result.Error = archiveFailure(e)
				receipt.Status = "partial"
			}
			receipt.Archives = append(receipt.Archives, result)
		}
	}
	encoded, _ := json.MarshalIndent(receipt, "", "  ")
	if e = writeArchiveFile(dir, "transfer.json", encoded); e != nil {
		return e
	}
	_, e = fmt.Fprintln(output, "Archive collection:", receipt.Status, "(transport verification is separate from capture completeness)")
	if e == nil && (receipt.Status == "failed" || receipt.Status == "partial") {
		return errors.New("ARCHIVE_COLLECTION_INCOMPLETE")
	}
	return e
}
