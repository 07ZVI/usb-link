//go:build darwin && usblink_local_remote

package localupdate

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func archiveFixture(id string) (archiveEntry, []byte) {
	line, _ := json.Marshal(map[string]any{"schema": 1, "id": id, "value": strings.Repeat("v", 17000)})
	data := append(append(append([]byte{}, line...), '\n'), line...)
	data = append(data, '\n')
	sum := sha256.Sum256(data)
	return archiveEntry{ID: id, Total: int64(len(data)), SHA256: hex.EncodeToString(sum[:]), Complete: true}, data
}
func archiveReply(v any) *http.Response { b, _ := json.Marshal(v); return reply(string(b)) }
func TestArchiveChunkIdentityBoundsAndHash(t *testing.T) {
	entry, data := archiveFixture(strings.Repeat("a", 32))
	for _, mode := range []string{"valid", "duplicate-offset", "changed-sha", "unknown-id", "corrupt-data", "short"} {
		t.Run(mode, func(t *testing.T) {
			c := &client{token: "test", http: &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
				var q struct {
					Offset int64  `json:"offset"`
					Length int    `json:"length"`
					SHA    string `json:"expected_sha256"`
				}
				_ = json.NewDecoder(r.Body).Decode(&q)
				if r.URL.Path != "/v1/diagnostics/chunk" || q.Length > 32768 || q.SHA != entry.SHA256 {
					t.Fatal("invalid fixed request")
				}
				chunk := archiveChunk{ID: entry.ID, Offset: q.Offset, Total: entry.Total, SHA256: entry.SHA256, Data: append([]byte{}, data[q.Offset:q.Offset+int64(q.Length)]...), Complete: true}
				switch mode {
				case "duplicate-offset":
					chunk.Offset = 0
				case "changed-sha":
					chunk.SHA256 = strings.Repeat("b", 64)
				case "unknown-id":
					chunk.ID = strings.Repeat("b", 32)
				case "corrupt-data":
					chunk.Data[0] ^= 1
				case "short":
					chunk.Data = chunk.Data[:len(chunk.Data)-1]
				}
				return archiveReply(chunk), nil
			})}}
			result, e := c.archiveBytes(context.Background(), entry)
			if mode == "valid" {
				if e != nil || !bytes.Equal(result, data) {
					t.Fatal(e)
				}
			} else if e == nil {
				t.Fatal("accepted", mode)
			}
		})
	}
}
func TestArchiveActiveSnapshotRetriesAndRecordsTransportProof(t *testing.T) {
	entry, data := archiveFixture(strings.Repeat("a", 32))
	entry.Complete = false
	indices, chunks := 0, 0
	c := &client{http: &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		if r.URL.Path == "/v1/diagnostics/index" {
			indices++
			return archiveReply(archiveIndex{Schema: 1, Entries: []archiveEntry{entry}, Diagnostics: json.RawMessage(`{"current_id":"` + entry.ID + `"}`)}), nil
		}
		chunks++
		if chunks == 1 {
			return &http.Response{StatusCode: 409, Body: io.NopCloser(strings.NewReader("changed"))}, nil
		}
		var q struct {
			Offset int64 `json:"offset"`
			Length int   `json:"length"`
		}
		_ = json.NewDecoder(r.Body).Decode(&q)
		return archiveReply(archiveChunk{ID: entry.ID, Offset: q.Offset, Total: entry.Total, SHA256: entry.SHA256, Data: data[q.Offset : q.Offset+int64(q.Length)]}), nil
	})}}
	dir := t.TempDir()
	if e := collectArchives(context.Background(), c, dir, io.Discard); e != nil {
		t.Fatal(e)
	}
	paths, _ := filepath.Glob(filepath.Join(dir, "capture-*", "transfer.json"))
	if len(paths) != 1 {
		t.Fatal(paths)
	}
	b, _ := os.ReadFile(paths[0])
	var receipt archiveCollection
	_ = json.Unmarshal(b, &receipt)
	if indices != 2 || receipt.Status != "complete" || len(receipt.Archives) != 1 || !receipt.Archives[0].Verified || receipt.Archives[0].Entry.Complete {
		t.Fatal(indices, string(b))
	}
	saved, _ := os.ReadFile(filepath.Join(filepath.Dir(paths[0]), entry.ID+".jsonl"))
	if !bytes.Equal(saved, data) {
		t.Fatal("archive differs")
	}
}
func TestArchiveIndexAndUnsupported(t *testing.T) {
	entry, _ := archiveFixture(strings.Repeat("a", 32))
	c := &client{http: &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		return archiveReply(archiveIndex{Schema: 1, Entries: []archiveEntry{entry, entry}, Diagnostics: json.RawMessage(`{}`)}), nil
	})}}
	if _, _, e := c.archiveIndex(context.Background()); e == nil {
		t.Fatal("duplicate archive ID accepted")
	}
	c.http.Transport = roundTripFunc(func(*http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: 404, Body: io.NopCloser(strings.NewReader("private server body"))}, nil
	})
	dir := t.TempDir()
	var out bytes.Buffer
	if e := collectArchives(context.Background(), c, dir, &out); e != nil {
		t.Fatal(e)
	}
	paths, _ := filepath.Glob(filepath.Join(dir, "capture-*", "transfer.json"))
	b, _ := os.ReadFile(paths[0])
	if !bytes.Contains(b, []byte("unsupported")) || strings.Contains(out.String(), "private") {
		t.Fatal(string(b), out.String())
	}
}
func TestArchiveFlagsNeverDispatchInstallOrSigning(t *testing.T) {
	for _, extra := range []string{"--status", "--cancel", "--stage-only", "--exe=x", "--manifest=x", "--sign-key=x", "--version=1.0.0", "--init-key=x", "--status=false"} {
		if e := run([]string{"--collect-archives", t.TempDir(), extra}, io.Discard); e == nil || !strings.Contains(e.Error(), "accepts only") {
			t.Fatal(extra, e)
		}
	}
}

func TestArchiveSnapshotRetriesAreBounded(t *testing.T) {
	entry, _ := archiveFixture(strings.Repeat("a", 32))
	entry.Complete = false
	indices, chunks := 0, 0
	c := &client{http: &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		if r.URL.Path == "/v1/diagnostics/index" {
			indices++
			return archiveReply(archiveIndex{Schema: 1, Entries: []archiveEntry{entry}, Diagnostics: json.RawMessage(`{}`)}), nil
		}
		chunks++
		return &http.Response{StatusCode: 409, Body: io.NopCloser(strings.NewReader("changed"))}, nil
	})}}
	dir := t.TempDir()
	if e := collectArchives(context.Background(), c, dir, io.Discard); e == nil {
		t.Fatal("incomplete collection must not report success")
	}
	if indices != 3 || chunks != 3 {
		t.Fatal(indices, chunks)
	}
	paths, _ := filepath.Glob(filepath.Join(dir, "capture-*", "transfer.json"))
	b, _ := os.ReadFile(paths[0])
	if !bytes.Contains(b, []byte("ARCHIVE_SNAPSHOT_CHANGED")) {
		t.Fatal(string(b))
	}
	files, _ := filepath.Glob(filepath.Join(dir, "capture-*", "*.jsonl"))
	if len(files) != 0 {
		t.Fatal("unverified archive persisted")
	}
}

func TestArchiveLargeEnvironmentLineSpansBoundedChunks(t *testing.T) {
	id := strings.Repeat("a", 32)
	data, _ := json.Marshal(map[string]any{"schema": 1, "id": id, "kind": "environment_baseline", "value": strings.Repeat("x", 128<<10)})
	data = append(data, '\n')
	sum := sha256.Sum256(data)
	entry := archiveEntry{ID: id, Total: int64(len(data)), SHA256: hex.EncodeToString(sum[:]), Complete: true}
	calls := 0
	c := &client{http: &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		calls++
		var q struct {
			Offset int64 `json:"offset"`
			Length int64 `json:"length"`
		}
		_ = json.NewDecoder(r.Body).Decode(&q)
		if q.Length > 32768 {
			t.Fatal("oversized HTTP chunk")
		}
		return archiveReply(archiveChunk{ID: id, Offset: q.Offset, Total: entry.Total, SHA256: entry.SHA256, Complete: true, Data: data[q.Offset : q.Offset+q.Length]}), nil
	})}}
	got, e := c.archiveBytes(context.Background(), entry)
	if e != nil || !bytes.Equal(got, data) || calls < 5 {
		t.Fatal(e, calls)
	}
}
