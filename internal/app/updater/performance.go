package updater

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"
)

func collectPerformance(ctx context.Context, client *http.Client, base, token, kind string, seconds int, output, speedClient, specifiedNonce string) error {
	if output == "" {
		return fmt.Errorf("profile output required")
	}
	var nonceBytes [16]byte
	if _, e := rand.Read(nonceBytes[:]); e != nil {
		return e
	}
	nonce := hex.EncodeToString(nonceBytes[:])
	if specifiedNonce != "" {
		if !validPublicMeasurementID(specifiedNonce) {
			return fmt.Errorf("invalid measurement id")
		}
		nonce = specifiedNonce
	}
	data, _ := json.Marshal(map[string]any{"kind": kind, "seconds": seconds, "nonce": nonce})
	q, e := http.NewRequestWithContext(ctx, "POST", base+"/v1/performance", strings.NewReader(string(data)))
	if e != nil {
		return e
	}
	q.Header.Set("Authorization", "Bearer "+token)
	q.Header.Set("Content-Type", "application/json")
	r, e := client.Do(q)
	if e != nil {
		return e
	}
	defer r.Body.Close()
	if r.StatusCode != 200 {
		b, _ := io.ReadAll(io.LimitReader(r.Body, 1024))
		return fmt.Errorf("capture server %d: %s", r.StatusCode, b)
	}
	reader := bufio.NewReaderSize(r.Body, 4096)
	line, e := reader.ReadString('\n')
	if e != nil {
		return e
	}
	var speed *exec.Cmd
	var log *os.File
	if strings.TrimSpace(line) == "READY "+nonce {
		if speedClient != "" {
			if kind != "CPU" && kind != "TRACE" {
				return fmt.Errorf("speed client requires timed profile")
			}
			log, e = os.OpenFile(output+".client.log", os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
			if e != nil {
				return e
			}
			defer log.Close()
			speed = exec.CommandContext(ctx, speedClient, "--start", "--once", "--output", output+".throughput.json")
			speed.Stdout = log
			speed.Stderr = log
			if e = speed.Start(); e != nil {
				return e
			}
			defer func() {
				if speed.ProcessState == nil {
					speed.Process.Kill()
					speed.Wait()
				}
			}()
		}
		line, e = reader.ReadString('\n')
		if e != nil {
			return e
		}
	}
	fields := strings.Fields(line)
	if len(fields) != 4 || fields[0] != "DONE" || fields[1] != nonce {
		return fmt.Errorf("invalid capture header")
	}
	n, e := strconv.ParseInt(fields[2], 10, 64)
	if e != nil || n < 1 || n > 64<<20 || len(fields[3]) != 64 {
		return fmt.Errorf("capture bounds")
	}
	file, e := os.OpenFile(output+".part", os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if e != nil {
		return e
	}
	success := false
	defer func() {
		file.Close()
		if !success {
			os.Remove(output + ".part")
		}
	}()
	h := sha256.New()
	got, e := io.CopyN(io.MultiWriter(file, h), reader, n)
	if e != nil || got != n {
		return fmt.Errorf("capture incomplete: %w", e)
	}
	if hex.EncodeToString(h.Sum(nil)) != fields[3] {
		return fmt.Errorf("capture hash mismatch")
	}
	if e = file.Close(); e != nil {
		return e
	}
	if _, e = os.Stat(output); e == nil {
		return fmt.Errorf("capture output exists")
	}
	if e = os.Rename(output+".part", output); e != nil {
		return e
	}
	success = true
	if speed != nil {
		if e = speed.Wait(); e != nil {
			return e
		}
	}
	receipt, _ := json.MarshalIndent(map[string]any{"kind": kind, "seconds": seconds, "bytes": n, "sha256": fields[3], "nonce": nonce, "completed_utc": time.Now().UTC().Format(time.RFC3339), "profiled_speed_is_not_acceptance": speed != nil}, "", "  ")
	if e = os.WriteFile(output+".receipt.json", append(receipt, '\n'), 0600); e != nil {
		return e
	}
	fmt.Printf("Captured %s (%d bytes): %s\n", kind, n, output)
	return nil
}

func validPublicMeasurementID(s string) bool {
	if len(s) != 32 {
		return false
	}
	for _, c := range s {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}
