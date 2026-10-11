package updater

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"runtime"
	"strconv"
	"strings"
	"suhang/usbnet/internal/diagnostics/rawusb"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

type macRaw struct {
	Direction         string        `json:"direction"`
	Nonce             string        `json:"nonce"`
	IPLength          int           `json:"ip_length"`
	SentPackets       [4]uint64     `json:"sent_packets"`
	SendBufferRetries [4]uint64     `json:"send_buffer_retries"`
	SentPayloadBytes  uint64        `json:"sent_payload_bytes"`
	SendSeconds       float64       `json:"send_seconds"`
	Receive           rawusb.Counts `json:"received"`
	Errors            []string      `json:"errors"`
	UserCPUSeconds    float64       `json:"user_cpu_seconds"`
	SystemCPUSeconds  float64       `json:"system_cpu_seconds"`
}

func collectRaw(ctx context.Context, client *http.Client, base, token, kind string, seconds int, output string) error {
	if output == "" {
		return fmt.Errorf("raw output required")
	}
	if _, e := os.Stat(output); e == nil {
		return fmt.Errorf("raw output exists")
	}
	direction, _, closed, ok := rawusb.Command(kind)
	if !ok {
		return fmt.Errorf("raw command")
	}
	var nonce [16]byte
	if _, e := rand.Read(nonce[:]); e != nil {
		return e
	}
	nonceString := hex.EncodeToString(nonce[:])
	m := macRaw{Direction: direction, Nonce: nonceString}
	userStart, systemStart := processCPU()
	var udp *net.UDPConn
	var counter *rawusb.Counter
	var receiving sync.WaitGroup
	var stopRead atomic.Bool
	var drainDeadline atomic.Int64
	var receiveErr error
	if direction == "windows_to_mac" {
		var e error
		udp, e = net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP("10.6.9.2"), Port: rawusb.Port})
		if e != nil {
			return e
		}
		if closed {
			udp.Close()
			udp = nil
		} else {
			defer udp.Close()
			if e = udp.SetReadBuffer(4 << 20); e != nil {
				return e
			}
			counter = rawusb.NewCounter()
			receiving.Add(1)
			go func() {
				defer receiving.Done()
				buf := make([]byte, 16000)
				for {
					if ctx.Err() != nil || stopRead.Load() && drainDeadline.Load() > 0 && time.Now().UnixNano() >= drainDeadline.Load() {
						return
					}
					udp.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
					n, addr, e := udp.ReadFromUDP(buf)
					if e != nil {
						if ne, ok := e.(net.Error); ok && ne.Timeout() {
							if stopRead.Load() || ctx.Err() != nil {
								return
							}
							continue
						}
						if !stopRead.Load() {
							receiveErr = e
						}
						return
					}
					if addr.IP.Equal(net.ParseIP("10.6.9.1")) && addr.Port == rawusb.Port {
						counter.Add(buf[:n], nonce)
					}
				}
			}()
			defer func() { stopRead.Store(true); udp.Close(); receiving.Wait() }()
		}
	}
	request, _ := json.Marshal(map[string]any{"kind": kind, "seconds": seconds, "nonce": nonceString})
	q, e := http.NewRequestWithContext(ctx, "POST", base+"/v1/performance", strings.NewReader(string(request)))
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
		return fmt.Errorf("raw server %d: %s", r.StatusCode, b)
	}
	reader := bufio.NewReaderSize(r.Body, 4096)
	line, e := reader.ReadString('\n')
	if e != nil {
		return e
	}
	fields := strings.Fields(line)
	if len(fields) != 3 || fields[0] != "READY" || fields[1] != nonceString {
		return fmt.Errorf("invalid raw readiness")
	}
	ipLength, e := strconv.Atoi(fields[2])
	if e != nil || ipLength < 8000 || ipLength > 16000 {
		return fmt.Errorf("invalid raw IP length")
	}
	m.IPLength = ipLength
	var sending sync.WaitGroup
	var sendMu sync.Mutex
	var senderDone context.CancelFunc
	if direction == "mac_to_windows" {
		if ipLength != rawusb.InputIPLength {
			return fmt.Errorf("raw input packet size changed")
		}
		// Four independent UDP sockets avoid serializing on one Go fd write lock.
		// Leave 250 ms for USB completion before the bridge closes its window.
		var senderCtx context.Context
		senderCtx, senderDone = context.WithTimeout(ctx, time.Duration(seconds)*time.Second-250*time.Millisecond)
		defer func() { senderDone(); sending.Wait() }()
		sendStart := time.Now()
		for flow := 0; flow < 4; flow++ {
			u, e := net.DialUDP("udp4", &net.UDPAddr{IP: net.ParseIP("10.6.9.2"), Port: rawusb.Port + 1 + flow}, &net.UDPAddr{IP: net.ParseIP("10.6.9.1"), Port: rawusb.Port})
			if e != nil {
				return e
			}
			if e = u.SetWriteBuffer(4 << 20); e != nil {
				u.Close()
				return e
			}
			deadline, _ := senderCtx.Deadline()
			u.SetWriteDeadline(deadline)
			sending.Add(1)
			go func(flow int, u *net.UDPConn) {
				defer sending.Done()
				defer u.Close()
				payload, _ := rawusb.Payload(ipLength, nonce, byte(flow))
				var n, retries uint64
				for senderCtx.Err() == nil {
					rawusb.Sequence(payload, n)
					size, e := u.Write(payload)
					if e != nil {
						if senderCtx.Err() != nil || time.Now().After(deadline) {
							break
						}
						if errors.Is(e, syscall.ENOBUFS) || errors.Is(e, syscall.EAGAIN) {
							retries++
							// Retry the same sequence; a rejected write is not a sent packet.
							// Yield to the kernel without applying a fixed throughput cap.
							runtime.Gosched()
							continue
						}
						if senderCtx.Err() == nil {
							sendMu.Lock()
							m.Errors = append(m.Errors, e.Error())
							sendMu.Unlock()
						}
						break
					}
					if size != len(payload) {
						sendMu.Lock()
						m.Errors = append(m.Errors, "short raw datagram write")
						sendMu.Unlock()
						break
					}
					n++
				}
				sendMu.Lock()
				m.SentPackets[flow] = n
				m.SendBufferRetries[flow] = retries
				m.SentPayloadBytes += n * uint64(len(payload))
				m.SendSeconds = max(m.SendSeconds, time.Since(sendStart).Seconds())
				sendMu.Unlock()
			}(flow, u)
		}
	}
	line, e = reader.ReadString('\n')
	if e != nil {
		return e
	}
	fields = strings.Fields(line)
	if len(fields) != 4 || fields[0] != "DONE" || fields[1] != nonceString {
		return fmt.Errorf("invalid raw result header")
	}
	n, e := strconv.ParseInt(fields[2], 10, 64)
	if e != nil || n < 1 || n > 64<<20 {
		return fmt.Errorf("raw result bounds")
	}
	data, e := io.ReadAll(io.LimitReader(reader, n+1))
	if e != nil || int64(len(data)) != n {
		return fmt.Errorf("raw result truncated")
	}
	sum := sha256.Sum256(data)
	if hex.EncodeToString(sum[:]) != fields[3] {
		return fmt.Errorf("raw result hash mismatch")
	}
	var capture rawusb.Capture
	if e = json.Unmarshal(data, &capture); e != nil {
		return e
	}
	if capture.Raw.Nonce != nonceString || capture.Raw.Kind != kind || capture.Raw.IPLength != ipLength {
		return fmt.Errorf("raw result identity mismatch")
	}
	if senderDone != nil {
		senderDone()
		sending.Wait()
	}
	if counter != nil {
		drainDeadline.Store(time.Now().Add(time.Second).UnixNano())
		stopRead.Store(true)
		receiving.Wait()
		m.Receive = counter.Stop()
		if receiveErr != nil {
			m.Errors = append(m.Errors, receiveErr.Error())
		}
	}
	userEnd, systemEnd := processCPU()
	m.UserCPUSeconds = userEnd - userStart
	m.SystemCPUSeconds = systemEnd - systemStart
	if e = writeExclusive(output, data); e != nil {
		return e
	}
	macData, _ := json.MarshalIndent(m, "", "  ")
	if e = writeExclusive(output+".mac.json", append(macData, '\n')); e != nil {
		return e
	}
	if len(capture.Profile) > 0 {
		ext := ".cpu.pprof"
		if capture.ProfileKind == "TRACE" {
			ext = ".runtime.trace"
		}
		if e = writeExclusive(output+ext, capture.Profile); e != nil {
			return e
		}
	}
	receipt, _ := json.MarshalIndent(map[string]any{"kind": kind, "nonce": nonceString, "bytes": n, "sha256": fields[3], "seconds": seconds, "closed_port": closed, "profiled_run_is_not_acceptance": capture.ProfileKind != "", "completed_utc": time.Now().UTC().Format(time.RFC3339)}, "", "  ")
	if e = writeExclusive(output+".receipt.json", append(receipt, '\n')); e != nil {
		return e
	}
	if capture.Raw.Error != "" || len(m.Errors) > 0 {
		return fmt.Errorf("raw experiment incomplete; inspect receipts")
	}
	fmt.Printf("Raw %s: %.2f MB/s USB completed, %.2f MB/s UDP payload; %s\n", kind, float64(capture.Raw.CompletedUSBBytes)/capture.Raw.Seconds/1e6, float64(capture.Raw.CompletedUDPPayloadBytes)/capture.Raw.Seconds/1e6, output)
	return nil
}
func writeExclusive(path string, data []byte) error {
	f, e := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if e != nil {
		return e
	}
	defer f.Close()
	_, e = f.Write(data)
	return e
}
