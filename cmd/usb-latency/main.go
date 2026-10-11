// usb-latency observes 64-byte authenticated UDP round trips on the USB subnet.
// It never changes firewall policy or accepts arbitrary hosts/ports.
package main

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
	"math"
	"net"
	"os"
	"os/signal"
	"runtime"
	"sort"
	"sync"
	"time"
)

const port = 10691

var magic = []byte("USBLRTT1")
var kernelTimestamps bool

type arrivalStamp struct {
	Sequence             uint64  `json:"sequence"`
	SendNS               int64   `json:"send_elapsed_ns"`
	ReadNS               int64   `json:"read_elapsed_ns"`
	SendUnixNS           int64   `json:"send_unix_ns"`
	KernelUnixNS         int64   `json:"kernel_receive_unix_ns"`
	ReadUnixNS           int64   `json:"read_unix_ns"`
	KernelRTTMS          float64 `json:"kernel_rtt_ms"`
	UserDelayMS          float64 `json:"kernel_to_read_ms"`
	WallMonoDifferenceMS float64 `json:"wall_monotonic_difference_ms"`
}

type secret struct {
	Key   string `json:"key"`
	Nonce string `json:"nonce"`
}
type credentials struct{ key, nonce []byte }

func newCredentials(path string) error {
	var k [32]byte
	var n [16]byte
	if _, e := rand.Read(k[:]); e != nil {
		return e
	}
	if _, e := rand.Read(n[:]); e != nil {
		return e
	}
	f, e := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if e != nil {
		return e
	}
	defer f.Close()
	return json.NewEncoder(f).Encode(secret{hex.EncodeToString(k[:]), hex.EncodeToString(n[:])})
}
func readCredentials(path string) (credentials, error) {
	var s secret
	b, e := os.ReadFile(path)
	if e != nil {
		return credentials{}, e
	}
	if len(b) > 256 {
		return credentials{}, fmt.Errorf("invalid credential size")
	}
	d := json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	if e = d.Decode(&s); e != nil {
		return credentials{}, e
	}
	k, e := hex.DecodeString(s.Key)
	if e != nil || len(k) != 32 {
		return credentials{}, fmt.Errorf("invalid key")
	}
	n, e := hex.DecodeString(s.Nonce)
	if e != nil || len(n) != 16 {
		return credentials{}, fmt.Errorf("invalid nonce")
	}
	return credentials{k, n}, nil
}
func packet(c credentials, seq uint64) []byte {
	b := make([]byte, 64)
	copy(b, magic)
	copy(b[8:24], c.nonce)
	binary.BigEndian.PutUint64(b[24:32], seq)
	h := hmac.New(sha256.New, c.key)
	h.Write(b[:48])
	copy(b[48:], h.Sum(nil)[:16])
	return b
}
func authenticate(c credentials, b []byte) (uint64, bool) {
	if len(b) != 64 || !bytes.Equal(b[:8], magic) || !bytes.Equal(b[8:24], c.nonce) {
		return 0, false
	}
	h := hmac.New(sha256.New, c.key)
	h.Write(b[:48])
	return binary.BigEndian.Uint64(b[24:32]), hmac.Equal(h.Sum(nil)[:16], b[48:])
}

type result struct {
	Method                                                            string  `json:"method"`
	Scenario                                                          string  `json:"scenario"`
	Started                                                           string  `json:"started_utc"`
	Seconds                                                           float64 `json:"seconds"`
	Sent, Received, Loss, Duplicates, Reordered, SkippedScheduleSlots uint64
	P50                                                               *float64       `json:"p50_ms"`
	P99                                                               *float64       `json:"p99_ms"`
	Max                                                               *float64       `json:"max_ms"`
	ActualPPS                                                         float64        `json:"actual_packets_per_second"`
	Samples                                                           []float64      `json:"rtt_ms"`
	Error                                                             string         `json:"error,omitempty"`
	Timeline                                                          []arrivalStamp `json:"timeline,omitempty"`
}

func summarize(v []float64) (*float64, *float64, *float64) {
	if len(v) == 0 {
		return nil, nil, nil
	}
	a := append([]float64(nil), v...)
	sort.Float64s(a)
	p50 := a[int(math.Ceil(.5*float64(len(a))))-1]
	p99 := a[int(math.Ceil(.99*float64(len(a))))-1]
	max := a[len(a)-1]
	return &p50, &p99, &max
}
func serve(ctx context.Context, c credentials, peer string, duration time.Duration) (any, error) {
	conn, e := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP("10.6.9.1"), Port: port})
	if e != nil {
		return nil, e
	}
	defer conn.Close()
	undo := context.AfterFunc(ctx, func() { conn.Close() })
	defer undo()
	expires := time.Now().Add(duration)
	conn.SetReadDeadline(expires)
	var echoed, invalid, limited uint64
	seen := make([]bool, 12001)
	buf := make([]byte, 65536)
	tokens := 32.0
	last := time.Now()
	maxSeq := uint64(duration.Seconds() * 100)
	for {
		n, from, e := conn.ReadFromUDP(buf)
		if e != nil {
			if ctx.Err() != nil {
				break
			}
			if v, ok := e.(net.Error); ok && v.Timeout() {
				break
			}
			return nil, e
		}
		seq, ok := authenticate(c, buf[:n])
		if !ok || from.IP.String() != peer || seq >= maxSeq || seen[seq] {
			invalid++
			continue
		}
		now := time.Now()
		tokens = math.Min(32, tokens+now.Sub(last).Seconds()*100)
		last = now
		if tokens < 1 {
			limited++
			continue
		}
		tokens--
		seen[seq] = true
		conn.SetWriteDeadline(now.Add(time.Second))
		if _, e = conn.WriteToUDP(buf[:n], from); e != nil {
			return nil, e
		}
		echoed++
	}
	return map[string]any{"method": "UDP64 authenticated echo; payload bytes only", "echoed": echoed, "invalid_or_duplicate": invalid, "rate_limited": limited, "interrupted": ctx.Err() != nil}, nil
}
func client(ctx context.Context, c credentials, peer string, duration time.Duration, scenario string) (result, error) {
	return clientMode(ctx, c, peer, duration, scenario, false)
}
func clientMode(ctx context.Context, c credentials, peer string, duration time.Duration, scenario string, isICMP bool) (result, error) {
	out := result{Method: "UDP64 RTT; includes both directions, host scheduling and socket processing; not video one-way delay", Scenario: scenario}
	var conn echoTransport
	var e error
	if isICMP {
		out.Method = "ICMP echo with authenticated 64-byte payload; Windows kernel reply; RTT includes both directions and client scheduling"
		var pc *icmp.PacketConn
		pc, e = icmp.ListenPacket("udp4", peer)
		if e == nil {
			conn = &icmpEchoTransport{PacketConn: pc, peer: net.ParseIP("10.6.9.1"), id: os.Getpid() & 0xffff}
		}
	} else {
		var udp *net.UDPConn
		udp, e = net.DialUDP("udp4", &net.UDPAddr{IP: net.ParseIP(peer)}, &net.UDPAddr{IP: net.ParseIP("10.6.9.1"), Port: port})
		if e == nil {
			conn = udp
			if kernelTimestamps {
				conn, e = timestamped(udp)
				if e != nil {
					udp.Close()
				}
			}
		}
	}
	if e != nil {
		return out, e
	}
	defer conn.Close()
	undo := context.AfterFunc(ctx, func() { conn.Close() })
	defer undo()
	count := int(duration.Seconds() * 100)
	sent := make([]time.Time, count)
	seen := make([]bool, count)
	var mu sync.Mutex
	var receiveErr error
	var lastSeq uint64
	haveSeq := false
	done := make(chan struct{})
	start := time.Now()
	out.Started = start.UTC().Format(time.RFC3339Nano)
	conn.SetReadDeadline(start.Add(duration + 500*time.Millisecond))
	go func() {
		defer close(done)
		buf := make([]byte, 65)
		for {
			n, e := conn.Read(buf)
			if e != nil {
				if v, ok := e.(net.Error); !ok || !v.Timeout() {
					receiveErr = e
				}
				return
			}
			arrival := time.Now()
			seq, ok := authenticate(c, buf[:n])
			if !ok || seq >= uint64(count) {
				continue
			}
			mu.Lock()
			if sent[seq].IsZero() {
				mu.Unlock()
				continue
			}
			if seen[seq] {
				out.Duplicates++
				mu.Unlock()
				continue
			}
			seen[seq] = true
			out.Received++
			out.Samples = append(out.Samples, arrival.Sub(sent[seq]).Seconds()*1000)
			if k, ok := conn.(interface{ KernelReceived() (time.Time, bool) }); ok {
				if kernel, valid := k.KernelReceived(); valid {
					monoMS := arrival.Sub(sent[seq]).Seconds() * 1000
					wallMS := float64(arrival.UnixNano()-sent[seq].UnixNano()) / 1e6
					out.Timeline = append(out.Timeline, arrivalStamp{seq, sent[seq].Sub(start).Nanoseconds(), arrival.Sub(start).Nanoseconds(), sent[seq].UnixNano(), kernel.UnixNano(), arrival.UnixNano(), float64(kernel.UnixNano()-sent[seq].UnixNano()) / 1e6, float64(arrival.UnixNano()-kernel.UnixNano()) / 1e6, wallMS - monoMS})
				}
			}
			if haveSeq && seq < lastSeq {
				out.Reordered++
			}
			if !haveSeq || seq > lastSeq {
				lastSeq = seq
			}
			haveSeq = true
			mu.Unlock()
		}
	}()
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			out.Error = "interrupted"
			goto finish
		case <-ticker.C:
			now := time.Now()
			slot := int(now.Sub(start)/(10*time.Millisecond)) - 1
			if slot >= count {
				goto finish
			}
			if slot < 0 {
				continue
			}
			mu.Lock()
			if !sent[slot].IsZero() {
				mu.Unlock()
				continue
			}
			sent[slot] = now
			mu.Unlock()
			if _, e = conn.Write(packet(c, uint64(slot))); e != nil {
				out.Error = e.Error()
				goto finish
			}
			out.Sent++
		}
	}
finish:
	if out.Error != "" {
		conn.Close()
	}
	<-done
	out.Seconds = time.Since(start).Seconds()
	out.SkippedScheduleSlots = uint64(count) - out.Sent
	out.Loss = out.Sent - out.Received
	out.ActualPPS = float64(out.Sent) / duration.Seconds()
	out.P50, out.P99, out.Max = summarize(out.Samples)
	if receiveErr != nil && ctx.Err() == nil && out.Error == "" {
		out.Error = receiveErr.Error()
	}
	if out.Sent == 0 && out.Error == "" {
		out.Error = "no packets sent"
	}
	return out, nil
}
func main() {
	if e := run(); e != nil {
		fmt.Fprintln(os.Stderr, e)
		os.Exit(1)
	}
}
func run() error {
	mode := flag.String("mode", "client", "keygen, server, client, or icmp-client")
	key := flag.String("key-file", "", "new per-run credential file; never a command-line secret")
	peer := flag.String("peer", "10.6.9.2", "authorized USB peer .2 (Mac) or .3 (iPad native client)")
	duration := flag.Duration("duration", 30*time.Second, "1s..120s; use a longer server lease than client run plus startup margin")
	output := flag.String("output", "", "new JSON result path")
	scenario := flag.String("scenario", "idle", "scenario label")
	flag.BoolVar(&kernelTimestamps, "kernel-timestamps", false, "Darwin UDP only: record SO_TIMESTAMP ancillary receive times and application reads")
	flag.Parse()
	if kernelTimestamps && *mode != "client" {
		return fmt.Errorf("kernel timestamps require UDP client mode")
	}
	if *key == "" {
		return fmt.Errorf("key-file required")
	}
	if *mode == "keygen" {
		return newCredentials(*key)
	}
	if *duration < time.Second || *duration > 120*time.Second || (*peer != "10.6.9.2" && *peer != "10.6.9.3") {
		return fmt.Errorf("duration or USB peer invalid")
	}
	if *mode == "server" && runtime.GOOS != "windows" {
		return fmt.Errorf("echo server runs only on Windows")
	}
	if *mode != "server" && *mode != "client" && *mode != "icmp-client" {
		return fmt.Errorf("invalid mode")
	}
	if *output == "" {
		return fmt.Errorf("output required")
	}
	c, e := readCredentials(*key)
	if e != nil {
		return e
	}
	f, e := os.OpenFile(*output, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if e != nil {
		return e
	}
	defer f.Close()
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	var v any
	if *mode == "server" {
		v, e = serve(ctx, c, *peer, *duration)
	} else {
		v, e = clientMode(ctx, c, *peer, *duration, *scenario, *mode == "icmp-client")
	}
	if e != nil {
		return e
	}
	if e = json.NewEncoder(f).Encode(v); e != nil {
		return e
	}
	return f.Sync()
}

// Darwin's datagram ICMP socket needs no raw-socket privilege. Payload HMAC,
// peer and type are checked; the kernel may rewrite the echo identifier.
type echoTransport interface {
	Read([]byte) (int, error)
	Write([]byte) (int, error)
	Close() error
	SetReadDeadline(time.Time) error
}
type icmpEchoTransport struct {
	*icmp.PacketConn
	peer net.IP
	id   int
	buf  [128]byte
}

func (c *icmpEchoTransport) Write(b []byte) (int, error) {
	seq := int(binary.BigEndian.Uint64(b[24:32]) & 0xffff)
	m := icmp.Message{Type: ipv4.ICMPTypeEcho, Code: 0, Body: &icmp.Echo{ID: c.id, Seq: seq, Data: b}}
	wire, e := m.Marshal(nil)
	if e != nil {
		return 0, e
	}
	_, e = c.WriteTo(wire, &net.UDPAddr{IP: c.peer})
	if e != nil {
		return 0, e
	}
	return len(b), nil
}
func (c *icmpEchoTransport) Read(b []byte) (int, error) {
	n, from, e := c.ReadFrom(c.buf[:])
	if e != nil {
		return 0, e
	}
	ip := net.ParseIP(from.String())
	if u, ok := from.(*net.UDPAddr); ok {
		ip = u.IP
	}
	if ip == nil || !ip.Equal(c.peer) {
		return 0, nil
	}
	m, e := icmp.ParseMessage(1, c.buf[:n])
	if e != nil || m.Type != ipv4.ICMPTypeEchoReply || m.Code != 0 {
		return 0, nil
	}
	body, ok := m.Body.(*icmp.Echo)
	if !ok || len(body.Data) != 64 {
		return 0, nil
	}
	return copy(b, body.Data), nil
}
