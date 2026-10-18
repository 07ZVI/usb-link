// Package bench provides a bounded TCP data test, never remote commands.
package bench

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"regexp"
	"strconv"
	"strings"
	"suhang/usbnet/internal/diagnostics/latencyprobe"
	"suhang/usbnet/internal/transport/usbaddress"
	"sync"
	"time"
)

const Port = 47772
const MaxBytes = 64 * 1024 * 1024
const Chunk = 32 * 1024

var noncePattern = regexp.MustCompile(`^[a-f0-9]{32}$`)

func Pattern() []byte {
	b := make([]byte, Chunk)
	for i := range b {
		b[i] = byte(i % 251)
	}
	return b
}

type Result struct {
	Nonce     string  `json:"nonce"`
	Direction string  `json:"direction"`
	Bytes     int64   `json:"bytes"`
	SHA256    string  `json:"sha256"`
	Seconds   float64 `json:"seconds"`
	Mbps      float64 `json:"mbps"`
}

// Handle limits header size, stream size and wall time; the listener also checks peer IP.
func Handle(conn net.Conn) (Result, error) {
	return handleContext(context.Background(), conn, false)
}

func handleContext(ctx context.Context, conn net.Conn, profileOnly bool) (Result, error) {
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(35 * time.Second))
	reader := bufio.NewReaderSize(conn, 256)
	line, err := reader.ReadSlice('\n')
	if err != nil {
		return Result{}, err
	}
	fields := strings.Fields(string(line))
	if len(fields) > 0 && fields[0] == latencyprobe.Protocol {
		return Result{}, handleLatency(ctx, conn, fields)
	}
	if len(fields) > 0 && fields[0] == PerfProtocol {
		return Result{}, handlePerformance(ctx, conn, fields)
	}
	if profileOnly {
		return Result{}, fmt.Errorf("local callers may only capture diagnostics")
	}
	conn.SetDeadline(time.Now().Add(20 * time.Second))
	if len(fields) != 4 || fields[0] != "SUHANG-USB-BENCH/1" || (fields[1] != "UP" && fields[1] != "DOWN") || !noncePattern.MatchString(fields[3]) {
		return Result{}, fmt.Errorf("invalid benchmark request")
	}
	n, err := strconv.ParseInt(fields[2], 10, 64)
	if err != nil || n < 1 || n > MaxBytes {
		return Result{}, fmt.Errorf("benchmark size out of bounds")
	}
	if _, err = fmt.Fprintf(conn, "READY %s\n", fields[3]); err != nil {
		return Result{}, err
	}
	result := Result{Nonce: fields[3], Direction: fields[1]}
	start := time.Now()
	hash := sha256.New()
	if fields[1] == "UP" {
		result.Bytes, err = io.CopyN(hash, reader, n)
	} else {
		data := Pattern()
		for result.Bytes < n {
			part := data[:min(int64(len(data)), n-result.Bytes)]
			var count int
			count, err = conn.Write(part)
			hash.Write(part[:count])
			result.Bytes += int64(count)
			if err != nil {
				break
			}
			if count != len(part) {
				err = io.ErrShortWrite
				break
			}
		}
	}
	result.Seconds = time.Since(start).Seconds()
	// Coarse Windows clocks can report no elapsed time; +Inf is not valid JSON.
	if result.Seconds > 0 {
		result.Mbps = float64(result.Bytes) * 8 / result.Seconds / 1e6
	}
	result.SHA256 = hex.EncodeToString(hash.Sum(nil))
	if err != nil {
		return result, err
	}
	err = json.NewEncoder(conn).Encode(result)
	return result, err
}

type Server struct {
	listener net.Listener
	cancel   context.CancelFunc
	wg       sync.WaitGroup
	mu       sync.Mutex
	active   net.Conn
	closed   bool
}

func Start(ctx context.Context, l *log.Logger) (*Server, error) {
	return StartForProfile(ctx, l, usbaddress.Legacy)
}
func StartForProfile(ctx context.Context, l *log.Logger, profile string) (*Server, error) {
	addresses, err := usbaddress.Lookup(profile)
	if err != nil {
		return nil, err
	}
	listenAddress := addresses.Windows
	if profile == usbaddress.Unified {
		listenAddress = "127.0.0.1"
	}
	listener, err := net.Listen("tcp4", net.JoinHostPort(listenAddress, "47772"))
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithCancel(ctx)
	s := &Server{listener: listener, cancel: cancel}
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			host, _, _ := net.SplitHostPort(conn.RemoteAddr().String())
			if (profile == usbaddress.Unified && host != "127.0.0.1") || (profile != usbaddress.Unified && host != addresses.Peer) {
				conn.Close()
				continue
			}
			s.mu.Lock()
			if s.closed {
				s.mu.Unlock()
				conn.Close()
				return
			}
			s.active = conn
			s.mu.Unlock()
			result, err := handleContext(ctx, conn, profile == usbaddress.Unified)
			l.Printf("BENCH result=%+v error=%v", result, err)
			s.mu.Lock()
			s.active = nil
			s.mu.Unlock()
			if ctx.Err() != nil {
				return
			}
		}
	}()
	return s, nil
}
func (s *Server) Close() {
	defer RestoreGC()
	s.cancel()
	s.listener.Close()
	s.mu.Lock()
	s.closed = true
	if s.active != nil {
		s.active.Close()
	}
	s.mu.Unlock()
	s.wg.Wait()
}
