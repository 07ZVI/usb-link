//go:build windows && amd64

package usbrecovery

import (
	"context"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"regexp"
	"suhang/usbnet/internal/transport/macdhcp"
	"suhang/usbnet/internal/transport/ncm"
	"suhang/usbnet/internal/transport/winusb"
	"sync"
	"time"
)

var helloPattern = regexp.MustCompile(`^USB-LINK-RECOVERY/1 ([a-f0-9]{32})$`)

// Run owns only the existing Mac WinUSB function, DHCP and fixed maintenance
// datagrams. It creates no Wintun adapter, OS listener, route or firewall rule.
func Run(ctx context.Context, l *log.Logger, enabled func() bool, attached func(bool), invitation func() ([]byte, error), api func() (http.Handler, *tls.Config, error), diagnostic func(string) ([]byte, error)) error {
	if !enabled() {
		return fmt.Errorf("developer debugging is disabled")
	}
	lease, e := winusb.OwnRuntime()
	if e != nil {
		return e
	}
	defer lease()
	device, e := winusb.InitializeNCM(0, false, 0, l)
	if e != nil {
		return e
	}
	defer device.Close()
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	attached(true)
	defer attached(false)
	ncm.WindowsIP = [4]byte{10, 6, 9, 1}
	ncm.MacIP = [4]byte{10, 6, 9, 2}
	dhcp := macdhcp.Server{Local: ncm.WindowsIP, Peer: ncm.MacIP}
	r, e := winusb.NewRead(device.ReadSize)
	if e != nil {
		return e
	}
	defer device.Data.CloseReads([]*winusb.Read{r})
	if e = device.Data.Submit(r, device.In.ID); e != nil {
		return e
	}
	var txMu sync.Mutex
	var seq uint16
	send := func(frames [][]byte) error {
		txMu.Lock()
		defer txMu.Unlock()
		for _, f := range frames {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			if len(f) == 0 {
				continue
			}
			b, e := ncm.EncodeInto(nil, [][]byte{f}, seq, device.Parameters)
			if e != nil {
				return e
			}
			seq++
			if e = device.Data.Write(device.Out.ID, b, 2*time.Second); e != nil {
				return e
			}
		}
		return nil
	}
	var conn *Conn
	var session string
	var tlsServer *http.Server
	var listener *SingleListener
	var workers sync.WaitGroup
	closeSession := func() {
		if conn != nil {
			conn.Close()
		}
		if listener != nil {
			listener.Close()
		}
		if tlsServer != nil {
			tlsServer.Close()
		}
	}
	defer func() { cancel(); closeSession(); workers.Wait() }()
	var peer [6]byte
	stream := ncm.Stream{}
	var lastDiagnostic time.Time
	var lastNonce string
	var diagnosticFrames [][]byte
	for ctx.Err() == nil {
		if !enabled() {
			return fmt.Errorf("developer debugging disabled")
		}
		ready, e := r.Ready(50)
		if e != nil {
			return e
		}
		if !ready {
			continue
		}
		b, e := device.Data.Result(r, false)
		if e != nil {
			return e
		}
		blocks, e := stream.Feed(b)
		if e != nil {
			return e
		}
		if e = device.Data.Submit(r, device.In.ID); e != nil {
			return e
		}
		for _, block := range blocks {
			for _, frame := range block.Frames {
				reply, consumed, failure := dhcp.Handle(frame, peer, time.Now())
				if failure != "" {
					return fmt.Errorf("%s", failure)
				}
				if consumed {
					if e = send([][]byte{reply}); e != nil {
						return e
					}
					peer = dhcp.MAC
					continue
				}
				eth, e := ncm.ParseEthernet(frame)
				if e != nil {
					continue
				}
				if peer != [6]byte{} && eth.Source != peer {
					continue
				}
				if reply, mac, e := ncm.ARPReply(frame); e == nil && reply != nil {
					if peer == [6]byte{} {
						peer = mac
					}
					if e = send([][]byte{reply}); e != nil {
						return e
					}
					continue
				}
				if peer == [6]byte{} {
					continue
				}
				if nonce, mac, ok := ncm.DiagnosticRequest(frame); ok && mac == peer {
					if time.Since(lastDiagnostic) < time.Second {
						continue
					}
					lastDiagnostic = time.Now()
					if nonce != lastNonce {
						content, e := diagnostic(nonce)
						if e != nil || len(content) > 256*1024 {
							continue
						}
						diagnosticFrames, e = ncm.DiagnosticFrames(content, nonce, peer)
						if e != nil {
							continue
						}
						lastNonce = nonce
					}
					if e = send(diagnosticFrames); e != nil {
						return e
					}
					continue
				}
				payload, mac, ok := ncm.USBUDPRequest(frame, Port)
				if !ok || mac != peer {
					continue
				}
				if match := helloPattern.FindSubmatch(payload); match != nil {
					nonce := string(match[1])
					if conn != nil && nonce != session {
						select {
						case <-conn.Done():
						default:
							continue
						}
					}
					inv, e := invitation()
					if e != nil {
						continue
					}
					if len(inv) > 1024 || !json.Valid(inv) {
						continue
					}
					if conn == nil || nonce != session {
						closeSession()
						decoded, _ := hex.DecodeString(nonce)
						var id [16]byte
						copy(id[:], decoded)
						peerMAC := peer
						conn = NewConn(ctx, id, func(p []byte) error { return send([][]byte{ncm.USBUDPFrame(p, peerMAC, Port)}) })
						session = nonce
						h, config, e := api()
						if e != nil {
							conn.Close()
							conn = nil
							continue
						}
						listener = NewListener(conn)
						tlsServer = &http.Server{Handler: h, ReadHeaderTimeout: 10 * time.Second, ReadTimeout: 180 * time.Second, WriteTimeout: 180 * time.Second, IdleTimeout: 10 * time.Second, MaxHeaderBytes: 8192}
						server, listen, active := tlsServer, listener, conn
						workers.Add(2)
						go func() { defer workers.Done(); server.Serve(tls.NewListener(listen, config)); active.Close() }()
						go func() { defer workers.Done(); <-active.Done(); listen.Close(); server.Close() }()
					}
					response := append([]byte(Hello+nonce+" "), inv...)
					if e = send([][]byte{ncm.USBUDPFrame(response, peer, Port)}); e != nil {
						return e
					}
					continue
				}
				if conn != nil {
					conn.Ingest(payload)
				}
			}
		}
	}
	return ctx.Err()
}
