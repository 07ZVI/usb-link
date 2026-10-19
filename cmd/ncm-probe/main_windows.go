//go:build windows && amd64 && usblink_local_remote

package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"suhang/usbnet/internal/diagnostics/probecontrol"
	"suhang/usbnet/internal/transport/ncm"
	"suhang/usbnet/internal/transport/winusb"
	"time"
)

const version = "0.2.4-phase01"

func run(l *log.Logger) error {
	group := flag.Int("group", 0, "介面組：0=MI_00/01，1=MI_02/03")
	parent := flag.Bool("parent", false, "只供人工判斷後測試已綁定 WinUSB 的複合父裝置；程式不改驅動")
	list := flag.Bool("list", false, "只列出裝置，不初始化或傳輸")
	seconds := flag.Int("seconds", 30, "收發測試秒數（5–120）")
	autoStart := flag.Bool("auto-start", false, "由安裝器啟動，不等待按鍵")
	waitMac := flag.Int("wait-mac", 0, "等待 Mac 開始探測的秒數，0–600")
	flag.Parse()
	if *group < 0 || *group > 1 || *seconds < 5 || *seconds > 120 || *waitMac < 0 || *waitMac > 600 {
		return fmt.Errorf("invalid group/duration")
	}
	l.Printf("version=%s OS=%s/%s toolchain=%s group=%d parent=%v", version, runtime.GOOS, runtime.GOARCH, runtime.Version(), *group, *parent)
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt)
	defer signal.Stop(stop)
	if *list {
		_, e := winusb.Enumerate(l)
		return e
	}
	device, e := winusb.InitializeNCM(*group, *parent, uint32((*seconds+*waitMac+5)*1000), l)
	if e != nil {
		return e
	}
	defer device.Close()
	data, in, out, p, readSize := device.Data, device.In, device.Out, device.Parameters, device.ReadSize
	if !*autoStart {
		l.Printf("請在 Mac 設定本組 USB 網路介面並開始探測，準備好後按 Enter。")
		entered := make(chan error, 1)
		go func() { _, e := bufio.NewReader(os.Stdin).ReadString('\n'); entered <- e }()
		select {
		case e = <-entered:
			if e != nil {
				return e
			}
		case <-stop:
			return fmt.Errorf("test interrupted")
		}
	} else {
		l.Printf("Windows 已準備好，保持此視窗開啟；Mac 端交給 Codex 檢查。等待上限 %d 秒。", *waitMac)
	}
	var reads []*winusb.Read
	defer func() { data.CloseReads(reads); l.Print("pending reads cancelled and drained") }()
	for i := 0; i < 4; i++ {
		r, e := winusb.NewRead(readSize)
		if e != nil {
			return e
		}
		reads = append(reads, r)
		if e = data.Submit(r, in.ID); e != nil {
			return e
		}
	}
	l.Print("4 overlapped bulk reads submitted")
	l.Print(probecontrol.ReadyMarker)
	stream := ncm.Stream{}
	deadline := time.Now().Add(time.Duration(*seconds+*waitMac) * time.Second)
	macStarted := *waitMac == 0
	started := func() {
		if !macStarted {
			macStarted = true
			deadline = time.Now().Add(time.Duration(*seconds) * time.Second)
			l.Print("Mac probe traffic detected; timed test started")
		}
	}
	var frozenDiagnostics []byte

	var seq uint16
	var frames, arpReplies, echoRequests, echoReplies, pingReplies int
	echoSeq := uint16(0x1903)
	echoSent := false
	send := func(f []byte, kind string) error {
		b, e := ncm.Encode([][]byte{f}, seq, p)
		if e != nil {
			return e
		}
		seq++
		if e = data.Write(out.ID, b, 2*time.Second); e != nil {
			return e
		}
		l.Printf("TX %s NTB16 bytes=%d (USB completion only)", kind, len(b))
		return nil
	}
	for cursor := 0; time.Now().Before(deadline); cursor = (cursor + 1) % len(reads) {
		select {
		case <-stop:
			return fmt.Errorf("test interrupted")
		default:
		}
		r := reads[cursor]
		ready, e := r.Ready(50)
		if e != nil {
			return e
		}
		if !ready {
			cursor--
			if cursor < 0 {
				cursor = len(reads) - 1
			}
			continue
		}
		b, e := data.Result(r, false)
		if e != nil {
			return fmt.Errorf("Bulk IN: %w", e)
		}
		if len(b) > 0 {
			l.Printf("RX USB bytes=%d prefix=%x", len(b), b[:min(16, len(b))])
		}
		blocks, e := stream.Feed(b)
		if e != nil {
			return fmt.Errorf("NTB decode STOP: %w", e)
		}
		for _, block := range blocks {
			l.Printf("NTH16 sequence=%d NDP16 indices=%v datagrams=%d", block.Sequence, block.NDPs, len(block.Frames))
			for _, frame := range block.Frames {
				frames++
				eth, e := ncm.ParseEthernet(frame)
				if e != nil {
					return e
				}
				l.Printf("RX Ethernet %s", eth.Summary())
				reply, mac, e := ncm.ARPReply(frame)
				if e != nil {
					return e
				}
				if reply != nil {
					started()
					if mac == ncm.ProbeMAC {
						return fmt.Errorf("probe MAC collision")
					}
					if e = send(reply, "ARP reply 10.77.0.2"); e != nil {
						return e
					}
					arpReplies++
					if !echoSent {
						if e = send(ncm.EchoRequest(mac, echoSeq), "ICMP Echo Request 10.77.0.2 -> 10.77.0.1"); e != nil {
							return e
						}
						echoSent = true
						echoRequests++
					}
				}
				if reply := ncm.EchoReply(frame); reply != nil {
					started()
					if e = send(reply, "ICMP Echo Reply to Mac ping"); e != nil {
						return e
					}
					pingReplies++
				}
				if nonce, mac, ok := ncm.DiagnosticRequest(frame); ok {
					started()
					if frozenDiagnostics == nil {
						frozenDiagnostics, e = diagnostics(*group)
						if e != nil {
							return e
						}
					}
					packets, err := ncm.DiagnosticFrames(frozenDiagnostics, nonce, mac)
					if err != nil {
						return err
					}
					for _, packet := range packets {
						b, err := ncm.Encode([][]byte{packet}, seq, p)
						if err != nil {
							return err
						}
						seq++
						if err = data.Write(out.ID, b, 2*time.Second); err != nil {
							return err
						}
					}
					l.Printf("sent fixed diagnostic snapshot: chunks=%d bytes=%d", len(packets), len(frozenDiagnostics))
				}
				if ncm.IsProbeEchoReply(frame, echoSeq) && echoSent {
					echoReplies++
					l.Print("RX matching probe ICMP Echo Reply: bidirectional packet evidence")
				}
			}
		}
		if e = data.Submit(r, in.ID); e != nil {
			return e
		}
	}
	l.Printf("SUMMARY frames=%d arp_replies_written=%d echo_requests_written=%d matching_echo_replies=%d mac_ping_replies_written=%d pending_stream_bytes=%d", frames, arpReplies, echoRequests, echoReplies, pingReplies, len(stream.Pending))
	if frames == 0 {
		return fmt.Errorf("STOP: no Mac frames; after manual review test other group once; no blind retry/kernel fallback")
	}
	if arpReplies == 0 || echoRequests == 0 {
		return fmt.Errorf("STOP: no ARP from 10.77.0.1 for 10.77.0.2; check phase0 mapping/configuration")
	}
	l.Print("RESULT=PENDING_MAC_CAPTURE; return Mac tcpdump log and Windows log; stage2 remains gated")
	return nil
}
func diagnostics(group int) ([]byte, error) {
	exe, err := os.Executable()
	if err != nil {
		return nil, err
	}
	logs := map[string]string{}
	for _, name := range []string{"installer.log", "ncm-probe.log"} {
		f, err := os.Open(filepath.Join(filepath.Dir(exe), name))
		if err != nil {
			logs[name] = err.Error()
			continue
		}
		info, err := f.Stat()
		if err != nil {
			f.Close()
			return nil, err
		}
		if info.Size() > 64*1024 {
			f.Seek(info.Size()-64*1024, io.SeekStart)
		}
		b, err := io.ReadAll(io.LimitReader(f, 64*1024))
		f.Close()
		if err != nil {
			return nil, err
		}
		logs[name] = string(b)
	}
	return json.Marshal(struct {
		Version string            `json:"version"`
		Group   int               `json:"group"`
		Logs    map[string]string `json:"logs"`
	}{version, group, logs})
}
func main() {
	exe, e := os.Executable()
	if e != nil {
		fmt.Fprintln(os.Stderr, e)
		os.Exit(1)
	}
	dir := filepath.Dir(exe)
	path := filepath.Join(dir, "ncm-probe.log")
	f, e := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
	if e != nil {
		fmt.Fprintln(os.Stderr, "無法建立記錄檔：", e)
		os.Exit(1)
	}
	l := log.New(io.MultiWriter(os.Stdout, f), "", log.Ldate|log.Ltime|log.Lmicroseconds)
	l.Print(strings.Repeat("=", 50))
	e = run(l)
	if e != nil {
		l.Printf("RESULT=STOP error=%v", e)
	}
	l.Printf("記錄檔：%s", path)
	f.Close()
	if e != nil {
		os.Exit(1)
	}
}
