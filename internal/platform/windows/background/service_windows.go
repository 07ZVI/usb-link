//go:build windows && amd64

package background

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"
	"io"
	"log"
	"os/exec"
	"path/filepath"
	"strings"
	"suhang/usbnet/internal/diagnostics/logfile"
	"suhang/usbnet/internal/diagnostics/probecontrol"
	"suhang/usbnet/internal/transport/winusb"
	"sync/atomic"
	"time"
	"unsafe"
)

type service struct{ dir string }

func RunService(dir string) error {
	root, err := Root()
	if err != nil {
		return err
	}
	if !strings.EqualFold(filepath.Dir(dir), root) {
		return fmt.Errorf("service must run from protected installation directory")
	}
	if err = noReparse(root); err != nil {
		return err
	}
	if err = noReparse(dir); err != nil {
		return err
	}
	return svc.Run(ServiceName, &service{dir})
}

func (s *service) Execute(_ []string, requests <-chan svc.ChangeRequest, changes chan<- svc.Status) (bool, uint32) {
	changes <- svc.Status{State: svc.StartPending}
	f, err := logfile.Open(filepath.Join(s.dir, "service.log"), 8*1024*1024)
	if err != nil {
		return false, 1
	}
	defer f.Close()
	l := log.New(f, "", log.Ldate|log.Ltime|log.Lmicroseconds)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	controls := make(chan svc.Cmd, 4)
	done := make(chan error, 1)
	go func() { done <- s.supervise(ctx, controls, l) }()
	changes <- svc.Status{State: svc.Running, Accepts: svc.AcceptStop | svc.AcceptShutdown | svc.AcceptPowerEvent}
	for {
		select {
		case err := <-done:
			l.Printf("SERVICE_STOPPED error=%v", err)
			if err != nil {
				return false, 1
			}
			return false, 0
		case request := <-requests:
			switch request.Cmd {
			case svc.Interrogate:
				changes <- request.CurrentStatus
			case svc.PowerEvent:
				var command svc.Cmd
				switch request.EventType {
				case 4:
					command = svc.Cmd(128)
				case 7, 18:
					command = svc.Cmd(129)
				}
				if command != 0 {
					select {
					case controls <- command:
					default:
					}
				}

			case svc.Cmd(128), svc.Cmd(129):
				select {
				case controls <- request.Cmd:
				default:
				}
			case svc.Stop, svc.Shutdown:
				cancel()
				ticker := time.NewTicker(time.Second)
				defer ticker.Stop()
				for checkpoint := uint32(1); ; checkpoint++ {
					changes <- svc.Status{State: svc.StopPending, CheckPoint: checkpoint, WaitHint: 60000}
					select {
					case err := <-done:
						l.Printf("SERVICE_STOPPED error=%v", err)
						return false, 0
					case <-ticker.C:
					}
				}
			}
		}
	}
}

func present() (string, error) {
	nodes, err := winusb.Enumerate(log.New(io.Discard, "", 0))
	if err != nil {
		return "", err
	}
	_, _, err = winusb.Pair(nodes, 0, false)
	if err != nil {
		return "", nil
	} // Missing/busy/unfinished pairing never starts I/O.
	for _, node := range nodes {
		if node.Parent != "" {
			return node.Parent, nil
		}
	}
	return "", nil
}

// WTS is Microsoft's supported service-to-user prompt; the service does not
// expose IPC over the network or bypass Session 0 isolation.
func consent(ctx context.Context, session uint32) bool {
	if session == 0xffffffff {
		return false
	}
	result := make(chan bool, 1)
	go func() {
		title, _ := windows.UTF16FromString("隨航 — 允許本次 USB 連線")
		message, _ := windows.UTF16FromString("偵測到以 USB 線連接的 Mac。是否允許這次專用網路連線？\n\n同意後可使用限定串流端口。每次重新接線都會詢問。\n拒絕或逾時不會建立連線。")
		var response uint32
		ok, _, _ := windows.NewLazySystemDLL("wtsapi32.dll").NewProc("WTSSendMessageW").Call(0, uintptr(session), uintptr(unsafe.Pointer(&title[0])), uintptr((len(title)-1)*2), uintptr(unsafe.Pointer(&message[0])), uintptr((len(message)-1)*2), 0x4|0x20|0x100, 60, uintptr(unsafe.Pointer(&response)), 1)
		result <- ok != 0 && response == 6
	}()
	select {
	case allowed := <-result:
		return allowed && ctx.Err() == nil && windows.WTSGetActiveConsoleSessionId() == session
	case <-ctx.Done():
		return false
	}
}

func (s *service) bridge(ctx context.Context, l *log.Logger) (bool, error) {
	var token [12]byte
	if _, err := rand.Read(token[:]); err != nil {
		return false, err
	}
	name := `Global\SuhangUSBBridgeStop-` + hex.EncodeToString(token[:])
	p, _ := windows.UTF16PtrFromString(name)
	event, err := windows.CreateEvent(nil, 1, 0, p)
	if err != nil {
		return false, err
	}
	defer windows.CloseHandle(event)
	var ready atomic.Bool
	output := io.MultiWriter(l.Writer(), probecontrol.NewReadyWriter(func() { ready.Store(true); l.Print("USB_INITIALIZED consent=true peer_connectivity=unverified") }))
	cmd := exec.Command(filepath.Join(s.dir, "suhang-usbnet.exe"), "--stop-event", name)
	cmd.Dir = s.dir
	cmd.Stdout = output
	cmd.Stderr = output
	if err = cmd.Start(); err != nil {
		return false, err
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	select {
	case err = <-done:
	case <-ctx.Done():
		windows.SetEvent(event)
		err = <-done
	}
	l.Printf("BRIDGE_STOP ready=%t error=%v", ready.Load(), err)
	return ready.Load(), err
}

func (s *service) supervise(ctx context.Context, controls <-chan svc.Cmd, l *log.Logger) error {
	l.Print("SERVICE_READY autostart=true waiting_for_cable=true consent_required=true")
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	gate := Gate{}
	for {
		select {
		case <-ctx.Done():
			return nil
		case command := <-controls:
			if command == svc.Cmd(129) {
				gate.Retry()
			}
			if command == svc.Cmd(128) {
				gate.Decided = true
			}
		case <-ticker.C:
			parent, err := present()
			if err != nil {
				l.Printf("ENUMERATE error=%v", err)
				continue
			}
			gate.Observe(parent)
			if !gate.CanAsk() {
				continue
			}
			session := windows.WTSGetActiveConsoleSessionId()
			if session == 0xffffffff {
				continue
			}
			l.Print("CONSENT_REQUESTED")
			consentCtx, cancelConsent := context.WithCancel(ctx)
			answer := make(chan bool, 1)
			go func() { answer <- consent(consentCtx, session) }()
			var allowed bool
			select {
			case allowed = <-answer:
			case <-ctx.Done():
				cancelConsent()
				return nil
			case <-controls:
				gate.Decided = true
				cancelConsent()
			}
			cancelConsent()
			latest, err := present()
			if err != nil {
				latest = ""
			}
			gate.Observe(latest)
			if !gate.Decide(parent, allowed) {
				l.Print("CONSENT_DECLINED_OR_STALE no_connection=true")
				continue
			}
			l.Print("CONSENT_ACCEPTED")
			if s.runConnection(ctx, controls, parent, l) {
				gate.Observe("")
			}
			// Never loop initialization after failure. Unplug or local retry
			// is required; the consent gate remains decided for this attachment.
			l.Print("WAITING_FOR_UNPLUG_OR_LOCAL_RETRY")
		}
	}
}

func (s *service) runConnection(ctx context.Context, controls <-chan svc.Cmd, parent string, l *log.Logger) (requestAgain bool) {
	childCtx, stop := context.WithCancel(ctx)
	defer stop()
	done := make(chan bool, 1)
	go func() { wasReady, _ := s.bridge(childCtx, l); done <- wasReady }()
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			stop()
			<-done
			return
		case command := <-controls:
			if command == svc.Cmd(128) || command == svc.Cmd(129) {
				requestAgain = command == svc.Cmd(129)
				stop()
			}
		case <-ticker.C:
			current, err := present()
			if err == nil && current != parent {
				requestAgain = true
				stop()
			}
		case <-done:
			return
		}
	}
}
