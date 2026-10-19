//go:build windows && amd64

package background

import (
	"context"
	"fmt"
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"
	"log"
	"os"
	"path/filepath"
	"strings"
	"suhang/usbnet/internal/contracts/coreipc"
	"time"
)

const CoreServiceName = "USBLinkCore"

type CoreControl struct {
	Suspend bool
	Resume  bool
}
type CoreContext struct {
	OwnerSID, Executable string
	Controls             <-chan CoreControl
	Log                  *log.Logger
}
type CoreOptions struct {
	Executable, OwnerSID string
	// Verify must authenticate this exact ProgramFiles executable, protected
	// owner binding and SCM configuration. Caller-supplied arbitrary roots are
	// not service authorization.
	Verify func(string) error
	Log    *log.Logger
	Run    func(context.Context, CoreContext) error
	Handle func(context.Context, coreipc.Peer, coreipc.Request) (coreipc.Response, error)
	// Dispatched runs when SCM first hosts the service, before any check.
	Dispatched func()
	// Terminated reports why the service is returning, for diagnostics only.
	Terminated func(reason string, exitCode uint32)
}

// RunCoreService reuses the SCM host rather than the obsolete Mac-only WTS
// consent loop. It never creates UI in Session0 or assumes SYSTEM is a user.
func RunCoreService(options CoreOptions) error {
	if options.Verify == nil || options.Run == nil || options.Handle == nil || options.Log == nil {
		return fmt.Errorf("CORE_SERVICE_CALLBACK_REQUIRED")
	}
	self, e := os.Executable()
	if e != nil || !strings.EqualFold(filepath.Clean(self), filepath.Clean(options.Executable)) {
		return fmt.Errorf("CORE_SERVICE_SOURCE_CHANGED")
	}
	if e = options.Verify(self); e != nil {
		return e
	}
	if e = coreipc.RequireSystemService(); e != nil {
		return e
	}
	sid, e := windows.StringToSid(options.OwnerSID)
	if e != nil || !sid.IsValid() || sid.IsWellKnown(windows.WinLocalSystemSid) {
		return fmt.Errorf("CORE_SERVICE_OWNER_REQUIRED")
	}
	return svc.Run(CoreServiceName, &coreService{options})
}

type coreService struct{ options CoreOptions }

func (s *coreService) Execute(_ []string, requests <-chan svc.ChangeRequest, changes chan<- svc.Status) (bool, uint32) {
	changes <- svc.Status{State: svc.StartPending, WaitHint: 30000, CheckPoint: 1}
	o := s.options
	if o.Dispatched != nil {
		o.Dispatched()
	}
	terminated := func(reason string, code uint32) {
		if o.Terminated != nil {
			o.Terminated(reason, code)
		}
	}
	if e := o.Verify(o.Executable); e != nil {
		o.Log.Print("CORE_SERVICE_IDENTITY_REJECTED")
		terminated("CORE_SERVICE_IDENTITY_REJECTED", 1)
		return true, 1
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	controls := make(chan CoreControl, 4)
	pipe, err := coreipc.Start(ctx, o.OwnerSID, o.Executable, o.Verify, o.Handle)
	if err != nil {
		o.Log.Printf("CORE_SERVICE_LOCAL_IPC_REJECTED error=%v", err)
		terminated(fmt.Sprintf("CORE_SERVICE_LOCAL_IPC_REJECTED: %v", err), 2)
		return true, 2
	}
	defer pipe.Close()
	done := make(chan error, 1)
	go func() { done <- o.Run(ctx, CoreContext{o.OwnerSID, o.Executable, controls, o.Log}) }()
	accepts := svc.AcceptStop | svc.AcceptShutdown | svc.AcceptPowerEvent
	changes <- svc.Status{State: svc.Running, Accepts: accepts}
	o.Log.Print("CORE_SERVICE_RUNNING usb_ready=unverified session0=true")
	for {
		select {
		case <-pipe.Done():
			cancel()
			<-done
			o.Log.Printf("CORE_SERVICE_LOCAL_IPC_STOPPED error=%v", pipe.Err())
			terminated(fmt.Sprintf("CORE_SERVICE_LOCAL_IPC_STOPPED: %v", pipe.Err()), 5)
			return true, 5
		case err := <-done:
			if err != nil {
				o.Log.Printf("CORE_SERVICE_CALLBACK_STOPPED error=%v", err)
				terminated(fmt.Sprintf("CORE_SERVICE_CALLBACK_STOPPED: %v", err), 3)
				return true, 3
			}
			terminated("CORE_APPLICATION_RETURNED", 0)
			return false, 0
		case r, ok := <-requests:
			if !ok {
				cancel()
				_ = pipe.Close()
				<-done
				terminated("SCM_REQUEST_CHANNEL_CLOSED", 0)
				return false, 0
			}
			switch r.Cmd {
			case svc.Interrogate:
				changes <- r.CurrentStatus
			case svc.PowerEvent:
				var c CoreControl
				switch r.EventType {
				case 4:
					c.Suspend = true
				case 7, 18:
					c.Resume = true
				}
				if c.Suspend || c.Resume {
					select {
					case controls <- c:
					default:
						o.Log.Print("CORE_POWER_CONTROL_PENDING")
					}
				}
			case svc.Stop, svc.Shutdown:
				cancel()
				_ = pipe.Close()
				ticker := time.NewTicker(time.Second)
				defer ticker.Stop()
				for checkpoint := uint32(1); ; checkpoint++ {
					changes <- svc.Status{State: svc.StopPending, CheckPoint: checkpoint, WaitHint: 60000}
					select {
					case err := <-done:
						if err != nil {
							o.Log.Printf("CORE_SERVICE_CLEANUP_FAILED error=%v", err)
							terminated(fmt.Sprintf("CORE_SERVICE_CLEANUP_FAILED: %v", err), 4)
							return true, 4
						}
						terminated("SCM_STOP_OR_SHUTDOWN", 0)
						return false, 0
					case <-ticker.C:
					}
				}
			}
		}
	}
}
