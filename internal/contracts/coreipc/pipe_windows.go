//go:build windows && amd64

package coreipc

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"golang.org/x/sys/windows"
	"os"
	"runtime"
	"strings"
	"sync"
	"time"
	"unsafe"
)

type Server struct {
	cancel context.CancelFunc
	done   chan struct{}
	once   sync.Once
	mu     sync.Mutex
	err    error
}

func (s *Server) Close() error          { s.once.Do(s.cancel); <-s.done; return nil }
func (s *Server) Done() <-chan struct{} { return s.done }
func (s *Server) Err() error            { s.mu.Lock(); defer s.mu.Unlock(); return s.err }
func tokenDWORD(t windows.Token, kind uint32) (uint32, error) {
	var v, n uint32
	e := windows.GetTokenInformation(t, kind, (*byte)(unsafe.Pointer(&v)), 4, &n)
	if e != nil || n != 4 {
		return 0, fmt.Errorf("CORE_TOKEN_QUERY_FAILED")
	}
	return v, nil
}
func tokenPeer(t windows.Token) (Peer, error) {
	u, e := t.GetTokenUser()
	if e != nil {
		return Peer{}, e
	}
	session, e := tokenDWORD(t, windows.TokenSessionId)
	if e != nil {
		return Peer{}, e
	}
	elevated, e := tokenDWORD(t, windows.TokenElevation)
	if e != nil {
		return Peer{}, e
	}
	return Peer{SID: u.User.Sid.String(), Session: session, Elevated: elevated != 0}, nil
}
func RequireSystemService() error {
	p, e := tokenPeer(windows.GetCurrentProcessToken())
	if e != nil || p.SID != "S-1-5-18" || p.Session != 0 {
		return fmt.Errorf("CORE_SYSTEM_SESSION0_REQUIRED")
	}
	return nil
}

// The pipe admits only SYSTEM and this bound account; its client ACE excludes
// FILE_CREATE_PIPE_INSTANCE. Remote clients and squatted first instances fail.
func Start(parent context.Context, ownerSID, executable string, verify func(string) error, handler func(context.Context, Peer, Request) (Response, error)) (*Server, error) {
	if RequireSystemService() != nil || verify == nil || handler == nil || verify(executable) != nil {
		return nil, fmt.Errorf("CORE_IPC_OWNER_UNPROVEN")
	}
	sid, e := windows.StringToSid(ownerSID)
	if e != nil || !sid.IsValid() || sid.IsWellKnown(windows.WinLocalSystemSid) {
		return nil, fmt.Errorf("CORE_IPC_OWNER_UNPROVEN")
	}
	sd, e := windows.SecurityDescriptorFromString("O:SYG:SYD:P(A;;GA;;;SY)(A;;0x12019b;;;" + ownerSID + ")")
	if e != nil {
		return nil, e
	}
	sa := windows.SecurityAttributes{Length: uint32(unsafe.Sizeof(windows.SecurityAttributes{})), SecurityDescriptor: sd}
	h, e := windows.CreateNamedPipe(windows.StringToUTF16Ptr(PipeName), windows.PIPE_ACCESS_DUPLEX|windows.FILE_FLAG_OVERLAPPED|windows.FILE_FLAG_FIRST_PIPE_INSTANCE, windows.PIPE_TYPE_BYTE|windows.PIPE_READMODE_BYTE|windows.PIPE_WAIT|windows.PIPE_REJECT_REMOTE_CLIENTS, 1, MaxMessage+4, MaxMessage+4, 0, &sa)
	if e != nil {
		return nil, fmt.Errorf("CORE_IPC_PIPE_UNAVAILABLE")
	}
	ctx, cancel := context.WithCancel(parent)
	s := &Server{cancel: cancel, done: make(chan struct{})}
	go func() {
		defer close(s.done)
		defer windows.CloseHandle(h)
		for ctx.Err() == nil {
			e := overlapped(ctx, h, nil, func(o *windows.Overlapped, n *uint32) error { return windows.ConnectNamedPipe(h, o) })
			if e == windows.ERROR_PIPE_CONNECTED {
				e = nil
			}
			if e != nil {
				if ctx.Err() != nil {
					return
				}
				s.mu.Lock()
				s.err = fmt.Errorf("CORE_IPC_LISTENER_FAILED: %w", e)
				s.mu.Unlock()
				return
			}
			requestCtx, stop := context.WithTimeout(ctx, 15*time.Second)
			serveOne(requestCtx, h, ownerSID, executable, verify, handler)
			stop()
			windows.DisconnectNamedPipe(h)
		}
	}()
	return s, nil
}
func overlapped(ctx context.Context, h windows.Handle, completed *uint32, call func(*windows.Overlapped, *uint32) error) error {
	event, e := windows.CreateEvent(nil, 1, 0, nil)
	if e != nil {
		return e
	}
	defer windows.CloseHandle(event)
	o := windows.Overlapped{HEvent: event}
	var local uint32
	if completed == nil {
		completed = &local
	}
	if ctx.Err() != nil {
		return ctx.Err()
	}
	e = call(&o, completed)
	if e != windows.ERROR_IO_PENDING {
		return e
	}
	// Cancellation does not release the OVERLAPPED or buffer before native
	// completion. No abandoned native call can overlap the next connection.
	for {
		state, we := windows.WaitForSingleObject(event, 100)
		if we != nil {
			_ = windows.CancelIoEx(h, &o)
			_ = windows.GetOverlappedResult(h, &o, completed, true)
			return we
		}
		if state == windows.WAIT_OBJECT_0 {
			break
		}
		if ctx.Err() != nil {
			_ = windows.CancelIoEx(h, &o)
			_, _ = windows.WaitForSingleObject(event, windows.INFINITE)
			_ = windows.GetOverlappedResult(h, &o, completed, false)
			return ctx.Err()
		}
	}
	return windows.GetOverlappedResult(h, &o, completed, false)
}
func transfer(ctx context.Context, h windows.Handle, b []byte, write bool) error {
	for len(b) > 0 {
		var n uint32
		e := overlapped(ctx, h, &n, func(o *windows.Overlapped, _ *uint32) error {
			if write {
				return windows.WriteFile(h, b, &n, o)
			}
			return windows.ReadFile(h, b, &n, o)
		})

		if e != nil {
			return e
		}
		if n == 0 || int(n) > len(b) {
			return fmt.Errorf("CORE_IPC_SHORT_IO")
		}
		b = b[n:]
	}
	return nil
}
func readFrame(ctx context.Context, h windows.Handle) ([]byte, error) {
	var head [4]byte
	if e := transfer(ctx, h, head[:], false); e != nil {
		return nil, e
	}
	n := binary.LittleEndian.Uint32(head[:])
	if n == 0 || n > MaxMessage {
		return nil, fmt.Errorf("CORE_IPC_FRAME_INVALID")
	}
	b := make([]byte, n)
	return b, transfer(ctx, h, b, false)
}
func writeFrame(ctx context.Context, h windows.Handle, b []byte) error {
	if len(b) == 0 || len(b) > MaxMessage {
		return fmt.Errorf("CORE_IPC_FRAME_INVALID")
	}
	var head [4]byte
	binary.LittleEndian.PutUint32(head[:], uint32(len(b)))
	if e := transfer(ctx, h, head[:], true); e != nil {
		return e
	}
	return transfer(ctx, h, b, true)
}
func verifiedPeer(h windows.Handle, ownerSID, exe string, verify func(string) error) (Peer, error) {
	var pid uint32
	if windows.GetNamedPipeClientProcessId(h, &pid) != nil || pid == 0 {
		return Peer{}, fmt.Errorf("CORE_IPC_CLIENT_QUERY_FAILED")
	}
	process, e := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION|windows.SYNCHRONIZE, false, pid)
	if e != nil {
		return Peer{}, e
	}
	defer windows.CloseHandle(process)
	var name [32768]uint16
	size := uint32(len(name))
	if windows.QueryFullProcessImageName(process, 0, &name[0], &size) != nil || !strings.EqualFold(windows.UTF16ToString(name[:size]), exe) || verify(exe) != nil {
		return Peer{}, fmt.Errorf("CORE_IPC_CLIENT_IMAGE_REJECTED")
	}
	var token windows.Token
	if windows.OpenProcessToken(process, windows.TOKEN_QUERY, &token) != nil {
		return Peer{}, fmt.Errorf("CORE_IPC_CLIENT_TOKEN_FAILED")
	}
	defer token.Close()
	p, e := tokenPeer(token)
	if e != nil {
		return Peer{}, e
	}
	p.PID = pid
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	ok, _, ie := windows.NewLazySystemDLL("advapi32.dll").NewProc("ImpersonateNamedPipeClient").Call(uintptr(h))
	if ok == 0 {
		return Peer{}, fmt.Errorf("CORE_IPC_IMPERSONATION_FAILED: %v", ie)
	}
	var client windows.Token
	e = windows.OpenThreadToken(windows.CurrentThread(), windows.TOKEN_QUERY, true, &client)
	var actual Peer
	if e == nil {
		actual, e = tokenPeer(client)
		client.Close()
	}
	if windows.RevertToSelf() != nil {
		os.Exit(1)
	}
	if e != nil || actual.SID != p.SID || actual.Session != p.Session || actual.Elevated != p.Elevated || p.SID != ownerSID || p.Session == 0 || windows.WTSGetActiveConsoleSessionId() != p.Session {
		return Peer{}, fmt.Errorf("CORE_IPC_CLIENT_IDENTITY_CHANGED")
	}
	var again uint32
	if windows.GetNamedPipeClientProcessId(h, &again) != nil || again != pid {
		return Peer{}, fmt.Errorf("CORE_IPC_CLIENT_CHANGED")
	}
	state, e := windows.WaitForSingleObject(process, 0)
	if e != nil || state != uint32(windows.WAIT_TIMEOUT) {
		return Peer{}, fmt.Errorf("CORE_IPC_CLIENT_EXITED")
	}
	var created, exited, kernel, user windows.Filetime
	if windows.GetProcessTimes(process, &created, &exited, &kernel, &user) != nil {
		return Peer{}, fmt.Errorf("CORE_IPC_CLIENT_CREATION_UNPROVEN")
	}
	p.Creation = uint64(created.HighDateTime)<<32 | uint64(created.LowDateTime)
	if p.Creation == 0 {
		return Peer{}, fmt.Errorf("CORE_IPC_CLIENT_CREATION_UNPROVEN")
	}
	return p, nil
}
func serveOne(ctx context.Context, h windows.Handle, ownerSID, exe string, verify func(string) error, handler func(context.Context, Peer, Request) (Response, error)) {
	b, e := readFrame(ctx, h)
	if e != nil {
		return
	}
	r, e := ParseRequest(b)
	if e != nil {
		return
	}
	p, e := verifiedPeer(h, ownerSID, exe, verify)
	if e != nil || AuthorizePeer(ownerSID, p, r.Method) != nil {
		return
	}
	reply, e := handler(ctx, p, r)
	if e != nil {
		reply = Response{Problem: "CORE_REQUEST_REJECTED"}
	}
	reply.Version = 1
	reply.ID = r.ID
	b, e = json.Marshal(reply)
	if e != nil || writeFrame(ctx, h, b) != nil {
		return
	}
	var ack [1]byte
	ackErr := transfer(ctx, h, ack[:], false)
	completeReply(reply, nil, ackErr, ack[0])
}

// Call authenticates the exact SCM service PID before sending any request.
// VerifyServer must query the owned service, process token/path and readback.
func Call(ctx context.Context, r Request, verifyServer func(uint32) error) (Response, error) {
	var out Response
	b, e := json.Marshal(r)
	if e != nil {
		return out, e
	}
	if _, e = ParseRequest(b); e != nil {
		return out, e
	}
	if verifyServer == nil {
		return out, fmt.Errorf("CORE_IPC_SERVER_PROOF_REQUIRED")
	}
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	var h windows.Handle
	for {
		h, e = windows.CreateFile(windows.StringToUTF16Ptr(PipeName), 0x12019b, 0, nil, windows.OPEN_EXISTING, windows.FILE_FLAG_OVERLAPPED|windows.SECURITY_SQOS_PRESENT|windows.SECURITY_IDENTIFICATION, 0)
		if e == nil {
			break
		}
		if e != windows.ERROR_PIPE_BUSY {
			return out, e
		}
		timer := time.NewTimer(50 * time.Millisecond)
		select {
		case <-ctx.Done():
			timer.Stop()
			return out, ctx.Err()
		case <-timer.C:
		}
	}
	defer windows.CloseHandle(h)
	var pid uint32
	if windows.GetNamedPipeServerProcessId(h, &pid) != nil || pid == 0 || verifyServer(pid) != nil {
		return out, fmt.Errorf("CORE_IPC_SERVER_REJECTED")
	}
	if e = writeFrame(ctx, h, b); e != nil {
		return out, e
	}
	b, e = readFrame(ctx, h)
	if e != nil {
		return out, e
	}
	out, e = ParseResponse(b, r.ID)
	if e != nil {
		return Response{}, e
	}
	if err := transfer(ctx, h, []byte{1}, true); err != nil {
		return Response{}, err
	}
	return out, nil
}

// VerifyOwnerClientLifetime rechecks only the previously authenticated UI
// lifetime. No client-supplied image/account/session can select a new authority.
func VerifyOwnerClientLifetime(ownerSID, executable string, pid, session uint32, creation uint64, verify func(string) error) error {
	if pid == 0 || session == 0 || session == 0xffffffff || creation == 0 || verify == nil {
		return fmt.Errorf("CORE_IPC_CLIENT_LIFETIME_INVALID")
	}
	process, e := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION|windows.SYNCHRONIZE, false, pid)
	if e != nil {
		return e
	}
	defer windows.CloseHandle(process)
	var name [32768]uint16
	size := uint32(len(name))
	if windows.QueryFullProcessImageName(process, 0, &name[0], &size) != nil || !strings.EqualFold(windows.UTF16ToString(name[:size]), executable) || verify(executable) != nil {
		return fmt.Errorf("CORE_IPC_CLIENT_IMAGE_REJECTED")
	}
	var token windows.Token
	if windows.OpenProcessToken(process, windows.TOKEN_QUERY, &token) != nil {
		return fmt.Errorf("CORE_IPC_CLIENT_TOKEN_FAILED")
	}
	defer token.Close()
	peer, e := tokenPeer(token)
	if e != nil || peer.SID != ownerSID || peer.Session != session || !peer.Elevated || windows.WTSGetActiveConsoleSessionId() != session {
		return fmt.Errorf("CORE_IPC_CLIENT_IDENTITY_CHANGED")
	}
	var created, exited, kernel, user windows.Filetime
	if windows.GetProcessTimes(process, &created, &exited, &kernel, &user) != nil || uint64(created.HighDateTime)<<32|uint64(created.LowDateTime) != creation {
		return fmt.Errorf("CORE_IPC_CLIENT_CREATION_UNPROVEN")
	}
	state, e := windows.WaitForSingleObject(process, 0)
	if e != nil || state != uint32(windows.WAIT_TIMEOUT) {
		return fmt.Errorf("CORE_IPC_CLIENT_EXITED")
	}
	return nil
}
