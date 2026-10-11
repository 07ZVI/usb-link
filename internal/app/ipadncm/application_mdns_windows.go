//go:build windows && amd64

package ipadncm

import (
	"fmt"
	"golang.org/x/sys/windows"
	"net"
	"runtime"
	"sync"
	"sync/atomic"
	"time"
	"unsafe"
)

// SDK x64 DNS_SERVICE_REGISTER_REQUEST: two ULONGs, four pointers, BOOL+pad.
type dnsRegisterRequest struct {
	Version, Index                           uint32
	Instance, Callback, Context, Credentials uintptr
	Unicast                                  uint32
	_                                        uint32
}

var _ [48 - int(unsafe.Sizeof(dnsRegisterRequest{}))]byte
var _ [int(unsafe.Sizeof(dnsRegisterRequest{})) - 48]byte

type dnsOperation struct {
	request *dnsRegisterRequest
	pin     runtime.Pinner
	done    chan uint32
}

var dnsOps = struct {
	sync.Mutex
	m map[uintptr]*dnsOperation
}{m: map[uintptr]*dnsOperation{}}
var dnsSequence atomic.Uint64
var dnsFree = windows.NewLazySystemDLL("dnsapi.dll").NewProc("DnsServiceFreeInstance")
var dnsCallback = windows.NewCallback(func(status, context, instance uintptr) uintptr {
	dnsOps.Lock()
	op := dnsOps.m[context]
	dnsOps.Unlock()
	if instance != 0 && (op == nil || instance != op.request.Instance) {
		dnsFree.Call(instance)
	}
	if op != nil {
		select {
		case op.done <- uint32(status):
		default:
		}
	}
	return 0
})

func forgetDNS(id uintptr, op *dnsOperation) {
	dnsOps.Lock()
	delete(dnsOps.m, id)
	dnsOps.Unlock()
	dnsFree.Call(op.request.Instance)
	op.pin.Unpin()
}

// A timeout intentionally retains the pinned request until process exit. Native
// Windows registration is process-lifetime scoped, so it cannot survive a crash.
func registerApplicationMDNS(index uint32, ip, token string) (func() string, string) {
	dll := windows.NewLazySystemDLL("dnsapi.dll")
	construct, register, deregister := dll.NewProc("DnsServiceConstructInstance"), dll.NewProc("DnsServiceRegister"), dll.NewProc("DnsServiceDeRegister")
	for _, p := range []*windows.LazyProc{construct, register, deregister, dnsFree} {
		if p.Find() != nil {
			return nil, "MDNS_API_UNAVAILABLE"
		}
	}
	if index == 0 || net.ParseIP(ip).To4() == nil {
		return nil, "MDNS_SCOPE_INVALID"
	}
	service, _ := windows.UTF16PtrFromString("USB-Link-" + token[:8] + "._nvstream._tcp.local")
	host, _ := windows.UTF16PtrFromString("suhang-usb-" + token[:8] + ".local")
	v4 := net.ParseIP(ip).To4()
	instance, _, _ := construct.Call(uintptr(unsafe.Pointer(service)), uintptr(unsafe.Pointer(host)), uintptr(unsafe.Pointer(&v4[0])), 0, 47989, 0, 0, 0, 0, 0)
	runtime.KeepAlive(service)
	runtime.KeepAlive(host)
	runtime.KeepAlive(v4)
	if instance == 0 {
		return nil, "MDNS_INSTANCE_CREATE_FAILED"
	}
	id := uintptr(dnsSequence.Add(1))
	op := &dnsOperation{request: &dnsRegisterRequest{Version: 1, Index: index, Instance: instance, Callback: dnsCallback, Context: id}, done: make(chan uint32, 1)}
	op.pin.Pin(op.request)
	dnsOps.Lock()
	dnsOps.m[id] = op
	dnsOps.Unlock()
	rc, _, _ := register.Call(uintptr(unsafe.Pointer(op.request)), 0)
	if rc != uintptr(windows.DNS_REQUEST_PENDING) {
		forgetDNS(id, op)
		return nil, "MDNS_REGISTER_" + fmt.Sprint(rc)
	}
	select {
	case status := <-op.done:
		if status != 0 {
			forgetDNS(id, op)
			return nil, "MDNS_REGISTER_CALLBACK_" + fmt.Sprint(status)
		}
	case <-time.After(6 * time.Second):
		// Keep request alive; issue deregistration after late registration callback.
		go func() {
			<-op.done
			deregister.Call(uintptr(unsafe.Pointer(op.request)), 0) /* pinned until exit: cancellation race not treated as verified cleanup */
		}()
		return nil, "MDNS_REGISTER_TIMEOUT_NOT_DISCOVERY_PROOF"
	}
	return func() string {
		rc, _, _ := deregister.Call(uintptr(unsafe.Pointer(op.request)), 0)
		if rc != uintptr(windows.DNS_REQUEST_PENDING) {
			return "MDNS_DEREGISTER_" + fmt.Sprint(rc)
		}
		select {
		case status := <-op.done:
			if status != 0 {
				return "MDNS_DEREGISTER_CALLBACK_" + fmt.Sprint(status)
			}
			forgetDNS(id, op)
			return ""
		case <-time.After(6 * time.Second):
			return "MDNS_DEREGISTER_TIMEOUT_PROCESS_EXIT_CLEARS"
		}
	}, ""
}
