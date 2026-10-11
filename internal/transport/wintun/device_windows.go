//go:build windows && amd64

// Package wintun uses only the published API of the unmodified signed DLL.
package wintun

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"golang.org/x/sys/windows"
	"os"
	"runtime"
	"suhang/usbnet/internal/diagnostics/memorydiag"
	"suhang/usbnet/internal/transport/usbaddress"
	"syscall"
	"unsafe"
)

const DLLSHA256 = "e5da8447dc2c320edc0fc52fa01885c103de8c118481f683643cacc3220dafce"
const AdapterName = "USB Link"

var moveMemory = windows.NewLazySystemDLL("ntdll.dll").NewProc("RtlMoveMemory")

type Device struct {
	created                                      bool
	dll                                          *windows.DLL
	adapter, session                             uintptr
	readEvent                                    windows.Handle
	receive, release, allocate, send, end, close *windows.Proc
	LUID                                         uint64
	Index                                        uint32
	GUID                                         windows.GUID
}

func Open(path string) (*Device, error) {
	return OpenNamed(path, AdapterName, "{A4611646-E050-4D25-B83E-633A5598F302}")
}

func OpenNamed(path, adapterName, adapterGUID string) (*Device, error) {
	return openNamed(path, adapterName, adapterGUID, true, nil, nil, nil)
}

// CreateOwnedNonpresentHost is only for usbhost's durable, exact owned-node
// transaction. It deliberately does not probe WintunOpenAdapter: even a failed
// probe queues the official DLL's asynchronous orphan cleanup. The caller must
// independently prove nonpresence immediately before this synchronous call.
type OwnedCreateObservation struct {
	Called, Returned, Succeeded, FixedGUIDVerified bool
	Index                                          uint32
	LUID                                           uint64
}

func CreateOwnedNonpresentHost(path string, beforeCreate func() error, observation *OwnedCreateObservation) (*Device, error) {
	if beforeCreate == nil || observation == nil {
		return nil, fmt.Errorf("USB_HOST_RECREATE_PRECHECK_REQUIRED")
	}
	return openNamed(path, usbaddress.HostName, usbaddress.HostGUID, false, beforeCreate, observation, nil)
}

// CreateOwnedNonpresentMac performs no Open probe and never adopts an existing
// handle. Its caller owns the durable exact factory transaction and joins the
// synchronous official creation call before releasing the configuration lease.
func CreateOwnedNonpresentMac(path string, beforeCreate func() error, observation *OwnedCreateObservation) (*Device, error) {
	if beforeCreate == nil || observation == nil {
		return nil, fmt.Errorf("USB_MAC_RECREATE_PRECHECK_REQUIRED")
	}
	return openNamed(path, AdapterName, "{A4611646-E050-4D25-B83E-633A5598F302}", false, beforeCreate, observation, nil)
}

func openNamed(path, adapterName, adapterGUID string, probe bool, beforeCreate func() error, observation *OwnedCreateObservation, ownedOpen *ownedOpenRequest) (*Device, error) {
	return openNamedWithProbe(path, adapterName, adapterGUID, probe, beforeCreate, observation, ownedOpen, nil)
}
func openNamedWithProbe(path, adapterName, adapterGUID string, probe bool, beforeCreate func() error, observation *OwnedCreateObservation, ownedOpen *ownedOpenRequest, fixture *lifecycleProbeRequest) (*Device, error) {
	if !((fixture == nil && (adapterName == AdapterName && adapterGUID == "{A4611646-E050-4D25-B83E-633A5598F302}" || adapterName == usbaddress.HostName && adapterGUID == usbaddress.HostGUID)) ||
		(fixture != nil && adapterName == LifecycleProbeName && adapterGUID == LifecycleProbeGUID && !probe && ownedOpen == nil && beforeCreate != nil && observation != nil)) {
		return nil, fmt.Errorf("unowned Wintun identity")
	}
	if err := moveMemory.Find(); err != nil {
		return nil, err
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	hash := sha256.Sum256(b)
	if hex.EncodeToString(hash[:]) != DLLSHA256 {
		return nil, fmt.Errorf("official Wintun hash mismatch")
	}
	h, err := windows.LoadLibraryEx(path, 0, windows.LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR|windows.LOAD_LIBRARY_SEARCH_SYSTEM32)
	if err != nil {
		return nil, err
	}
	memorydiag.RecordStage("wintun_dll_loaded")
	d := &Device{dll: &windows.DLL{Name: path, Handle: h}}
	ok := false
	defer func() {
		if !ok {
			d.Close()
		}
	}()
	procs := map[string]**windows.Proc{"WintunReceivePacket": &d.receive, "WintunReleaseReceivePacket": &d.release, "WintunAllocateSendPacket": &d.allocate, "WintunSendPacket": &d.send, "WintunEndSession": &d.end, "WintunCloseAdapter": &d.close}
	for name, target := range procs {
		*target, err = d.dll.FindProc(name)
		if err != nil {
			return nil, err
		}
	}
	find := func(name string) (*windows.Proc, error) { return d.dll.FindProc(name) }
	open, err := find("WintunOpenAdapter")
	if err != nil {
		return nil, err
	}
	holdModule := ModuleLifetimeHoldEnabled()
	if fixture != nil {
		holdModule = fixture.hold
	}
	if holdModule {
		// Open (even when it fails), Create and Close queue work on the official
		// DLL. Pin before the first such call, never retain an adapter handle.
		if err = holdWintunModule(d.dll, path, open); err != nil {
			return nil, err
		}
	}
	name, _ := windows.UTF16PtrFromString(adapterName)
	guid, _ := windows.GUIDFromString(adapterGUID)
	if ownedOpen != nil {
		if e := ownedOpen.verify(); e != nil {
			return nil, e
		}
		d.adapter, _, err = open.Call(uintptr(unsafe.Pointer(name)))
		if d.adapter == 0 {
			return nil, fmt.Errorf("USB_HOST_PERSISTENT_OPEN_FAILED")
		}
		memorydiag.RecordStage("wintun_owned_adapter_opened")
	} else {
		if probe {
			existing, _, _ := open.Call(uintptr(unsafe.Pointer(name)))
			if existing != 0 {
				d.close.Call(existing)
				return nil, fmt.Errorf("USB Link adapter already exists; existing adapter preserved")
			}
		}
		create, e := find("WintunCreateAdapter")
		if e != nil {
			return nil, e
		}
		kind, _ := windows.UTF16PtrFromString("Suhang")
		if beforeCreate != nil {
			if e = beforeCreate(); e != nil {
				return nil, e
			}
		}
		// This official PnP call is synchronous and must never be abandoned.
		if observation != nil {
			observation.Called = true
		}
		d.adapter, _, err = create.Call(uintptr(unsafe.Pointer(name)), uintptr(unsafe.Pointer(kind)), uintptr(unsafe.Pointer(&guid)))
		if observation != nil {
			observation.Returned = true
			observation.Succeeded = d.adapter != 0
		}
		if d.adapter == 0 {
			return nil, fmt.Errorf("WintunCreateAdapter: %w", err)
		}
		d.created = true
		memorydiag.RecordStage("wintun_adapter_created")
	}

	luidProc, err := find("WintunGetAdapterLUID")
	if err != nil {
		return nil, err
	}
	var luid uint64
	luidProc.Call(d.adapter, uintptr(unsafe.Pointer(&luid)))
	d.LUID = luid
	if observation != nil {
		observation.LUID = luid
	}
	ip := windows.NewLazySystemDLL("iphlpapi.dll")
	r, _, _ := ip.NewProc("ConvertInterfaceLuidToIndex").Call(uintptr(unsafe.Pointer(&luid)), uintptr(unsafe.Pointer(&d.Index)))
	if r != 0 {
		return nil, fmt.Errorf("LUID to index: %w", windows.Errno(r))
	}
	if observation != nil {
		observation.Index = d.Index
	}
	r, _, _ = ip.NewProc("ConvertInterfaceLuidToGuid").Call(uintptr(unsafe.Pointer(&luid)), uintptr(unsafe.Pointer(&d.GUID)))
	if r != 0 {
		return nil, fmt.Errorf("LUID to GUID: %w", windows.Errno(r))
	}
	if d.GUID != guid {
		return nil, fmt.Errorf("Wintun GUID changed")
	}
	if ownedOpen != nil {
		if d.Index != ownedOpen.index || d.LUID != ownedOpen.luid {
			return nil, fmt.Errorf("USB_HOST_PERSISTENT_OPEN_MAPPING_CHANGED")
		}
		if e := ownedOpen.verify(); e != nil {
			return nil, e
		}
	}

	if observation != nil {
		observation.FixedGUIDVerified = true
	}
	start, err := find("WintunStartSession")
	if err != nil {
		return nil, err
	}
	d.session, _, err = start.Call(d.adapter, 4*1024*1024)
	if d.session == 0 {
		return nil, fmt.Errorf("WintunStartSession: %w", err)
	}
	memorydiag.RecordStage("wintun_session_started_ring4MiB")
	event, err := find("WintunGetReadWaitEvent")
	if err != nil {
		return nil, err
	}
	v, _, err := event.Call(d.session)
	if v == 0 {
		return nil, fmt.Errorf("Wintun read event: %w", err)
	}
	d.readEvent = windows.Handle(v)
	ok = true
	return d, nil
}

func (d *Device) Receive() ([]byte, error) {
	return d.ReceiveWithBuffer(nil)
}

// The optional allocator returns exclusively owned Go storage. The native ring
// packet is still synchronously copied and released before returning.
func (d *Device) ReceiveWithBuffer(allocate func(int) []byte) ([]byte, error) {
	var n uint32
	// SyscallN keeps synchronous arguments alive without Proc.Call's conservative
	// heap escape. The API writes n only during this call; returned memory belongs
	// to Wintun until ReleaseReceivePacket below.
	ptr, _, err := syscall.SyscallN(d.receive.Addr(), d.session, uintptr(unsafe.Pointer(&n)))
	if ptr == 0 {
		return nil, err
	}
	defer syscall.SyscallN(d.release.Addr(), d.session, ptr)
	if n < 20 || n > 65535 {
		return nil, fmt.Errorf("invalid Wintun packet size %d", n)
	}
	// The native ring address stays native. Copy synchronously before releasing it.
	var b []byte
	if allocate == nil {
		b = make([]byte, int(n))
	} else {
		b = allocate(int(n))
		if len(b) != int(n) {
			return nil, fmt.Errorf("invalid owned buffer length")
		}
	}
	copy(b, nativePacket(ptr, int(n)))
	runtime.KeepAlive(b)
	return b, nil
}
func (d *Device) Wait() error {
	v, err := windows.WaitForSingleObject(d.readEvent, 50)
	if err != nil {
		return err
	}
	if v != windows.WAIT_OBJECT_0 && v != uint32(windows.WAIT_TIMEOUT) {
		return fmt.Errorf("Wintun wait=%d", v)
	}
	return nil
}
func (d *Device) Send(b []byte) error {
	if len(b) < 20 || len(b) > 65535 {
		return fmt.Errorf("invalid IP packet length")
	}
	ptr, _, err := syscall.SyscallN(d.allocate.Addr(), d.session, uintptr(len(b)))
	if ptr == 0 {
		return err
	}
	copy(nativePacket(ptr, len(b)), b)
	syscall.SyscallN(d.send.Addr(), d.session, ptr)
	runtime.KeepAlive(b)
	return nil
}

// Call only after the receive goroutine has stopped and all buffers released.
func (d *Device) Close() {
	if d.session != 0 {
		d.end.Call(d.session)
		d.session = 0
	}
	if d.adapter != 0 {
		d.close.Call(d.adapter)
		d.adapter = 0
	}
	if d.dll != nil {
		// Experiment ON keeps a single module PIN until process exit. This is
		// still the balanced per-device LoadLibrary reference, not an adapter.
		d.dll.Release()
		d.dll = nil
	}
}

// ReadEvent is owned by the session; callers must stop waiting before Close.
func (d *Device) ReadEvent() windows.Handle { return d.readEvent }

type ownedOpenRequest struct {
	index  uint32
	luid   uint64
	verify func() error
}

// This entry never creates an adapter. The caller holds its configuration lease
// and supplies exact protected receipt + fresh full native identity/address proof.
func OpenOwnedPersistentHost(path string, index uint32, luid uint64, verify func() error) (*Device, error) {
	if index == 0 || luid == 0 || verify == nil {
		return nil, fmt.Errorf("USB_HOST_PERSISTENT_OPEN_PRECHECK_REQUIRED")
	}
	return openNamed(path, usbaddress.HostName, usbaddress.HostGUID, false, nil, nil, &ownedOpenRequest{index, luid, verify})
}

// OpenOwnedPersistentMac is the retained fixed-Mac counterpart. It is never a
// factory fallback; the caller supplies a protected exactScope/full active proof.
func OpenOwnedPersistentMac(path string, index uint32, luid uint64, verify func() error) (*Device, error) {
	if index == 0 || luid == 0 || verify == nil {
		return nil, fmt.Errorf("USB_MAC_PERSISTENT_OPEN_PRECHECK_REQUIRED")
	}
	return openNamed(path, AdapterName, "{A4611646-E050-4D25-B83E-633A5598F302}", false, nil, nil, &ownedOpenRequest{index, luid, verify})
}

// FactoryHandleHeld observes only this private official-DLL creation handle.
// It is not live identity authorization; callers still perform native proof.
func (d *Device) FactoryHandleHeld() bool {
	return d != nil && d.created && d.adapter != 0 && d.session != 0 && d.dll != nil
}

// HandleHeld is private-object lifetime metadata, never native authorization.
func (d *Device) HandleHeld() bool {
	return d != nil && d.adapter != 0 && d.session != 0 && d.dll != nil
}
