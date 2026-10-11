//go:build windows && amd64

package winusb

import (
	"fmt"
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
	"log"
	"runtime"
	"strings"
	"suhang/usbnet/internal/diagnostics/bench"
	"suhang/usbnet/internal/transport/ncm"
	"unsafe"
)

var usb = windows.NewLazySystemDLL("winusb.dll")
var setup = windows.NewLazySystemDLL("setupapi.dll")
var cm = windows.NewLazySystemDLL("cfgmgr32.dll")

var usbProcs = map[string]*windows.LazyProc{
	"WinUsb_ControlTransfer":            usb.NewProc("WinUsb_ControlTransfer"),
	"WinUsb_Free":                       usb.NewProc("WinUsb_Free"),
	"WinUsb_GetAssociatedInterface":     usb.NewProc("WinUsb_GetAssociatedInterface"),
	"WinUsb_GetDescriptor":              usb.NewProc("WinUsb_GetDescriptor"),
	"WinUsb_GetPipePolicy":              usb.NewProc("WinUsb_GetPipePolicy"),
	"WinUsb_Initialize":                 usb.NewProc("WinUsb_Initialize"),
	"WinUsb_QueryInterfaceSettings":     usb.NewProc("WinUsb_QueryInterfaceSettings"),
	"WinUsb_QueryPipe":                  usb.NewProc("WinUsb_QueryPipe"),
	"WinUsb_ReadPipe":                   usb.NewProc("WinUsb_ReadPipe"),
	"WinUsb_SetCurrentAlternateSetting": usb.NewProc("WinUsb_SetCurrentAlternateSetting"),
	"WinUsb_SetPipePolicy":              usb.NewProc("WinUsb_SetPipePolicy"),
	"WinUsb_WritePipe":                  usb.NewProc("WinUsb_WritePipe"),
}

//go:uintptrescapes
func boolCall(name string, args ...uintptr) error {
	cached := bench.CachedWinUSB()
	proc := usbProcs[name]
	if proc == nil {
		return fmt.Errorf("unknown WinUSB function %s", name)
	}
	if !cached {
		proc = usb.NewProc(name)
	}
	r, _, e := proc.Call(args...)
	if r == 0 {
		if cached && e == windows.ERROR_IO_PENDING {
			return e
		}
		return fmt.Errorf("%s: %w", name, e)
	}
	return nil
}
func CheckDLLs() error {
	for _, d := range []*windows.LazyDLL{usb, setup, cm} {
		if e := d.Load(); e != nil {
			return e
		}
	}
	return nil
}

type devInfo struct {
	Size     uint32
	Class    windows.GUID
	DevInst  uint32
	Reserved uintptr
}
type Node struct {
	ID, Parent, Service string
	DriverINF           string
	Paths               []string
	Problem             uint32
}

func strProp(set uintptr, info *devInfo, prop uintptr) string {
	b := make([]uint16, 2048)
	var typ, size uint32
	r, _, _ := setup.NewProc("SetupDiGetDeviceRegistryPropertyW").Call(set, uintptr(unsafe.Pointer(info)), prop, uintptr(unsafe.Pointer(&typ)), uintptr(unsafe.Pointer(&b[0])), uintptr(len(b)*2), uintptr(unsafe.Pointer(&size)))
	if r == 0 {
		return ""
	}
	return windows.UTF16ToString(b)
}
func Enumerate(logger *log.Logger) ([]Node, error) {
	if e := CheckDLLs(); e != nil {
		return nil, e
	}
	enumerator, _ := windows.UTF16PtrFromString("USB")
	set, _, e := setup.NewProc("SetupDiGetClassDevsW").Call(0, uintptr(unsafe.Pointer(enumerator)), 0, 6) // PRESENT | ALLCLASSES
	if set == ^uintptr(0) {
		return nil, fmt.Errorf("SetupDiGetClassDevsW: %w", e)
	}
	defer setup.NewProc("SetupDiDestroyDeviceInfoList").Call(set)
	var nodes []Node
	for i := uintptr(0); ; i++ {
		d := devInfo{Size: uint32(unsafe.Sizeof(devInfo{}))}
		r, _, e := setup.NewProc("SetupDiEnumDeviceInfo").Call(set, i, uintptr(unsafe.Pointer(&d)))
		if r == 0 {
			if e == windows.ERROR_NO_MORE_ITEMS {
				break
			}
			return nil, e
		}
		b := make([]uint16, 2048)
		r, _, e = setup.NewProc("SetupDiGetDeviceInstanceIdW").Call(set, uintptr(unsafe.Pointer(&d)), uintptr(unsafe.Pointer(&b[0])), uintptr(len(b)), 0)
		if r == 0 {
			return nil, e
		}
		id := windows.UTF16ToString(b)
		if !strings.HasPrefix(strings.ToUpper(id), `USB\VID_05AC&PID_1903`) {
			continue
		}
		n := Node{ID: id, Service: strProp(set, &d, 4)}
		if driverKey := strProp(set, &d, 9); driverKey != "" {
			if k, err := registry.OpenKey(registry.LOCAL_MACHINE, `SYSTEM\CurrentControlSet\Control\Class\`+driverKey, registry.QUERY_VALUE); err == nil {
				n.DriverINF, _, _ = k.GetStringValue("InfPath")
				k.Close()
			}
		}
		var status uint32
		cm.NewProc("CM_Get_DevNode_Status").Call(uintptr(unsafe.Pointer(&status)), uintptr(unsafe.Pointer(&n.Problem)), uintptr(d.DevInst), 0)
		var parent uint32
		cr, _, _ := cm.NewProc("CM_Get_Parent").Call(uintptr(unsafe.Pointer(&parent)), uintptr(d.DevInst), 0)
		if cr == 0 {
			pb := make([]uint16, 2048)
			cr, _, _ = cm.NewProc("CM_Get_Device_IDW").Call(uintptr(parent), uintptr(unsafe.Pointer(&pb[0])), uintptr(len(pb)), 0)
			if cr == 0 {
				n.Parent = windows.UTF16ToString(pb)
			}
		}
		logger.Printf("device id=%s parent=%s service=%s original_or_current_inf=%s problem=%d description=%s", n.ID, n.Parent, n.Service, n.DriverINF, n.Problem, strProp(set, &d, 0))
		if strings.EqualFold(n.Service, "WinUSB") {
			key, e := registry.OpenKey(registry.LOCAL_MACHINE, `SYSTEM\CurrentControlSet\Enum\`+id+`\Device Parameters`, registry.QUERY_VALUE)
			if e != nil {
				logger.Printf("Device Parameters: %v", e)
			} else {
				guids, _, e := key.GetStringsValue("DeviceInterfaceGUIDs")
				if e != nil {
					v, _, singleErr := key.GetStringValue("DeviceInterfaceGUID")
					if singleErr == nil {
						guids = []string{v}
					} else {
						logger.Printf("DeviceInterfaceGUIDs: %v", e)
					}
				}
				key.Close()
				for _, gs := range guids {
					g, e := windows.GUIDFromString(gs)
					if e != nil {
						logger.Printf("GUID parse: %v", e)
						continue
					}
					idp, _ := windows.UTF16PtrFromString(id)
					var size uint32
					cr, _, _ := cm.NewProc("CM_Get_Device_Interface_List_SizeW").Call(uintptr(unsafe.Pointer(&size)), uintptr(unsafe.Pointer(&g)), uintptr(unsafe.Pointer(idp)), 0)
					if cr != 0 || size < 2 || size > 65536 {
						logger.Printf("interface list size CR=0x%x size=%d", cr, size)
						continue
					}
					buf := make([]uint16, size)
					cr, _, _ = cm.NewProc("CM_Get_Device_Interface_ListW").Call(uintptr(unsafe.Pointer(&g)), uintptr(unsafe.Pointer(idp)), uintptr(unsafe.Pointer(&buf[0])), uintptr(size), 0)
					if cr != 0 {
						logger.Printf("interface list CR=0x%x", cr)
						continue
					}
					for start := 0; start < len(buf) && buf[start] != 0; {
						end := start
						for end < len(buf) && buf[end] != 0 {
							end++
						}
						if end == len(buf) {
							break
						}
						path := windows.UTF16ToString(buf[start:end])
						n.Paths = append(n.Paths, path)
						logger.Printf("WinUSB path=%s", path)
						start = end + 1
					}
				}
			}
		}
		nodes = append(nodes, n)
	}
	return nodes, nil
}
func Pair(nodes []Node, group int, parentMode bool) (string, string, error) {
	control, data := fmt.Sprintf("&MI_%02X", group*2), fmt.Sprintf("&MI_%02X", group*2+1)
	var controls, datas []Node
	for _, n := range nodes {
		id := strings.ToUpper(n.ID)
		if !strings.EqualFold(n.Service, "WinUSB") || len(n.Paths) == 0 {
			continue
		}
		if parentMode && !strings.Contains(strings.Split(id, `\`)[1], "&MI_") {
			controls = append(controls, n)
		} else if !parentMode {
			if strings.Contains(id, control+`\`) {
				controls = append(controls, n)
			}
			if strings.Contains(id, data+`\`) {
				datas = append(datas, n)
			}
		}
	}
	if parentMode {
		if len(controls) != 1 || len(controls[0].Paths) != 1 {
			return "", "", fmt.Errorf("parent mode requires exactly one WinUSB-bound Apple parent with one path")
		}
		return controls[0].Paths[0], "", nil
	}
	var pairs [][2]string
	for _, c := range controls {
		for _, d := range datas {
			if c.Parent != "" && strings.EqualFold(c.Parent, d.Parent) && len(c.Paths) == 1 && len(d.Paths) == 1 {
				pairs = append(pairs, [2]string{c.Paths[0], d.Paths[0]})
			}
		}
	}
	if len(pairs) != 1 {
		return "", "", fmt.Errorf("group %d: need exactly one sibling WinUSB pair MI_%02X/MI_%02X; found %d (do not bind parent automatically)", group, group*2, group*2+1, len(pairs))
	}
	return pairs[0][0], pairs[0][1], nil
}

type Interface struct {
	openedPath string
	Handle     uintptr
	File       windows.Handle
	Own        bool
}

func Open(path string) (*Interface, error) {
	p, e := windows.UTF16PtrFromString(path)
	if e != nil {
		return nil, e
	}
	f, e := windows.CreateFile(p, windows.GENERIC_READ|windows.GENERIC_WRITE, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE, nil, windows.OPEN_EXISTING, windows.FILE_FLAG_OVERLAPPED, 0)
	if e != nil {
		return nil, e
	}
	var h uintptr
	e = boolCall("WinUsb_Initialize", uintptr(f), uintptr(unsafe.Pointer(&h)))
	if e != nil {
		windows.CloseHandle(f)
		return nil, e
	}
	return &Interface{openedPath: path, Handle: h, File: f, Own: true}, nil
}
func (i *Interface) Close() {
	if i == nil || i.Handle == 0 {
		return
	}
	boolCall("WinUsb_Free", i.Handle)
	if i.Own {
		windows.CloseHandle(i.File)
	}
	i.Handle = 0
	i.File = 0
	i.openedPath = ""
}
func (i *Interface) Associated(n byte) (*Interface, error) {
	var h uintptr
	e := boolCall("WinUsb_GetAssociatedInterface", i.Handle, uintptr(n), uintptr(unsafe.Pointer(&h)))
	if e != nil {
		return nil, e
	}
	return &Interface{Handle: h, File: i.File, Own: false}, nil
}
func (i *Interface) Descriptor(typ, index byte, lang uint16, size int) ([]byte, error) {
	if size < 1 || size > 65535 {
		return nil, fmt.Errorf("descriptor size")
	}
	b := make([]byte, size)
	var n uint32
	e := boolCall("WinUsb_GetDescriptor", i.Handle, uintptr(typ), uintptr(index), uintptr(lang), uintptr(unsafe.Pointer(&b[0])), uintptr(size), uintptr(unsafe.Pointer(&n)))
	runtime.KeepAlive(b)
	if e != nil {
		return nil, e
	}
	if int(n) > size {
		return nil, fmt.Errorf("descriptor overflow")
	}
	return b[:n], nil
}

type InterfaceDescriptor = ncm.InterfaceDescriptor

func (i *Interface) Query(alt byte) (InterfaceDescriptor, error) {
	var d InterfaceDescriptor
	e := boolCall("WinUsb_QueryInterfaceSettings", i.Handle, uintptr(alt), uintptr(unsafe.Pointer(&d)))
	return d, e
}
func (i *Interface) Alt(alt byte) error {
	return boolCall("WinUsb_SetCurrentAlternateSetting", i.Handle, uintptr(alt))
}

type Pipe = ncm.PipeDescriptor

func (i *Interface) Pipes(alt byte) ([]Pipe, error) {
	d, e := i.Query(alt)
	if e != nil {
		return nil, e
	}
	var pipes []Pipe
	for j := byte(0); j < d.Endpoints; j++ {
		var p Pipe
		e = boolCall("WinUsb_QueryPipe", i.Handle, uintptr(alt), uintptr(j), uintptr(unsafe.Pointer(&p)))
		if e != nil {
			return nil, e
		}
		pipes = append(pipes, p)
	}
	return pipes, nil
}
func (i *Interface) Policy(pipe byte, policy uint32, value []byte) error {
	return boolCall("WinUsb_SetPipePolicy", i.Handle, uintptr(pipe), uintptr(policy), uintptr(len(value)), uintptr(unsafe.Pointer(&value[0])))
}
func (i *Interface) PolicyUint(pipe byte, policy uint32) (uint32, error) {
	var v, n uint32
	n = 4
	e := boolCall("WinUsb_GetPipePolicy", i.Handle, uintptr(pipe), uintptr(policy), uintptr(unsafe.Pointer(&n)), uintptr(unsafe.Pointer(&v)))
	return v, e
}

// The 8-byte WINUSB_SETUP_PACKET is passed BY VALUE on Windows x64.
func (i *Interface) Control(rt, request byte, value, index uint16, b []byte) (uint32, error) {
	packet := uint64(rt) | uint64(request)<<8 | uint64(value)<<16 | uint64(index)<<32 | uint64(len(b))<<48
	var p uintptr
	var n uint32
	var pin runtime.Pinner
	if len(b) > 0 {
		pin.Pin(&b[0])
		defer pin.Unpin()
		p = uintptr(unsafe.Pointer(&b[0]))
	}
	e := boolCall("WinUsb_ControlTransfer", i.Handle, uintptr(packet), p, uintptr(len(b)), uintptr(unsafe.Pointer(&n)), 0)
	runtime.KeepAlive(b)
	return n, e
}
