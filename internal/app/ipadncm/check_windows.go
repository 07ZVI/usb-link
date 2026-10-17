//go:build windows && amd64

package ipadncm

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
	"runtime"
	"strings"
	"suhang/usbnet/internal/diagnostics/grouptrial"
	"suhang/usbnet/internal/security/deviceguard"
	"suhang/usbnet/internal/transport/winusb"
	"time"
	"unsafe"
)

type Device struct {
	VID                           string                         `json:"vid"`
	PID                           string                         `json:"pid"`
	USBProduct                    string                         `json:"usb_product,omitempty"`
	USBProductReadStatus          string                         `json:"usb_product_read_status,omitempty"`
	USBSerialReadStatus           string                         `json:"usb_serial_read_status,omitempty"`
	USBSerialFailureShape         *USBIdentityStringFailureShape `json:"usb_serial_failure_shape,omitempty"`
	USBSerialPaddingNULUnits      int                            `json:"usb_serial_exact_padding_nul_units_consumed,omitempty"`
	USBSerialSHA256               string                         `json:"usb_descriptor_serial_sha256,omitempty"`
	USBSerialIndex                byte                           `json:"usb_serial_descriptor_index,omitempty"`
	USBIdentityLanguage           uint16                         `json:"usb_identity_langid,omitempty"`
	USBDescriptorIdentityVerified bool                           `json:"usb_serial_product_and_native_binding_verified"`
	Configurations                []Configuration                `json:"configurations"`
	CurrentConfiguration          byte                           `json:"current_configuration"`
	USBSpeedCode                  byte                           `json:"usb_speed_code"`
	Errors                        []string                       `json:"errors,omitempty"`
	hub                           string
	port                          uint32
	pid                           uint16
	usbSerial                     string // Descriptor value is private; diagnostics export only its digest.
	usbIdentityPortStable         bool
	usbBCDDevice                  uint16 // Cached from the already-read device descriptor.
}
type Node struct {
	IDPrefix            string   `json:"id_prefix"`
	Service             string   `json:"service"`
	Problem             uint32   `json:"problem"`
	ProblemStatus       string   `json:"problem_status,omitempty"`
	ProblemStatusError  string   `json:"problem_status_error,omitempty"`
	DevNodeStatus       string   `json:"devnode_status,omitempty"`
	StateError          string   `json:"state_error,omitempty"`
	DriverVersion       string   `json:"driver_version,omitempty"`
	EnumeratorClass     string   `json:"enumerator_class,omitempty"`
	EnumeratorError     string   `json:"enumerator_class_read_error,omitempty"`
	CompositeCaps       *uint64  `json:"usbccgp_capabilities,omitempty"`
	CompositeCapsError  string   `json:"usbccgp_capabilities_read_error,omitempty"`
	OriginalConfig      *uint64  `json:"original_configuration_value,omitempty"`
	OriginalConfigError string   `json:"original_configuration_read_error,omitempty"`
	DriverINF           string   `json:"driver_inf,omitempty"`
	LowerFilters        []string `json:"lower_filters,omitempty"`
	UpperFilters        []string `json:"upper_filters,omitempty"`
	InterfacePathCount  int      `json:"interface_path_count"`
	paths               []string
	instanceID          string
	locationPaths       []string // Cached physical location; never exported.
	devInst             windows.DEVINST
}
type Snapshot struct {
	Devices                  []Device `json:"apple_mobile_devices"`
	Nodes                    []Node   `json:"apple_mobile_nodes"`
	HubsScanned              int      `json:"hubs_scanned"`
	HubErrors                int      `json:"hub_errors"`
	Error                    string   `json:"error,omitempty"`
	ConnectionReadErrors     int      `json:"connection_info_read_errors,omitempty"`
	ConnectionReadErrorCodes []string `json:"connection_info_read_error_codes,omitempty"`
	ConnectionNotPresent     int      `json:"connection_info_not_present_samples,omitempty"`
}
type Result struct {
	Protocol               string           `json:"protocol"`
	Version                string           `json:"version"`
	Started                string           `json:"started_utc"`
	Status                 string           `json:"status"`
	Before                 Snapshot         `json:"before"`
	After                  *Snapshot        `json:"after,omitempty"`
	ProductType            string           `json:"product_type,omitempty"`
	ProductVersion         string           `json:"product_version,omitempty"`
	MetadataError          string           `json:"metadata_error,omitempty"`
	USBIdentifiersVerified bool             `json:"usb_identifiers_verified_not_apple_pairing"`
	IdentitySource         string           `json:"identity_source,omitempty"`
	IdentityRecheck        *Snapshot        `json:"after_identity_usb_recheck,omitempty"`
	IdentityTargetStable   bool             `json:"physical_target_stable_after_identity_query"`
	Mux                    MuxDiagnostic    `json:"apple_usb_query"`
	ControlSnapshot        *Snapshot        `json:"control_snapshot,omitempty"`
	ControlAttempts        []ControlAttempt `json:"control_attempts,omitempty"`
	Access                 string           `json:"control_access"`
	GetMode                []byte           `json:"get_mode,omitempty"`
	SetAttempted           bool             `json:"set_mode_attempted"`
	SetAcknowledged        bool             `json:"set_mode_acknowledged"`
	SetError               string           `json:"set_mode_error,omitempty"`
	ModeConsent            bool             `json:"mode_change_consent"`
	ReenumerationSeen      bool             `json:"ncm_descriptors_appeared"`
	DriverChanged          bool             `json:"driver_changed"`
	NetworkVerified        bool             `json:"network_verified"`
	MoonlightVerified      bool             `json:"moonlight_verified"`
}

func eno(e error) string {
	var n windows.Errno
	if errors.As(e, &n) {
		return fmt.Sprintf("WIN32_%d", uint32(n))
	}
	return "API_FAILED"
}
func open(path string) (windows.Handle, error) {
	p, e := windows.UTF16PtrFromString(path)
	if e != nil {
		return 0, e
	}
	return windows.CreateFile(p, windows.GENERIC_WRITE, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE, nil, windows.OPEN_EXISTING, windows.FILE_FLAG_OVERLAPPED, 0)
}

// Buffers and OVERLAPPED stay alive until completion or completed cancellation.
func ioctl(ctx context.Context, h windows.Handle, code uint32, b []byte) (uint32, error) {
	ev, e := windows.CreateEvent(nil, 1, 0, nil)
	if e != nil {
		return 0, e
	}
	defer windows.CloseHandle(ev)
	ov := windows.Overlapped{HEvent: ev}
	var pin runtime.Pinner
	pin.Pin(&ov)
	pin.Pin(&b[0])
	defer pin.Unpin()
	var n uint32
	pin.Pin(&n)
	e = windows.DeviceIoControl(h, code, &b[0], uint32(len(b)), &b[0], uint32(len(b)), &n, &ov)
	if e != windows.ERROR_IO_PENDING {
		return n, e
	}
	ms := uint32(1000)
	if d, ok := ctx.Deadline(); ok {
		left := time.Until(d).Milliseconds()
		if left <= 0 {
			left = 1
		}
		if left < int64(ms) {
			ms = uint32(left)
		}
	}
	state, we := windows.WaitForSingleObject(ev, ms)
	if we != nil || state != windows.WAIT_OBJECT_0 {
		windows.CancelIoEx(h, &ov)
		windows.GetOverlappedResult(h, &ov, &n, true)
		return n, windows.ERROR_TIMEOUT
	}
	e = windows.GetOverlappedResult(h, &ov, &n, false)
	return n, e
}
func descriptor(ctx context.Context, h windows.Handle, port uint32, kind, index byte, length int) ([]byte, error) {
	return descriptorLanguage(ctx, h, port, kind, index, 0, length)
}
func descriptorLanguage(ctx context.Context, h windows.Handle, port uint32, kind, index byte, language uint16, length int) ([]byte, error) {
	if length < 1 || length > 65535 {
		return nil, windows.ERROR_INVALID_PARAMETER
	}
	b := make([]byte, 12+length)
	binary.LittleEndian.PutUint32(b, port)
	b[4] = 0x80
	b[5] = 6
	binary.LittleEndian.PutUint16(b[6:], uint16(kind)<<8|uint16(index))
	binary.LittleEndian.PutUint16(b[8:], language)
	binary.LittleEndian.PutUint16(b[10:], uint16(length))
	n, e := ioctl(ctx, h, 0x220410, b)
	if e != nil {
		return nil, e
	}
	if n < 12 || int(n) > len(b) {
		return nil, windows.ERROR_INVALID_DATA
	}
	return b[12:n], nil
}
func mobilePID(p uint16) bool { return p >= 0x12a0 && p <= 0x12ff }

// Inspect reads USB/PnP state without attempting a mode request.
func Inspect() Snapshot {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	return inventory(ctx)
}
func inventory(ctx context.Context) Snapshot { return inventoryProduct(ctx, 0) }

// A nonzero product reads cached hub connection information only, without USB descriptor requests.
func inventoryProduct(ctx context.Context, product uint16) Snapshot {
	s := Snapshot{}
	g, _ := windows.GUIDFromString("{F18A0E88-C30C-11D0-8815-00A0C906BED8}")
	paths, e := windows.CM_Get_Device_Interface_List("", &g, 0)
	if e != nil {
		s.Error = eno(e)
		return s
	}
	for _, path := range paths {
		if ctx.Err() != nil {
			s.Error = "TIME_LIMIT"
			break
		}
		h, e := open(path)
		if e != nil {
			s.HubErrors++
			continue
		}
		b := make([]byte, 76)
		_, e = ioctl(ctx, h, 0x220408, b)
		if e != nil {
			windows.CloseHandle(h)
			s.HubErrors++
			continue
		}
		s.HubsScanned++
		ports := int(b[6])
		if ports > 127 {
			ports = 127
		}
		for p := 1; p <= ports && ctx.Err() == nil; p++ {
			info := make([]byte, 4096)
			binary.LittleEndian.PutUint32(info, uint32(p))
			got, er := ioctl(ctx, h, 0x220448, info)
			if er != nil || got < 35 {
				s.ConnectionReadErrors++
				code := "CONNECTION_INFO_SHORT_READ"
				if er != nil {
					code = "CONNECTION_INFO_" + eno(er)
				}
				if len(s.ConnectionReadErrorCodes) < 16 {
					s.ConnectionReadErrorCodes = append(s.ConnectionReadErrorCodes, code)
				}
				continue
			}
			if binary.LittleEndian.Uint32(info[31:]) != 1 {
				s.ConnectionNotPresent++
				continue
			}
			dd := info[4:22]
			if dd[0] != 18 || dd[1] != 1 || binary.LittleEndian.Uint16(dd[8:]) != 0x05ac {
				continue
			}
			pid := binary.LittleEndian.Uint16(dd[10:])
			if (product == 0 && !mobilePID(pid)) || (product != 0 && pid != product) {
				continue
			}
			d := Device{VID: "05AC", PID: fmt.Sprintf("%04X", pid), CurrentConfiguration: info[22], USBSpeedCode: info[23], hub: path, port: uint32(p), pid: pid}
			d.usbBCDDevice = binary.LittleEndian.Uint16(dd[12:14])
			if product != 0 {
				s.Devices = append(s.Devices, d)
				continue
			}
			if pid == 0x12ab {
				readUSBDescriptorIdentity(ctx, h, &d, dd)
			} else if dd[15] != 0 {
				d.USBProduct = usbProductString(ctx, h, uint32(p), dd[15])
			}
			if dd[17] > 16 {
				d.Errors = append(d.Errors, "CONFIGURATION_COUNT_OUT_OF_BOUNDS")
			} else {
				for i := 0; i < int(dd[17]) && ctx.Err() == nil; i++ {
					hd, er := descriptor(ctx, h, uint32(p), 2, byte(i), 9)
					if er != nil || len(hd) != 9 {
						d.Errors = append(d.Errors, fmt.Sprintf("CONFIG_%d_HEADER_UNAVAILABLE", i))
						continue
					}
					n := int(binary.LittleEndian.Uint16(hd[2:]))
					if n < 9 {
						d.Errors = append(d.Errors, "CONFIG_SIZE_INVALID")
						continue
					}
					full, er := descriptor(ctx, h, uint32(p), 2, byte(i), n)
					if er != nil {
						d.Errors = append(d.Errors, fmt.Sprintf("CONFIG_%d_READ_%s", i, eno(er)))
						continue
					}
					cfg, er := Parse(full, i)
					if er != nil {
						d.Errors = append(d.Errors, er.Error())
						continue
					}
					d.Configurations = append(d.Configurations, cfg)
				}
			}
			s.Devices = append(s.Devices, d)
		}
		windows.CloseHandle(h)
	}
	if product != 0 {
		return s
	}
	nodes := inventoryPnP(ctx)
	s.Nodes = nodes.Nodes
	if nodes.Error != "" {
		s.Error = nodes.Error
	}
	if s.Error == "" {
		for i := range s.Devices {
			if s.Devices[i].pid == 0x12ab {
				verifyUSBDescriptorRoot(ctx, &s.Devices[i], s.Nodes)
			}
		}
	}
	return s
}

// SetupAPI reads cached devnodes and registry properties only. This path must
// not open a hub, read USB descriptors or send any device/control requests.
func inventoryPnP(ctx context.Context) Snapshot {
	s := Snapshot{}
	set, e := windows.SetupDiGetClassDevsEx(nil, "USB", 0, windows.DIGCF_PRESENT|windows.DIGCF_ALLCLASSES, 0, "")
	if e != nil {
		s.Error = eno(e)
		return s
	}
	defer set.Close()
	complete := false
	for i := 0; i < 4096; i++ {
		if ctx.Err() != nil {
			s.Error = "TIME_LIMIT"
			break
		}
		info, er := set.EnumDeviceInfo(i)
		if er == windows.ERROR_NO_MORE_ITEMS {
			complete = true
			break
		}
		if er != nil {
			s.Error = eno(er)
			break
		}
		id, er := set.DeviceInstanceID(info)
		if er != nil {
			s.Error = "PNP_ID_QUERY_FAILED"
			break
		}
		upper := strings.ToUpper(id)
		if !strings.HasPrefix(upper, `USB\VID_05AC&PID_12`) {
			continue
		}
		part := strings.SplitN(id, `\`, 3)
		if len(part) != 3 {
			continue
		}
		n := Node{IDPrefix: part[0] + `\` + part[1], instanceID: id, devInst: info.DevInst}
		location, locationError := set.DeviceRegistryProperty(info, windows.SPDRP_LOCATION_PATHS)
		if locationError == nil {
			n.locationPaths, _ = location.([]string)
		}
		v, _ := set.DeviceRegistryProperty(info, windows.SPDRP_SERVICE)
		n.Service, _ = v.(string)
		v, _ = set.DeviceRegistryProperty(info, windows.SPDRP_DRIVER)
		if driver, ok := v.(string); ok {
			if k, er := registry.OpenKey(registry.LOCAL_MACHINE, `SYSTEM\CurrentControlSet\Control\Class\`+driver, registry.QUERY_VALUE); er == nil {
				n.DriverINF, _, _ = k.GetStringValue("InfPath")
				n.DriverVersion, _, _ = k.GetStringValue("DriverVersion")
				k.Close()
			}
		}
		if k, er := registry.OpenKey(registry.LOCAL_MACHINE, `SYSTEM\CurrentControlSet\Enum\`+id, registry.QUERY_VALUE); er == nil {
			n.LowerFilters, _, _ = k.GetStringsValue("LowerFilters")
			n.UpperFilters, _, _ = k.GetStringsValue("UpperFilters")
			k.Close()
		}
		if strings.EqualFold(n.Service, "usbccgp") {
			readCompositeSettings(set, info, &n)
		}
		var status uint32
		if er := windows.CM_Get_DevNode_Status(&status, &n.Problem, info.DevInst, 0); er != nil {
			n.StateError = eno(er)
		} else {
			n.DevNodeStatus = fmt.Sprintf("0x%08x", status)
		}
		n.ProblemStatus, n.ProblemStatusError = problemStatus(set, info)
		if strings.EqualFold(n.Service, "WinUSB") {
			k, er := registry.OpenKey(registry.LOCAL_MACHINE, `SYSTEM\CurrentControlSet\Enum\`+id+`\Device Parameters`, registry.QUERY_VALUE)
			if er == nil {
				gs, _, er := k.GetStringsValue("DeviceInterfaceGUIDs")
				if er != nil {
					one, _, er := k.GetStringValue("DeviceInterfaceGUID")
					if er == nil {
						gs = []string{one}
					}
				}
				k.Close()
				for _, str := range gs {
					guid, er := windows.GUIDFromString(str)
					if er == nil {
						ps, er := windows.CM_Get_Device_Interface_List(id, &guid, 0)
						if er == nil {
							n.paths = append(n.paths, ps...)
						}
					}
				}
			}
		}
		n.InterfacePathCount = len(n.paths)
		s.Nodes = append(s.Nodes, n)
	}
	if !complete && s.Error == "" {
		s.Error = "PNP_ENUM_LIMIT"
	}
	return s
}

func hasNCM(s Snapshot) bool {
	for _, d := range s.Devices {
		for _, c := range d.Configurations {
			if c.NCMControls > 0 {
				return true
			}
		}
	}
	return false
}

func HasActiveNCM(s Snapshot) bool {
	return len(s.Devices) == 1 && s.Error == "" && activeNCM(s.Devices[0].Configurations, s.Devices[0].CurrentConfiguration)
}

func sameUSBTarget(a, b Snapshot) bool {
	if a.Error != "" || b.Error != "" || len(a.Devices) != 1 || len(b.Devices) != 1 || a.Devices[0].hub != b.Devices[0].hub || a.Devices[0].port != b.Devices[0].port || a.Devices[0].pid != b.Devices[0].pid {
		return false
	}
	return a.Devices[0].pid != 0x12ab || descriptorAttachment(a).same(descriptorAttachment(b))
}
func Run(version string, consent func() bool) Result {
	return RunWithControlLease(version, consent, nil)
}

type ControlAttempt struct {
	Node         string `json:"node_id_prefix"`
	Transport    string `json:"transport,omitempty"`
	OpenStage    string `json:"open_stage"`
	OpenError    string `json:"open_error,omitempty"`
	PolicyError  string `json:"policy_error,omitempty"`
	GetModeError string `json:"get_mode_error,omitempty"`
	GetModeBytes uint32 `json:"get_mode_bytes"`
}

// Open locally to distinguish CreateFile failure from WinUsb_Initialize failure.
// The shared Mac bridge's opening behavior is left unchanged.
func openControl(path string) (*winusb.Interface, string, error) {
	p, e := windows.UTF16PtrFromString(path)
	if e != nil {
		return nil, "PATH_ENCODING", e
	}
	f, e := windows.CreateFile(p, windows.GENERIC_READ|windows.GENERIC_WRITE, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE, nil, windows.OPEN_EXISTING, windows.FILE_FLAG_OVERLAPPED, 0)
	if e != nil {
		return nil, "CREATE_FILE", e
	}
	var h uintptr
	v, _, e := windows.NewLazySystemDLL("winusb.dll").NewProc("WinUsb_Initialize").Call(uintptr(f), uintptr(unsafe.Pointer(&h)))
	if v == 0 {
		windows.CloseHandle(f)
		return nil, "WINUSB_INITIALIZE", e
	}
	return &winusb.Interface{Handle: h, File: f, Own: true}, "OPENED", nil
}

// The optional lease is acquired only after read-only iPad identity succeeds.
// The caller handles consent and restoring the service; it returns a cleanup
// even on failure so any partial stop is restored before returning.
func RunWithControlLease(version string, consent func() bool, acquire func() (func(), bool)) Result {
	return runWithControlLease(version, consent, acquire, false, nil)
}

// Explicit opt-in keeps the existing Mac bridge and older probe entry points
// on their original WinUSB path.
func RunAppleControlWithLease(version string, consent func() bool, acquire func() (func(), bool)) Result {
	return runWithControlLease(version, consent, acquire, true, nil)
}

// Re-activate after this launch's grouping restart. No saved/external identity
// is accepted: successful prior mode evidence and the unchanged exact root are
// required, in addition to all existing hash/control/lease/GET_MODE gates.
func RunAppleControlForVerifiedRoot(version string, previous Result, consent func() bool, acquire func() (func(), bool)) Result {
	return runWithControlLease(version, consent, acquire, true, &previous)
}

func sameRootInstance(a, b Snapshot) bool {
	if !sameUSBTarget(a, b) {
		return false
	}
	var previous, current string
	for _, n := range a.Nodes {
		if n.IDPrefix == `USB\VID_05AC&PID_12AB` {
			previous = n.instanceID
		}
	}
	for _, n := range b.Nodes {
		if n.IDPrefix == `USB\VID_05AC&PID_12AB` {
			current = n.instanceID
		}
	}
	return grouptrial.SameVerifiedRoot(true, previous, current)
}

func reactivationRootReady(s Snapshot) string {
	for _, n := range s.Nodes {
		if n.IDPrefix == `USB\VID_05AC&PID_12AB` {
			if n.StateError != "" || n.Problem != 0 || n.DevNodeStatus == "" {
				return "REACTIVATION_ROOT_NOT_READY"
			}
			if grouptrial.NeedsWindowsRestart(n.DevNodeStatus) {
				return "TARGET_WINDOWS_RESTART_REQUIRED"
			}
			return ""
		}
	}
	return "REACTIVATION_ROOT_ABSENT"
}

type modeControl interface {
	Policy(byte, uint32, []byte) error
	Control(byte, byte, uint16, uint16, []byte) (uint32, error)
	Close()
}

func runWithControlLease(version string, consent func() bool, acquire func() (func(), bool), apple bool, previous *Result, networkOnly ...bool) Result {
	return runWithSelectedControlLease(version, consent, acquire, apple, previous, nil, networkOnly...)
}

func runWithSelectedControlLease(version string, consent func() bool, acquire func() (func(), bool), apple bool, previous *Result, direct localNCMDirectAttempt, networkOnly ...bool) Result {
	ctx, cancel := context.WithTimeout(connectionContext(), 60*time.Second)
	defer cancel()
	r := Result{Protocol: "SUHANG-IPAD-NCM-CHECK/1", Version: version, Started: time.Now().UTC().Format(time.RFC3339), Status: "INCOMPLETE", Access: "NOT_TESTED"}
	defer func() {
		RecordConnectionArchiveEvent("mode_result", struct {
			Attempt uint64 `json:"software_attempt"`
			Result  Result `json:"result"`
		}{currentSoftwareAttempt(), r})
	}()
	network := len(networkOnly) == 1 && networkOnly[0]
	r.Before = inventory(ctx)
	if r.Before.Error != "" {
		r.Status = "INVENTORY_INCOMPLETE"
		return r
	}
	if len(r.Before.Devices) != 1 {
		r.Status = "NEED_ONE_APPLE_MOBILE_DEVICE"
		return r
	}
	if previous != nil {
		active := HasActiveNCM(previous.Before) || (previous.After != nil && previous.ReenumerationSeen && HasActiveNCM(*previous.After))
		if !apple || !modeResultIdentity(*previous, active) || !sameRootInstance(previous.Before, r.Before) {
			r.Status = "CURRENT_LAUNCH_EXACT_ROOT_IDENTITY_REQUIRED"
			return r
		}
		if err := reactivationRootReady(r.Before); err != "" {
			r.Status = err
			return r
		}
		r.USBIdentifiersVerified = previous.USBIdentifiersVerified
		r.ProductType, r.ProductVersion = previous.ProductType, previous.ProductVersion
		r.IdentitySource = "CURRENT_LAUNCHER_SUCCESSFUL_MODE_EXACT_ROOT"
	} else if network {
		if !networkOnlyUSBEligible(r.Before) {
			r.Status = "NETWORK_ONLY_USB_LAYOUT_UNCONFIRMED"
			return r
		}
		r.USBIdentifiersVerified = true
		r.ProductType = usbIPadModel(r.Before.Devices[0].USBProduct)
		r.IdentitySource = "CURRENT_USB_IDENTIFIERS_AND_NCM_LAYOUT_NO_APPLE_SESSION"
	} else {
		r.IdentitySource = "FRESH_APPLE_USB_QUERY"
		r.ProductType, r.ProductVersion, r.MetadataError = queryModel(ctx, "127.0.0.1:27015", &r.Mux)
		if apple {
			fresh := inventory(ctx)
			r.IdentityRecheck = &fresh
			r.IdentityTargetStable = sameRootInstance(r.Before, fresh)
			if r.MetadataError == "" && !r.IdentityTargetStable {
				r.Status = "USB_TARGET_CHANGED_DURING_IDENTITY_QUERY"
				return r
			}
		}
	}
	if network && r.USBIdentifiersVerified {
		allowed := consent()
		archiveUSBConsent("before_photo_target_bind", allowed, ctx.Err() == nil)
		if !allowed {
			r.Status = "MODE_CHANGE_DECLINED"
			return r
		}
		if err := BindPhotoIsolationTarget(r.Before); err != nil {
			r.Status = "PHOTO_ISOLATION_RECOVERY_OR_SCOPE_UNCONFIRMED"
			return r
		}
		if err := BindLocalPhotoPolicyTarget(r.Before); err != nil {
			r.Status = "PHOTO_POLICY_RECOVERY_OR_SCOPE_UNCONFIRMED"
			return r
		}
	}
	if direct != nil && r.Before.Devices[0].CurrentConfiguration != 3 {
		r.Status = "DIRECT_INITIAL_LAYOUT_REQUIRED"
		return r
	}
	if (!apple && hasNCM(r.Before)) || (apple && HasActiveNCM(r.Before) && (r.USBIdentifiersVerified || strings.HasPrefix(r.ProductType, "iPad"))) {
		r.Status = "NCM_DESCRIPTORS_PRESENT"
		return r
	}
	if !r.USBIdentifiersVerified && !strings.HasPrefix(r.ProductType, "iPad") {
		r.Status = "IPAD_IDENTITY_UNCONFIRMED"
		if r.MetadataError == "APPLE_USB_DEVICE_NOT_READY" || r.MetadataError == "APPLE_USB_QUERY_CANCELLED_OR_TIMED_OUT" {
			r.Status = r.MetadataError
		}
		return r
	}
	r.Access = "NO_EXISTING_WINUSB_CONTROL_PATH"
	target := r.Before.Devices[0]
	nodes := r.Before.Nodes
	if acquire != nil {
		cleanup, ok := acquire()
		if cleanup != nil {
			defer cleanup()
		}
		if !ok {
			r.Status = "CONTROL_SERVICE_PAUSE_NOT_COMPLETED"
			return r
		}
		if ctx.Err() != nil {
			r.Status = "TIME_LIMIT_NO_CHANGE"
			return r
		}
		fresh := inventory(ctx)
		r.ControlSnapshot = &fresh
		if fresh.Error != "" || len(fresh.Devices) != 1 || fresh.Devices[0].hub != target.hub || fresh.Devices[0].port != target.port || fresh.Devices[0].pid != target.pid {
			r.Status = "USB_TARGET_CHANGED_NO_CONTROL_REQUEST"
			return r
		}
		if previous != nil && !sameRootInstance(previous.Before, fresh) {
			r.Status = "ROOT_CHANGED_AFTER_SERVICE_PAUSE_NO_REQUEST"
			return r
		}
		if previous != nil {
			if err := reactivationRootReady(fresh); err != "" {
				r.Status = err
				return r
			}
		}
		nodes = fresh.Nodes
	}
	for _, node := range nodes {
		if !strings.Contains(strings.ToUpper(node.IDPrefix), "PID_"+target.PID) || !strings.EqualFold(node.Service, "WinUSB") {
			continue
		}
		for _, path := range node.paths {
			var w modeControl
			var stage string
			var e error
			transport := "WINUSB"
			openDone := RecordConnectionOperation("usb_control_open")
			if direct != nil {
				transport = "LOCAL_DIRECT_APPLE_MUX1_BUFFERED_CONTROL"
				w, stage, e = direct.open(ctx, node, path)
			} else if apple {
				transport = "APPLE_MUX1_BUFFERED_CONTROL"
				w, stage, e = openAppleControl(ctx, node, path)
			} else {
				w, stage, e = openControl(path)
			}
			openDone()
			r.ControlAttempts = append(r.ControlAttempts, ControlAttempt{Node: node.IDPrefix, Transport: transport, OpenStage: stage})
			a := &r.ControlAttempts[len(r.ControlAttempts)-1]
			if e != nil {
				a.OpenError = eno(e)
				r.Access = "WINUSB_OPEN_FAILED"
				if apple {
					r.Access = "APPLE_CONTROL_OPEN_FAILED"
				}
				continue
			}
			if e = w.Policy(0, 3, []byte{0xe8, 3, 0, 0}); e != nil {
				a.PolicyError = eno(e)
				r.Access = "CONTROL_TIMEOUT_POLICY_UNAVAILABLE"
				w.Close()
				continue
			}
			b := make([]byte, 4)
			getModeDone := RecordConnectionOperation("usb_get_mode")
			n, e := w.Control(0xc0, 0x45, 0, 0, b)
			getModeDone()
			a.GetModeBytes = n
			if e != nil {
				a.GetModeError = eno(e)
			}
			if e != nil || n != 4 {
				r.Access = "GET_MODE_UNAVAILABLE"
				w.Close()
				continue
			}
			r.Access = "GET_MODE_CONFIRMED"
			r.GetMode = b
			if b[0] != 3 || b[1] != 3 || b[2] != 3 || b[3] != 0 {
				r.Status = "MODE_NOT_INITIAL_NO_CHANGE"
				w.Close()
				return r
			}
			if ctx.Err() != nil {
				r.Status = "TIME_LIMIT_NO_CHANGE"
				w.Close()
				return r
			}
			r.ModeConsent = consent()
			archiveUSBConsent("before_mode_request", r.ModeConsent, ctx.Err() == nil)
			if !r.ModeConsent {
				r.Status = "MODE_CHANGE_DECLINED"
				w.Close()
				return r
			}
			if ctx.Err() != nil {
				r.Status = "TIME_LIMIT_NO_CHANGE"
				w.Close()
				return r
			}
			if direct != nil {
				if err := direct.prepare(ctx, r.Before, r.GetMode, consent); err != nil {
					r.Status = err.Error()
					w.Close()
					return r
				}
			}
			// Register before sending: re-enumeration can finish during Control.
			// Registration failure retains the bounded polling fallback.
			var arrivals <-chan struct{}
			if direct == nil {
				if changes, unsubscribe, err := deviceguard.SubscribeChanges(); err == nil {
					arrivals = changes
					defer unsubscribe()
				}
			}
			allowed := ctx.Err() == nil && consent()
			archiveUSBConsent("after_arrival_subscription", allowed, ctx.Err() == nil)
			if !allowed {
				r.Status = "MODE_CHANGE_DECLINED_OR_CANCELLED"
				w.Close()
				return r
			}
			// Include re-enumeration in the operation window. This records a
			// possible prompt trigger, never an observation of the iPad's UI.
			modeDone := RecordConnectionOperation("usb_mode_switch")
			if direct == nil {
				defer modeDone()
			}
			r.SetAttempted = true
			reply := []byte{255}
			requestedMode := uint16(3)
			if direct != nil {
				requestedMode = 5
			}
			requestDone := RecordConnectionOperation("usb_set_mode_request")
			n, e = w.Control(0xc0, 0x52, 0, requestedMode, reply)
			requestDone()
			w.Close()
			r.SetAcknowledged = e == nil && n == 1 && reply[0] == 0
			if e != nil {
				r.SetError = "CONTROL_REQUEST_FAILED"
			} else if !r.SetAcknowledged {
				r.SetError = "MODE_ACK_NOT_ZERO"
			}
			if direct != nil {
				modeDone()
				direct.observe(ctx, &r)
				return r
			}
			// Observe only the same hub and physical port. Never confuse another
			// attached device or a pre-existing Mac network adapter with this iPad.
			observed := false
			var preflight func() bool
			if apple && network && target.pid == 0x12ab && target.CurrentConfiguration == 3 {
				preflight = func() bool { return modeArrivalCacheReady(ctx, target) }
			}
			observeModeArrival(ctx, arrivals, 8*time.Second, 250*time.Millisecond, preflight, func() bool {
				started := time.Now()
				after := inventory(ctx)
				r.After = &after
				RecordConnectionArchiveEvent("mode_sample", struct {
					Attempt    uint64   `json:"software_attempt"`
					StartedUTC string   `json:"read_started_utc"`
					ElapsedMS  int64    `json:"read_elapsed_ms"`
					USB        Snapshot `json:"usb"`
				}{currentSoftwareAttempt(), started.UTC().Format(time.RFC3339Nano), time.Since(started).Milliseconds(), after})
				if ctx.Err() != nil {
					return false
				}
				for _, d := range after.Devices {
					if d.hub == target.hub && d.port == target.port {
						for _, cfg := range d.Configurations {
							if cfg.NCMControls > 0 && (!apple || cfg.Value == d.CurrentConfiguration) && (!network || networkOnlyUSBEligible(after)) {
								if network && (!sameRootInstance(r.Before, after) || BindPhotoIsolationTarget(after) != nil) {
									r.Status = "PHOTO_ISOLATION_RECOVERY_OR_SCOPE_UNCONFIRMED"
									observed = true
									return true
								}
								if network {
									allowed := consent()
									archiveUSBConsent("after_mode_same_root_and_photo_recovery", allowed, ctx.Err() == nil)
									if !allowed || BindLocalPhotoPolicyTarget(after) != nil {
										r.Status = "PHOTO_POLICY_RECOVERY_OR_SCOPE_UNCONFIRMED"
										observed = true
										return true
									}
								}
								r.ReenumerationSeen = true
								r.Status = "NCM_DESCRIPTORS_AFTER_REQUEST"
								observed = true
								return true
							}
						}
					}
				}
				return false
			})
			if observed {
				return r
			}
			r.Status = "MODE_REQUEST_SENT_NCM_NOT_OBSERVED"
			return r
		}
	}
	r.Status = "CONTROL_ACCESS_BLOCKED_NOT_A_SUPPORT_VERDICT"
	return r
}

// Network-only launcher: no usbmux/lockdown metadata, StartSession or pairing.
func RunNetworkOnlyAppleControl(version string, consent func() bool, acquire func() (func(), bool), previous *Result) Result {
	return runWithControlLease(version, consent, acquire, true, previous, true)
}
func networkOnlyUSBEligible(s Snapshot) bool {
	if s.Error != "" || exactIPadRoot(s) == "" || len(s.Devices) != 1 || len(s.Devices[0].Errors) != 0 || !s.Devices[0].USBDescriptorIdentityVerified {
		return false
	}
	return networkUSBPreflight(s.Devices[0].Configurations, s.Devices[0].CurrentConfiguration)
}
func modeResultIdentity(r Result, active bool) bool {
	if r.USBIdentifiersVerified {
		return networkModeIdentity(r.IdentitySource, r.MetadataError, r.Status, active)
	}
	return startupModeIdentity(r.ProductType, r.MetadataError, r.Status, active)
}
