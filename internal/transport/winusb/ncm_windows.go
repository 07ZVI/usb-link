//go:build windows && amd64

package winusb

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"log"
	"net"
	"suhang/usbnet/internal/transport/ncm"
	"unicode/utf16"
)

type NCMDevice struct {
	Control, Data *Interface
	In, Out       Pipe
	Parameters    ncm.Parameters
	MaxSegment    uint16
	ReadSize      int
	handles       []*Interface
	logger        *log.Logger
	Datagram      *ncm.DatagramTrial
	ControlNumber uint16
}

func (i *Interface) datagramControl(rt, request byte, value, index uint16, b []byte) (int, error) {
	n, e := i.Control(rt, request, value, index, b)
	return int(n), e
}
func (d *NCMDevice) Close() {
	d.logger.Printf("restore data alt0: %v", d.Data.Alt(0))
	d.logger.Printf("restore maximum datagram: %v", d.Datagram.Restore(d.Control.datagramControl, d.ControlNumber, d.MaxSegment))
	for i := len(d.handles) - 1; i >= 0; i-- {
		d.handles[i].Close()
	}
}

// InitializeNCM is the same verified phase-1 sequence, shared by probe and bridge.
func InitializeNCM(group int, parent bool, timeoutMS uint32, l *log.Logger) (*NCMDevice, error) {
	return initializeNCM(group, parent, timeoutMS, l, false, ncm.MTUCapAuto)
}

// InitializeNCMWithTrial may raise the maximum datagram size, never beyond the
// ceiling that limit allows.
func InitializeNCMWithTrial(group int, parent bool, timeoutMS uint32, l *log.Logger, limit ncm.MTUCap) (*NCMDevice, error) {
	return initializeNCM(group, parent, timeoutMS, l, true, limit)
}

func initializeNCM(group int, parent bool, timeoutMS uint32, l *log.Logger, trial bool, limit ncm.MTUCap) (*NCMDevice, error) {
	nodes, e := Enumerate(l)
	if e != nil {
		return nil, e
	}
	cp, dp, e := Pair(nodes, group, parent)
	if e != nil {
		return nil, e
	}
	root, e := Open(cp)
	if e != nil {
		return nil, e
	}
	handles := []*Interface{root}
	ok := false
	defer func() {
		if !ok {
			for j := len(handles) - 1; j >= 0; j-- {
				handles[j].Close()
			}
		}
	}()
	control := root
	var data *Interface
	if parent {
		interfaces := []*Interface{root}
		for idx := byte(0); idx < 3; idx++ {
			h, e := root.Associated(idx)
			if e != nil {
				return nil, fmt.Errorf("associated interface %d: %w", idx, e)
			}
			interfaces = append(interfaces, h)
			handles = append(handles, h)
		}
		control = nil
		for _, h := range interfaces {
			d, e := h.Query(0)
			if e != nil {
				return nil, e
			}
			l.Printf("associated interface=%+v", d)
			if int(d.Number) == group*2 {
				control = h
			}
			if int(d.Number) == group*2+1 {
				data = h
			}
		}
		if control == nil || data == nil {
			return nil, fmt.Errorf("parent group missing")
		}
	} else {
		data, e = Open(dp)
		if e != nil {
			return nil, e
		}
		handles = append(handles, data)
	}
	cd, e := control.Query(0)
	if e != nil {
		return nil, e
	}
	dd, e := data.Query(0)
	if e != nil {
		return nil, e
	}
	l.Printf("control alt0=%+v data alt0=%+v", cd, dd)
	if e = control.Policy(0, 3, []byte{0xd0, 7, 0, 0}); e != nil {
		return nil, e
	}
	if int(cd.Number) != group*2 || int(dd.Number) != group*2+1 {
		return nil, fmt.Errorf("interface number mismatch; stop")
	}
	var dataSettings [2]InterfaceDescriptor
	var dataPipes [2][]Pipe
	for alt := byte(0); alt <= 1; alt++ {
		d, e := data.Query(alt)
		if e != nil {
			return nil, fmt.Errorf("data alt%d query: %w", alt, e)
		}
		pipes, e := data.Pipes(alt)
		if e != nil {
			return nil, e
		}
		l.Printf("data descriptor=%+v pipes=%+v", d, pipes)
		dataSettings[alt], dataPipes[alt] = d, pipes
	}
	dev, e := root.Descriptor(1, 0, 0, 18)
	if e != nil {
		return nil, e
	}
	l.Printf("device descriptor=%x", dev)
	if len(dev) != 18 || binary.LittleEndian.Uint16(dev[8:]) != 0x05ac || binary.LittleEndian.Uint16(dev[10:]) != 0x1903 {
		return nil, fmt.Errorf("wrong VID/PID")
	}
	header, e := root.Descriptor(2, 0, 0, 9)
	if e != nil || len(header) != 9 {
		return nil, fmt.Errorf("configuration header: %x %v", header, e)
	}
	config, e := root.Descriptor(2, 0, 0, int(binary.LittleEndian.Uint16(header[2:])))
	if e != nil {
		return nil, e
	}
	l.Printf("configuration descriptor=%x", config)
	l.Print(ncm.DescriptorSummaryPrefix + describeNCMDescriptors(dev, config, cd.Number, dataSettings, dataPipes[1]))
	f, e := ncm.ParsePairedFunction(config, cd.Number, dataSettings[0], dataSettings[1], dataPipes[1])
	if e != nil {
		return nil, e
	}
	l.Printf("CDC descriptors=%v iMACAddress=%d wMaxSegmentSize=%d capabilities=0x%x", f.Descriptors, f.MACIndex, f.MaxSegment, f.Capabilities)
	if f.Data != dd.Number {
		return nil, fmt.Errorf("CDC Union does not match selected data interface")
	}
	l.Print("CDC Union and separately opened same-parent data interface verified; alt1 bulk pair confirmed")
	lang := uint16(0x409)
	langs, e := root.Descriptor(3, 0, 0, 255)
	if e == nil && len(langs) >= 4 {
		lang = binary.LittleEndian.Uint16(langs[2:])
	}
	macString, e := root.Descriptor(3, f.MACIndex, lang, 255)
	if e != nil {
		return nil, e
	}
	if len(macString) < 2 || macString[1] != 3 || int(macString[0]) != len(macString) || len(macString)%2 != 0 {
		return nil, fmt.Errorf("invalid MAC string descriptor")
	}
	u := make([]uint16, (len(macString)-2)/2)
	for i := range u {
		u[i] = binary.LittleEndian.Uint16(macString[2+i*2:])
	}
	s := string(utf16.Decode(u))
	mb, e := hex.DecodeString(s)
	if e != nil || len(mb) != 6 {
		return nil, fmt.Errorf("invalid MAC string %q", s)
	}
	l.Printf("iMACAddress=%s, probe uses local MAC=%s (avoid Mac source collision)", net.HardwareAddr(mb), net.HardwareAddr(ncm.ProbeMAC[:]))
	param := make([]byte, 28)
	l.Printf("GET_NTB_PARAMETERS setup=a1 80 value=0 index=%d length=28", cd.Number)
	n, e := control.Control(0xa1, 0x80, 0, uint16(cd.Number), param)
	if e != nil {
		return nil, e
	}
	if n != 28 {
		return nil, fmt.Errorf("GET_NTB_PARAMETERS transferred %d", n)
	}
	p, e := ncm.ParseParameters(param)
	if e != nil {
		return nil, e
	}
	l.Printf("NTB parameters=%+v raw=%x", p, param)
	if e = data.Alt(0); e != nil {
		return nil, fmt.Errorf("alt0: %w", e)
	}
	l.Print("data alt0 OK")
	var datagram *ncm.DatagramTrial
	defer func() {
		if !ok && datagram != nil {
			l.Printf("restore data alt0 before datagram: %v", data.Alt(0))
			l.Printf("failed initialization datagram restore: %v", datagram.Restore(control.datagramControl, uint16(cd.Number), f.MaxSegment))
		}
	}()
	if trial {
		datagram, e = ncm.TryDatagramCapped(control.datagramControl, uint16(cd.Number), f.Capabilities, f.MaxSegment, limit)
		if e != nil {
			l.Printf("MTU_TRIAL frame negotiation unavailable: %v; IP MTU remains 1500", e)
		}
		if datagram != nil && e != nil && datagram.Changed {
			return nil, e
		}
		if datagram != nil {
			l.Printf("MTU_TRIAL maximum_frame original=%d current=%d changed=%t IP_MTU_not_proven=true", datagram.Original, datagram.Current, datagram.Changed)
		}
	}
	l.Printf("SET_NTB_FORMAT setup=21 84 value=0 index=%d length=0", cd.Number)
	_, e = control.Control(0x21, 0x84, 0, uint16(cd.Number), nil)
	l.Printf("SET_NTB_FORMAT NTB16 result=%v (failure recorded; continuing)", e)
	// Verify current wire format when optional SET fails; never send NTB16 if NTB32 is confirmed.
	format := make([]byte, 2)
	n, formatErr := control.Control(0xa1, 0x83, 0, uint16(cd.Number), format)
	l.Printf("GET_NTB_FORMAT bytes=%x transferred=%d error=%v", format, n, formatErr)
	if formatErr == nil && (n != 2 || binary.LittleEndian.Uint16(format) != 0) {
		return nil, fmt.Errorf("device is not in NTB16 mode; stop")
	}
	// Keep the advertised input size so failure of optional SET cannot truncate reads.
	inSize := make([]byte, 4)
	binary.LittleEndian.PutUint32(inSize, p.InMax)
	_, e = control.Control(0x21, 0x86, 0, uint16(cd.Number), inSize)
	l.Printf("SET_NTB_INPUT_SIZE=%d result=%v (failure recorded; continuing)", p.InMax, e)
	if e = data.Alt(1); e != nil {
		return nil, fmt.Errorf("STOP: alt1 failed: %w", e)
	}
	defer func() {
		if !ok {
			l.Printf("restore data alt0: %v", data.Alt(0))
		}
	}()
	l.Print("data alt1 OK; no interrupt endpoint required")
	pipes, e := data.Pipes(1)
	if e != nil {
		return nil, e
	}
	var in, out Pipe
	for _, pipe := range pipes {
		l.Printf("active pipe=%+v", pipe)
		if pipe.Type == 2 {
			if pipe.ID&0x80 != 0 {
				if in.ID != 0 {
					return nil, fmt.Errorf("multiple bulk IN")
				}
				in = pipe
			} else {
				if out.ID != 0 {
					return nil, fmt.Errorf("multiple bulk OUT")
				}
				out = pipe
			}
		}
	}
	if in.ID == 0 || out.ID == 0 || in.MaxPacket == 0 {
		return nil, fmt.Errorf("STOP: missing Bulk IN/OUT")
	}
	timeout := make([]byte, 4)
	binary.LittleEndian.PutUint32(timeout, timeoutMS)
	if e = data.Policy(in.ID, 3, timeout); e != nil {
		return nil, e
	}
	if e = data.Policy(out.ID, 3, []byte{0xd0, 7, 0, 0}); e != nil {
		return nil, e
	}
	if e = data.Policy(in.ID, 7, []byte{1}); e != nil {
		return nil, fmt.Errorf("RAW_IO: %w", e)
	}
	l.Printf("RAW_IO=TRUE; OUT timeout=2000ms; IN timeout=%dms (0=unlimited); pending reads cancelled explicitly on stop", timeoutMS)
	maxTransfer, e := data.PolicyUint(in.ID, 8)
	if e != nil {
		return nil, e
	}
	readSize := (int(p.InMax) + int(in.MaxPacket) - 1) / int(in.MaxPacket) * int(in.MaxPacket)
	if uint32(readSize) > maxTransfer {
		return nil, fmt.Errorf("advertised input buffer %d exceeds RAW_IO maximum %d; stop", readSize, maxTransfer)
	}
	l.Printf("read buffer=%d maxTransfer=%d packet=%d", readSize, maxTransfer, in.MaxPacket)

	ok = true
	return &NCMDevice{Control: control, Data: data, In: in, Out: out, Parameters: p, MaxSegment: f.MaxSegment, ReadSize: readSize, handles: handles, logger: l, Datagram: datagram, ControlNumber: uint16(cd.Number)}, nil
}

// describeNCMDescriptors summarizes descriptors this function already read. It
// issues no USB request, and a failure here can never change initialization.
func describeNCMDescriptors(device, config []byte, control byte, settings [2]InterfaceDescriptor, pipes []Pipe) (text string) {
	defer func() {
		if recover() != nil {
			text = "unavailable"
		}
	}()
	return ncm.SummarizeDescriptors(device, config, control, settings[0], settings[1], pipes).String()
}

// MatchesOpenedPair checks the immutable paths used by these actual owned
// handles. It is local lifetime/scope corroboration, not USB consent or native
// driver authorization. Associated-parent layouts are deliberately unsupported.
func (d *NCMDevice) MatchesOpenedPair(control, data string) bool {
	return d != nil && d.Control != nil && d.Data != nil && d.Control.Own && d.Data.Own && d.Control.Handle != 0 && d.Data.Handle != 0 && d.Control.File != 0 && d.Data.File != 0 && control != "" && data != "" && d.Control.openedPath == control && d.Data.openedPath == data
}
