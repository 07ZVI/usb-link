package ncm

import (
	"encoding/binary"
	"fmt"
	"strings"
)

// DescriptorSummaryPrefix marks the one-line summary the Mac bridge writes
// after it has read the descriptors it already needs for initialization.
const DescriptorSummaryPrefix = "USB_MAC_NCM_DESCRIPTOR_SUMMARY "

const (
	summaryMaxEndpoints = 8
	summaryMaxAlts      = 4
	summaryMaxIADs      = 4
)

// EndpointSummary is one endpoint descriptor exactly as it appears in the
// configuration descriptor (or, for WinUSB pipe queries, as the driver reports it).
type EndpointSummary struct {
	Address   byte
	Attribute byte
	MaxPacket uint16
	Interval  byte
}

// Type names the transfer type bits of bmAttributes.
func (e EndpointSummary) Type() string {
	switch e.Attribute & 3 {
	case 0:
		return "control"
	case 1:
		return "iso"
	case 2:
		return "bulk"
	}
	return "int"
}

func (e EndpointSummary) In() bool { return e.Address&0x80 != 0 }

type IADSummary struct {
	First, Count, Class, Subclass, Protocol byte
}

// InterfaceSetting is one alternate setting of an interface.
type InterfaceSetting struct {
	Alt, Class, Subclass, Protocol byte
	Declared                       byte // bNumEndpoints
	Endpoints                      []EndpointSummary
}

// DescriptorSummary is a read-only description of the Mac's CDC-NCM function,
// built only from descriptors the bridge has already read. It never causes a
// USB request and carries no serial number, MAC address or other identity.
type DescriptorSummary struct {
	DevicePresent                 bool
	VID, PID, BCDDevice           uint16
	DeviceClass, DeviceSubclass   byte
	DeviceProtocol, EP0MaxPacket  byte
	Configurations                byte
	ConfigPresent                 bool
	ConfigValue, ConfigAttributes byte
	ConfigMaxPowerMA              int
	ConfigTotalLength             uint16
	ConfigInterfaces              byte
	ConfigMalformed               bool
	// ScopedView: the configuration omits the data interface the Union points to
	// (a per-function view), so an absent IAD or endpoint is not proof about the device.
	ScopedView              bool
	IADs                    []IADSummary
	ControlInterface        byte
	ControlAlts             []InterfaceSetting
	HeaderPresent           bool
	HeaderBCD               uint16
	UnionPresent            bool
	UnionMaster             byte
	UnionSlaves             []byte
	EthernetPresent         bool
	MACIndex                byte
	EthernetStatistics      uint32
	MaxSegment              uint16
	MulticastFilters        uint16
	PowerFilters            byte
	NCMPresent              bool
	NCMVersion              uint16
	NetworkCapabilities     byte
	DataInterface           byte
	DataAlts                []InterfaceSetting // from the configuration descriptor
	QueriedDataAlts         []InterfaceDescriptor
	QueriedDataPipes        []EndpointSummary // WinUSB pipes of the active alternate setting
	QueriedDataPipesAlt     byte
	OtherFunctionalSubtypes []byte
}

// ControlInterruptIn reports whether the control interface exposes an
// interrupt IN endpoint in any alternate setting of the configuration view.
func (s DescriptorSummary) ControlInterruptIn() bool {
	for _, a := range s.ControlAlts {
		for _, e := range a.Endpoints {
			if e.Type() == "int" && e.In() {
				return true
			}
		}
	}
	return false
}

func (s DescriptorSummary) bulk(in bool) bool {
	pipes := s.QueriedDataPipes
	if len(pipes) == 0 {
		for _, a := range s.DataAlts {
			pipes = append(pipes, a.Endpoints...)
		}
	}
	for _, p := range pipes {
		if p.Type() == "bulk" && p.In() == in {
			return true
		}
	}
	return false
}

// SummarizeDescriptors never fails and never reads past its inputs. Malformed
// or truncated input produces a partial summary with ConfigMalformed set.
// device is the 18-byte device descriptor, config the full configuration
// descriptor (or the interface view WinUSB returned), control the control
// interface number, and alt0/alt1/pipes the already-queried data interface.
func SummarizeDescriptors(device, config []byte, control byte, alt0, alt1 InterfaceDescriptor, pipes []PipeDescriptor) DescriptorSummary {
	s := DescriptorSummary{ControlInterface: control}
	if len(device) == 18 && device[0] == 18 && device[1] == 1 {
		s.DevicePresent = true
		s.DeviceClass, s.DeviceSubclass, s.DeviceProtocol, s.EP0MaxPacket = device[4], device[5], device[6], device[7]
		s.VID = binary.LittleEndian.Uint16(device[8:])
		s.PID = binary.LittleEndian.Uint16(device[10:])
		s.BCDDevice = binary.LittleEndian.Uint16(device[12:])
		s.Configurations = device[17]
	}
	hint := byte(0xff)
	if alt0.Type == 4 {
		hint = alt0.Number
	}
	s.summarizeConfig(config, hint)
	if !s.ConfigPresent {
		s.DataInterface = hint
	}
	for _, d := range []InterfaceDescriptor{alt0, alt1} {
		if d.Type == 4 {
			s.QueriedDataAlts = append(s.QueriedDataAlts, d)
		}
	}
	s.ScopedView = s.ConfigPresent && len(s.QueriedDataAlts) > 0 && len(s.DataAlts) == 0
	for i, p := range pipes {
		if i == summaryMaxEndpoints {
			break
		}
		s.QueriedDataPipes = append(s.QueriedDataPipes, EndpointSummary{Address: p.ID, Attribute: byte(p.Type), MaxPacket: p.MaxPacket, Interval: p.Interval})
	}
	s.QueriedDataPipesAlt = alt1.Alt
	return s
}

func (s *DescriptorSummary) summarizeConfig(b []byte, dataHint byte) {
	if len(b) < 9 || b[0] != 9 || b[1] != 2 {
		s.ConfigMalformed = len(b) != 0
		return
	}
	s.ConfigPresent = true
	s.ConfigTotalLength = binary.LittleEndian.Uint16(b[2:])
	s.ConfigInterfaces, s.ConfigValue, s.ConfigAttributes = b[4], b[5], b[7]
	s.ConfigMaxPowerMA = int(b[8]) * 2
	if int(s.ConfigTotalLength) != len(b) {
		s.ConfigMalformed = true
	}
	type numbered struct {
		number  byte
		setting InterfaceSetting
	}
	var settings []numbered
	for i := 0; i < len(b); {
		n := int(b[i])
		if n < 2 || i+n > len(b) {
			s.ConfigMalformed = true
			break
		}
		d := b[i : i+n]
		switch d[1] {
		case 4:
			if n < 9 {
				s.ConfigMalformed = true
			} else if len(settings) < 16 {
				settings = append(settings, numbered{d[2], InterfaceSetting{Alt: d[3], Declared: d[4], Class: d[5], Subclass: d[6], Protocol: d[7]}})
			}
		case 5:
			if n >= 7 && len(settings) > 0 {
				last := &settings[len(settings)-1].setting
				if len(last.Endpoints) < summaryMaxEndpoints {
					last.Endpoints = append(last.Endpoints, EndpointSummary{Address: d[2], Attribute: d[3], MaxPacket: binary.LittleEndian.Uint16(d[4:]), Interval: d[6]})
				}
			}
		case 0x0b:
			if n >= 8 && len(s.IADs) < summaryMaxIADs {
				s.IADs = append(s.IADs, IADSummary{First: d[2], Count: d[3], Class: d[4], Subclass: d[5], Protocol: d[6]})
			}
		case 0x24:
			if len(settings) > 0 && settings[len(settings)-1].number == s.ControlInterface && n >= 3 {
				s.functional(d)
			}
		}
		i += n
	}
	s.DataInterface = dataHint
	if s.UnionPresent && len(s.UnionSlaves) > 0 {
		s.DataInterface = s.UnionSlaves[0]
	}
	for _, v := range settings {
		switch v.number {
		case s.ControlInterface:
			if len(s.ControlAlts) < summaryMaxAlts {
				s.ControlAlts = append(s.ControlAlts, v.setting)
			}
		case s.DataInterface:
			if len(s.DataAlts) < summaryMaxAlts {
				s.DataAlts = append(s.DataAlts, v.setting)
			}
		}
	}
}

func (s *DescriptorSummary) functional(d []byte) {
	n := len(d)
	switch d[2] {
	case 0:
		if n >= 5 {
			s.HeaderPresent = true
			s.HeaderBCD = binary.LittleEndian.Uint16(d[3:])
		}
	case 6:
		if n >= 5 {
			s.UnionPresent = true
			s.UnionMaster = d[3]
			s.UnionSlaves = nil
			for _, slave := range d[4:] {
				if len(s.UnionSlaves) < 4 {
					s.UnionSlaves = append(s.UnionSlaves, slave)
				}
			}
		}
	case 0xf:
		if n >= 13 {
			s.EthernetPresent = true
			s.MACIndex = d[3]
			s.EthernetStatistics = binary.LittleEndian.Uint32(d[4:])
			s.MaxSegment = binary.LittleEndian.Uint16(d[8:])
			s.MulticastFilters = binary.LittleEndian.Uint16(d[10:])
			s.PowerFilters = d[12]
		}
	case 0x1a:
		if n >= 6 {
			s.NCMPresent = true
			s.NCMVersion = binary.LittleEndian.Uint16(d[3:])
			s.NetworkCapabilities = d[5]
		}
	default:
		if len(s.OtherFunctionalSubtypes) < 8 {
			s.OtherFunctionalSubtypes = append(s.OtherFunctionalSubtypes, d[2])
		}
	}
}

func yesNo(v bool) string {
	if v {
		return "yes"
	}
	return "no"
}

func formatEndpoints(list []EndpointSummary) string {
	if len(list) == 0 {
		return "none"
	}
	parts := make([]string, len(list))
	for i, e := range list {
		parts[i] = fmt.Sprintf("0x%02x:%s:max%d:iv%d", e.Address, e.Type(), e.MaxPacket, e.Interval)
	}
	return strings.Join(parts, ",")
}

func formatSettings(list []InterfaceSetting) string {
	if len(list) == 0 {
		return "none"
	}
	parts := make([]string, len(list))
	for i, a := range list {
		parts[i] = fmt.Sprintf("alt%d{class=%02x/%02x/%02x declared=%d ep=%s}", a.Alt, a.Class, a.Subclass, a.Protocol, a.Declared, formatEndpoints(a.Endpoints))
	}
	return strings.Join(parts, " ")
}

// String is one line of space-separated groups: device, configuration, IAD,
// control interface, CDC functional descriptors, data interface. It is built
// only from fixed numeric fields.
func (s DescriptorSummary) String() string {
	var b strings.Builder
	if s.DevicePresent {
		fmt.Fprintf(&b, "device{vid=%04x pid=%04x bcdDevice=0x%04x class=%02x/%02x/%02x ep0=%d configurations=%d}",
			s.VID, s.PID, s.BCDDevice, s.DeviceClass, s.DeviceSubclass, s.DeviceProtocol, s.EP0MaxPacket, s.Configurations)
	} else {
		b.WriteString("device{unavailable}")
	}
	if s.ConfigPresent {
		fmt.Fprintf(&b, " config{value=%d attributes=0x%02x max_power=%dmA total_length=%d interfaces=%d scoped_view=%s malformed=%s}",
			s.ConfigValue, s.ConfigAttributes, s.ConfigMaxPowerMA, s.ConfigTotalLength, s.ConfigInterfaces, yesNo(s.ScopedView), yesNo(s.ConfigMalformed))
	} else {
		fmt.Fprintf(&b, " config{unavailable malformed=%s}", yesNo(s.ConfigMalformed))
	}
	if len(s.IADs) == 0 {
		b.WriteString(" iad{present=no}")
	} else {
		b.WriteString(" iad{present=yes")
		for _, a := range s.IADs {
			fmt.Fprintf(&b, " first=%d count=%d class=%02x/%02x/%02x", a.First, a.Count, a.Class, a.Subclass, a.Protocol)
		}
		b.WriteString("}")
	}
	fmt.Fprintf(&b, " control{interface=%d %s interrupt_in=%s}", s.ControlInterface, formatSettings(s.ControlAlts), yesNo(s.ControlInterruptIn()))
	fmt.Fprintf(&b, " cdc{header=%s", yesNo(s.HeaderPresent))
	if s.HeaderPresent {
		fmt.Fprintf(&b, "(bcdCDC=0x%04x)", s.HeaderBCD)
	}
	fmt.Fprintf(&b, " union=%s", yesNo(s.UnionPresent))
	if s.UnionPresent {
		fmt.Fprintf(&b, "(master=%d slaves=%v)", s.UnionMaster, s.UnionSlaves)
	}
	fmt.Fprintf(&b, " ethernet=%s", yesNo(s.EthernetPresent))
	if s.EthernetPresent {
		fmt.Fprintf(&b, "(iMACAddress_present=%s wMaxSegmentSize=%d bmEthernetStatistics=0x%08x wNumberMCFilters=0x%04x bNumberPowerFilters=%d)",
			yesNo(s.MACIndex != 0), s.MaxSegment, s.EthernetStatistics, s.MulticastFilters, s.PowerFilters)
	}
	fmt.Fprintf(&b, " ncm=%s", yesNo(s.NCMPresent))
	if s.NCMPresent {
		fmt.Fprintf(&b, "(bcdNcmVersion=0x%04x bmNetworkCapabilities=0x%02x)", s.NCMVersion, s.NetworkCapabilities)
	}
	if len(s.OtherFunctionalSubtypes) > 0 {
		fmt.Fprintf(&b, " other_subtypes=%v", s.OtherFunctionalSubtypes)
	}
	b.WriteString("}")
	fmt.Fprintf(&b, " data{interface=%d config_view=%s queried=", s.DataInterface, formatSettings(s.DataAlts))
	if len(s.QueriedDataAlts) == 0 {
		b.WriteString("none")
	}
	for i, d := range s.QueriedDataAlts {
		if i > 0 {
			b.WriteString(" ")
		}
		fmt.Fprintf(&b, "alt%d{class=%02x/%02x/%02x declared=%d}", d.Alt, d.Class, d.Subclass, d.Protocol, d.Endpoints)
	}
	fmt.Fprintf(&b, " pipes_alt%d=%s bulk_in=%s bulk_out=%s}", s.QueriedDataPipesAlt, formatEndpoints(s.QueriedDataPipes), yesNo(s.bulk(true)), yesNo(s.bulk(false)))
	return b.String()
}
