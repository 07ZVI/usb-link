package ncm

import (
	"encoding/binary"
	"fmt"
)

type Function struct {
	Control, Data, MACIndex byte
	MaxSegment              uint16
	Capabilities            byte
	Descriptors             []string
}

func ParseFunction(b []byte, control byte) (Function, error) {
	return parseFunction(b, control, true)
}

// These layouts also match WinUSB's interface/pipe query structures. The
// Windows adapter aliases them so the evidence is passed without reassembly.
type InterfaceDescriptor struct{ Length, Type, Number, Alt, Endpoints, Class, Subclass, Protocol, String byte }
type PipeDescriptor struct {
	Type      uint32
	ID        byte
	MaxPacket uint16
	Interval  byte
}

// ParsePairedFunction handles separate WinUSB children. Its caller must first
// establish a unique same-parent PnP pair. CDC descriptors prove the Union;
// direct queries on that paired data handle prove alternate settings and pipes.
func ParsePairedFunction(b []byte, control byte, alt0, alt1 InterfaceDescriptor, pipes []PipeDescriptor) (Function, error) {
	f, err := parseFunction(b, control, false)
	if err != nil {
		return f, err
	}
	if f.Data == control {
		return f, fmt.Errorf("CDC Union points to control interface")
	}
	for alt, d := range []InterfaceDescriptor{alt0, alt1} {
		if d.Length != 9 || d.Type != 4 || d.Number != f.Data || d.Alt != byte(alt) || d.Class != 0x0a || d.Subclass != 0 || d.Protocol > 1 {
			return f, fmt.Errorf("paired data alt%d does not match CDC Union/class: %+v", alt, d)
		}
	}
	if alt0.Endpoints != 0 || alt1.Endpoints != 2 || len(pipes) != 2 {
		return f, fmt.Errorf("paired data settings need empty alt0 and two alt1 bulk endpoints")
	}
	var in, out bool
	for _, p := range pipes {
		if p.Type != 2 || p.ID&0x70 != 0 || p.ID&0x0f == 0 || p.MaxPacket == 0 || p.MaxPacket > 1024 {
			return f, fmt.Errorf("invalid paired bulk pipe: %+v", p)
		}
		if p.ID&0x80 != 0 {
			if in {
				return f, fmt.Errorf("duplicate paired bulk IN")
			}
			in = true
		} else {
			if out {
				return f, fmt.Errorf("duplicate paired bulk OUT")
			}
			out = true
		}
	}
	if !in || !out {
		return f, fmt.Errorf("paired data lacks bulk IN/OUT")
	}
	// A full configuration is also accepted, but any data descriptors it does
	// include must agree with the independently queried interface settings.
	var seen [2]bool
	for i := 0; i < len(b); i += int(b[i]) {
		d := b[i : i+int(b[i])]
		if d[1] != 4 || d[2] != f.Data || d[3] > 1 {
			continue
		}
		alt := d[3]
		expected := []InterfaceDescriptor{alt0, alt1}[alt]
		actual := InterfaceDescriptor{d[0], d[1], d[2], d[3], d[4], d[5], d[6], d[7], d[8]}
		if seen[alt] || actual != expected {
			return f, fmt.Errorf("configuration/query conflict for data alt%d", alt)
		}
		seen[alt] = true
	}
	return f, nil
}

func parseFunction(b []byte, control byte, requireData bool) (Function, error) {
	f := Function{Control: control}
	if len(b) < 9 || b[0] != 9 || b[1] != 2 || int(binary.LittleEndian.Uint16(b[2:])) != len(b) {
		return f, fmt.Errorf("invalid configuration descriptor")
	}
	var current byte = 255
	var header, union, ecm, ncm bool
	var data bool
	for i := 0; i < len(b); {
		n := int(b[i])
		if n < 2 || i+n > len(b) {
			return f, fmt.Errorf("malformed descriptor at %d", i)
		}
		d := b[i : i+n]
		if d[1] == 4 {
			if n < 9 {
				return f, fmt.Errorf("short interface descriptor")
			}
			current = d[2]
			if current == control && (d[5] != 2 || d[6] != 0x0d) {
				return f, fmt.Errorf("interface %d is not NCM control", control)
			}
			if union && current == f.Data && d[3] == 1 && d[5] == 0x0a {
				data = true
			}
		}
		if d[1] == 0x24 && current == control {
			if n < 3 {
				return f, fmt.Errorf("short functional descriptor")
			}
			f.Descriptors = append(f.Descriptors, fmt.Sprintf("subtype=0x%02x raw=%x", d[2], d))
			switch d[2] {
			case 0:
				if n < 5 {
					return f, fmt.Errorf("short Header")
				}
				header = true
			case 6:
				if n != 5 || d[3] != control {
					return f, fmt.Errorf("unsupported Union")
				}
				f.Data = d[4]
				union = true
			case 0xf:
				if n < 13 {
					return f, fmt.Errorf("short ECM")
				}
				f.MACIndex = d[3]
				f.MaxSegment = binary.LittleEndian.Uint16(d[8:])
				ecm = true
			case 0x1a:
				if n < 6 {
					return f, fmt.Errorf("short NCM")
				}
				f.Capabilities = d[5]
				ncm = true
			}
		}
		i += n
	}
	if !header || !union || !ecm || !ncm || (requireData && !data) || f.MACIndex == 0 || f.MaxSegment < 60 {
		return f, fmt.Errorf("incomplete CDC function: Header=%v Union=%v ECM=%v NCM=%v dataAlt1=%v", header, union, ecm, ncm, data)
	}
	return f, nil
}
