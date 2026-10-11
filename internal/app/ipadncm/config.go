package ipadncm

import (
	"encoding/binary"
	"errors"
)

type Interface struct {
	Number    byte                   `json:"number"`
	Alternate byte                   `json:"alternate"`
	Class     byte                   `json:"class"`
	Subclass  byte                   `json:"subclass"`
	Protocol  byte                   `json:"protocol"`
	Endpoints []Endpoint             `json:"endpoints"`
	Slaves    []byte                 `json:"union_slaves,omitempty"`
	Functions []FunctionalDescriptor `json:"functional_descriptors,omitempty"`
}

// Structural sizes/versions only; omit string indices and all device identifiers.
type FunctionalDescriptor struct {
	Subtype      byte    `json:"subtype"`
	Length       byte    `json:"length"`
	Version      *uint16 `json:"version,omitempty"`
	Capabilities *byte   `json:"capabilities,omitempty"`
	MaxSegment   *uint16 `json:"max_segment_size,omitempty"`
}
type Endpoint struct {
	Address   byte   `json:"address"`
	Type      byte   `json:"type"`
	MaxPacket uint16 `json:"max_packet"`
}
type Configuration struct {
	Index        int           `json:"index"`
	Value        byte          `json:"value"`
	Interfaces   []Interface   `json:"interfaces"`
	NCMControls  int           `json:"ncm_controls"`
	Associations []Association `json:"interface_associations,omitempty"`
}

type Association struct {
	First    byte `json:"first_interface"`
	Count    byte `json:"interface_count"`
	Class    byte `json:"class"`
	Subclass byte `json:"subclass"`
	Protocol byte `json:"protocol"`
}

func activeNCM(configs []Configuration, current byte) bool {
	for _, c := range configs {
		if c.Value == current && c.NCMControls > 0 {
			return true
		}
	}
	return false
}

// Parse only structural descriptors; never fetch strings, MACs or serials.
func Parse(b []byte, index int) (Configuration, error) {
	c := Configuration{Index: index}
	if len(b) < 9 || b[0] != 9 || b[1] != 2 || int(binary.LittleEndian.Uint16(b[2:])) != len(b) {
		return c, errors.New("INVALID_CONFIGURATION")
	}
	c.Value = b[5]
	current := -1
	for off := 0; off < len(b); {
		n := int(b[off])
		if n < 2 || off+n > len(b) {
			return c, errors.New("INVALID_DESCRIPTOR_LENGTH")
		}
		d := b[off : off+n]
		switch d[1] {
		case 0x0b:
			if n < 8 || d[3] == 0 || int(d[2])+int(d[3]) > 256 {
				return c, errors.New("INVALID_INTERFACE_ASSOCIATION")
			}
			c.Associations = append(c.Associations, Association{d[2], d[3], d[4], d[5], d[6]})
		case 4:
			if n < 9 {
				return c, errors.New("INVALID_INTERFACE")
			}
			c.Interfaces = append(c.Interfaces, Interface{Number: d[2], Alternate: d[3], Class: d[5], Subclass: d[6], Protocol: d[7]})
			current = len(c.Interfaces) - 1
			if d[5] == 2 && d[6] == 13 && d[3] == 0 {
				c.NCMControls++
			}
		case 5:
			if n < 7 || current < 0 {
				return c, errors.New("INVALID_ENDPOINT")
			}
			c.Interfaces[current].Endpoints = append(c.Interfaces[current].Endpoints, Endpoint{d[2], d[3] & 3, binary.LittleEndian.Uint16(d[4:])})
		case 0x24:
			if n >= 3 && current >= 0 && (d[2] == 0 || d[2] == 0x0f || d[2] == 0x1a) {
				f := FunctionalDescriptor{Subtype: d[2], Length: d[0]}
				if (d[2] == 0 || d[2] == 0x1a) && n >= 5 {
					v := binary.LittleEndian.Uint16(d[3:5])
					f.Version = &v
				}
				if d[2] == 0x1a && n >= 6 {
					v := d[5]
					f.Capabilities = &v
				}
				if d[2] == 0x0f && n >= 10 {
					v := binary.LittleEndian.Uint16(d[8:10])
					f.MaxSegment = &v
				}
				c.Interfaces[current].Functions = append(c.Interfaces[current].Functions, f)
			}
			if n >= 3 && d[2] == 6 {
				if n < 5 || current < 0 || d[3] != c.Interfaces[current].Number {
					return c, errors.New("INVALID_UNION")
				}
				c.Interfaces[current].Slaves = append([]byte(nil), d[4:]...)
			}
		}
		off += n
	}
	return c, nil
}
