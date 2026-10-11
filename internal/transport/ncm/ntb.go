// Package ncm implements bounded CDC-NCM NTB16 framing. No driver code is copied.
package ncm

import (
	"encoding/binary"
	"fmt"
)

var le = binary.LittleEndian

const MaxNTB = 65535

type Parameters struct {
	Length, Formats                                      uint16
	InMax                                                uint32
	InDivisor, InRemainder, InAlignment, Reserved        uint16
	OutMax                                               uint32
	OutDivisor, OutRemainder, OutAlignment, OutDatagrams uint16
}

func ParseParameters(b []byte) (Parameters, error) {
	if len(b) != 28 || le.Uint16(b) < 28 {
		return Parameters{}, fmt.Errorf("GET_NTB_PARAMETERS length=%d, need 28", len(b))
	}
	p := Parameters{le.Uint16(b), le.Uint16(b[2:]), le.Uint32(b[4:]), le.Uint16(b[8:]), le.Uint16(b[10:]), le.Uint16(b[12:]), le.Uint16(b[14:]), le.Uint32(b[16:]), le.Uint16(b[20:]), le.Uint16(b[22:]), le.Uint16(b[24:]), le.Uint16(b[26:])}
	if p.Formats&1 == 0 || p.InMax < 64 || p.InMax > 16*1024*1024 || p.OutMax < 64 {
		return p, fmt.Errorf("unsupported NTB16 parameters: %+v", p)
	}
	for _, v := range [][2]uint16{{p.InDivisor, p.InRemainder}, {p.OutDivisor, p.OutRemainder}} {
		if v[0] == 0 || v[1] >= v[0] {
			return p, fmt.Errorf("invalid payload divisor/remainder")
		}
	}
	for _, a := range []uint16{p.InAlignment, p.OutAlignment} {
		if a < 4 || a&(a-1) != 0 {
			return p, fmt.Errorf("invalid NDP alignment %d", a)
		}
	}
	return p, nil
}

type Block struct {
	Sequence uint16
	NDPs     []uint16
	Frames   [][]byte
	storage  *blockStorage
}

func Decode(b []byte) (Block, error) {
	var out Block
	if len(b) < 12 || string(b[:4]) != "NCMH" || le.Uint16(b[4:]) != 12 {
		return out, fmt.Errorf("not NTH16 (header=%x)", b[:min(len(b), 12)])
	}
	n := int(le.Uint16(b[8:]))
	if n != len(b) {
		return out, fmt.Errorf("block length=%d, received=%d", n, len(b))
	}
	out.Sequence = le.Uint16(b[6:])
	idx := int(le.Uint16(b[10:]))
	seen := map[int]bool{}
	type span struct{ lo, hi int }
	spans := []span{{0, 12}}
	payloads := []span{}
	for idx != 0 {
		if seen[idx] || idx < 12 || idx%4 != 0 || idx+8 > n {
			return out, fmt.Errorf("invalid or cyclic NDP index %d", idx)
		}
		seen[idx] = true
		sig := string(b[idx : idx+4])
		if sig != "NCM0" {
			return out, fmt.Errorf("unsupported NDP signature %q (CRC/NTB32 not enabled)", sig)
		}
		size := int(le.Uint16(b[idx+4:]))
		if size < 16 || size%4 != 0 || idx+size > n {
			return out, fmt.Errorf("invalid NDP length %d", size)
		}
		spans = append(spans, span{idx, idx + size})
		out.NDPs = append(out.NDPs, uint16(idx))
		terminated := false
		for d := idx + 8; d < idx+size; d += 4 {
			off, l := int(le.Uint16(b[d:])), int(le.Uint16(b[d+2:]))
			if off == 0 && l == 0 {
				terminated = true
				break
			}
			if off == 0 || l < 14 || off+l > n {
				return out, fmt.Errorf("invalid datagram offset=%d length=%d", off, l)
			}
			payloads = append(payloads, span{off, off + l})
			out.Frames = append(out.Frames, b[off:off+l])
		}
		if !terminated {
			return out, fmt.Errorf("missing NDP terminator")
		}
		idx = int(le.Uint16(b[idx+6:]))
	}
	if len(seen) == 0 {
		return out, fmt.Errorf("missing NDP")
	}
	all := append(spans, payloads...)
	for i, a := range all {
		for _, c := range all[i+1:] {
			if a.lo < c.hi && c.lo < a.hi {
				return out, fmt.Errorf("overlapping NTB metadata/datagrams")
			}
		}
	}
	return out, nil
}

func Encode(frames [][]byte, sequence uint16, p Parameters) ([]byte, error) {
	return EncodeInto(nil, frames, sequence, p)
}

// EncodeInto reuses caller-owned storage. The caller must finish consuming the
// returned bytes before reusing dst; it never aliases the source frame slices.
func EncodeInto(dst []byte, frames [][]byte, sequence uint16, p Parameters) ([]byte, error) {
	if len(frames) == 0 || (p.OutDatagrams != 0 && len(frames) > int(p.OutDatagrams)) {
		return nil, fmt.Errorf("invalid datagram count")
	}
	alignment, divisor, remainder := int(p.OutAlignment), int(p.OutDivisor), int(p.OutRemainder)
	if alignment < 4 || alignment&(alignment-1) != 0 || divisor < 1 || remainder >= divisor {
		return nil, fmt.Errorf("invalid output alignment")
	}
	ndp := (12 + alignment - 1) / alignment * alignment
	cursor := ndp + 8 + 4*(len(frames)+1)
	var small [32]int
	offsets := small[:min(len(frames), len(small))]
	if len(frames) > len(small) {
		offsets = make([]int, len(frames))
	}
	for i, f := range frames {
		if len(f) < 14 || len(f) > 65535 {
			return nil, fmt.Errorf("invalid Ethernet length")
		}
		// NCM payload begins after the 14-byte Ethernet header.
		cursor += (remainder - (cursor+14)%divisor + divisor) % divisor
		offsets[i] = cursor
		cursor += len(f)
	}
	limit := min(uint32(MaxNTB), p.OutMax)
	if cursor > int(limit) {
		return nil, fmt.Errorf("NTB length %d exceeds %d", cursor, limit)
	}
	b := dst
	if cap(b) < cursor {
		b = make([]byte, cursor)
	} else {
		b = b[:cursor]
		clear(b)
	}
	copy(b, "NCMH")
	le.PutUint16(b[4:], 12)
	le.PutUint16(b[6:], sequence)
	le.PutUint16(b[8:], uint16(cursor))
	le.PutUint16(b[10:], uint16(ndp))
	copy(b[ndp:], "NCM0")
	le.PutUint16(b[ndp+4:], uint16(8+4*(len(frames)+1)))
	for i, f := range frames {
		le.PutUint16(b[ndp+8+4*i:], uint16(offsets[i]))
		le.PutUint16(b[ndp+10+4*i:], uint16(len(f)))
		copy(b[offsets[i]:], f)
	}
	return b, nil
}

// Stream preserves NTH boundaries across partial or coalesced USB completions.
// It rejects unexplained leading bytes rather than silently resynchronizing.
type Stream struct {
	Pending     []byte
	Pool        BufferPool
	pendingPool BufferPool
}

func (s *Stream) Feed(b []byte) ([]Block, error) {
	if len(s.Pending)+len(b) > 2*65536 {
		return nil, fmt.Errorf("stream buffer limit")
	}
	if s.Pool != nil || s.pendingPool != nil {
		return s.feedPooled(b)
	}
	s.Pending = append(s.Pending, b...)
	var blocks []Block
	for len(s.Pending) >= 12 {
		if string(s.Pending[:4]) != "NCMH" {
			return nil, fmt.Errorf("unexpected format/header %x", s.Pending[:12])
		}
		n := int(le.Uint16(s.Pending[8:]))
		if n < 12 {
			return nil, fmt.Errorf("invalid stream block length %d", n)
		}
		if len(s.Pending) < n {
			break
		}
		// The accumulator already owns its bytes. Returned frames retain that
		// allocation; any partial tail is detached below before future Feed.
		block, e := Decode(s.Pending[:n])
		if e != nil {
			return nil, e
		}
		blocks = append(blocks, block)
		s.Pending = s.Pending[n:]
	}
	if len(blocks) > 0 {
		if len(s.Pending) == 0 {
			s.Pending = nil
		} else {
			s.Pending = append([]byte(nil), s.Pending...)
		}
	}
	return blocks, nil
}
