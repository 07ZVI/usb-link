package ipadncm

import (
	"bytes"
	"encoding/binary"
	"errors"
)

// AppleUsbFilter 486.40.9's 0x2200a0 buffered request carries an eight-byte
// USB setup packet followed by the IN payload. Only the two mode operations
// already used by this probe are admitted; this is not a generic IOCTL API.
func appleModePacket(rt, request byte, value, index uint16, payload int) ([]byte, error) {
	if rt != 0xc0 || value != 0 || !((request == 0x45 && index == 0 && payload == 4) || (request == 0x52 && index == 3 && payload == 1)) {
		return nil, errors.New("mode operation not allowed")
	}
	b := make([]byte, 8+payload)
	b[0], b[1] = rt, request
	binary.LittleEndian.PutUint16(b[2:4], value)
	binary.LittleEndian.PutUint16(b[4:6], index)
	binary.LittleEndian.PutUint16(b[6:8], uint16(payload))
	return b, nil
}

func appleModeReply(header, b []byte, n uint32, out []byte) (uint32, error) {
	if len(header) != 8 || n < 8 || uint64(n) > uint64(len(b)) || len(b) < 8 || !bytes.Equal(header, b[:8]) || int(n)-8 > len(out) {
		return 0, errors.New("invalid Apple control reply")
	}
	count := n - 8
	copy(out, b[8:n])
	return count, nil
}
