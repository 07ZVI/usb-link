package ncm

import (
	"encoding/binary"
	"fmt"
)

type ControlTransfer func(requestType, request byte, value, index uint16, data []byte) (int, error)

type DatagramTrial struct {
	Original, Current uint16
	Changed           bool
}

func readDatagram(t ControlTransfer, index uint16, maximum uint16) (uint16, error) {
	b := make([]byte, 2)
	n, err := t(0xa1, 0x87, 0, index, b)
	if err != nil {
		return 0, fmt.Errorf("GET_MAX_DATAGRAM_SIZE: %w", err)
	}
	v := binary.LittleEndian.Uint16(b)
	if n != 2 || v < 1514 || v > maximum {
		return 0, fmt.Errorf("invalid maximum datagram readback bytes=%d value=%d", n, v)
	}
	return v, nil
}

// TryDatagram uses only the CDC-NCM maximum-frame request at data alt0. It
// proves a frame setting, never an IP MTU. Any ambiguous write is rolled back
// and read back before the original transport can resume.
func TryDatagram(t ControlTransfer, index uint16, capability byte, maximum uint16) (*DatagramTrial, error) {
	if capability&8 == 0 || maximum < 9014 {
		return nil, nil
	}
	old, err := readDatagram(t, index, maximum)
	if err != nil {
		return nil, err
	} // No mutation occurred.
	target := uint16(min(int(maximum), 16014))
	d := &DatagramTrial{Original: old, Current: old}
	if old >= target {
		return d, nil
	}
	b := make([]byte, 2)
	binary.LittleEndian.PutUint16(b, target)
	d.Changed = true // A failed SET may still have changed the function.
	n, setErr := t(0x21, 0x88, 0, index, b)
	if setErr == nil && n == 2 {
		d.Current, setErr = readDatagram(t, index, maximum)
		if setErr == nil && d.Current == target {
			return d, nil
		}
	}
	if err = d.Restore(t, index, maximum); err != nil {
		return d, fmt.Errorf("MAX_DATAGRAM_RESTORE_FAILED: %w", err)
	}
	return nil, fmt.Errorf("maximum datagram trial rejected: set=%v bytes=%d", setErr, n)
}
func (d *DatagramTrial) Restore(t ControlTransfer, index uint16, maximum uint16) error {
	if d == nil || !d.Changed {
		return nil
	}
	b := make([]byte, 2)
	binary.LittleEndian.PutUint16(b, d.Original)
	n, err := t(0x21, 0x88, 0, index, b)
	if err != nil || n != 2 {
		return fmt.Errorf("restore SET bytes=%d error=%v", n, err)
	}
	v, err := readDatagram(t, index, maximum)
	if err != nil || v != d.Original {
		return fmt.Errorf("restore readback=%d expected=%d error=%v", v, d.Original, err)
	}
	d.Current, d.Changed = v, false
	return nil
}
