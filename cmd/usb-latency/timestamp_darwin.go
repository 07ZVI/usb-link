//go:build darwin && usblink_local_remote

package main

import (
	"encoding/binary"
	"fmt"
	"golang.org/x/sys/unix"
	"net"
	"time"
)

type timestampUDP struct {
	*net.UDPConn
	kernel time.Time
	valid  bool
	oob    [512]byte
}

func timestamped(conn *net.UDPConn) (echoTransport, error) {
	raw, err := conn.SyscallConn()
	if err != nil {
		return nil, err
	}
	var optionErr error
	if err = raw.Control(func(fd uintptr) { optionErr = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_TIMESTAMP, 1) }); err != nil {
		return nil, err
	}
	if optionErr != nil {
		return nil, optionErr
	}
	return &timestampUDP{UDPConn: conn}, nil
}
func (c *timestampUDP) Read(b []byte) (int, error) {
	n, on, flags, _, err := c.ReadMsgUDP(b, c.oob[:])
	c.valid = false
	if err != nil {
		return n, err
	}
	if flags&unix.MSG_CTRUNC != 0 {
		return n, fmt.Errorf("kernel timestamp control data truncated")
	}
	c.kernel, c.valid, err = kernelTimestamp(c.oob[:on])
	if err == nil && !c.valid {
		err = fmt.Errorf("kernel receive timestamp missing")
	}
	return n, err
}
func (c *timestampUDP) KernelReceived() (time.Time, bool) { return c.kernel, c.valid }
func kernelTimestamp(oob []byte) (time.Time, bool, error) {
	msgs, err := unix.ParseSocketControlMessage(oob)
	if err != nil {
		return time.Time{}, false, err
	}
	for _, m := range msgs {
		if m.Header.Level != unix.SOL_SOCKET || m.Header.Type != unix.SCM_TIMESTAMP {
			continue
		}
		// Darwin 64-bit struct timeval: int64 seconds, int32 usec, padding.
		if len(m.Data) < 16 {
			return time.Time{}, false, fmt.Errorf("short SCM_TIMESTAMP")
		}
		sec := int64(binary.NativeEndian.Uint64(m.Data[:8]))
		us := int32(binary.NativeEndian.Uint32(m.Data[8:12]))
		if sec < 0 || us < 0 || us >= 1000000 {
			return time.Time{}, false, fmt.Errorf("invalid SCM_TIMESTAMP timeval")
		}
		return time.Unix(sec, int64(us)*1000), true, nil
	}
	return time.Time{}, false, nil
}
