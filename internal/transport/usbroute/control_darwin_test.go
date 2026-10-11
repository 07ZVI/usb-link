//go:build darwin

package usbroute

import (
	"golang.org/x/sys/unix"
	"net"
	"testing"
)

func TestSocketActuallyBoundToInterface(t *testing.T) {
	iface, err := net.InterfaceByName("lo0")
	if err != nil {
		t.Fatal(err)
	}
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	raw, err := conn.SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	if err = bindIndex(raw, iface.Index); err != nil {
		t.Fatal(err)
	}
	var bound int
	var sockErr error
	if err = raw.Control(func(fd uintptr) { bound, sockErr = unix.GetsockoptInt(int(fd), unix.IPPROTO_IP, unix.IP_BOUND_IF) }); err != nil {
		t.Fatal(err)
	}
	if sockErr != nil || bound != iface.Index {
		t.Fatalf("socket bound=%d wanted=%d error=%v", bound, iface.Index, sockErr)
	}
	if _, err = conn.WriteToUDP([]byte("scope"), conn.LocalAddr().(*net.UDPAddr)); err != nil {
		t.Fatal(err)
	}
	b := make([]byte, 16)
	n, _, err := conn.ReadFromUDP(b)
	if err != nil || string(b[:n]) != "scope" {
		t.Fatalf("scoped loopback exchange: %q %v", b[:n], err)
	}
}
