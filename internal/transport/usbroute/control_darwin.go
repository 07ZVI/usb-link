//go:build darwin

package usbroute

import (
	"fmt"
	"golang.org/x/sys/unix"
	"net"
	"syscall"
)

// Control keeps USB maintenance traffic on the interface owning its source IP,
// even when an unrelated VPN has a more preferred unscoped route.
func Control(network, address string, conn syscall.RawConn) error {
	if network != "tcp4" && network != "udp4" {
		return fmt.Errorf("USB maintenance requires IPv4 socket")
	}
	interfaces, err := net.Interfaces()
	if err != nil {
		return err
	}
	index := 0
	for _, iface := range interfaces {
		addrs, err := iface.Addrs()
		if err != nil {
			return err
		}
		for _, addr := range addrs {
			ip, _, err := net.ParseCIDR(addr.String())
			if err != nil || !ip.Equal(net.IPv4(10, 6, 9, 2)) {
				continue
			}
			if index != 0 && index != iface.Index {
				return fmt.Errorf("USB maintenance source belongs to multiple interfaces")
			}
			if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 || len(iface.HardwareAddr) != 6 {
				return fmt.Errorf("USB maintenance source interface is not active Ethernet")
			}
			index = iface.Index
		}
	}
	if index == 0 {
		return fmt.Errorf("USB source interface unavailable: %w", syscall.EADDRNOTAVAIL)
	}
	return bindIndex(conn, index)
}

func bindIndex(conn syscall.RawConn, index int) error {
	var sockErr error
	err := conn.Control(func(fd uintptr) { sockErr = unix.SetsockoptInt(int(fd), unix.IPPROTO_IP, unix.IP_BOUND_IF, index) })
	if err != nil {
		return err
	}
	return sockErr
}
