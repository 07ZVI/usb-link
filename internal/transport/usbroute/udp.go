package usbroute

import (
	"context"
	"fmt"
	"net"
)

func ListenUDP(ctx context.Context, local *net.UDPAddr) (*net.UDPConn, error) {
	if local == nil || !local.IP.Equal(net.IPv4(10, 6, 9, 2)) {
		return nil, fmt.Errorf("USB maintenance requires its fixed source address")
	}
	config := net.ListenConfig{Control: Control}
	socket, err := config.ListenPacket(ctx, "udp4", local.String())
	if err != nil {
		return nil, err
	}
	udp, ok := socket.(*net.UDPConn)
	if !ok {
		socket.Close()
		return nil, fmt.Errorf("USB maintenance UDP socket unavailable")
	}
	return udp, nil
}
