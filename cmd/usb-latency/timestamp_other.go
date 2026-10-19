//go:build !darwin && usblink_local_remote

package main

import (
	"fmt"
	"net"
)

func timestamped(*net.UDPConn) (echoTransport, error) {
	return nil, fmt.Errorf("kernel receive timestamp diagnostic currently requires Darwin UDP")
}
