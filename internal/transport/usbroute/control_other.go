//go:build !darwin

package usbroute

import "syscall"

func Control(network, address string, conn syscall.RawConn) error { return nil }
