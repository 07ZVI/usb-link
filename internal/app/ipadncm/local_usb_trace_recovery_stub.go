//go:build !windows || !amd64

package ipadncm

func RestoreLocalUSBTrace(string) error { return nil }
