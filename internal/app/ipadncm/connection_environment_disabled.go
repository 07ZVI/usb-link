//go:build !windows || !amd64 || !usblink_local_remote

package ipadncm

import "context"

func RequestConnectionEnvironmentCapture()                      {}
func RecordConnectionEnvironmentPID(uint32)                     {}
func RecordConnectionEnvironmentPNP(any)                        {}
func StartConnectionEnvironment(context.Context, string) func() { return func() {} }
