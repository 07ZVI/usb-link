//go:build windows && amd64

package bench

import "suhang/usbnet/internal/diagnostics/memorydiag"

func init() { memorySnapshot = memorydiag.Snapshot }
