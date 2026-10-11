//go:build windows && amd64

package ipadncm

import (
	"context"
	"encoding/binary"
	"golang.org/x/sys/windows"
)

func usbProductString(ctx context.Context, h windows.Handle, port uint32, index byte) string {
	langs, e := descriptor(ctx, h, port, 3, 0, 255)
	if e != nil || len(langs) < 4 || langs[1] != 3 || langs[0] < 4 || int(langs[0]) > len(langs) {
		return ""
	}
	b, e := descriptorLanguage(ctx, h, port, 3, index, binary.LittleEndian.Uint16(langs[2:]), 255)
	if e != nil {
		return ""
	}
	return parseUSBString(b)
}
