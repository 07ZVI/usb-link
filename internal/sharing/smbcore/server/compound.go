package server

import (
	"encoding/binary"
	"suhang/usbnet/internal/sharing/smbcore/transport"
	"suhang/usbnet/internal/sharing/smbcore/wire"
)

// Validate the entire chain before executing the first operation. Bound both
// command count and possible response bytes; a malformed tail must not create,
// rename or delete files before the connection is rejected.
func (c *conn) validCompound(msg []byte) bool {
	if len(msg) > transport.MaxMessageLen {
		return false
	}
	offset, budget := 0, uint64(0)
	for count := 0; count < 64; count++ {
		sub := msg[offset:]
		var h wire.Header
		if h.Parse(sub) != nil || h.IsResponse() {
			return false
		}
		if count == 0 && h.Flags&wire.FlagRelatedOps != 0 {
			return false
		}
		if h.NextCommand != 0 {
			if h.NextCommand < wire.HeaderSize || h.NextCommand%8 != 0 || uint64(h.NextCommand)+wire.HeaderSize > uint64(len(sub)) {
				return false
			}
			sub = sub[:h.NextCommand]
		}
		if h.Command == wire.CmdCancel {
			return count == 0 && h.NextCommand == 0 && len(sub) == wire.HeaderSize+4 && binary.LittleEndian.Uint16(sub[wire.HeaderSize:]) == 4
		}
		if h.Command == wire.CmdNegotiate && (count != 0 || h.NextCommand != 0) {
			return false
		}
		cost := uint64(256)
		switch h.Command {
		case wire.CmdRead:
			var req wire.ReadRequest
			if req.Parse(sub) == nil {
				cost += uint64(min(req.Length, c.srv.maxRead))
			}
		case wire.CmdQueryDirectory:
			var req wire.QueryDirectoryRequest
			if req.Parse(sub) == nil {
				cost += uint64(min(req.OutputBufferLength, c.srv.maxTransact))
			}
		case wire.CmdQueryInfo:
			var req wire.QueryInfoRequest
			if req.Parse(sub) == nil {
				cost += uint64(min(req.OutputBufferLength, c.srv.maxTransact))
			}
		case wire.CmdIoctl:
			var req wire.IoctlRequest
			if req.Parse(sub) == nil {
				cost += uint64(min(req.MaxOutputResponse, c.srv.maxTransact))
			}
		case wire.CmdSessionSetup:
			cost += 16 << 10
		case wire.CmdNegotiate:
			cost += uint64(len(c.srv.securityBuffer))
		}
		budget += cost
		if budget > transport.MaxMessageLen {
			return false
		}
		if h.NextCommand == 0 {
			return true
		}
		offset += int(h.NextCommand)
	}
	return false
}
