package server

import (
	"bytes"
	"encoding/binary"
	"suhang/usbnet/internal/sharing/smbcore/wire"
)

// Apple's native client starts with a multiprotocol probe. Only its SMB2
// upgrade is accepted; there is no SMB1 authentication or file service.
func (c *conn) upgradeNegotiate(msg []byte) bool {
	if len(msg) < 35 || len(msg) > 8192 || !bytes.Equal(msg[:4], []byte{0xff, 'S', 'M', 'B'}) || msg[4] != 0x72 || msg[32] != 0 {
		return false
	}
	n := int(binary.LittleEndian.Uint16(msg[33:35]))
	if n != len(msg)-35 {
		return false
	}
	dialect := uint16(0)
	for p := msg[35:]; len(p) > 0; {
		if p[0] != 2 {
			return false
		}
		p = p[1:]
		end := bytes.IndexByte(p, 0)
		if end < 0 {
			return false
		}
		switch string(p[:end]) {
		case "SMB 2.???":
			dialect = 0x02ff
		case "SMB 2.002":
			if dialect == 0 {
				dialect = wire.DialectSMB202
			}
		}
		p = p[end+1:]
	}
	if dialect == 0 {
		return false
	}
	out := make([]byte, wire.HeaderSize)
	h := wire.Header{Command: wire.CmdNegotiate, Credit: 1, Flags: wire.FlagServerToRedir}
	h.EncodeAt(out)
	response := wire.NegotiateResponse{SecurityMode: wire.SigningEnabled, DialectRevision: dialect, ServerGuid: c.srv.guid, Capabilities: wire.CapLargeMTU, MaxTransactSize: c.srv.maxTransact, MaxReadSize: c.srv.maxRead, MaxWriteSize: c.srv.maxWrite}
	return c.fc.WriteMessage(response.Append(out)) == nil
}
