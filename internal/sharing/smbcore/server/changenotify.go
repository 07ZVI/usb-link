package server

import (
	"context"
	"errors"

	"suhang/usbnet/internal/sharing/smbcore/wire"
)

const (
	FileNotifyChangeFileName   uint32 = 0x00000001
	FileNotifyChangeDirName    uint32 = 0x00000002
	FileNotifyChangeAttributes uint32 = 0x00000004
	FileNotifyChangeSize       uint32 = 0x00000008
	FileNotifyChangeLastWrite  uint32 = 0x00000010
	FileNotifyChangeLastAccess uint32 = 0x00000020
	FileNotifyChangeCreation   uint32 = 0x00000040
	FileNotifyChangeEA         uint32 = 0x00000080
	FileNotifyChangeSecurity   uint32 = 0x00000100
	SMB2WatchTree              uint16 = 0x0001
)

const (
	fileActionAdded    uint32 = 0x00000001
	fileActionRemoved  uint32 = 0x00000002
	fileActionModified uint32 = 0x00000003
	fileActionRenamed  uint32 = 0x00000004
)

type changeNotifyRequest struct {
	Flags              uint16
	OutputBufferLength uint32
	FileId             [16]byte
	CompletionFilter   uint32
}

func (r *changeNotifyRequest) Parse(msg []byte) error {
	if len(msg) < 64+32 {
		return errors.New("wire: change_notify needs 32 bytes")
	}
	b := msg[64:]
	r.Flags = le16(b[2:4])
	r.OutputBufferLength = le32(b[4:8])
	copy(r.FileId[:], b[8:24])
	r.CompletionFilter = le32(b[24:28])
	return nil
}

type notifyEvent struct {
	action uint32
	name   string
}

func (c *conn) handleChangeNotify(ctx context.Context, msg []byte, hdr *wire.Header, tr *tree) (uint32, bool) {
	var req changeNotifyRequest
	if err := req.Parse(msg); err != nil {
		return c.errBody(wire.StatusInvalidParameter), false
	}
	// No polling goroutines for unbounded directory watches. Clients can refresh.
	return c.errBody(wire.StatusNotSupported), false
}

func (c *conn) handleCancel(_ []byte, hdr *wire.Header) {
	c.pendingMu.Lock()
	defer c.pendingMu.Unlock()
	op := c.pendingByMsg[hdr.MessageId]
	if hdr.Flags&wire.FlagAsyncCommand != 0 {
		op = c.pending[hdr.AsyncId]
	}
	if op != nil && op.sessionID == hdr.SessionId {
		op.cancel()
	}
	// MS-SMB2: CANCEL consumes no credits and never produces a response.
}
