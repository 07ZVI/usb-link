package server

import (
	"context"
	"encoding/binary"

	"suhang/usbnet/internal/sharing/smbcore/vfs"
	"suhang/usbnet/internal/sharing/smbcore/wire"
)

func (c *conn) handleLock(ctx context.Context, msg []byte, tr *tree) uint32 {
	var req wire.LockRequest
	if err := req.Parse(msg); err != nil {
		return c.errBody(wire.StatusInvalidParameter)
	}
	oh, ok := tr.opens[req.FileId]
	if !ok {
		return c.errBody(wire.StatusInvalidHandle)
	}
	locker, ok := oh.h.(vfs.RangeLocker)
	if !ok {
		return c.errBody(wire.StatusNotSupported)
	}
	// Validate the whole batch before taking any lock. Mixed lock/unlock batches
	// and unknown flags must not leave partial side effects.
	if len(req.Locks) == 0 {
		return c.errBody(wire.StatusInvalidParameter)
	}
	unlockBatch := req.Locks[0].Flags&wire.LockFlagUnlock != 0
	for _, l := range req.Locks {
		kind := l.Flags & 7
		if l.Flags&^uint32(0x17) != 0 || kind != wire.LockFlagExclusiveLock && kind != wire.LockFlagSharedLock && kind != wire.LockFlagUnlock || (kind == wire.LockFlagUnlock) != unlockBatch {
			return c.errBody(wire.StatusInvalidParameter)
		}
	}
	for i, l := range req.Locks {
		exclusive, unlock := l.Flags&wire.LockFlagExclusiveLock != 0, l.Flags&wire.LockFlagUnlock != 0
		if err := locker.Lock(ctx, l.Offset, l.Length, exclusive, unlock); err != nil {
			if !unlockBatch {
				recovery, cancel := context.WithTimeout(context.WithoutCancel(ctx), cleanupCloseTimeout)
				defer cancel()
				for j := i - 1; j >= 0; j-- {
					previous := req.Locks[j]
					if e := locker.Lock(recovery, previous.Offset, previous.Length, previous.Flags&wire.LockFlagExclusiveLock != 0, true); e != nil {
						// Closing the OS handle releases every retained range lock, including
						// when consent/cancellation prevents individual rollback calls.
						_ = closeSMBHandle(recovery, oh)
						delete(tr.opens, req.FileId)
						break
					}
				}
			}
			return c.errBody(wire.StatusLockConflict)
		}
	}

	c.out = wire.LockResponseAppend(c.out)
	return wire.StatusSuccess
}

func (c *conn) handleIoctl(ctx context.Context, msg []byte, tr *tree) uint32 {
	var req wire.IoctlRequest
	if err := req.Parse(msg); err != nil {
		return c.errBody(wire.StatusInvalidParameter)
	}
	if req.MaxOutputResponse > c.srv.maxTransact {
		return c.errBody(wire.StatusInvalidParameter)
	}
	switch req.CtlCode {
	case wire.FSCTLValidateNegotiateInfo:
		if !c.validateNegotiate(req.Input) {
			return c.errBody(wire.StatusAccessDenied)
		}
		if req.MaxOutputResponse < 24 {
			return c.errBody(wire.StatusBufferTooSmall)
		}
		resp := buildValidateNegotiateInfo(c.negotiatedDialect, c.srv.guid)
		binary.LittleEndian.PutUint32(resp, c.negotiatedCapabilities)
		c.out = wire.IoctlResponseAppend(c.out, req.CtlCode, req.FileId, nil, resp, req.Flags)
		return wire.StatusSuccess
	case wire.FSCTLQueryNetworkInterfaceInfo:
		c.out = wire.IoctlResponseAppend(c.out, req.CtlCode, req.FileId, nil, nil, req.Flags)
		return wire.StatusSuccess
	case wire.FSCTLPipeWait:
		c.out = wire.IoctlResponseAppend(c.out, req.CtlCode, req.FileId, nil, nil, req.Flags)
		return wire.StatusSuccess
	case wire.FSCTLPipeTransceive:
		if tr != nil {
			if oh, ok := tr.opens[req.FileId]; ok {
				if pp, ok2 := oh.h.(vfs.PipeProcessor); ok2 {
					result := pp.ProcessPipe(ctx, req.Input)
					if uint64(len(result)) > uint64(req.MaxOutputResponse) {
						return c.errBody(wire.StatusBufferTooSmall)
					}
					c.out = wire.IoctlResponseAppend(c.out, req.CtlCode, req.FileId, nil, result, req.Flags)
					return wire.StatusSuccess
				}
			}
		}
		return c.errBody(wire.StatusNotSupported)
	default:
		if tr == nil {
			return c.errBody(wire.StatusInvalidDeviceRequest)
		}
		if _, ok := tr.opens[req.FileId]; !ok {
			return c.errBody(wire.StatusInvalidHandle)
		}
		return c.errBody(wire.StatusNotSupported)
	}
}

func (c *conn) validateNegotiate(input []byte) bool {
	if len(input) < 24 || c.negotiatedDialect == 0 {
		return false
	}
	count := int(binary.LittleEndian.Uint16(input[22:24]))
	if count == 0 || 24+2*count != len(input) || binary.LittleEndian.Uint32(input) != c.negotiateRequest.Capabilities || [16]byte(input[4:20]) != c.negotiateRequest.ClientGuid || binary.LittleEndian.Uint16(input[20:22]) != c.negotiateRequest.SecurityMode {
		return false
	}
	if count != len(c.negotiateRequest.Dialects) {
		return false
	}
	for i, d := range c.negotiateRequest.Dialects {
		if binary.LittleEndian.Uint16(input[24+2*i:]) != d {
			return false
		}
	}
	return true
}

func buildValidateNegotiateInfo(dialect uint16, guid [16]byte) []byte {
	out := make([]byte, 24)
	for i := range 4 {
		out[i] = byte(wire.CapLargeMTU >> (8 * i))
	}
	copy(out[4:20], guid[:])
	out[20] = byte(wire.SigningEnabled)
	out[21] = 0
	out[22] = byte(dialect)
	out[23] = byte(dialect >> 8)
	return out
}
