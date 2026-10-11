package server

import (
	"context"
	"encoding/binary"
	"fmt"

	"suhang/usbnet/internal/sharing/smbcore/vfs"
	"suhang/usbnet/internal/sharing/smbcore/wire"
)

func (c *conn) handleQueryInfo(ctx context.Context, msg []byte, tr *tree) uint32 {
	var req wire.QueryInfoRequest
	if err := req.Parse(msg); err != nil {
		c.log.Debug("SMB query info parse", "err", err)
		return c.errBody(wire.StatusInvalidParameter)
	}
	c.log.Debug("SMB query info", "type", req.InfoType, "class", req.FileInfoClass)
	oh, ok := tr.opens[req.FileId]
	if !ok {
		return c.errBody(wire.StatusInvalidHandle)
	}

	switch req.InfoType {
	case wire.InfoFile:
		fi, err := oh.h.Stat(ctx)
		if err != nil {
			return c.errBody(osErrToStatus(err))
		}
		basic := wire.FileBasicInformation{
			CreationTime:   wire.TimeToFiletime(fi.CreationTime),
			LastAccessTime: wire.TimeToFiletime(fi.LastAccess),
			LastWriteTime:  wire.TimeToFiletime(fi.LastWrite),
			ChangeTime:     wire.TimeToFiletime(fi.ChangeTime),
			FileAttributes: toFileAttributes(fi),
		}
		standard := wire.FileStandardInformation{
			AllocationSize: uint64(fi.Size),
			EndOfFile:      uint64(fi.Size),
			NumberOfLinks:  1,
			DeletePending:  boolToU8(oh.deletePending),
			Directory:      boolToU8(fi.IsDir),
		}
		var info []byte
		switch req.FileInfoClass {
		case wire.FileBasicInfoClass:
			info = basic.Append(nil)
		case wire.FileStandardInfoClass:
			info = standard.Append(nil)
		case wire.FileAllInformation:
			info = wire.FileAllInformationAppend(nil, basic, standard, fi.Name)
		case wire.FileNetworkOpenInformation:
			info = networkOpenInfo(basic, fi.Size)
		default:
			return c.errBody(wire.StatusInvalidInfoClass)
		}
		minimum := len(info)
		if req.FileInfoClass == wire.FileAllInformation {
			minimum = 100
		}
		return c.queryInfoResponse(info, minimum, req.OutputBufferLength)

	case wire.InfoFilesystem:
		info, err := c.filesystemInfo(ctx, req.FileInfoClass, oh.h)
		if err != nil {
			return c.errBody(osErrToStatus(err))
		}
		if info == nil {
			return c.errBody(wire.StatusInvalidInfoClass)
		}
		minimum := len(info)
		if req.FileInfoClass == wire.FileFsAttributeInformation {
			minimum = 12
		}
		if req.FileInfoClass == wire.FileFsVolumeInformation {
			minimum = 18
		}
		return c.queryInfoResponse(info, minimum, req.OutputBufferLength)

	default:
		return c.errBody(wire.StatusNotSupported)
	}
}

func (c *conn) queryInfoResponse(info []byte, minimum int, length uint32) uint32 {
	if length > c.srv.maxTransact {
		return c.errBody(wire.StatusInvalidParameter)
	}
	if uint64(length) < uint64(minimum) {
		return c.errBody(wire.StatusBufferTooSmall)
	}
	status := uint32(wire.StatusSuccess)
	if uint64(len(info)) > uint64(length) {
		info = info[:length]
		status = wire.StatusBufferOverflow
	}
	c.out = wire.QueryInfoResponseAppend(c.out, info)
	return status
}

func networkOpenInfo(basic wire.FileBasicInformation, size int64) []byte {
	out := make([]byte, 56)
	putLE64(out[0:8], basic.CreationTime)
	putLE64(out[8:16], basic.LastAccessTime)
	putLE64(out[16:24], basic.LastWriteTime)
	putLE64(out[24:32], basic.ChangeTime)
	putLE64(out[32:40], uint64(size))
	putLE64(out[40:48], uint64(size))
	out[48], out[49], out[50], out[51] = byte(basic.FileAttributes), byte(basic.FileAttributes>>8), byte(basic.FileAttributes>>16), byte(basic.FileAttributes>>24)
	return out
}

func (c *conn) filesystemInfo(ctx context.Context, class uint8, handle vfs.Handle) ([]byte, error) {
	switch class {
	case wire.FileFsAttributeInformation:
		name := wire.UTF16ToBytes("USB Link")
		out := make([]byte, 12+len(name))
		binary.LittleEndian.PutUint32(out[0:4], 0x6) // preserved names, Unicode; no ADS or ACL claim
		binary.LittleEndian.PutUint32(out[4:8], 255)
		for i := range 4 {
			out[8+i] = byte(uint32(len(name)) >> (8 * i))
		}
		copy(out[12:], name)
		return out, nil
	case wire.FileFsSizeInformation, wire.FileFsFullSizeInformation:
		provider, ok := handle.(vfs.VolumeInfoer)
		if !ok {
			return nil, wire.NewNTError(wire.StatusNotSupported)
		}
		info, err := provider.VolumeInfo(ctx)
		if err != nil {
			return nil, fmt.Errorf("SMB volume information: %w", err)
		}
		length, offset := 24, 16
		if class == wire.FileFsFullSizeInformation {
			length, offset = 32, 24
		}
		out := make([]byte, length)
		put64LE(out[0:8], info.TotalBytes/4096)
		put64LE(out[8:16], info.FreeBytes/4096)
		if offset == 24 {
			put64LE(out[16:24], info.FreeBytes/4096)
		}
		binary.LittleEndian.PutUint32(out[offset:], 8)
		binary.LittleEndian.PutUint32(out[offset+4:], 512)
		return out, nil
	case wire.FileFsDeviceInformation:
		out := make([]byte, 8)
		binary.LittleEndian.PutUint32(out, 7)
		binary.LittleEndian.PutUint32(out[4:], 0x10)
		return out, nil
	case wire.FileFsVolumeInformation:
		label := wire.UTF16ToBytes("USB Link")
		out := make([]byte, 18+len(label))
		out[8] = 0x04
		for i := range 4 {
			out[12+i] = byte(uint32(len(label)) >> (8 * i))
		}
		copy(out[18:], label)
		return out, nil
	default:
		return nil, nil
	}
}

func (c *conn) handleSetInfo(ctx context.Context, msg []byte, tr *tree) uint32 {
	var req wire.SetInfoRequest
	if err := req.Parse(msg); err != nil {
		return c.errBody(wire.StatusInvalidParameter)
	}
	oh, ok := tr.opens[req.FileId]
	if !ok {
		return c.errBody(wire.StatusInvalidHandle)
	}

	if req.InfoType == wire.InfoFile {
		switch req.FileInfoClass {
		case wire.FileDispositionInformation:
			if oh.desiredAccess&(0x10000|0x10000000) == 0 {
				return c.errBody(wire.StatusAccessDenied)
			}
			if len(req.Buffer) < 1 {
				return c.errBody(wire.StatusInvalidParameter)
			}
			oh.deletePending = req.Buffer[0] != 0

		case wire.FileBasicInfoClass:
			if oh.desiredAccess&(0x100|0x10000000|0x40000000) == 0 {
				return c.errBody(wire.StatusAccessDenied)
			}
			var bi wire.FileBasicInformation
			if err := bi.Parse(req.Buffer); err != nil {
				return c.errBody(wire.StatusInvalidParameter)
			}
			if si, ok := oh.h.(vfs.SetInfoer); ok {
				var req vfs.SetInfoRequest
				if bi.CreationTime != 0 && bi.CreationTime != ^uint64(0) {
					t := wire.FiletimeToTime(bi.CreationTime)
					req.CreationTime = &t
				}
				if bi.LastAccessTime != 0 && bi.LastAccessTime != ^uint64(0) {
					t := wire.FiletimeToTime(bi.LastAccessTime)
					req.LastAccessTime = &t
				}
				if bi.LastWriteTime != 0 && bi.LastWriteTime != ^uint64(0) {
					t := wire.FiletimeToTime(bi.LastWriteTime)
					req.LastWriteTime = &t
				}
				if bi.ChangeTime != 0 && bi.ChangeTime != ^uint64(0) {
					t := wire.FiletimeToTime(bi.ChangeTime)
					req.ChangeTime = &t
				}
				if bi.FileAttributes != 0 {
					req.Attributes = &bi.FileAttributes
				}
				if err := si.SetInfo(ctx, &req); err != nil {
					return c.errBody(osErrToStatus(err))
				}
			} else {
				return c.errBody(wire.StatusNotSupported)
			}

		case wire.FileEndOfFileInformation:
			if len(req.Buffer) < 8 {
				return c.errBody(wire.StatusInvalidParameter)
			}
			newSize := readLE64(req.Buffer[0:8])
			if newSize < 0 {
				return c.errBody(wire.StatusInvalidParameter)
			}
			if si, ok := oh.h.(vfs.SetInfoer); ok {
				if err := si.SetInfo(ctx, &vfs.SetInfoRequest{EndOfFile: &newSize}); err != nil {
					return c.errBody(osErrToStatus(err))
				}
			} else {
				return c.errBody(wire.StatusNotSupported)
			}

		case wire.FileRenameInformation:
			if oh.desiredAccess&(0x10000|0x10000000) == 0 {
				return c.errBody(wire.StatusAccessDenied)
			}
			if len(req.Buffer) < 20 {
				return c.errBody(wire.StatusInvalidParameter)
			}
			replaceIfExist := req.Buffer[0] != 0
			fnLen := le32(req.Buffer[16:20])
			if fnLen%2 != 0 || uint64(20)+uint64(fnLen) > uint64(len(req.Buffer)) || readLE64(req.Buffer[8:16]) != 0 {
				return c.errBody(wire.StatusInvalidParameter)
			}
			newName := wire.UTF16FromBytes(req.Buffer[20 : 20+uint64(fnLen)])
			if rn, ok := oh.h.(vfs.Renamer); ok {
				if err := rn.Rename(ctx, newName, replaceIfExist); err != nil {
					return c.errBody(osErrToStatus(err))
				}
			} else {
				return c.errBody(wire.StatusNotSupported)
			}
			if tr.oplocks != nil {
				tr.oplocks.release(oh.path)
			}
			oh.path = newName

		default:
			return c.errBody(wire.StatusNotSupported)
		}
		c.out = wire.SetInfoResponseAppend(c.out)
		return wire.StatusSuccess
	}
	return c.errBody(wire.StatusNotSupported)
}

func (c *conn) handleFlush(ctx context.Context, msg []byte, tr *tree) uint32 {
	if len(msg) < 88 {
		return c.errBody(wire.StatusInvalidParameter)
	}
	var fid [16]byte
	copy(fid[:], msg[72:88])
	h, ok := tr.opens[fid]
	if !ok {
		return c.errBody(wire.StatusInvalidHandle)
	}
	if flusher, ok := h.h.(vfs.Flusher); ok {
		if err := flusher.Flush(ctx); err != nil {
			return c.errBody(osErrToStatus(err))
		}
	}
	c.out = wire.FlushResponseAppend(c.out)
	return wire.StatusSuccess
}

func boolToU8(b bool) uint8 {
	if b {
		return 1
	}
	return 0
}

func put64LE(dst []byte, v uint64) {
	for i := range 8 {
		dst[i] = byte(v >> (8 * i))
	}
}

func putLE64(dst []byte, v uint64) {
	for i := range 8 {
		dst[i] = byte(v >> (8 * i))
	}
}

func readLE64(b []byte) int64 {
	return int64(uint64(b[0]) | uint64(b[1])<<8 | uint64(b[2])<<16 | uint64(b[3])<<24 |
		uint64(b[4])<<32 | uint64(b[5])<<40 | uint64(b[6])<<48 | uint64(b[7])<<56)
}
