package wire

import (
	"bytes"
	"encoding/binary"
	"testing"
)

func TestDirectoryInformationLayouts(t *testing.T) {
	for _, v := range []struct {
		class uint8
		fixed int
	}{{1, 64}, {2, 68}, {3, 94}, {12, 12}, {37, 104}, {38, 80}} {
		info := FileInfo{Name: "資料 [1].txt", EndOfFile: 123, FileAttributes: 32, CreationTime: 42}
		out, start := AppendDirectoryInfo(nil, info, v.class)
		name := UTF16ToBytes(info.Name)
		if start != 0 || !bytes.Equal(out[v.fixed:v.fixed+len(name)], name) || len(out)%8 != 0 {
			t.Fatal(v, out)
		}
		lengthOffset := 60
		if v.class == FileNamesInformation {
			lengthOffset = 8
		}
		if binary.LittleEndian.Uint32(out[lengthOffset:]) != uint32(len(name)) {
			t.Fatal("name length", v)
		}
		if v.class != FileNamesInformation && (binary.LittleEndian.Uint64(out[40:]) != 123 || binary.LittleEndian.Uint64(out[8:]) != 42) {
			t.Fatal("metadata", v)
		}
	}
}

func TestIoctlReadsActualMaxOutputAndFlagsOffsets(t *testing.T) {
	msg := make([]byte, 124)
	binary.LittleEndian.PutUint16(msg[64:], 57)
	binary.LittleEndian.PutUint32(msg[68:], FSCTLPipeTransceive)
	binary.LittleEndian.PutUint32(msg[88:], 120)
	binary.LittleEndian.PutUint32(msg[92:], 4)
	binary.LittleEndian.PutUint32(msg[108:], 4280)
	binary.LittleEndian.PutUint32(msg[112:], 1)
	copy(msg[120:], "test")
	var req IoctlRequest
	if e := req.Parse(msg); e != nil || req.MaxOutputResponse != 4280 || req.Flags != 1 || string(req.Input) != "test" {
		t.Fatal(req, e)
	}
	binary.LittleEndian.PutUint32(msg[88:], 64)
	if req.Parse(msg) == nil {
		t.Fatal("header accepted as ioctl input")
	}
	binary.LittleEndian.PutUint32(msg[88:], ^uint32(0))
	if req.Parse(msg) == nil {
		t.Fatal("out-of-bounds ioctl input accepted")
	}
}
