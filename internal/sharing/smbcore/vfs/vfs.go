package vfs

import (
	"context"
	"errors"
	"iter"
	"math"
	"time"
)

type Share interface {
	Name() string
	Backend() Backend
}

type DiskShare struct {
	name    string
	backend Backend
}

func NewDiskShare(name string, backend Backend) DiskShare {
	return DiskShare{name: name, backend: backend}
}

func (s DiskShare) Name() string     { return s.name }
func (s DiskShare) Backend() Backend { return s.backend }

const (
	DispositionSupersede   uint32 = 0x00000000
	DispositionOpen        uint32 = 0x00000001
	DispositionCreate      uint32 = 0x00000002
	DispositionOpenIf      uint32 = 0x00000003
	DispositionOverwrite   uint32 = 0x00000004
	DispositionOverwriteIf uint32 = 0x00000005
)

type OpenOptions struct {
	DesiredAccess uint32
	Path          string
	Disposition   uint32
	CreateDir     bool
	Append        bool
}

type FileInfo struct {
	Name         string
	Size         int64
	IsDir        bool
	Attributes   uint32
	CreationTime time.Time
	LastAccess   time.Time
	LastWrite    time.Time
	ChangeTime   time.Time
}

type Handle interface {
	Read(ctx context.Context, offset int64, p []byte) (int, error)
	Write(ctx context.Context, offset int64, p []byte) (int, error)
	Close(ctx context.Context) error
	Stat(ctx context.Context) (FileInfo, error)
	Enumerate(ctx context.Context, pattern string) iter.Seq2[FileInfo, error]
}

type Backend interface {
	Open(ctx context.Context, opts OpenOptions) (Handle, error)
}

type Remover interface {
	Remove(ctx context.Context, path string) error
}

// Delete the object represented by the open handle, never a stale pathname.
// Backends without this guarantee must refuse delete-on-close.
type HandleRemover interface{ Remove(context.Context) error }

var ErrNotSameDevice = errors.New("SMB rename crosses shared roots")

func ValidFileRange(offset, length uint64) bool {
	return offset <= math.MaxInt64 && length <= math.MaxInt64-offset
}

type SetInfoer interface {
	SetInfo(ctx context.Context, info *SetInfoRequest) error
}

type SetInfoRequest struct {
	CreationTime   *time.Time
	LastAccessTime *time.Time
	LastWriteTime  *time.Time
	ChangeTime     *time.Time
	Attributes     *uint32
	EndOfFile      *int64
}

type Renamer interface {
	Rename(ctx context.Context, newPath string, replaceIfExists bool) error
}

type Mkdirer interface {
	Mkdir(ctx context.Context, path string) error
}

type Copier interface {
	CopyChunk(ctx context.Context, srcPath string, srcOffset, dstOffset, length int64) error
}

type PipeProcessor interface {
	ProcessPipe(ctx context.Context, input []byte) []byte
}

type VolumeInfo struct{ TotalBytes, FreeBytes uint64 }
type VolumeInfoer interface {
	VolumeInfo(context.Context) (VolumeInfo, error)
}
type Flusher interface{ Flush(context.Context) error }
type RangeLocker interface {
	Lock(context.Context, uint64, uint64, bool, bool) error
}
