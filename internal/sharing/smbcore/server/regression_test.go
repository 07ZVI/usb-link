package server

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"iter"
	"log/slog"
	"net"
	"testing"
	"time"

	"suhang/usbnet/internal/sharing/smbcore/auth"
	"suhang/usbnet/internal/sharing/smbcore/signing"
	"suhang/usbnet/internal/sharing/smbcore/transport"
	"suhang/usbnet/internal/sharing/smbcore/vfs"
	"suhang/usbnet/internal/sharing/smbcore/wire"
)

type regressionFile struct {
	path            string
	closed, removed int
	rows            []vfs.FileInfo
	pos             int
	locks           map[uint64]bool
	failLock        uint64
	lockCalls       int
	readOffset      int64
}

func (f *regressionFile) Read(_ context.Context, offset int64, p []byte) (int, error) {
	f.readOffset = offset
	return len(p), nil
}
func (*regressionFile) Write(_ context.Context, _ int64, p []byte) (int, error) { return len(p), nil }
func (f *regressionFile) Close(context.Context) error                           { f.closed++; return nil }
func (f *regressionFile) Stat(context.Context) (vfs.FileInfo, error) {
	return vfs.FileInfo{Name: f.path, Size: 100}, nil
}
func (f *regressionFile) Enumerate(context.Context, string) iter.Seq2[vfs.FileInfo, error] {
	return func(yield func(vfs.FileInfo, error) bool) {
		for f.pos < len(f.rows) {
			row := f.rows[f.pos]
			f.pos++
			if !yield(row, nil) {
				return
			}
		}
	}
}
func (f *regressionFile) ResetEnumeration() error { f.pos = 0; return nil }
func (f *regressionFile) Rename(_ context.Context, name string, _ bool) error {
	f.path = name
	return nil
}
func (f *regressionFile) Remove(context.Context) error { f.removed++; return nil }
func (f *regressionFile) Lock(_ context.Context, offset, _ uint64, _, unlock bool) error {
	f.lockCalls++
	if unlock {
		delete(f.locks, offset)
		return nil
	}
	if offset == f.failLock {
		return errors.New("conflict")
	}
	if f.locks == nil {
		f.locks = map[uint64]bool{}
	}
	f.locks[offset] = true
	return nil
}

type regressionBackend struct {
	f                  *regressionFile
	opens, pathDeletes int
}

func (b *regressionBackend) Open(context.Context, vfs.OpenOptions) (vfs.Handle, error) {
	b.opens++
	return b.f, nil
}
func (b *regressionBackend) Remove(context.Context, string) error { b.pathDeletes++; return nil }

func fixture(t *testing.T) (*conn, *tree, *regressionFile, *regressionBackend, [16]byte) {
	t.Helper()
	f := &regressionFile{path: "old", failLock: ^uint64(0)}
	b := &regressionBackend{f: f}
	s, err := New(WithShares(vfs.NewDiskShare("USB", b)), WithMaxCredits(32), WithLogger(slog.New(slog.NewTextHandler(io.Discard, nil))))
	if err != nil {
		t.Fatal(err)
	}
	fid := [16]byte{1}
	tr := &tree{share: s.shares[0], opens: map[[16]byte]*openHandle{fid: {h: f, fileId: fid, path: "old", desiredAccess: 0x10000000}}}
	c := &conn{srv: s, log: s.log, sessions: map[uint64]*session{1: {authenticated: true, trees: map[uint32]*tree{1: tr}}}, creditBalance: 32, pending: map[uint64]*pendingOp{}, pendingByMsg: map[uint64]*pendingOp{}}
	return c, tr, f, b, fid
}
func packet(command uint16, body int) []byte {
	h := wire.NewHeader(command)
	h.SessionId, h.TreeId, h.MessageId = 1, 1, 5
	return append(h.Append(nil), make([]byte, body)...)
}
func setInfoPacket(fid [16]byte, class uint8, data []byte) []byte {
	p := packet(wire.CmdSetInfo, 32)
	binary.LittleEndian.PutUint16(p[64:], 33)
	p[66], p[67] = wire.InfoFile, class
	binary.LittleEndian.PutUint32(p[68:], uint32(len(data)))
	binary.LittleEndian.PutUint16(p[72:], 96)
	copy(p[80:], fid[:])
	return append(p, data...)
}
func directoryPacket(fid [16]byte, class, flags uint8, length uint32) []byte {
	p := packet(wire.CmdQueryDirectory, 32)
	binary.LittleEndian.PutUint16(p[64:], 33)
	p[66], p[67] = class, flags
	copy(p[72:], fid[:])
	binary.LittleEndian.PutUint32(p[92:], length)
	return p
}
func queryPacket(fid [16]byte, class uint8, length uint32) []byte {
	p := packet(wire.CmdQueryInfo, 40)
	binary.LittleEndian.PutUint16(p[64:], 41)
	p[66], p[67] = wire.InfoFile, class
	binary.LittleEndian.PutUint32(p[68:], length)
	copy(p[88:], fid[:])
	return p
}
func compound(packets ...[]byte) []byte {
	var out []byte
	for i, p := range packets {
		p = append([]byte(nil), p...)
		if i+1 < len(packets) {
			p = append(p, make([]byte, (8-len(p)%8)%8)...)
			binary.LittleEndian.PutUint32(p[20:], uint32(len(p)))
		}
		out = append(out, p...)
	}
	return out
}

func TestRenameAndDeleteUsesHandleAndUpdatesOpenPath(t *testing.T) {
	c, tr, f, b, fid := fixture(t)
	name := wire.UTF16ToBytes("new")
	data := make([]byte, 20)
	binary.LittleEndian.PutUint32(data[16:], uint32(len(name)))
	data = append(data, name...)
	if status := c.handleSetInfo(context.Background(), setInfoPacket(fid, wire.FileRenameInformation, data), tr); status != wire.StatusSuccess {
		t.Fatal(status)
	}
	if tr.opens[fid].path != "new" || f.path != "new" {
		t.Fatal("stale rename path")
	}
	tr.opens[fid].deletePending = true
	p := packet(wire.CmdClose, 24)
	binary.LittleEndian.PutUint16(p[64:], 24)
	copy(p[72:], fid[:])
	if status := c.handleClose(context.Background(), p, tr); status != wire.StatusSuccess {
		t.Fatal(status)
	}
	if f.removed != 1 || f.closed != 1 || b.pathDeletes != 0 || len(tr.opens) != 0 {
		t.Fatal("pathname delete or leaked handle", f, b, tr)
	}
}

func TestDisconnectHonorsDeleteOnClose(t *testing.T) {
	c, tr, f, b, fid := fixture(t)
	tr.opens[fid].deletePending = true
	c.closeAllOpens(context.Background(), tr)
	if f.removed != 1 || f.closed != 1 || b.pathDeletes != 0 {
		t.Fatal(f, b)
	}
}

func TestReadonlyOpenCannotRenameOrSetDeletePending(t *testing.T) {
	c, tr, _, _, fid := fixture(t)
	tr.opens[fid].desiredAccess = 0x80000000
	for _, class := range []uint8{wire.FileDispositionInformation, wire.FileRenameInformation} {
		if status := c.handleSetInfo(context.Background(), setInfoPacket(fid, class, []byte{1}), tr); status != wire.StatusAccessDenied {
			t.Fatal(class, status)
		}
	}
}

func TestQueryInfoDistinguishesFixedSmallVariableOverflowAndUnknownClass(t *testing.T) {
	c, tr, _, _, fid := fixture(t)
	for _, v := range []struct {
		class  uint8
		length uint32
		status uint32
	}{
		{wire.FileBasicInfoClass, 39, wire.StatusBufferTooSmall}, {wire.FileBasicInfoClass, 40, wire.StatusSuccess},
		{wire.FileAllInformation, 99, wire.StatusBufferTooSmall}, {wire.FileAllInformation, 100, wire.StatusBufferOverflow},
		{0xff, 128, wire.StatusInvalidInfoClass},
	} {
		c.out = nil
		if got := c.handleQueryInfo(context.Background(), queryPacket(fid, v.class, v.length), tr); got != v.status {
			t.Errorf("%+v: got %#x", v, got)
		}
	}
}

func TestDirectoryFormatsSmallBufferAndSingleEntryPagination(t *testing.T) {
	for _, class := range []uint8{1, 2, 3, 12, 37, 38} {
		c, tr, f, _, fid := fixture(t)
		f.rows = []vfs.FileInfo{{Name: "one"}, {Name: "two"}}
		if got := c.handleQueryDirectory(context.Background(), directoryPacket(fid, class, 0, 1), tr); got != wire.StatusBufferTooSmall {
			t.Fatal(class, got)
		}
		c.out = nil
		if got := c.handleQueryDirectory(context.Background(), directoryPacket(fid, class, wire.QueryDirReturnSingle, 512), tr); got != wire.StatusSuccess {
			t.Fatal(class, got)
		}
		fixed := wire.DirectoryInfoSize(class)
		if wire.UTF16FromBytes(c.out[8+fixed:8+fixed+6]) != "one" || f.pos != 1 {
			t.Fatal("lost first entry or ignored single flag", class, f.pos, c.out)
		}
		c.out = nil
		if got := c.handleQueryDirectory(context.Background(), directoryPacket(fid, class, wire.QueryDirReturnSingle, 512), tr); got != wire.StatusSuccess {
			t.Fatal(class, got)
		}
		if wire.UTF16FromBytes(c.out[8+fixed:8+fixed+6]) != "two" {
			t.Fatal("lost second entry", class)
		}
	}
}

func TestChangeNotifyErrorHasProperHeaderAndIndependentCompoundContinues(t *testing.T) {
	c, _, _, _, _ := fixture(t)
	p := packet(wire.CmdChangeNotify, 32)
	binary.LittleEndian.PutUint16(p[64:], 32)
	if !c.handleMessage(context.Background(), compound(p, packet(wire.CmdEcho, 4))) {
		t.Fatal("closed connection")
	}
	var first, second wire.Header
	if first.Parse(c.out) != nil || first.Status != wire.StatusNotSupported || first.NextCommand == 0 || second.Parse(c.out[first.NextCommand:]) != nil || second.Status != wire.StatusSuccess {
		t.Fatal(first, second, c.out)
	}
}

func TestCompoundBeyondFourAndMalformedTailHasNoSideEffects(t *testing.T) {
	c, _, _, b, _ := fixture(t)
	var messages [][]byte
	for range 6 {
		messages = append(messages, packet(wire.CmdEcho, 4))
	}
	if !c.handleMessage(context.Background(), compound(messages...)) {
		t.Fatal("six-command compound rejected")
	}
	count := 0
	for remaining := c.out; ; {
		var h wire.Header
		if h.Parse(remaining) != nil {
			t.Fatal("bad compound response")
		}
		count++
		if h.NextCommand == 0 {
			break
		}
		remaining = remaining[h.NextCommand:]
	}
	if count != 6 {
		t.Fatal(count)
	}
	create := packet(wire.CmdCreate, 56)
	binary.LittleEndian.PutUint16(create[64:], 57)
	broken := compound(create, packet(wire.CmdEcho, 4))
	broken[len(create)] = 0
	c.out = nil
	if c.handleMessage(context.Background(), broken) || b.opens != 0 {
		t.Fatal("malformed tail executed create", b.opens)
	}
}

func TestCompoundSignaturesIncludeFinalOffsetsAndPadding(t *testing.T) {
	c, _, _, _, _ := fixture(t)
	signer, _ := signing.NewSigner(make([]byte, 16))
	c.sessions[1].signer = signer
	if !c.handleMessage(context.Background(), compound(packet(wire.CmdEcho, 4), packet(wire.CmdEcho, 4))) {
		t.Fatal("compound failed")
	}
	var h wire.Header
	_ = h.Parse(c.out)
	for _, p := range [][]byte{c.out[:h.NextCommand], c.out[h.NextCommand:]} {
		if ok, e := signer.Verify(p); e != nil || !ok {
			t.Fatal("bad final signature", e)
		}
	}
}

func TestCancelNoResponseNoCreditConsumptionAndConnectionRemainsUsable(t *testing.T) {
	c, _, _, _, _ := fixture(t)
	op := c.registerPending(5, 1)
	p := packet(wire.CmdCancel, 4)
	binary.LittleEndian.PutUint16(p[64:], 4)
	credits := c.creditBalance
	if !c.handleMessage(context.Background(), p) || len(c.out) != 0 || c.creditBalance != credits {
		t.Fatal("cancel replied or consumed credits")
	}
	select {
	case <-op.done:
	default:
		t.Fatal("message cancel not delivered")
	}
	if !c.handleMessage(context.Background(), packet(wire.CmdEcho, 4)) {
		t.Fatal("cancel closed connection")
	}
}

type rejectAuth struct{}

func (rejectAuth) Accept(context.Context, []byte) (auth.AcceptResult, error) {
	return auth.AcceptResult{}, auth.ErrLogonFailed
}
func TestFailedAuthenticationDoesNotExhaustSessionSlots(t *testing.T) {
	c, _, _, _, _ := fixture(t)
	c.sessions = map[uint64]*session{}
	c.srv.authFactory = func() auth.Authenticator { return rejectAuth{} }
	p := packet(wire.CmdSessionSetup, 24)
	binary.LittleEndian.PutUint16(p[64:], 25)
	for range 8 {
		h := wire.NewHeader(wire.CmdSessionSetup)
		if got := c.handleSessionSetup(context.Background(), p, &h); got != wire.StatusLogonFailure || len(c.sessions) != 0 {
			t.Fatal(got, len(c.sessions))
		}
	}
}

func TestNegotiateValidationUsesActuallySelectedDialect(t *testing.T) {
	c, _, _, _, _ := fixture(t)
	p := packet(wire.CmdNegotiate, 38)
	binary.LittleEndian.PutUint16(p[64:], 36)
	binary.LittleEndian.PutUint16(p[66:], 1)
	binary.LittleEndian.PutUint16(p[68:], wire.SigningEnabled)
	binary.LittleEndian.PutUint16(p[100:], wire.DialectSMB21)
	h := wire.NewHeader(wire.CmdNegotiate)
	if got := c.handleNegotiate(p, &h); got != wire.StatusSuccess || c.negotiatedDialect != wire.DialectSMB21 {
		t.Fatal(got, c.negotiatedDialect)
	}
	input := make([]byte, 26)
	binary.LittleEndian.PutUint16(input[20:], wire.SigningEnabled)
	binary.LittleEndian.PutUint16(input[22:], 1)
	binary.LittleEndian.PutUint16(input[24:], wire.DialectSMB21)
	ioctl := packet(wire.CmdIoctl, 56)
	binary.LittleEndian.PutUint16(ioctl[64:], 57)
	binary.LittleEndian.PutUint32(ioctl[68:], wire.FSCTLValidateNegotiateInfo)
	binary.LittleEndian.PutUint32(ioctl[88:], 120)
	binary.LittleEndian.PutUint32(ioctl[92:], 26)
	binary.LittleEndian.PutUint32(ioctl[108:], 24)
	ioctl = append(ioctl, input...)
	c.out = nil
	if got := c.handleIoctl(context.Background(), ioctl, nil); got != wire.StatusSuccess || binary.LittleEndian.Uint16(c.out[48+22:]) != wire.DialectSMB21 {
		t.Fatal(got, c.out)
	}
	ioctl[len(ioctl)-1] ^= 1
	if got := c.handleIoctl(context.Background(), ioctl, nil); got != wire.StatusAccessDenied {
		t.Fatal("changed negotiation accepted", got)
	}
}

func TestLockBatchRollbackAndPrevalidation(t *testing.T) {
	c, tr, f, _, fid := fixture(t)
	f.failLock = 20
	p := packet(wire.CmdLock, 24+2*24)
	binary.LittleEndian.PutUint16(p[64:], 48)
	binary.LittleEndian.PutUint16(p[66:], 2)
	copy(p[72:], fid[:])
	for i, offset := range []uint64{10, 20} {
		b := p[88+i*24:]
		binary.LittleEndian.PutUint64(b, offset)
		binary.LittleEndian.PutUint64(b[8:], 4)
		binary.LittleEndian.PutUint32(b[16:], wire.LockFlagExclusiveLock)
	}
	if got := c.handleLock(context.Background(), p, tr); got != wire.StatusLockConflict || len(f.locks) != 0 {
		t.Fatal("partial locks retained", got, f.locks)
	}
	f.lockCalls = 0
	binary.LittleEndian.PutUint32(p[88+24+16:], 0x80000002)
	if got := c.handleLock(context.Background(), p, tr); got != wire.StatusInvalidParameter || f.lockCalls != 0 {
		t.Fatal("invalid tail mutated locks", got, f.lockCalls)
	}
}

func TestReadBeyond64GiBAndIntegerOverflowRejected(t *testing.T) {
	c, tr, f, _, fid := fixture(t)
	p := packet(wire.CmdRead, 48)
	binary.LittleEndian.PutUint16(p[64:], 49)
	binary.LittleEndian.PutUint32(p[68:], 1)
	binary.LittleEndian.PutUint64(p[72:], 65<<30)
	copy(p[80:], fid[:])
	if got := c.handleRead(context.Background(), p, tr); got != wire.StatusSuccess || f.readOffset != 65<<30 {
		t.Fatal(got, f.readOffset)
	}
	binary.LittleEndian.PutUint64(p[72:], 1<<63-1)
	if got := c.handleRead(context.Background(), p, tr); got != wire.StatusInvalidParameter {
		t.Fatal("signed range overflow accepted", got)
	}
}

func TestIdleConnectionClosesWhenServerContextIsCanceled(t *testing.T) {
	c, _, _, _, _ := fixture(t)
	serverSide, clientSide := net.Pipe()
	defer clientSide.Close()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { c.srv.serveConn(ctx, serverSide); close(done) }()
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("idle connection survived cancellation")
	}
}

func TestCancelOverWireProducesOnlyFollowingEchoResponse(t *testing.T) {
	c, _, _, _, _ := fixture(t)
	serverSide, clientSide := net.Pipe()
	defer clientSide.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go c.srv.serveConn(ctx, serverSide)
	clientSide.SetDeadline(time.Now().Add(time.Second))
	frame := transport.NewFramedConn(clientSide)
	p := packet(wire.CmdCancel, 4)
	binary.LittleEndian.PutUint16(p[64:], 4)
	if e := frame.WriteMessage(p); e != nil {
		t.Fatal(e)
	}
	// Echo without a session has a session-deleted error, but the connection is alive.
	if e := frame.WriteMessage(packet(wire.CmdEcho, 4)); e != nil {
		t.Fatal(e)
	}
	out, e := frame.ReadMessage()
	var h wire.Header
	if e != nil || h.Parse(out) != nil || h.Command != wire.CmdEcho {
		t.Fatal("unexpected CANCEL reply or closed connection", h, e)
	}
}

func TestVerificationDoesNotMutateSignedRequest(t *testing.T) {
	signer, _ := signing.NewSigner(make([]byte, 16))
	p := packet(wire.CmdEcho, 4)
	_ = signer.Sign(p)
	p[48] ^= 1
	before := append([]byte(nil), p...)
	if ok, _ := signer.Verify(p); ok || !bytes.Equal(p, before) {
		t.Fatal("verify modified original wire bytes")
	}
}
