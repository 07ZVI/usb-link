package server

import (
	"context"
	"crypto/rand"
	"crypto/sha512"
	"encoding/binary"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"strings"
	"sync"
	"time"

	"suhang/usbnet/internal/sharing/smbcore/auth"
	"suhang/usbnet/internal/sharing/smbcore/encryption"
	"suhang/usbnet/internal/sharing/smbcore/signing"
	"suhang/usbnet/internal/sharing/smbcore/transport"
	"suhang/usbnet/internal/sharing/smbcore/vfs"
	"suhang/usbnet/internal/sharing/smbcore/wire"
)

const (
	defaultMaxTransact uint32 = 65536
	defaultMaxRead     uint32 = 1 << 20
	defaultMaxWrite    uint32 = 1 << 20
	defaultMaxCredits  uint32 = 8192

	cleanupCloseTimeout = 5 * time.Second
)

type Server struct {
	addr           string
	authFactory    auth.Factory
	shares         []vfs.Share
	shareByName    map[string]vfs.Share
	aliases        [][2]string
	observe        func(uint16, uint32)
	dialect        uint16
	maxTransact    uint32
	maxRead        uint32
	maxWrite       uint32
	maxCredits     uint32
	requireEnc     bool
	log            *slog.Logger
	guid           [16]byte
	securityBuffer []byte

	mu       sync.Mutex
	listener net.Listener
}

type Option func(*Server)

func WithAddr(addr string) Option { return func(s *Server) { s.addr = addr } }

func WithAuth(f auth.Factory) Option { return func(s *Server) { s.authFactory = f } }

func WithShares(shares ...vfs.Share) Option {
	return func(s *Server) { s.shares = append(s.shares, shares...) }
}

// Compatibility aliases resolve old bookmarks but are not duplicate entries
// in native share discovery.
func WithShareAlias(alias, target string) Option {
	return func(s *Server) { s.aliases = append(s.aliases, [2]string{alias, target}) }
}

func WithObserver(f func(uint16, uint32)) Option { return func(s *Server) { s.observe = f } }

func WithLogger(l *slog.Logger) Option { return func(s *Server) { s.log = l } }

func WithMaxCredits(n uint32) Option { return func(s *Server) { s.maxCredits = n } }

func WithNegotiationToken(token []byte) Option {
	return func(s *Server) { s.securityBuffer = append([]byte(nil), token...) }
}

func WithEncryptionRequired() Option { return func(s *Server) { s.requireEnc = true } }

func WithDialect(d uint16) Option { return func(s *Server) { s.dialect = d } }

func New(opts ...Option) (*Server, error) {
	s := &Server{
		addr:        ":445",
		dialect:     wire.DialectSMB302,
		maxTransact: defaultMaxTransact,
		maxRead:     defaultMaxRead,
		maxWrite:    defaultMaxWrite,
		maxCredits:  defaultMaxCredits,
		log:         slog.Default(),
	}
	for _, opt := range opts {
		opt(s)
	}
	if len(s.shares) == 0 {
		return nil, errors.New("server: at least one share is required")
	}
	if s.authFactory == nil {
		s.authFactory = auth.AlwaysAllowFactory()
	}
	s.shareByName = make(map[string]vfs.Share, len(s.shares))
	for _, sh := range s.shares {
		s.shareByName[strings.ToUpper(sh.Name())] = sh
	}
	for _, a := range s.aliases {
		target, ok := s.shareByName[strings.ToUpper(a[1])]
		if !ok || s.shareByName[strings.ToUpper(a[0])] != nil || a[0] == "" {
			return nil, errors.New("server: invalid share alias")
		}
		s.shareByName[strings.ToUpper(a[0])] = target
	}

	if _, ok := s.shareByName["IPC$"]; !ok {
		shareNames := make([][2]string, len(s.shares)+1)
		shareNames[0] = [2]string{"IPC$", "Remote IPC"}
		for i, sh := range s.shares {
			shareNames[i+1] = [2]string{sh.Name(), ""}
		}
		pb := vfs.NewPipeBackend()
		pb.Register("srvsvc", vfs.SrvsvcHandler(shareNames))
		ipcShare := vfs.NewDiskShare("IPC$", pb)
		s.shares = append(s.shares, ipcShare)
		s.shareByName["IPC$"] = ipcShare
	}

	if _, err := rand.Read(s.guid[:]); err != nil {
		return nil, fmt.Errorf("server: generate guid: %w", err)
	}
	return s, nil
}

func (s *Server) ListenAndServe(ctx context.Context) error {
	ln, err := net.Listen("tcp", s.addr)
	if err != nil {
		return fmt.Errorf("server: listen %s: %w", s.addr, err)
	}
	s.mu.Lock()
	s.listener = ln
	s.mu.Unlock()
	defer func() {
		s.mu.Lock()
		s.listener = nil
		s.mu.Unlock()
		_ = ln.Close()
	}()
	s.log.Info("smb server listening", "addr", ln.Addr().String())

	go func() {
		<-ctx.Done()
		_ = ln.Close()
	}()

	var wg sync.WaitGroup
	for {
		c, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				wg.Wait()
				return nil
			}
			return fmt.Errorf("server: accept: %w", err)
		}
		wg.Go(func() {
			s.serveConn(ctx, c)
		})
	}
}

func (s *Server) Shutdown() error {
	s.mu.Lock()
	ln := s.listener
	s.listener = nil
	s.mu.Unlock()
	if ln != nil {
		return ln.Close()
	}
	return nil
}

type session struct {
	auth           auth.Authenticator
	identity       *auth.Identity
	authenticated  bool
	trees          map[uint32]*tree
	nextTreeID     uint32
	signer         *signing.Signer
	requireSign    bool
	encryptionKey  []byte
	decryptionKey  []byte
	requireEncrypt bool
	encCCM         *encryption.AESCCM
	decCCM         *encryption.AESCCM
}

type tree struct {
	share   vfs.Share
	opens   map[[16]byte]*openHandle
	nextID  uint64
	oplocks *oplockTable
}

type openHandle struct {
	h             vfs.Handle
	fileId        [16]byte
	path          string
	deletePending bool
	desiredAccess uint32
	enumDone      bool
	enumPending   *vfs.FileInfo
	enumMu        sync.Mutex
}

type conn struct {
	srv           *Server
	fc            *transport.FramedConn
	log           *slog.Logger
	out           []byte
	sessions      map[uint64]*session
	nextSess      uint64
	creditBalance uint32

	nextAsync    uint64
	pending      map[uint64]*pendingOp
	pendingByMsg map[uint64]*pendingOp
	pendingMu    sync.Mutex
	asyncResp    chan []byte
	connDone     chan struct{}

	preauthHash            []byte
	negotiatedDialect      uint16
	negotiatedCapabilities uint32
	negotiateRequest       wire.NegotiateRequest
}

func (s *Server) serveConn(ctx context.Context, c net.Conn) {
	defer func() { _ = c.Close() }()
	connCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	stop := context.AfterFunc(connCtx, func() { _ = c.Close() })
	defer stop()

	sha := sha512.New()
	sha.Write(nil)
	cn := &conn{
		srv:           s,
		fc:            transport.NewFramedConn(c),
		log:           s.log,
		sessions:      make(map[uint64]*session),
		creditBalance: 1,
		pending:       make(map[uint64]*pendingOp),
		pendingByMsg:  make(map[uint64]*pendingOp),
		asyncResp:     make(chan []byte, 64),
		connDone:      make(chan struct{}),
		preauthHash:   sha.Sum(nil),
	}
	defer cn.cleanup()

	for {
		if err := ctx.Err(); err != nil {
			return
		}
		cn.drainAsync()

		msg, err := cn.fc.ReadMessage()
		if err != nil {
			if !errors.Is(err, net.ErrClosed) {
				cn.log.Debug("read error", "err", err)
			}
			return
		}
		if len(msg) >= 4 && msg[0] == 0xff {
			if !cn.upgradeNegotiate(msg) {
				return
			}
			continue
		}

		if len(msg) >= 4 && msg[0] == 0xFD {
			dec, dErr := cn.openTransform(msg)
			if dErr != nil {
				cn.log.Debug("decrypt error", "err", dErr)
				return
			}
			msg = dec
		} else if len(msg) >= wire.HeaderSize {
			sessID := binary.LittleEndian.Uint64(msg[40:48])
			if sess := cn.getSession(sessID); sess != nil && sess.requireEncrypt {
				cn.log.Debug("plaintext on encrypted session, dropping")
				return
			}
		}

		cn.out = cn.out[:0]
		cmdBefore := uint16(0)
		if len(msg) >= wire.HeaderSize {
			cmdBefore = binary.LittleEndian.Uint16(msg[12:14])
		}
		if cmdBefore == wire.CmdNegotiate || cmdBefore == wire.CmdSessionSetup {
			cn.updatePreauth(msg)
		}
		cn.log.Debug("SMB request", "command", cmdBefore)
		if !cn.handleMessage(connCtx, msg) {
			return
		}
		if len(cn.out) == 0 {
			continue
		}
		if len(cn.out) > 0 {
			if sealed, ok := cn.maybeSealResponse(cn.out); ok {
				cn.out = sealed
			}
			if err := cn.fc.WriteMessage(cn.out); err != nil {
				cn.log.Debug("write error", "err", err)
				return
			}
		}
	}
}

func (c *conn) drainAsync() {
	for {
		select {
		case resp := <-c.asyncResp:
			if err := c.fc.WriteMessage(resp); err != nil {
				c.log.Debug("write async error", "err", err)
				return
			}
		default:
			return
		}
	}
}

func (c *conn) handleMessage(ctx context.Context, msg []byte) bool {
	if !c.validCompound(msg) {
		c.out = nil
		return false
	}
	var firstHeader wire.Header
	_ = firstHeader.Parse(msg)
	if firstHeader.Command == wire.CmdCancel {
		c.handleCancel(msg, &firstHeader)
		return true
	}
	type signingEntry struct {
		start   int
		session *session
	}
	var responses []signingEntry
	off := 0
	first := true
	chainFailed := false
	lastStatus := uint32(wire.StatusSuccess)
	var lastFileId [16]byte
	var lastSessionID uint64
	var lastTreeID uint32
	prevRespStart := -1

	for commands := 0; off+wire.HeaderSize <= len(msg); commands++ {
		if commands >= 64 {
			c.out = nil
			return false
		}
		sub := msg[off:]
		var hdr wire.Header
		if err := hdr.Parse(sub); err != nil {
			c.log.Debug("bad header in compound", "err", err)
			return false
		}
		if hdr.NextCommand != 0 {
			if hdr.NextCommand < wire.HeaderSize || hdr.NextCommand%8 != 0 || uint64(hdr.NextCommand) > uint64(len(sub))-wire.HeaderSize {
				c.out = nil
				return false
			}
			sub = sub[:hdr.NextCommand]
		}
		related := hdr.Flags&wire.FlagRelatedOps != 0 && !first
		if related {
			hdr.SessionId, hdr.TreeId = lastSessionID, lastTreeID
		}
		requestSession := c.getSession(hdr.SessionId)
		if !related {
			chainFailed = false
		}

		charge := uint32(hdr.CreditCharge)
		if charge == 0 {
			charge = 1
		}
		if c.creditBalance >= charge {
			c.creditBalance -= charge
		} else {
			c.creditBalance = 0
		}

		if sess := c.getSession(hdr.SessionId); sess != nil && sess.signer != nil {
			if hdr.Flags&wire.FlagSigned != 0 {
				ok, vErr := sess.signer.Verify(sub)
				if vErr != nil || !ok {
					chainFailed = true
					lastStatus = wire.StatusAccessDenied
				}
			} else if sess.requireSign {
				chainFailed = true
				lastStatus = wire.StatusAccessDenied
			}
		}

		// Verify the original wire bytes before substituting related file IDs.
		if related {
			if fo := fileIdOffset(hdr.Command); fo >= 0 && fo+16 <= len(sub) {
				allOnes := true
				for _, b := range sub[fo : fo+16] {
					allOnes = allOnes && b == 0xff
				}
				if allOnes {
					sub = append([]byte(nil), sub...)
					copy(sub[fo:fo+16], lastFileId[:])
				}
			}
		}

		if prevRespStart >= 0 {
			for len(c.out)%8 != 0 {
				c.out = append(c.out, 0)
			}
			delta := uint32(len(c.out) - prevRespStart)
			binary.LittleEndian.PutUint32(c.out[prevRespStart+20:prevRespStart+24], delta)
		}
		respStart := len(c.out)
		c.out = append(c.out, make([]byte, wire.HeaderSize)...)

		var status uint32
		switch {
		case chainFailed:
			status = c.errBody(lastStatus)
		default:
			status = c.dispatch(ctx, sub, &hdr, &lastFileId, related)
		}
		c.log.Debug("SMB operation", "command", hdr.Command, "status", status)
		if c.srv.observe != nil {
			c.srv.observe(hdr.Command, status)
		}
		lastStatus = status
		lastSessionID = hdr.SessionId
		lastTreeID = hdr.TreeId
		if status != wire.StatusSuccess && status != wire.StatusMoreProcessingRequired {
			chainFailed = true
		}

		// Native Apple clients establish their ordinary request window from
		// session-setup credits. Give the completed session its bounded window.
		if hdr.Command == wire.CmdSessionSetup && status == wire.StatusSuccess {
			c.creditBalance = 0
		}
		grant := c.srv.maxCredits - c.creditBalance
		c.creditBalance += grant
		if grant > 0xFFFF {
			hdr.Credit = 0xFFFF
		} else {
			hdr.Credit = uint16(grant)
		}

		hdr.Flags |= wire.FlagServerToRedir
		if related {
			hdr.Flags |= wire.FlagRelatedOps
		} else {
			hdr.Flags &^= wire.FlagRelatedOps
		}
		hdr.Signature = [16]byte{}
		hdr.Flags &^= wire.FlagAsyncCommand
		hdr.Status = status
		nextCommand := hdr.NextCommand
		hdr.NextCommand = 0
		hdr.EncodeAt(c.out[respStart:])

		if hdr.Command == wire.CmdNegotiate || hdr.Command == wire.CmdSessionSetup {
			c.updatePreauth(c.out[respStart:])
		}

		responseSession := c.getSession(hdr.SessionId)
		if responseSession == nil {
			responseSession = requestSession
		}
		responses = append(responses, signingEntry{respStart, responseSession})

		prevRespStart = respStart
		first = false
		if nextCommand == 0 {
			break
		}
		off += int(nextCommand)
	}
	// NextCommand fields and alignment padding are part of each signature.
	for i, entry := range responses {
		sess := entry.session
		if sess == nil || sess.signer == nil {
			continue
		}
		end := len(c.out)
		if i+1 < len(responses) {
			end = responses[i+1].start
		}
		response := c.out[entry.start:end]
		command := binary.LittleEndian.Uint16(response[12:14])
		if sess.requireEncrypt && command != wire.CmdNegotiate && command != wire.CmdSessionSetup {
			continue
		}
		flags := binary.LittleEndian.Uint32(response[16:20]) | wire.FlagSigned
		binary.LittleEndian.PutUint32(response[16:20], flags)
		if err := sess.signer.Sign(response); err != nil {
			return false
		}
	}
	return true

}

func fileIdOffset(cmd uint16) int {
	switch cmd {
	case wire.CmdClose, wire.CmdFlush, wire.CmdQueryDirectory, wire.CmdLock, wire.CmdIoctl:
		return 64 + 8
	case wire.CmdRead, wire.CmdWrite, wire.CmdSetInfo:
		return 64 + 16
	case wire.CmdQueryInfo:
		return 64 + 24
	default:
		return -1
	}
}

func (c *conn) getSession(id uint64) *session { return c.sessions[id] }

func (c *conn) cleanup() {
	close(c.connDone)
	c.pendingMu.Lock()
	for _, op := range c.pending {
		op.cancel()
	}
	c.pending = nil
	c.pendingByMsg = nil
	c.pendingMu.Unlock()

	ctx, cancel := context.WithTimeout(context.Background(), cleanupCloseTimeout)
	defer cancel()
	for _, sess := range c.sessions {
		for _, tr := range sess.trees {
			c.closeAllOpens(ctx, tr)
		}
	}
}

func (c *conn) updatePreauth(msg []byte) {
	if len(c.preauthHash) == 0 {
		return
	}
	sha := sha512.New()
	sha.Write(c.preauthHash)
	sha.Write(msg)
	c.preauthHash = sha.Sum(nil)
}

func (s *session) getTree(id uint32) *tree { return s.trees[id] }

// ServeUSBConnection accepts a connection already admitted by the bounded
// physical-USB listener. It never opens a network listener itself.
func (s *Server) ServeUSBConnection(ctx context.Context, c net.Conn) {
	defer func() {
		if recover() != nil {
			s.log.Warn("invalid SMB request closed")
		}
	}()
	stop := context.AfterFunc(ctx, func() { c.Close() })
	defer stop()
	s.serveConn(ctx, c)
}
