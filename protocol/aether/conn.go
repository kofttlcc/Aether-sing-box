package aether

import (
	"context"
	"crypto/ecdh"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/buf"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

const (
	// DefaultHeartbeatInterval is used when HeartbeatInterval == 0.
	DefaultHeartbeatInterval    = 30 * time.Second
	minControlWriteTimeout      = 500 * time.Millisecond
	maxControlWriteTimeout      = 5 * time.Second
	clientInitialBurstGrace     = 25 * time.Millisecond
	clientInitialBurstWaitSkip  = 50 * time.Millisecond
	clientWriteFlushWaitTimeout = 50 * time.Millisecond
	pendingServerRespFlushDelay = 100 * time.Millisecond
)

var (
	_ net.Conn             = (*Conn)(nil)
	_ N.ExtendedConn       = (*Conn)(nil)
	_ N.EarlyWriter        = (*Conn)(nil)
	_ N.EarlyReader        = (*Conn)(nil)
	_ N.EarlyConn          = (*Conn)(nil)
	_ N.WriteCloser        = (*Conn)(nil)
	_ N.FrontHeadroom      = (*Conn)(nil)
	_ N.RearHeadroom       = (*Conn)(nil)
	_ N.WriterWithMTU      = (*Conn)(nil)
	_ N.ReaderWithUpstream = (*Conn)(nil)
	_ N.WriterWithUpstream = (*Conn)(nil)
	_ common.WithUpstream  = (*Conn)(nil)
)

// ClientConnOptions configures a client-side 0-RTT Aether v2 stream/datagram Conn.
type ClientConnOptions struct {
	Credentials       ClientCredentials
	ServerStaticPub   *ecdh.PublicKey
	Command           uint8
	CipherSuite       uint8
	TargetAddr        M.Socksaddr
	HeartbeatInterval time.Duration // 0 defaults to 30s; <0 disables heartbeat & DPD
	DisableShaping    bool
	TimeFunc          func() time.Time
}

// ServerConnOptions configures server-side Aether v2 handshake acceptance.
type ServerConnOptions struct {
	Authenticator     *ServerAuthenticator
	ReplayFilter      *SlidingBloomFilter
	HeartbeatInterval time.Duration // 0 defaults to 30s; <0 disables heartbeat & DPD
	DisableShaping    bool
	TimeFunc          func() time.Time
}

// ServerAcceptResult holds the accepted Conn and authenticated request metadata.
type ServerAcceptResult struct {
	Conn        *Conn
	Command     uint8
	CipherSuite uint8
	TargetAddr  M.Socksaddr
	UserName    string
	UserIndex   int
}

// Conn implements Aether v2 transport over a reliable byte stream (typically TCP) with
// 0-RTT client burst coalescing, single-write 84B server response coalescing,
// head-only traffic shaping, control-plane decoupling, deadline fusing, and DPD.
type Conn struct {
	rawConn net.Conn

	isClient          bool
	disableShaping    bool
	heartbeatInterval time.Duration
	pongTimeout       time.Duration
	protoNow          func() time.Time

	// Client handshake config and state.
	creds       ClientCredentials
	serverPub   *ecdh.PublicKey
	command     uint8
	cipherSuite uint8
	targetAddr  M.Socksaddr

	initBurstMu      sync.Mutex
	clientHS         *ClientHandshakeState
	handshakeWritten atomic.Bool
	handshakeRead    atomic.Bool
	writeStartOnce   sync.Once
	writeStartCh     chan struct{}
	initSentOnce     sync.Once
	initSentCh       chan struct{}

	// Server initial response prefix coalesced into the very first S2C encrypted frame.
	serverRespPrefix  [ServerRespPrefixSize]byte
	serverRespPending atomic.Bool

	// Write path state: app writes lock writeMu; writeMu -> initBurstMu / rawWriteMu.
	writeMu           sync.Mutex
	rawWriteMu        sync.Mutex
	sendCipher        *DirectionalCipher
	sendFrameIdx      uint64
	writePlainScratch []byte
	writeCloseSent    atomic.Bool
	writeBroken       atomic.Bool

	// Read path state: respMu coordinates single-reader 84B ServerResponsePrefix attempts
	// (closing respDoneCh once completed or fatally failed); readMu serializes app Read/ReadBuffer;
	// readStateMu guards the bounded 1-frame unread handoff between background readLoop and callers.
	respMu               sync.Mutex
	respCurrAttempt      *respAttempt
	respDoneCh           chan struct{}
	respDoneOnce         sync.Once
	respKickCh           chan struct{}
	respWg               sync.WaitGroup
	readMu               sync.Mutex
	readStateMu          sync.Mutex
	readReadyCh          chan struct{}
	readConsumedCh       chan struct{}
	readDlKickCh         chan struct{}
	recvCipher           *DirectionalCipher
	respBuf              [ServerRespPrefixSize]byte
	respOff              int
	lenHdrBuf            [EncryptedLengthSize]byte
	lenHdrOff            int
	bodyHdrReady         bool
	bodyExpectedPlainLen uint16
	bodyBuf              []byte
	bodyOff              int
	readPlainScratch     []byte
	unreadBuf            []byte
	unreadOff            int
	unreadEnd            int
	pendingRawEOF        atomic.Bool
	readEOF              atomic.Bool
	readErrMu            sync.Mutex
	readErr              error

	// Decoupled deadline state.
	writeDlMu        sync.Mutex
	appWriteDeadline time.Time
	readDlMu         sync.Mutex
	appReadDeadline  time.Time

	// Control-plane coordinator, Pong signal channel (cap 1), and DPD timestamps.
	lastReadNs  atomic.Int64
	lastWriteNs atomic.Int64
	pongCh      chan struct{}
	doneCh      chan struct{}
	closeOnce   sync.Once
	closed      atomic.Bool
	userClosed  atomic.Bool

	coordMu         sync.Mutex
	coordStarted    bool
	coordDone       chan struct{}
	readLoopStarted bool
	readLoopWg      sync.WaitGroup
}

func normalizeHeartbeat(interval time.Duration) (normalized, pongTimeout time.Duration) {
	if interval == 0 {
		interval = DefaultHeartbeatInterval
	}
	if interval < 0 {
		return -1, 0
	}
	if interval >= 20*time.Second {
		pongTimeout = interval / 2
	} else {
		pongTimeout = interval / 2
		if pongTimeout < 500*time.Millisecond {
			pongTimeout = 500 * time.Millisecond
		}
	}
	return interval, pongTimeout
}

// DialEarlyConn wraps rawConn as a lazy 0-RTT client Aether v2 connection without
// performing any network I/O until the first Write or Read.
func DialEarlyConn(rawConn net.Conn, opts ClientConnOptions) (*Conn, error) {
	return DialEarlyConnContext(context.Background(), rawConn, opts)
}

// DialEarlyConnContext wraps rawConn as a lazy 0-RTT client Aether v2 connection,
// resolving deterministic time functions from ctx when opts.TimeFunc is nil.
func DialEarlyConnContext(ctx context.Context, rawConn net.Conn, opts ClientConnOptions) (*Conn, error) {
	if rawConn == nil {
		return nil, errors.New("aether: nil rawConn")
	}
	if !IsValidCommand(opts.Command) {
		return nil, fmt.Errorf("%w: 0x%02x", ErrInvalidCommand, opts.Command)
	}
	cipherSuite := opts.CipherSuite
	if cipherSuite == 0 {
		cipherSuite = CipherAES256GCM
	}
	if !IsValidCipherSuite(cipherSuite) {
		return nil, fmt.Errorf("%w: 0x%02x", ErrUnsupportedCipherSuite, cipherSuite)
	}
	targetAddr, err := normalizeClientTargetAddr(opts.Command, opts.TargetAddr)
	if err != nil {
		return nil, err
	}
	var zero [PSKSize]byte
	if opts.Credentials.UPSK == zero {
		return nil, ErrAuthenticationFailed
	}
	if opts.Credentials.HasServerPSK && opts.Credentials.IPSK == zero {
		return nil, ErrAuthenticationFailed
	}

	protoNow := opts.TimeFunc
	if protoNow == nil {
		if ctx != nil {
			protoNow = ResolveTimeFunc(ctx)
		} else {
			protoNow = time.Now
		}
	}
	hbInterval, pongTimeout := normalizeHeartbeat(opts.HeartbeatInterval)
	nowNs := time.Now().UnixNano()

	c := &Conn{
		rawConn:           rawConn,
		isClient:          true,
		disableShaping:    opts.DisableShaping,
		heartbeatInterval: hbInterval,
		pongTimeout:       pongTimeout,
		protoNow:          protoNow,
		creds:             opts.Credentials,
		serverPub:         opts.ServerStaticPub,
		command:           opts.Command,
		cipherSuite:       cipherSuite,
		targetAddr:        targetAddr,
		writeStartCh:      make(chan struct{}),
		initSentCh:        make(chan struct{}),
		respDoneCh:        make(chan struct{}),
		respKickCh:        make(chan struct{}, 1),
		readReadyCh:       make(chan struct{}, 1),
		readConsumedCh:    make(chan struct{}, 1),
		readDlKickCh:      make(chan struct{}, 1),
		pongCh:            make(chan struct{}, 1),
		doneCh:            make(chan struct{}),
	}
	c.lastReadNs.Store(nowNs)
	c.lastWriteNs.Store(nowNs)
	return c, nil
}

type respAttempt struct {
	done       chan struct{}
	timeoutErr error
}

// AcceptServerConn reads and authenticates a client handshake prefix + encrypted
// VarHeader from rawConn, preparing the coalesced 84-byte ServerResponsePrefix
// for the first outbound S2C encrypted frame.
func AcceptServerConn(ctx context.Context, rawConn net.Conn, opts ServerConnOptions) (*ServerAcceptResult, error) {
	if rawConn == nil {
		return nil, errors.New("aether: nil rawConn")
	}
	if opts.Authenticator == nil {
		return nil, errors.New("aether: nil server authenticator")
	}
	if opts.ReplayFilter == nil {
		return nil, errors.New("aether: nil replay filter")
	}

	prefixBuf := buf.NewSize(opts.Authenticator.ClientPrefixSize())
	defer prefixBuf.Release()
	if _, err := io.ReadFull(rawConn, prefixBuf.Extend(opts.Authenticator.ClientPrefixSize())); err != nil {
		return nil, fmt.Errorf("aether: read client handshake prefix: %w", err)
	}

	hs, fixedPlain, err := opts.Authenticator.OpenClientFixedPrefix(prefixBuf.Bytes())
	if err != nil {
		return nil, err
	}
	fixedHdr, err := DecodeFixedHeader(fixedPlain[:])
	if err != nil {
		return nil, err
	}
	if err := opts.ReplayFilter.ValidateAndRecord(hs.ClientSalt, fixedHdr.TimestampSec); err != nil {
		return nil, err
	}

	encVarLen := int(fixedHdr.VarHeaderLen) + AEADTagSize
	encVarBuf := buf.NewSize(encVarLen)
	defer encVarBuf.Release()
	if _, err := io.ReadFull(rawConn, encVarBuf.Extend(encVarLen)); err != nil {
		return nil, fmt.Errorf("aether: read encrypted var header: %w", err)
	}

	varPlainBuf := buf.NewSize(int(fixedHdr.VarHeaderLen))
	defer varPlainBuf.Release()
	varPlain, err := hs.OpenVarHeader(varPlainBuf.FreeBytes()[:0], encVarBuf.Bytes())
	if err != nil {
		return nil, err
	}

	targetAddr, initialPayload, err := DecodeVarHeader(varPlain, fixedHdr.NoiseLen)
	if err != nil {
		return nil, err
	}

	respPlain, err := EncodeRespHeader(fixedHdr.CipherSuite)
	if err != nil {
		return nil, err
	}
	respPrefix, sendCipher, recvCipher, err := hs.Complete(fixedHdr.CipherSuite, respPlain)
	if err != nil {
		return nil, err
	}

	protoNow := opts.TimeFunc
	if protoNow == nil {
		if ctx != nil {
			protoNow = ResolveTimeFunc(ctx)
		} else {
			protoNow = time.Now
		}
	}
	hbInterval, pongTimeout := normalizeHeartbeat(opts.HeartbeatInterval)
	nowNs := time.Now().UnixNano()

	c := &Conn{
		rawConn:           rawConn,
		isClient:          false,
		disableShaping:    opts.DisableShaping,
		heartbeatInterval: hbInterval,
		pongTimeout:       pongTimeout,
		protoNow:          protoNow,
		sendCipher:        sendCipher,
		recvCipher:        recvCipher,
		serverRespPrefix:  respPrefix,
		readReadyCh:       make(chan struct{}, 1),
		readConsumedCh:    make(chan struct{}, 1),
		readDlKickCh:      make(chan struct{}, 1),
		pongCh:            make(chan struct{}, 1),
		doneCh:            make(chan struct{}),
	}
	c.handshakeWritten.Store(true)
	c.handshakeRead.Store(true)
	c.serverRespPending.Store(true)
	c.lastReadNs.Store(nowNs)
	c.lastWriteNs.Store(nowNs)

	if len(initialPayload) > 0 {
		c.setUnreadLocked(initialPayload)
	}
	// Clear any server handshake deadline applied to rawConn before launching background readLoop.
	_ = rawConn.SetReadDeadline(time.Time{})
	c.startCoordinator()
	c.startReadLoop()

	return &ServerAcceptResult{
		Conn:        c,
		Command:     fixedHdr.Command,
		CipherSuite: fixedHdr.CipherSuite,
		TargetAddr:  targetAddr,
		UserName:    hs.UserName,
		UserIndex:   hs.UserIndex,
	}, nil
}

func (c *Conn) startCoordinator() {
	c.coordMu.Lock()
	if !c.closed.Load() && !c.coordStarted {
		c.coordStarted = true
		c.coordDone = make(chan struct{})
		go c.coordinatorLoop()
	}
	c.coordMu.Unlock()
}

func (c *Conn) startReadLoop() {
	c.coordMu.Lock()
	if !c.closed.Load() && !c.readLoopStarted {
		c.readLoopStarted = true
		c.readLoopWg.Add(1)
		go c.readLoop()
	}
	c.coordMu.Unlock()
}

// NeedHandshakeForWrite reports whether ClientInitialBurst has not yet been written.
func (c *Conn) NeedHandshakeForWrite() bool {
	if !c.isClient {
		return false
	}
	return !c.handshakeWritten.Load()
}

// NeedHandshakeForRead reports whether the 84-byte ServerResponsePrefix has not yet been read.
func (c *Conn) NeedHandshakeForRead() bool {
	if !c.isClient {
		return false
	}
	return !c.handshakeRead.Load()
}

// NeedHandshake satisfies N.EarlyConn for sing-box EarlyWriter compatibility.
func (c *Conn) NeedHandshake() bool {
	return c.NeedHandshakeForWrite()
}

// FrontHeadroom reports per-frame encryption header headroom hint for sing/common/bufio.
func (c *Conn) FrontHeadroom() int {
	return EncryptedLengthSize + MinFramePlainSize
}

// RearHeadroom reports AEAD tag overhead hint for sing/common/bufio.
func (c *Conn) RearHeadroom() int {
	return AEADTagSize
}

// WriterMTU reports Aether's maximum unpadded data frame payload (16384B).
func (c *Conn) WriterMTU() int {
	return MaxFrameDataSize
}

// Upstream returns the underlying raw net.Conn.
func (c *Conn) Upstream() any {
	return c.rawConn
}

// ReaderReplaceable reports false so sing/common/bufio never bypasses Aether frame decryption.
func (c *Conn) ReaderReplaceable() bool {
	return false
}

// WriterReplaceable reports false so sing/common/bufio never bypasses Aether frame encryption.
func (c *Conn) WriterReplaceable() bool {
	return false
}

func (c *Conn) LocalAddr() net.Addr  { return c.rawConn.LocalAddr() }
func (c *Conn) RemoteAddr() net.Addr { return c.rawConn.RemoteAddr() }

// SetDeadline sets both read and write application deadlines.
func (c *Conn) SetDeadline(t time.Time) error {
	rErr := c.SetReadDeadline(t)
	wErr := c.SetWriteDeadline(t)
	if rErr != nil {
		return rErr
	}
	return wErr
}

// SetReadDeadline stores the read deadline; once readLoop owns rawConn reads, deadlines
// govern consumer waits in Read/ReadBuffer without cancelling background control-frame reads.
func (c *Conn) SetReadDeadline(t time.Time) error {
	c.readDlMu.Lock()
	c.appReadDeadline = t
	err := c.applyEffectiveReadDeadlineLocked()
	c.readDlMu.Unlock()
	if c.respKickCh != nil && !c.handshakeRead.Load() {
		select {
		case c.respKickCh <- struct{}{}:
		default:
		}
	}
	if c.readDlKickCh != nil {
		select {
		case c.readDlKickCh <- struct{}{}:
		default:
		}
	}
	return err
}

// SetWriteDeadline stores the isolated application write deadline without disturbing control writes.
func (c *Conn) SetWriteDeadline(t time.Time) error {
	if c.closed.Load() {
		return net.ErrClosed
	}
	c.writeDlMu.Lock()
	c.appWriteDeadline = t
	c.writeDlMu.Unlock()
	return nil
}

func (c *Conn) getAppWriteDeadline() time.Time {
	c.writeDlMu.Lock()
	dl := c.appWriteDeadline
	c.writeDlMu.Unlock()
	return dl
}

func (c *Conn) applyEffectiveReadDeadlineLocked() error {
	if c.isClient && !c.handshakeRead.Load() {
		return c.rawConn.SetReadDeadline(c.appReadDeadline)
	}
	return nil
}

func (c *Conn) controlWriteTimeout() time.Duration {
	if c.heartbeatInterval > 0 {
		t := c.pongTimeout
		if t < minControlWriteTimeout {
			t = minControlWriteTimeout
		}
		if t > maxControlWriteTimeout {
			t = maxControlWriteTimeout
		}
		return t
	}
	return maxControlWriteTimeout
}

// writeRawLocked serializes physical rawConn writes and atomically fuses writeBroken + closes rawConn
// on any write error or short write.
func (c *Conn) writeRawLocked(b []byte, deadline time.Time) error {
	c.rawWriteMu.Lock()
	defer c.rawWriteMu.Unlock()

	if c.closed.Load() || c.writeBroken.Load() {
		return net.ErrClosed
	}
	if !deadline.IsZero() {
		if !deadline.After(time.Now()) {
			c.writeBroken.Store(true)
			return os.ErrDeadlineExceeded
		}
		if err := c.rawConn.SetWriteDeadline(deadline); err != nil {
			c.writeBroken.Store(true)
			_ = c.closeInternal(false)
			return err
		}
	}

	n, err := c.rawConn.Write(b)
	if err == nil && n != len(b) {
		err = io.ErrShortWrite
	}
	if err != nil {
		c.writeBroken.Store(true)
		_ = c.closeInternal(false)
		return err
	}
	if !deadline.IsZero() {
		_ = c.rawConn.SetWriteDeadline(time.Time{})
	}
	c.lastWriteNs.Store(time.Now().UnixNano())
	return nil
}

// sendClientInitialBurst sends ClientPrefix || EncryptedVarHeader carrying up to
// MaxInitialPayloadLen bytes in one single *buf.Buffer rawConn.Write.
func (c *Conn) sendClientInitialBurst(initialData []byte, deadline time.Time) (int, error) {
	c.initBurstMu.Lock()
	defer c.initBurstMu.Unlock()

	if c.handshakeWritten.Load() {
		return 0, nil
	}
	if c.closed.Load() || c.writeBroken.Load() {
		return 0, net.ErrClosed
	}
	if !deadline.IsZero() && !deadline.After(time.Now()) {
		c.writeBroken.Store(true)
		return 0, os.ErrDeadlineExceeded
	}

	noiseLen, err := RandomNoiseLen()
	if err != nil {
		return 0, err
	}
	addrLen := M.SocksaddrSerializer.AddrPortLen(c.targetAddr)
	maxInit := MaxVarHeaderLen - noiseLen - addrLen
	if maxInit < 0 {
		return 0, ErrInvalidVarHeaderLen
	}
	initLen := len(initialData)
	if initLen > maxInit {
		initLen = maxInit
	}

	fh := FixedHeader{
		Version:      ProtocolVersion,
		Command:      c.command,
		CipherSuite:  c.cipherSuite,
		Reserved:     0,
		TimestampSec: c.protoNow().Unix(),
		NoiseLen:     uint16(noiseLen),
		VarHeaderLen: uint16(noiseLen + addrLen + initLen),
	}
	fixedPlain, err := EncodeFixedHeader(fh)
	if err != nil {
		return 0, err
	}

	hs, prefixBytes, err := StartClientHandshake(c.creds, c.serverPub, fixedPlain)
	if err != nil {
		return 0, err
	}

	varPlainBuf := buf.NewSize(int(fh.VarHeaderLen))
	defer varPlainBuf.Release()
	varPlainBuf.WriteRandom(noiseLen)
	if err := M.SocksaddrSerializer.WriteAddrPort(varPlainBuf, c.targetAddr); err != nil {
		return 0, err
	}
	if initLen > 0 {
		if _, err := varPlainBuf.Write(initialData[:initLen]); err != nil {
			return 0, err
		}
	}

	encVarLen := int(fh.VarHeaderLen) + AEADTagSize
	pkt := buf.NewSize(len(prefixBytes) + encVarLen)
	defer pkt.Release()
	if _, err := pkt.Write(prefixBytes); err != nil {
		return 0, err
	}
	sealedOut := pkt.Extend(encVarLen)
	sealed := hs.SealVarHeader(sealedOut[:0], varPlainBuf.Bytes())
	if len(sealed) != encVarLen {
		return 0, fmt.Errorf("aether: unexpected encrypted var header size %d != %d", len(sealed), encVarLen)
	}

	if err := c.writeRawLocked(pkt.Bytes(), deadline); err != nil {
		return 0, err
	}

	c.clientHS = hs
	c.lastReadNs.Store(time.Now().UnixNano())
	c.handshakeWritten.Store(true)
	c.markClientInitSent()
	if c.heartbeatInterval > 0 {
		c.startCoordinator()
	}
	return initLen, nil
}

func (c *Conn) notifyClientWriteStarting() {
	if c.writeStartCh == nil {
		return
	}
	c.writeStartOnce.Do(func() {
		close(c.writeStartCh)
	})
}

func (c *Conn) markClientInitSent() {
	c.notifyClientWriteStarting()
	if c.initSentCh == nil {
		return
	}
	c.initSentOnce.Do(func() {
		close(c.initSentCh)
	})
}

// waitOrFlushClientInitialBurst waits briefly (up to 25ms) for a concurrent application Write
// to supply 0-RTT InitialPayload (avoiding empty-burst races under sing-box route.ConnectionManager),
// aborting immediately if a Write begins or ReadDeadline is tight (<50ms), and flushing 0B otherwise.
func (c *Conn) waitOrFlushClientInitialBurst() error {
	if !c.isClient || c.handshakeWritten.Load() {
		return nil
	}

	c.readDlMu.Lock()
	appDl := c.appReadDeadline
	c.readDlMu.Unlock()

	if !appDl.IsZero() && !appDl.After(time.Now()) {
		return os.ErrDeadlineExceeded
	}

	skipGrace := !appDl.IsZero() && time.Until(appDl) < clientInitialBurstWaitSkip
	if !skipGrace {
		graceTimer := time.NewTimer(clientInitialBurstGrace)
		writeStarted := false
		select {
		case <-c.initSentCh:
			graceTimer.Stop()
			return nil
		case <-c.doneCh:
			graceTimer.Stop()
			return net.ErrClosed
		case <-c.writeStartCh:
			writeStarted = true
		case <-graceTimer.C:
		}
		graceTimer.Stop()

		if writeStarted && !c.handshakeWritten.Load() {
			fallbackTimer := time.NewTimer(clientWriteFlushWaitTimeout)
			select {
			case <-c.initSentCh:
				fallbackTimer.Stop()
				return nil
			case <-c.doneCh:
				fallbackTimer.Stop()
				return net.ErrClosed
			case <-fallbackTimer.C:
			}
			fallbackTimer.Stop()
		}
	}

	if c.handshakeWritten.Load() {
		return nil
	}
	c.readDlMu.Lock()
	curAppDl := c.appReadDeadline
	c.readDlMu.Unlock()
	if !curAppDl.IsZero() && !curAppDl.After(time.Now()) {
		return os.ErrDeadlineExceeded
	}
	_, err := c.sendClientInitialBurst(nil, time.Now().Add(c.controlWriteTimeout()))
	return err
}

func (c *Conn) closeRespDone() {
	if c.respDoneCh == nil {
		return
	}
	c.respDoneOnce.Do(func() {
		close(c.respDoneCh)
	})
}

func (c *Conn) startOrJoinRespAttempt() *respAttempt {
	c.respMu.Lock()
	defer c.respMu.Unlock()

	if c.handshakeRead.Load() || c.getReadErr() != nil || c.closed.Load() {
		return nil
	}
	if c.respCurrAttempt != nil {
		return c.respCurrAttempt
	}
	att := &respAttempt{done: make(chan struct{})}
	c.respCurrAttempt = att
	c.respWg.Add(1)
	go c.runRespReadAttempt(att)
	return att
}

func (c *Conn) runRespReadAttempt(att *respAttempt) {
	defer c.respWg.Done()
	defer close(att.done)

	for c.respOff < ServerRespPrefixSize {
		n, err := c.rawConn.Read(c.respBuf[c.respOff:ServerRespPrefixSize])
		if n > 0 {
			c.respOff += n
			if c.respOff >= ServerRespPrefixSize {
				if errors.Is(err, io.EOF) {
					c.pendingRawEOF.Store(true)
				}
				break
			}
		}
		if err != nil {
			if isTimeoutError(err) {
				att.timeoutErr = err
				c.respMu.Lock()
				if c.respCurrAttempt == att {
					c.respCurrAttempt = nil
				}
				c.respMu.Unlock()
				return
			}
			if errors.Is(err, io.EOF) {
				err = io.ErrUnexpectedEOF
			}
			c.setReadErr(err)
			_ = c.closeInternal(false)
			c.closeRespDone()
			return
		}
	}

	respPlain, sendCipher, recvCipher, err := c.clientHS.Complete(c.respBuf[:], c.cipherSuite)
	if err == nil {
		err = DecodeAndValidateRespHeader(respPlain[:], c.cipherSuite)
	}
	if err != nil {
		c.setReadErr(err)
		_ = c.closeInternal(false)
		c.closeRespDone()
		return
	}

	c.sendCipher = sendCipher
	c.recvCipher = recvCipher
	c.readDlMu.Lock()
	c.handshakeRead.Store(true)
	_ = c.rawConn.SetReadDeadline(time.Time{})
	c.readDlMu.Unlock()
	c.lastReadNs.Store(time.Now().UnixNano())
	c.closeRespDone()
	c.startCoordinator()
	c.startReadLoop()
}

// awaitServerRespForWrite waits for the 84-byte ServerResponsePrefix via respDoneCh while
// respecting dl without holding any mutex across rawConn.Read or mutating Read's deadline.
func (c *Conn) awaitServerRespForWrite(dl time.Time) error {
	if c.handshakeRead.Load() {
		return nil
	}
	if !dl.IsZero() && !dl.After(time.Now()) {
		c.writeBroken.Store(true)
		return os.ErrDeadlineExceeded
	}

	var timer *time.Timer
	var timerC <-chan time.Time
	if !dl.IsZero() {
		timer = time.NewTimer(time.Until(dl))
		timerC = timer.C
		defer timer.Stop()
	}

	for {
		if c.handshakeRead.Load() {
			return nil
		}
		if err := c.getReadErr(); err != nil {
			return err
		}
		if c.closed.Load() {
			return net.ErrClosed
		}
		att := c.startOrJoinRespAttempt()
		if att == nil {
			if !c.handshakeRead.Load() && c.getReadErr() == nil && !c.closed.Load() {
				return net.ErrClosed
			}
			continue
		}

		select {
		case <-c.respDoneCh:
			if c.handshakeRead.Load() {
				return nil
			}
			if err := c.getReadErr(); err != nil {
				return err
			}
			return net.ErrClosed
		case <-c.doneCh:
			return net.ErrClosed
		case <-timerC:
			c.writeBroken.Store(true)
			return os.ErrDeadlineExceeded
		case <-att.done:
			if c.handshakeRead.Load() || c.getReadErr() != nil || c.closed.Load() {
				continue
			}
			select {
			case <-c.respDoneCh:
			case <-c.doneCh:
				return net.ErrClosed
			case <-timerC:
				c.writeBroken.Store(true)
				return os.ErrDeadlineExceeded
			case <-c.respKickCh:
			}
		}
	}
}

func (c *Conn) getReadErr() error {
	c.readErrMu.Lock()
	err := c.readErr
	c.readErrMu.Unlock()
	return err
}

func (c *Conn) setReadErr(err error) {
	c.readErrMu.Lock()
	if c.readErr == nil {
		c.readErr = err
	}
	c.readErrMu.Unlock()
}

// ensureClientHandshakeRead joins the single-reader attempt to receive and open the 84-byte ServerResponsePrefix.
func (c *Conn) ensureClientHandshakeRead() error {
	for {
		if c.handshakeRead.Load() {
			return nil
		}
		if err := c.getReadErr(); err != nil {
			return err
		}
		if c.closed.Load() {
			return net.ErrClosed
		}
		att := c.startOrJoinRespAttempt()
		if att == nil {
			if c.handshakeRead.Load() {
				return nil
			}
			if err := c.getReadErr(); err != nil {
				return err
			}
			return net.ErrClosed
		}

		select {
		case <-c.respDoneCh:
			if c.handshakeRead.Load() {
				return nil
			}
			if err := c.getReadErr(); err != nil {
				return err
			}
			return net.ErrClosed
		case <-c.doneCh:
			return net.ErrClosed
		case <-att.done:
			if c.handshakeRead.Load() {
				return nil
			}
			if err := c.getReadErr(); err != nil {
				return err
			}
			if att.timeoutErr != nil {
				return att.timeoutErr
			}
		}
	}
}

// Write writes data over the encrypted Aether v2 session. On a fresh client connection,
// up to MaxInitialPayloadLen bytes coalesce with ClientPrefix + EncryptedVarHeader into a single write.
func (c *Conn) Write(p []byte) (int, error) {
	if c.closed.Load() || c.writeBroken.Load() || c.writeCloseSent.Load() {
		return 0, net.ErrClosed
	}
	if len(p) == 0 {
		return 0, nil
	}

	c.writeMu.Lock()
	defer c.writeMu.Unlock()

	if c.closed.Load() || c.writeBroken.Load() || c.writeCloseSent.Load() {
		return 0, net.ErrClosed
	}

	dl := c.getAppWriteDeadline()
	if !dl.IsZero() && !dl.After(time.Now()) {
		c.writeBroken.Store(true)
		return 0, os.ErrDeadlineExceeded
	}

	totalWritten := 0
	remaining := p

	if c.isClient && !c.handshakeWritten.Load() {
		c.notifyClientWriteStarting()
		initSent, err := c.sendClientInitialBurst(remaining, dl)
		if err != nil {
			return totalWritten, err
		}
		totalWritten += initSent
		remaining = remaining[initSent:]
		if len(remaining) == 0 {
			return totalWritten, nil
		}
	}

	if c.isClient && !c.handshakeRead.Load() {
		if err := c.awaitServerRespForWrite(dl); err != nil {
			return totalWritten, err
		}
	}

	for len(remaining) > 0 {
		if !dl.IsZero() && !dl.After(time.Now()) {
			c.writeBroken.Store(true)
			return totalWritten, os.ErrDeadlineExceeded
		}
		chunkLen, err := c.writeOneDataFrameLocked(remaining, dl)
		if err != nil {
			return totalWritten, err
		}
		totalWritten += chunkLen
		remaining = remaining[chunkLen:]
	}
	return totalWritten, nil
}

// WriteBuffer writes buffer's bytes to Conn and unconditionally releases buffer on every return path.
func (c *Conn) WriteBuffer(buffer *buf.Buffer) error {
	if buffer != nil {
		defer buffer.Release()
	}
	if c.closed.Load() || c.writeBroken.Load() || c.writeCloseSent.Load() {
		return net.ErrClosed
	}
	if buffer == nil || buffer.Len() == 0 {
		return nil
	}
	_, err := c.Write(buffer.Bytes())
	return err
}

func (c *Conn) writeOneDataFrameLocked(remaining []byte, deadline time.Time) (int, error) {
	chunkLen, padLen, err := NextDataChunk(len(remaining), c.sendFrameIdx, c.disableShaping)
	if err != nil {
		return 0, err
	}
	if err := c.writeSealedFrameLocked(FrameData, padLen, remaining[:chunkLen], deadline); err != nil {
		return 0, err
	}
	c.sendFrameIdx++
	return chunkLen, nil
}

func (c *Conn) writeSealedFrameLocked(frameType uint8, padLen uint8, data []byte, deadline time.Time) error {
	plainBody, err := AppendFrameBody(c.writePlainScratch[:0], frameType, padLen, data)
	if err != nil {
		return err
	}
	c.writePlainScratch = plainBody[:0]

	hdrPrefixLen := 0
	if c.serverRespPending.Load() {
		hdrPrefixLen = ServerRespPrefixSize
	}
	wireFrameLen := EncryptedLengthSize + len(plainBody) + AEADTagSize

	pkt := buf.NewSize(hdrPrefixLen + wireFrameLen)
	defer pkt.Release()

	if hdrPrefixLen > 0 {
		if _, err := pkt.Write(c.serverRespPrefix[:]); err != nil {
			return err
		}
	}
	frameOut := pkt.Extend(wireFrameLen)
	sealed, err := c.sendCipher.SealFrame(frameOut[:0], plainBody)
	if err != nil {
		c.writeBroken.Store(true)
		_ = c.closeInternal(false)
		return err
	}
	if len(sealed) != wireFrameLen {
		return fmt.Errorf("aether: unexpected sealed frame length %d != %d", len(sealed), wireFrameLen)
	}

	if err := c.writeRawLocked(pkt.Bytes(), deadline); err != nil {
		return err
	}
	if hdrPrefixLen > 0 {
		c.serverRespPending.Store(false)
	}
	return nil
}

func (c *Conn) sendControlFrame(frameType uint8) error {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()

	if c.closed.Load() || c.writeBroken.Load() {
		return net.ErrClosed
	}

	var padLen uint8
	if frameType == FramePing || frameType == FramePong {
		var err error
		padLen, err = RandomPingPadLen()
		if err != nil {
			return err
		}
	}
	ctrlDeadline := time.Now().Add(c.controlWriteTimeout())
	return c.writeSealedFrameLocked(frameType, padLen, nil, ctrlDeadline)
}

// CloseWrite half-closes the outbound Aether stream by sending a FrameCloseWrite
// while leaving the inbound read path active.
func (c *Conn) CloseWrite() error {
	if c.closed.Load() || c.writeBroken.Load() {
		return net.ErrClosed
	}

	c.writeMu.Lock()
	defer c.writeMu.Unlock()

	if c.closed.Load() || c.writeBroken.Load() {
		return net.ErrClosed
	}
	if c.writeCloseSent.Load() {
		return nil
	}

	ctrlDeadline := time.Now().Add(c.controlWriteTimeout())
	if c.isClient && !c.handshakeWritten.Load() {
		c.notifyClientWriteStarting()
		if _, err := c.sendClientInitialBurst(nil, ctrlDeadline); err != nil {
			return err
		}
	}
	if c.isClient && !c.handshakeRead.Load() {
		if err := c.awaitServerRespForWrite(ctrlDeadline); err != nil {
			return err
		}
	}

	var padLen uint8
	shapingCloseWrite := !c.disableShaping && c.sendFrameIdx < ShapingFrameLimit
	if shapingCloseWrite {
		p, err := cryptoRandRange(ShapingPadMin, ShapingPadMax)
		if err != nil {
			return err
		}
		padLen = uint8(p)
	}
	if err := c.writeSealedFrameLocked(FrameCloseWrite, padLen, nil, ctrlDeadline); err != nil {
		return err
	}
	if shapingCloseWrite {
		c.sendFrameIdx++
	}
	c.writeCloseSent.Store(true)
	return nil
}

// Read decrypts application data frames from the peer, briefly waiting (25ms) for any concurrent Write
// to supply 0-RTT InitialPayload before flushing a 0-byte Client Initial Burst (server-speaks-first)
// and skipping 0-byte chaff frames.
func (c *Conn) Read(p []byte) (int, error) {
	if c.userClosed.Load() {
		return 0, net.ErrClosed
	}
	if len(p) == 0 {
		return 0, nil
	}

	if c.isClient && !c.handshakeWritten.Load() {
		if err := c.waitOrFlushClientInitialBurst(); err != nil {
			return 0, err
		}
	}
	if c.isClient && !c.handshakeRead.Load() {
		if err := c.ensureClientHandshakeRead(); err != nil {
			return 0, err
		}
	}

	c.readMu.Lock()
	defer c.readMu.Unlock()

	if err := c.ensureUnreadDataLocked(); err != nil {
		return 0, err
	}
	c.readStateMu.Lock()
	n := copy(p, c.unreadBuf[c.unreadOff:c.unreadEnd])
	c.unreadOff += n
	drained := c.unreadOff >= c.unreadEnd
	c.readStateMu.Unlock()
	if drained {
		c.notifyReadConsumed()
	}
	return n, nil
}

// ReadBuffer fills up to buffer.FreeLen() decrypted bytes into buffer without ever calling buffer.Release().
func (c *Conn) ReadBuffer(buffer *buf.Buffer) error {
	if c.userClosed.Load() {
		return net.ErrClosed
	}
	if buffer == nil || buffer.FreeLen() <= 0 {
		return io.ErrShortBuffer
	}

	if c.isClient && !c.handshakeWritten.Load() {
		if err := c.waitOrFlushClientInitialBurst(); err != nil {
			return err
		}
	}
	if c.isClient && !c.handshakeRead.Load() {
		if err := c.ensureClientHandshakeRead(); err != nil {
			return err
		}
	}

	c.readMu.Lock()
	defer c.readMu.Unlock()

	if err := c.ensureUnreadDataLocked(); err != nil {
		return err
	}
	c.readStateMu.Lock()
	src := c.unreadBuf[c.unreadOff:c.unreadEnd]
	avail := buffer.FreeLen()
	if len(src) > avail {
		src = src[:avail]
	}
	n, err := buffer.Write(src)
	c.unreadOff += n
	drained := c.unreadOff >= c.unreadEnd
	c.readStateMu.Unlock()
	if drained {
		c.notifyReadConsumed()
	}
	return err
}

func (c *Conn) setUnreadLocked(data []byte) {
	if len(data) == 0 {
		return
	}
	if cap(c.unreadBuf) < len(data) {
		allocSize := MaxFrameDataSize
		if len(data) > allocSize {
			allocSize = len(data)
		}
		c.unreadBuf = make([]byte, allocSize)
	}
	copy(c.unreadBuf[:len(data)], data)
	c.unreadOff = 0
	c.unreadEnd = len(data)
}

func (c *Conn) notifyReadReady() {
	if c.readReadyCh == nil {
		return
	}
	select {
	case c.readReadyCh <- struct{}{}:
	default:
	}
}

func (c *Conn) notifyReadConsumed() {
	if c.readConsumedCh == nil {
		return
	}
	select {
	case c.readConsumedCh <- struct{}{}:
	default:
	}
}

func (c *Conn) deliverReadData(data []byte) bool {
	for {
		if c.closed.Load() {
			return false
		}
		c.readStateMu.Lock()
		if c.unreadEnd <= c.unreadOff {
			c.setUnreadLocked(data)
			c.readStateMu.Unlock()
			c.notifyReadReady()
			return true
		}
		c.readStateMu.Unlock()

		select {
		case <-c.readConsumedCh:
		case <-c.doneCh:
			return false
		}
	}
}

func (c *Conn) ensureUnreadDataLocked() error {
	var dlTimer *time.Timer
	defer func() {
		if dlTimer != nil {
			dlTimer.Stop()
		}
	}()

	for {
		c.readStateMu.Lock()
		hasData := c.unreadEnd > c.unreadOff
		c.readStateMu.Unlock()
		if hasData {
			return nil
		}
		if c.userClosed.Load() {
			return net.ErrClosed
		}
		if c.readEOF.Load() {
			return io.EOF
		}
		if err := c.getReadErr(); err != nil {
			return err
		}
		if c.closed.Load() {
			return net.ErrClosed
		}

		c.readDlMu.Lock()
		dl := c.appReadDeadline
		c.readDlMu.Unlock()

		var timerC <-chan time.Time
		if !dl.IsZero() {
			rem := time.Until(dl)
			if rem <= 0 {
				return os.ErrDeadlineExceeded
			}
			if dlTimer == nil {
				dlTimer = time.NewTimer(rem)
			} else {
				if !dlTimer.Stop() {
					select {
					case <-dlTimer.C:
					default:
					}
				}
				dlTimer.Reset(rem)
			}
			timerC = dlTimer.C
		} else if dlTimer != nil {
			if !dlTimer.Stop() {
				select {
				case <-dlTimer.C:
				default:
				}
			}
			timerC = nil
		}

		select {
		case <-c.readReadyCh:
		case <-c.readDlKickCh:
		case <-c.doneCh:
		case <-timerC:
			return os.ErrDeadlineExceeded
		}
	}
}

// readLoop continuously reads and decrypts inbound frames from rawConn once handshakeRead is true,
// keeping control-plane Ping/Pong and DPD lastReadNs active even when no caller is inside Read/ReadBuffer.
func (c *Conn) readLoop() {
	defer c.readLoopWg.Done()

	for {
		if c.closed.Load() {
			c.notifyReadReady()
			return
		}
		if c.pendingRawEOF.Load() && !c.bodyHdrReady && c.lenHdrOff == 0 {
			c.readEOF.Store(true)
			c.notifyReadReady()
			return
		}

		if !c.bodyHdrReady {
			for c.lenHdrOff < EncryptedLengthSize {
				n, err := c.rawConn.Read(c.lenHdrBuf[c.lenHdrOff:])
				if n > 0 {
					c.lenHdrOff += n
					if c.lenHdrOff >= EncryptedLengthSize {
						if errors.Is(err, io.EOF) {
							c.pendingRawEOF.Store(true)
						}
						break
					}
				}
				if err != nil {
					if errors.Is(err, io.EOF) && c.lenHdrOff == 0 {
						c.readEOF.Store(true)
						c.notifyReadReady()
						return
					}
					if errors.Is(err, io.EOF) {
						err = io.ErrUnexpectedEOF
					}
					c.setReadErr(err)
					_ = c.closeInternal(false)
					c.notifyReadReady()
					return
				}
			}

			plainLen, err := c.recvCipher.OpenLengthHeader(c.lenHdrBuf[:])
			if err != nil {
				c.setReadErr(err)
				_ = c.closeInternal(false)
				c.notifyReadReady()
				return
			}
			c.lenHdrOff = 0
			c.bodyExpectedPlainLen = plainLen
			c.bodyOff = 0
			c.bodyHdrReady = true
		}

		encBodyLen := int(c.bodyExpectedPlainLen) + AEADTagSize
		if cap(c.bodyBuf) < encBodyLen {
			allocCap := MaxFramePlainSize + AEADTagSize
			if encBodyLen > allocCap {
				allocCap = encBodyLen
			}
			c.bodyBuf = make([]byte, encBodyLen, allocCap)
		} else {
			c.bodyBuf = c.bodyBuf[:encBodyLen]
		}

		for c.bodyOff < encBodyLen {
			n, err := c.rawConn.Read(c.bodyBuf[c.bodyOff:encBodyLen])
			if n > 0 {
				c.bodyOff += n
				if c.bodyOff >= encBodyLen {
					if errors.Is(err, io.EOF) {
						c.pendingRawEOF.Store(true)
					}
					break
				}
			}
			if err != nil {
				if errors.Is(err, io.EOF) {
					err = io.ErrUnexpectedEOF
				}
				c.setReadErr(err)
				_ = c.closeInternal(false)
				c.notifyReadReady()
				return
			}
		}
		c.bodyHdrReady = false
		c.bodyOff = 0

		if cap(c.readPlainScratch) < int(c.bodyExpectedPlainLen) {
			c.readPlainScratch = make([]byte, 0, MaxFramePlainSize)
		}
		plainBody, err := c.recvCipher.OpenPayloadBody(c.readPlainScratch[:0], c.bodyBuf[:encBodyLen])
		if err != nil {
			c.setReadErr(err)
			_ = c.closeInternal(false)
			c.notifyReadReady()
			return
		}

		frameType, data, err := ParseFrameBody(plainBody)
		if err != nil {
			c.setReadErr(err)
			_ = c.closeInternal(false)
			c.notifyReadReady()
			return
		}
		c.lastReadNs.Store(time.Now().UnixNano())

		switch frameType {
		case FrameData:
			if len(data) == 0 {
				c.readPlainScratch = plainBody[:0]
				continue
			}
			if c.readEOF.Load() {
				c.readPlainScratch = plainBody[:0]
				c.setReadErr(fmt.Errorf("%w: unexpected data frame after close_write", ErrInvalidFrameType))
				_ = c.closeInternal(false)
				c.notifyReadReady()
				return
			}
			if !c.deliverReadData(data) {
				c.readPlainScratch = plainBody[:0]
				return
			}
			c.readPlainScratch = plainBody[:0]
		case FramePing:
			c.readPlainScratch = plainBody[:0]
			select {
			case c.pongCh <- struct{}{}:
			default:
			}
		case FramePong:
			c.readPlainScratch = plainBody[:0]
		case FrameCloseWrite:
			c.readPlainScratch = plainBody[:0]
			c.readEOF.Store(true)
			c.notifyReadReady()
		}
	}
}

func (c *Conn) sendPendingServerRespControl() error {
	if !c.serverRespPending.Load() || c.closed.Load() || c.writeBroken.Load() {
		return nil
	}
	c.writeMu.Lock()
	defer c.writeMu.Unlock()

	if !c.serverRespPending.Load() || c.closed.Load() || c.writeBroken.Load() {
		return nil
	}
	ctrlDeadline := time.Now().Add(c.controlWriteTimeout())
	if c.heartbeatInterval > 0 {
		padLen, err := RandomPingPadLen()
		if err != nil {
			return err
		}
		return c.writeSealedFrameLocked(FramePing, padLen, nil, ctrlDeadline)
	}
	var padLen uint8
	if !c.disableShaping && c.sendFrameIdx < ShapingFrameLimit {
		p, err := cryptoRandRange(ShapingPadMin, ShapingPadMax)
		if err != nil {
			return err
		}
		padLen = uint8(p)
	}
	if err := c.writeSealedFrameLocked(FrameData, padLen, nil, ctrlDeadline); err != nil {
		return err
	}
	c.sendFrameIdx++
	return nil
}

func (c *Conn) coordinatorLoop() {
	defer close(c.coordDone)

	var respFlushTimer *time.Timer
	var respFlushC <-chan time.Time
	if !c.isClient && c.serverRespPending.Load() {
		respFlushTimer = time.NewTimer(pendingServerRespFlushDelay)
		respFlushC = respFlushTimer.C
		defer respFlushTimer.Stop()
	}

	if c.heartbeatInterval <= 0 {
		for {
			select {
			case <-c.doneCh:
				return
			case <-c.pongCh:
				if c.closed.Load() || c.writeBroken.Load() {
					return
				}
				if err := c.sendControlFrame(FramePong); err != nil {
					return
				}
			case <-respFlushC:
				respFlushC = nil
				if c.closed.Load() || c.writeBroken.Load() {
					return
				}
				if err := c.sendPendingServerRespControl(); err != nil {
					return
				}
			}
		}
	}

	jitterTarget, err := nextHeartbeatJitter(c.heartbeatInterval)
	if err != nil {
		jitterTarget = c.heartbeatInterval
	}
	var pingOutstanding bool
	var handshakeWaitOutstanding bool
	var baselineLastReadNs int64

	timer := time.NewTimer(jitterTarget)
	defer timer.Stop()

	resetTimer := func(d time.Duration) {
		if d < time.Millisecond {
			d = time.Millisecond
		}
		if !timer.Stop() {
			select {
			case <-timer.C:
			default:
			}
		}
		timer.Reset(d)
	}

	for {
		select {
		case <-c.doneCh:
			return
		case <-c.pongCh:
			if c.closed.Load() || c.writeBroken.Load() {
				return
			}
			if c.isClient && !c.handshakeRead.Load() {
				continue
			}
			if err := c.sendControlFrame(FramePong); err != nil {
				return
			}
		case <-respFlushC:
			respFlushC = nil
			if c.closed.Load() || c.writeBroken.Load() {
				return
			}
			if err := c.sendPendingServerRespControl(); err != nil {
				return
			}
		case <-timer.C:
			if c.closed.Load() || c.writeBroken.Load() {
				return
			}
			select {
			case <-c.pongCh:
				if !c.isClient || c.handshakeRead.Load() {
					if err := c.sendControlFrame(FramePong); err != nil {
						return
					}
				}
			default:
			}
			if c.readEOF.Load() {
				resetTimer(c.heartbeatInterval)
				continue
			}

			now := time.Now()
			lastRead := c.lastReadNs.Load()

			if c.isClient && !c.handshakeRead.Load() {
				if handshakeWaitOutstanding {
					_ = c.closeInternal(false)
					return
				}
				elapsed := now.Sub(time.Unix(0, lastRead))
				if elapsed < jitterTarget {
					resetTimer(jitterTarget - elapsed)
					continue
				}
				handshakeWaitOutstanding = true
				resetTimer(c.pongTimeout)
				continue
			}

			if handshakeWaitOutstanding {
				handshakeWaitOutstanding = false
				jitterTarget, err = nextHeartbeatJitter(c.heartbeatInterval)
				if err != nil {
					jitterTarget = c.heartbeatInterval
				}
				elapsed := now.Sub(time.Unix(0, lastRead))
				if elapsed < jitterTarget {
					resetTimer(jitterTarget - elapsed)
				} else {
					resetTimer(time.Millisecond)
				}
				continue
			}

			if pingOutstanding {
				if lastRead > baselineLastReadNs {
					pingOutstanding = false
					jitterTarget, err = nextHeartbeatJitter(c.heartbeatInterval)
					if err != nil {
						jitterTarget = c.heartbeatInterval
					}
					elapsed := now.Sub(time.Unix(0, lastRead))
					if elapsed < jitterTarget {
						resetTimer(jitterTarget - elapsed)
					} else {
						resetTimer(time.Millisecond)
					}
					continue
				}
				_ = c.closeInternal(false)
				return
			}

			elapsed := now.Sub(time.Unix(0, lastRead))
			if elapsed < jitterTarget {
				resetTimer(jitterTarget - elapsed)
				continue
			}

			baselineLastReadNs = lastRead
			if err := c.sendControlFrame(FramePing); err != nil {
				return
			}
			pingOutstanding = true
			resetTimer(c.pongTimeout)
		}
	}
}

func nextHeartbeatJitter(interval time.Duration) (time.Duration, error) {
	if interval <= 0 {
		return 0, nil
	}
	minD := (interval * 3) / 4
	maxD := (interval * 5) / 4
	if minD < time.Millisecond {
		minD = time.Millisecond
	}
	if maxD <= minD {
		return minD, nil
	}
	span := int(maxD - minD)
	offset, err := cryptoRandRange(0, span)
	if err != nil {
		return interval, err
	}
	return minD + time.Duration(offset), nil
}

func isTimeoutError(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, os.ErrDeadlineExceeded) {
		return true
	}
	var ne net.Error
	return errors.As(err, &ne) && ne.Timeout()
}

// Close shuts down the Aether connection, closes rawConn, and waits for any background goroutines to exit.
func (c *Conn) Close() error {
	c.userClosed.Store(true)
	return c.closeInternal(true)
}

func (c *Conn) closeInternal(wait bool) error {
	var err error
	c.closeOnce.Do(func() {
		c.closed.Store(true)
		c.writeBroken.Store(true)
		close(c.doneCh)
		err = c.rawConn.Close()
	})
	if wait {
		c.coordMu.Lock()
		done := c.coordDone
		c.coordMu.Unlock()
		if done != nil {
			<-done
		}
		c.respMu.Lock()
		c.respMu.Unlock()
		c.respWg.Wait()
		c.readLoopWg.Wait()
	}
	return err
}
