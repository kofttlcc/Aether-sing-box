package aether

import (
	"context"
	"crypto/rand"
	"errors"
	"io"
	"math/big"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing/common/logger"
)

const (
	// DefaultHandshakeTimeout caps unauthenticated handshake reads so slowloris probes cannot pin handshake slots indefinitely.
	DefaultHandshakeTimeout = 6 * time.Second
	// DefaultHandshakeLimit bounds concurrent in-flight handshakes.
	DefaultHandshakeLimit = 256
	// DefaultDrainLimit bounds concurrent StealthDrain goroutines.
	DefaultDrainLimit = 512
	// MinDrainDuration and MaxDrainDuration bound uniform randomized anti-probing drains.
	MinDrainDuration = 3 * time.Second
	MaxDrainDuration = 10 * time.Second
	// DefaultLogRateInterval throttles probe rejection warnings per source IP.
	DefaultLogRateInterval = 10 * time.Second

	maxWarnMapEntries = 4096
)

const (
	ReasonAuthFailed = "auth_failed"
	ReasonReplay     = "replay"
	ReasonClockSkew  = "clock_skew"
	ReasonTimeout    = "timeout"
	ReasonMalformed  = "malformed"
)

const prefixReadErrPrefix = "aether: read client handshake prefix:"

// DrainGuardOptions configures concurrency limits, stealth drain timing, and logging for DrainGuard.
type DrainGuardOptions struct {
	HandshakeLimit int
	DrainLimit     int
	MinDrain       time.Duration
	MaxDrain       time.Duration
	LogInterval    time.Duration
	Logger         logger.ContextLogger
	NowFunc        func() time.Time
	RandInt64      func(maxExclusive int64) (int64, error)
}

// DrainGuard enforces bounded handshake and stealth-drain concurrency along with
// per-source-IP rate-limited logging for Aether inbound handshakes.
type DrainGuard struct {
	handshakeSem chan struct{}
	drainSem     chan struct{}
	minDrain     time.Duration
	maxDrain     time.Duration
	logInterval  time.Duration
	logger       logger.ContextLogger
	nowFunc      func() time.Time
	randInt64    func(maxExclusive int64) (int64, error)

	warnMu   sync.Mutex
	warnLast map[string]time.Time
}

// NewDrainGuard creates a DrainGuard with Aether v2 defaults for unset options.
func NewDrainGuard(opts DrainGuardOptions) *DrainGuard {
	hsLimit := opts.HandshakeLimit
	if hsLimit <= 0 {
		hsLimit = DefaultHandshakeLimit
	}
	drainLimit := opts.DrainLimit
	if drainLimit <= 0 {
		drainLimit = DefaultDrainLimit
	}
	minDrain := opts.MinDrain
	if minDrain <= 0 {
		minDrain = MinDrainDuration
	}
	maxDrain := opts.MaxDrain
	if maxDrain < minDrain {
		maxDrain = MaxDrainDuration
		if maxDrain < minDrain {
			maxDrain = minDrain
		}
	}
	logInterval := opts.LogInterval
	if logInterval <= 0 {
		logInterval = DefaultLogRateInterval
	}
	nowFunc := opts.NowFunc
	if nowFunc == nil {
		nowFunc = time.Now
	}
	randFunc := opts.RandInt64
	if randFunc == nil {
		randFunc = cryptoRandInt64
	}
	return &DrainGuard{
		handshakeSem: make(chan struct{}, hsLimit),
		drainSem:     make(chan struct{}, drainLimit),
		minDrain:     minDrain,
		maxDrain:     maxDrain,
		logInterval:  logInterval,
		logger:       opts.Logger,
		nowFunc:      nowFunc,
		randInt64:    randFunc,
		warnLast:     make(map[string]time.Time),
	}
}

func cryptoRandInt64(maxExclusive int64) (int64, error) {
	if maxExclusive <= 0 {
		return 0, nil
	}
	n, err := rand.Int(rand.Reader, big.NewInt(maxExclusive))
	if err != nil {
		return 0, err
	}
	return n.Int64(), nil
}

// AcquireHandshake blocks until a handshake slot is acquired or ctx is canceled,
// returning an idempotent release function that frees the slot at most once.
func (g *DrainGuard) AcquireHandshake(ctx context.Context) (release func(), ok bool) {
	select {
	case g.handshakeSem <- struct{}{}:
		return g.newHandshakeRelease(), true
	case <-ctx.Done():
		return func() {}, false
	}
}

// TryAcquireHandshake attempts to acquire a handshake slot without blocking.
func (g *DrainGuard) TryAcquireHandshake() (release func(), ok bool) {
	select {
	case g.handshakeSem <- struct{}{}:
		return g.newHandshakeRelease(), true
	default:
		return func() {}, false
	}
}

func (g *DrainGuard) newHandshakeRelease() func() {
	var once sync.Once
	return func() {
		once.Do(func() {
			<-g.handshakeSem
		})
	}
}

// HandshakeInFlight reports the current number of occupied handshake slots.
func (g *DrainGuard) HandshakeInFlight() int {
	return len(g.handshakeSem)
}

// DrainInFlight reports the current number of active StealthDrain slots.
func (g *DrainGuard) DrainInFlight() int {
	return len(g.drainSem)
}

// ClassifyHandshakeFailure categorizes an AcceptServerConn failure and decides
// whether the connection should undergo StealthDrain (true) or close cleanly
// with TCP FIN immediately (false, for slowloris timeout / truncated prefix EOF).
func ClassifyHandshakeFailure(err error) (reason string, shouldDrain bool) {
	if err == nil {
		return "", false
	}
	switch {
	case errors.Is(err, ErrAuthenticationFailed),
		errors.Is(err, ErrLowOrderX25519Point),
		errors.Is(err, ErrInvalidSharedSecret),
		errors.Is(err, ErrInvalidX25519Key):
		return ReasonAuthFailed, true
	case errors.Is(err, ErrSaltReplayed):
		return ReasonReplay, true
	case errors.Is(err, ErrTimestampOutOfWindow):
		return ReasonClockSkew, true
	case errors.Is(err, ErrInvalidVersion),
		errors.Is(err, ErrInvalidCommand),
		errors.Is(err, ErrUnsupportedCipherSuite),
		errors.Is(err, ErrInvalidReserved),
		errors.Is(err, ErrInvalidNoiseLength),
		errors.Is(err, ErrInvalidVarHeaderLen),
		errors.Is(err, ErrInvalidVarHeader),
		errors.Is(err, ErrInvalidRespHeader),
		errors.Is(err, ErrInvalidFrameLength),
		errors.Is(err, ErrMalformedControlFrame):
		return ReasonMalformed, true
	}

	if isTimeoutError(err) {
		return ReasonTimeout, false
	}

	// Slowloris/truncated client prefixes (<96B / <112B) that close before the
	// fixed prefix finishes wrap prefix read I/O errors with prefixReadErrPrefix.
	if strings.Contains(err.Error(), prefixReadErrPrefix) &&
		(errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF)) {
		return ReasonTimeout, false
	}

	// Post-prefix wire/header errors (such as corrupted/truncated encrypted VarHeader)
	// undergo StealthDrain so probe timing does not leak which header stage failed.
	return ReasonMalformed, true
}

// StealthDrain sheds or quietly drains an invalid connection over a uniform random
// [3s, 10s] window before closing cleanly with TCP FIN (never RST). Callers must
// release handshakeSem before calling StealthDrain.
func (g *DrainGuard) StealthDrain(
	ctx context.Context,
	conn net.Conn,
	sourceIP string,
	reason string,
	cause error,
	onClose func(error),
) {
	g.logWarnRateLimited(ctx, sourceIP, reason, cause)

	if conn == nil {
		if onClose != nil {
			onClose(cause)
		}
		return
	}

	select {
	case g.drainSem <- struct{}{}:
		defer func() { <-g.drainSem }()
	default:
		// Shed overflow drains cleanly with TCP FIN so drain floods cannot
		// starve legitimate handshakes or trigger RST signatures.
		_ = conn.Close()
		if onClose != nil {
			onClose(cause)
		}
		return
	}

	if ctx != nil && ctx.Done() != nil {
		stopWatch := context.AfterFunc(ctx, func() {
			_ = conn.Close()
		})
		defer stopWatch()
	}

	drainDur := g.randomDrainDuration()
	wallStart := time.Now()
	_ = conn.SetReadDeadline(g.nowFunc().Add(drainDur))
	_, copyErr := io.Copy(io.Discard, conn)
	if copyErr == nil {
		// Peer half-closed (TCP FIN) before drainDur elapsed; hold the socket open for
		// the remaining drain window so early FIN does not create a timing side channel.
		if remaining := drainDur - time.Since(wallStart); remaining > 0 {
			timer := time.NewTimer(remaining)
			if ctx != nil && ctx.Done() != nil {
				select {
				case <-timer.C:
				case <-ctx.Done():
				}
			} else {
				<-timer.C
			}
			timer.Stop()
		}
	}
	_ = conn.Close()
	if onClose != nil {
		onClose(cause)
	}
}

// CloseTimeout rate-limits the warning log and closes conn cleanly with TCP FIN
// (never RST / CloseOnHandshakeFailure) before invoking onClose.
func (g *DrainGuard) CloseTimeout(
	ctx context.Context,
	conn net.Conn,
	sourceIP string,
	reason string,
	cause error,
	onClose func(error),
) {
	if reason == "" {
		reason = ReasonTimeout
	}
	g.logWarnRateLimited(ctx, sourceIP, reason, cause)
	if conn != nil {
		_ = conn.Close()
	}
	if onClose != nil {
		onClose(cause)
	}
}

func (g *DrainGuard) randomDrainDuration() time.Duration {
	span := int64(g.maxDrain - g.minDrain)
	if span <= 0 {
		return g.minDrain
	}
	offset, err := g.randInt64(span + 1)
	if err != nil || offset < 0 {
		return g.minDrain
	}
	if offset > span {
		offset = span
	}
	return g.minDrain + time.Duration(offset)
}

func (g *DrainGuard) logWarnRateLimited(ctx context.Context, sourceIP, reason string, cause error) {
	if g.logger == nil {
		return
	}
	if sourceIP == "" {
		sourceIP = "unknown"
	}
	if reason == "" {
		reason = ReasonMalformed
	}

	now := g.nowFunc()
	allowed := false

	g.warnMu.Lock()
	if len(g.warnLast) >= maxWarnMapEntries {
		for k, ts := range g.warnLast {
			if now.Sub(ts) >= g.logInterval {
				delete(g.warnLast, k)
			}
		}
		if len(g.warnLast) >= maxWarnMapEntries {
			clear(g.warnLast)
		}
	}
	last, exists := g.warnLast[sourceIP]
	if !exists || now.Sub(last) >= g.logInterval {
		g.warnLast[sourceIP] = now
		allowed = true
	}
	g.warnMu.Unlock()

	if !allowed {
		return
	}
	g.logger.WarnContext(ctx, "aether inbound probe rejected (", reason, ") from ", sourceIP, ": ", cause)
}

func normalizeSourceIP(conn net.Conn, metadata adapter.InboundContext) string {
	if metadata.Source.Addr.IsValid() {
		return metadata.Source.Addr.Unmap().String()
	}
	if metadata.Source.Fqdn != "" {
		return metadata.Source.Fqdn
	}
	if conn != nil && conn.RemoteAddr() != nil {
		raw := conn.RemoteAddr().String()
		if host, _, err := net.SplitHostPort(raw); err == nil && host != "" {
			return host
		}
		return raw
	}
	return "unknown"
}
