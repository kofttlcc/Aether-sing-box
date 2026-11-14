package aether

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/json/badoption"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/stretchr/testify/require"
)

type recordingLogger struct {
	mu    sync.Mutex
	warns []string
	infos []string
}

func (l *recordingLogger) Trace(...any)                         {}
func (l *recordingLogger) Debug(...any)                         {}
func (l *recordingLogger) Info(args ...any)                     { l.appendInfo(args...) }
func (l *recordingLogger) Warn(args ...any)                     { l.appendWarn(args...) }
func (l *recordingLogger) Error(...any)                         {}
func (l *recordingLogger) Fatal(...any)                         {}
func (l *recordingLogger) Panic(...any)                         {}
func (l *recordingLogger) TraceContext(context.Context, ...any) {}
func (l *recordingLogger) DebugContext(context.Context, ...any) {}
func (l *recordingLogger) InfoContext(_ context.Context, args ...any) {
	l.appendInfo(args...)
}
func (l *recordingLogger) WarnContext(_ context.Context, args ...any) {
	l.appendWarn(args...)
}
func (l *recordingLogger) ErrorContext(context.Context, ...any) {}
func (l *recordingLogger) FatalContext(context.Context, ...any) {}
func (l *recordingLogger) PanicContext(context.Context, ...any) {}

func (l *recordingLogger) appendWarn(args ...any) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.warns = append(l.warns, fmt.Sprint(args...))
}

func (l *recordingLogger) appendInfo(args ...any) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.infos = append(l.infos, fmt.Sprint(args...))
}

func (l *recordingLogger) warnMessages() []string {
	l.mu.Lock()
	defer l.mu.Unlock()
	out := make([]string, len(l.warns))
	copy(out, l.warns)
	return out
}

type noopMockRouter struct {
	adapter.Router
}

func (r *noopMockRouter) RouteConnectionEx(ctx context.Context, conn net.Conn, metadata adapter.InboundContext, onClose N.CloseHandlerFunc) {
	if conn != nil {
		_ = conn.Close()
	}
	if onClose != nil {
		onClose(nil)
	}
}

func (r *noopMockRouter) RoutePacketConnectionEx(ctx context.Context, conn N.PacketConn, metadata adapter.InboundContext, onClose N.CloseHandlerFunc) {
	if conn != nil {
		_ = conn.Close()
	}
	if onClose != nil {
		onClose(nil)
	}
}

func TestClassifyHandshakeFailure(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name        string
		err         error
		wantReason  string
		shouldDrain bool
	}{
		{"nil", nil, "", false},
		{"auth_failed", ErrAuthenticationFailed, ReasonAuthFailed, true},
		{"low_order_epk", fmt.Errorf("wrap: %w", ErrLowOrderX25519Point), ReasonAuthFailed, true},
		{"invalid_shared", ErrInvalidSharedSecret, ReasonAuthFailed, true},
		{"invalid_x25519", ErrInvalidX25519Key, ReasonAuthFailed, true},
		{"replay", fmt.Errorf("replay: %w", ErrSaltReplayed), ReasonReplay, true},
		{"clock_skew", fmt.Errorf("skew: %w", ErrTimestampOutOfWindow), ReasonClockSkew, true},
		{"invalid_version", ErrInvalidVersion, ReasonMalformed, true},
		{"invalid_command", ErrInvalidCommand, ReasonMalformed, true},
		{"unsupported_cipher", ErrUnsupportedCipherSuite, ReasonMalformed, true},
		{"invalid_reserved", ErrInvalidReserved, ReasonMalformed, true},
		{"invalid_noise_len", ErrInvalidNoiseLength, ReasonMalformed, true},
		{"invalid_var_len", ErrInvalidVarHeaderLen, ReasonMalformed, true},
		{"invalid_var_hdr", ErrInvalidVarHeader, ReasonMalformed, true},
		{"prefix_deadline", fmt.Errorf("%s %w", prefixReadErrPrefix, context.DeadlineExceeded), ReasonTimeout, false},
		{"prefix_net_timeout", fmt.Errorf("%s %w", prefixReadErrPrefix, &net.OpError{Op: "read", Err: timeoutStubErr{}}), ReasonTimeout, false},
		{"prefix_0b_eof", fmt.Errorf("%s %w", prefixReadErrPrefix, io.EOF), ReasonTimeout, false},
		{"prefix_short_unexpected_eof", fmt.Errorf("%s %w", prefixReadErrPrefix, io.ErrUnexpectedEOF), ReasonTimeout, false},
		{"post_prefix_varhdr_eof", fmt.Errorf("aether: read encrypted var header: %w", io.ErrUnexpectedEOF), ReasonMalformed, true},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			reason, drain := ClassifyHandshakeFailure(tc.err)
			require.Equal(t, tc.wantReason, reason)
			require.Equal(t, tc.shouldDrain, drain)
		})
	}
}

type timeoutStubErr struct{}

func (timeoutStubErr) Error() string   { return "i/o timeout" }
func (timeoutStubErr) Timeout() bool   { return true }
func (timeoutStubErr) Temporary() bool { return true }

func TestDrainGuardDefaultsAndUniformDistribution(t *testing.T) {
	t.Parallel()

	g := NewDrainGuard(DrainGuardOptions{})
	require.Equal(t, 256, cap(g.handshakeSem))
	require.Equal(t, 512, cap(g.drainSem))
	require.Equal(t, 3*time.Second, MinDrainDuration)
	require.Equal(t, 10*time.Second, MaxDrainDuration)
	require.Equal(t, 6*time.Second, DefaultHandshakeTimeout)

	const samples = 10000
	const buckets = 10
	counts := make([]int, buckets)
	span := float64(MaxDrainDuration - MinDrainDuration)
	var sumSec float64
	var sumSqSec float64

	for i := 0; i < samples; i++ {
		d := g.randomDrainDuration()
		require.GreaterOrEqual(t, d, MinDrainDuration)
		require.LessOrEqual(t, d, MaxDrainDuration)

		sec := d.Seconds()
		sumSec += sec
		sumSqSec += sec * sec

		bucket := int(float64(d-MinDrainDuration) / span * buckets)
		if bucket >= buckets {
			bucket = buckets - 1
		}
		counts[bucket]++
	}

	mean := sumSec / samples
	variance := sumSqSec/samples - mean*mean
	stddev := math.Sqrt(variance)

	// Uniform[3, 10] has mean 6.5s and stddev (10-3)/sqrt(12) ~= 2.0207s.
	require.InDelta(t, 6.5, mean, 0.15)
	require.InDelta(t, 7.0/math.Sqrt(12.0), stddev, 0.12)

	expectedPerBucket := samples / buckets
	for b, c := range counts {
		require.GreaterOrEqual(t, c, expectedPerBucket-180, "bucket %d too sparse", b)
		require.LessOrEqual(t, c, expectedPerBucket+180, "bucket %d too dense", b)
	}
}

func TestStealthDrainDefaultWindowFINNotRST(t *testing.T) {
	t.Parallel()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer ln.Close()

	recLog := &recordingLogger{}
	g := NewDrainGuard(DrainGuardOptions{Logger: recLog})

	var onCloseCalls atomic.Int32
	var onCloseErr atomic.Value
	srvDone := make(chan struct{})
	go func() {
		defer close(srvDone)
		srvConn, err := ln.Accept()
		if err != nil {
			return
		}
		// Read initial probe payload while leaving write-half open like an active prober.
		probe := make([]byte, 128)
		_, _ = io.ReadFull(srvConn, probe)
		g.StealthDrain(context.Background(), srvConn, "127.0.0.1", ReasonAuthFailed, ErrAuthenticationFailed, func(err error) {
			onCloseCalls.Add(1)
			if err != nil {
				onCloseErr.Store(err)
			}
		})
	}()

	cliConn, err := net.Dial("tcp", ln.Addr().String())
	require.NoError(t, err)
	defer cliConn.Close()

	probe := make([]byte, 128)
	_, err = rand.Read(probe)
	require.NoError(t, err)
	_, err = cliConn.Write(probe)
	require.NoError(t, err)

	start := time.Now()
	buf := make([]byte, 64)
	_ = cliConn.SetReadDeadline(time.Now().Add(12 * time.Second))
	n, readErr := cliConn.Read(buf)
	elapsed := time.Since(start)

	require.Zero(t, n)
	require.ErrorIs(t, readErr, io.EOF, "StealthDrain must close with normal TCP FIN (io.EOF), never RST")
	require.False(t, errors.Is(readErr, syscall.ECONNRESET))
	require.GreaterOrEqual(t, elapsed, 2850*time.Millisecond)
	require.LessOrEqual(t, elapsed, 10800*time.Millisecond)

	<-srvDone
	require.Equal(t, int32(1), onCloseCalls.Load())
	require.ErrorIs(t, onCloseErr.Load().(error), ErrAuthenticationFailed)
	require.Zero(t, g.DrainInFlight())
}

func TestCloseTimeoutCleanFINNoDrain(t *testing.T) {
	t.Parallel()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer ln.Close()

	recLog := &recordingLogger{}
	g := NewDrainGuard(DrainGuardOptions{Logger: recLog})

	var onCloseCalls atomic.Int32
	srvDone := make(chan struct{})
	go func() {
		defer close(srvDone)
		srvConn, err := ln.Accept()
		if err != nil {
			return
		}
		g.CloseTimeout(context.Background(), srvConn, "127.0.0.1", ReasonTimeout, context.DeadlineExceeded, func(err error) {
			onCloseCalls.Add(1)
		})
	}()

	cliConn, err := net.Dial("tcp", ln.Addr().String())
	require.NoError(t, err)
	defer cliConn.Close()

	start := time.Now()
	buf := make([]byte, 16)
	_ = cliConn.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, readErr := cliConn.Read(buf)
	elapsed := time.Since(start)

	require.Zero(t, n)
	require.ErrorIs(t, readErr, io.EOF)
	require.Less(t, elapsed, 500*time.Millisecond)
	<-srvDone
	require.Equal(t, int32(1), onCloseCalls.Load())

	warns := recLog.warnMessages()
	require.Len(t, warns, 1)
	require.Contains(t, warns[0], ReasonTimeout)
}

func TestDrainGuardSemaphoreNonStarvationAndShedding(t *testing.T) {
	t.Parallel()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer ln.Close()

	g := NewDrainGuard(DrainGuardOptions{
		HandshakeLimit: 4,
		DrainLimit:     4,
		MinDrain:       450 * time.Millisecond,
		MaxDrain:       550 * time.Millisecond,
	})

	const floodCount = 16
	var wg sync.WaitGroup
	drainingEntered := make(chan struct{}, 4)

	go func() {
		for i := 0; i < floodCount; i++ {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			wg.Add(1)
			go func(conn net.Conn) {
				defer wg.Done()
				rel, ok := g.AcquireHandshake(context.Background())
				if !ok {
					_ = conn.Close()
					return
				}
				// Release handshakeSem strictly before StealthDrain!
				rel()
				select {
				case drainingEntered <- struct{}{}:
				default:
				}
				g.StealthDrain(context.Background(), conn, "127.0.0.1", ReasonAuthFailed, ErrAuthenticationFailed, nil)
			}(c)
		}
	}()

	clients := make([]net.Conn, 0, floodCount)
	for i := 0; i < floodCount; i++ {
		c, err := net.Dial("tcp", ln.Addr().String())
		require.NoError(t, err)
		clients = append(clients, c)
		defer c.Close()
	}

	// Wait until all 4 drain slots are busy, then confirm handshakeSem is still 0 (not starved!).
	for i := 0; i < 4; i++ {
		<-drainingEntered
	}
	require.Eventually(t, func() bool {
		return g.DrainInFlight() == 4
	}, time.Second, 10*time.Millisecond)
	require.Zero(t, g.HandshakeInFlight(), "handshakeSem must stay freed even when drainSem is saturated")

	// Legitimate handshake acquire must succeed immediately without blocking.
	legitRel, ok := g.TryAcquireHandshake()
	require.True(t, ok)
	legitRel()

	// Verify excess 12 flood conns closed immediately cleanly with io.EOF (FIN, never RST).
	var fastClosed atomic.Int32
	var readWG sync.WaitGroup
	for _, c := range clients {
		c := c
		readWG.Add(1)
		go func() {
			defer readWG.Done()
			start := time.Now()
			buf := make([]byte, 8)
			_ = c.SetReadDeadline(time.Now().Add(2 * time.Second))
			_, err := c.Read(buf)
			require.ErrorIs(t, err, io.EOF)
			if time.Since(start) < 250*time.Millisecond {
				fastClosed.Add(1)
			}
		}()
	}
	readWG.Wait()
	wg.Wait()
	require.Equal(t, int32(12), fastClosed.Load(), "overflow beyond drainSem must close immediately via FIN")
}

func TestDrainGuardRateLimitedWarnLog(t *testing.T) {
	t.Parallel()

	var nowUnix atomic.Int64
	nowUnix.Store(1_700_000_000)

	recLog := &recordingLogger{}
	g := NewDrainGuard(DrainGuardOptions{
		Logger:      recLog,
		LogInterval: 10 * time.Second,
		NowFunc: func() time.Time {
			return time.Unix(nowUnix.Load(), 0)
		},
	})

	// 50 probes from 127.0.0.1 with varying ephemeral ports normalize to one IP key.
	for port := 10000; port < 10050; port++ {
		meta := adapter.InboundContext{
			Source: M.ParseSocksaddrHostPort("127.0.0.1", uint16(port)),
		}
		ip := normalizeSourceIP(nil, meta)
		g.CloseTimeout(context.Background(), nil, ip, ReasonAuthFailed, ErrAuthenticationFailed, nil)
	}

	warns := recLog.warnMessages()
	require.Len(t, warns, 1, "50 rapid probes from 127.0.0.1 must rate-limit to 1 warning")
	require.Contains(t, warns[0], "127.0.0.1")
	require.Contains(t, warns[0], ReasonAuthFailed)

	// Different source IP logs independently.
	g.CloseTimeout(context.Background(), nil, "127.0.0.2", ReasonClockSkew, ErrTimestampOutOfWindow, nil)
	warns = recLog.warnMessages()
	require.Len(t, warns, 2)
	require.Contains(t, warns[1], ReasonClockSkew)

	// After advancing clock past 10s, 127.0.0.1 logs again.
	nowUnix.Add(11)
	g.CloseTimeout(context.Background(), nil, "127.0.0.1", ReasonReplay, ErrSaltReplayed, nil)
	warns = recLog.warnMessages()
	require.Len(t, warns, 3)
	require.Contains(t, warns[2], ReasonReplay)

	// Bounded map eviction check (> maxWarnMapEntries distinct IPs).
	for i := 0; i < maxWarnMapEntries+50; i++ {
		ip := fmt.Sprintf("10.%d.%d.%d", (i>>16)&0xff, (i>>8)&0xff, i&0xff)
		g.CloseTimeout(context.Background(), nil, ip, ReasonMalformed, ErrInvalidVersion, nil)
	}
	g.warnMu.Lock()
	mapSize := len(g.warnLast)
	g.warnMu.Unlock()
	require.LessOrEqual(t, mapSize, maxWarnMapEntries)
}

func TestInboundHandshakeTimeoutAndSlowlorisCleanClose(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	listenAddr := badoption.Addr(netip.MustParseAddr("127.0.0.1"))
	inAny, err := NewInbound(ctx, &noopMockRouter{}, log.NewNOPFactory().Logger(), "aether-in", option.AetherInboundOptions{
		ListenOptions: option.ListenOptions{
			Listen:     &listenAddr,
			ListenPort: 0,
		},
		Password:         "test-drain-inbound-secret",
		HandshakeTimeout: badoption.Duration(180 * time.Millisecond),
	})
	require.NoError(t, err)
	in := inAny.(*Inbound)
	scope := adapter.NewScope(ctx, log.NewNOPFactory().Logger())
	require.NoError(t, in.Start(adapter.StartStateStart, scope))
	defer scope.Close()

	addr := in.listener.TCPListener().Addr().String()

	// 1) Slowloris 0B probe: waits silently, must close with FIN right after ~180ms (not 3-10s drain!).
	slowConn, err := net.Dial("tcp", addr)
	require.NoError(t, err)
	defer slowConn.Close()

	start := time.Now()
	_ = slowConn.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 8)
	n, readErr := slowConn.Read(buf)
	elapsed := time.Since(start)
	require.Zero(t, n)
	require.ErrorIs(t, readErr, io.EOF)
	require.GreaterOrEqual(t, elapsed, 140*time.Millisecond)
	require.Less(t, elapsed, time.Second)
	require.Eventually(t, func() bool {
		return in.drainGuard.HandshakeInFlight() == 0
	}, time.Second, 10*time.Millisecond)

	// 2) Short <96B EOF probe: closes write immediately after 20B -> fast FIN without StealthDrain.
	shortConn, err := net.Dial("tcp", addr)
	require.NoError(t, err)
	defer shortConn.Close()

	_, err = shortConn.Write(make([]byte, 20))
	require.NoError(t, err)
	require.NoError(t, shortConn.(*net.TCPConn).CloseWrite())

	start = time.Now()
	_ = shortConn.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, readErr = shortConn.Read(buf)
	elapsed = time.Since(start)
	require.Zero(t, n)
	require.ErrorIs(t, readErr, io.EOF)
	require.Less(t, elapsed, time.Second)
	require.Zero(t, strings.TrimSpace(""))
}

func TestStealthDrainEarlyClientFINHoldsFullDuration(t *testing.T) {
	t.Parallel()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer ln.Close()

	g := NewDrainGuard(DrainGuardOptions{
		MinDrain: 400 * time.Millisecond,
		MaxDrain: 600 * time.Millisecond,
	})

	srvDone := make(chan struct{})
	go func() {
		defer close(srvDone)
		srvConn, err := ln.Accept()
		if err != nil {
			return
		}
		probe := make([]byte, 96)
		_, _ = io.ReadFull(srvConn, probe)
		g.StealthDrain(context.Background(), srvConn, "127.0.0.1", ReasonAuthFailed, ErrAuthenticationFailed, nil)
	}()

	cliConn, err := net.Dial("tcp", ln.Addr().String())
	require.NoError(t, err)
	defer cliConn.Close()

	_, err = cliConn.Write(make([]byte, 96))
	require.NoError(t, err)
	require.NoError(t, cliConn.(*net.TCPConn).CloseWrite())

	start := time.Now()
	buf := make([]byte, 16)
	_ = cliConn.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, readErr := cliConn.Read(buf)
	elapsed := time.Since(start)

	require.Zero(t, n)
	require.ErrorIs(t, readErr, io.EOF)
	require.GreaterOrEqual(t, elapsed, 380*time.Millisecond)
	require.LessOrEqual(t, elapsed, 1200*time.Millisecond)
	<-srvDone
	require.Zero(t, g.DrainInFlight())
}

func TestStealthDrainContextCancelDuringEarlyFINHold(t *testing.T) {
	t.Parallel()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer ln.Close()

	g := NewDrainGuard(DrainGuardOptions{
		MinDrain: 3 * time.Second,
		MaxDrain: 5 * time.Second,
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	srvDone := make(chan struct{})
	go func() {
		defer close(srvDone)
		srvConn, err := ln.Accept()
		if err != nil {
			return
		}
		probe := make([]byte, 96)
		_, _ = io.ReadFull(srvConn, probe)
		g.StealthDrain(ctx, srvConn, "127.0.0.1", ReasonReplay, ErrSaltReplayed, nil)
	}()

	cliConn, err := net.Dial("tcp", ln.Addr().String())
	require.NoError(t, err)
	defer cliConn.Close()

	_, err = cliConn.Write(make([]byte, 96))
	require.NoError(t, err)
	require.NoError(t, cliConn.(*net.TCPConn).CloseWrite())

	time.AfterFunc(120*time.Millisecond, cancel)

	start := time.Now()
	buf := make([]byte, 16)
	_ = cliConn.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, readErr := cliConn.Read(buf)
	elapsed := time.Since(start)

	require.Zero(t, n)
	require.ErrorIs(t, readErr, io.EOF)
	require.Less(t, elapsed, 750*time.Millisecond)
	<-srvDone
	require.Zero(t, g.DrainInFlight())
}
