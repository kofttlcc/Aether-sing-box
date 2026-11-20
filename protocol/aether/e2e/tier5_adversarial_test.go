package e2e_test

import (
	"bufio"
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/urltest"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/protocol/aether"
	"github.com/sagernet/sing-box/protocol/group"
	"github.com/sagernet/sing/common/buf"
	"github.com/sagernet/sing/common/json/badoption"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/common/ntp"
	"github.com/sagernet/sing/service"
	"github.com/sagernet/sing/service/pause"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/sys/cpu"
)

func TestTier5Adversarial(t *testing.T) {
	// T5-01 runs sequentially first because it temporarily toggles global cpu.* flags
	// to test both AES-GCM and ChaCha20 fallback branches of SelectCipherSuite("auto").
	t.Run("T5-01_SelectCipherSuite_AutoAndFallbackAndMismatch", runT501SelectCipherSuite)

	t.Run("T5-02_SecretResolution_Argon2id_Base64_EIHColonSplitting", runT502SecretsAndEIH)
	t.Run("T5-03_SlidingBloomFilter_GenerationBoundaries_WrapAround_NTPSkew", runT503BloomBoundaries)
	t.Run("T5-04_SlidingBloomFilter_RaceAndContextTimeFunc", runT504BloomRace)
	t.Run("T5-05_ReplayFilter_InvalidAEADNeverPollutesBloom", runT505InvalidAEADNoBloomPollution)
	t.Run("T5-06_Handshake_AAD_NonceSeparation_LowOrderPoints", runT506HandshakeAADAndLowOrder)
	t.Run("T5-07_Wire_FixedHeader_VarHeader_BoundaryLimits", runT507WireHeaderBoundaries)
	t.Run("T5-08_Frame_AEAD_PlainFrameLen_Padding_FrameType_Chaff", runT508MalformedFramesAndChaff)
	t.Run("T5-09_DrainGuard_Semaphores256And512_NonBlockingShedding", runT509SemaphoreSaturation)
	t.Run("T5-10_StealthDrain_Uniform3sTo10s_EarlyFIN_CtxCancel", runT510StealthDrainFINAndCancel)
	t.Run("T5-11_DrainGuard_PerIPRateLimit_ConcurrencyAnd4096Bound", runT511RateLimitConcurrency)
	t.Run("T5-12_Conn_ExtendedConn_BufferOwnershipAndReplaceability", runT512ExtendedConnBuffers)
	t.Run("T5-13_Conn_WriteBrokenFusing_And_DeadlineIsolation", runT513WriteBrokenAndDeadlines)
	t.Run("T5-14_Conn_CloseWrite_ConcurrentDeadlinesAndClose_RaceStress", runT514CloseWriteRaceStress)
	t.Run("T5-15_Conn_HeadOnlyShaping_Frames0To5_And_Frame6Plus", runT515HeadOnlyShapingFrames)
	t.Run("T5-16_PacketConn_CommandUDP_TruncatedSocksaddr_JumboBoundaries", runT516PacketConnBoundaries)
	t.Run("T5-17_Outbound_SimultaneousMultiplexUoTCommandUDP_Precedence", runT517OutboundPrecedence)
	t.Run("T5-18_URLTest_ConcurrentReferencesSelectPerformUpdateCheck_Race", runT518URLTestRace)
	t.Run("T5-19_Workflow_UpstreamSyncRelease_StaticContract", runT519WorkflowContract)
	t.Run("T5-20_Authenticator_MultiUserDirectVsEIH_UserTableValidation", runT520AuthenticatorModes)
	t.Run("T5-21_StaticX25519_0RTTPFS_MismatchIsolation", runT521StaticPFSMismatch)
	t.Run("T5-22_Handshake_SingleUseState_And_MaskedEPKBiasRemoval", runT522SingleUseAndEPKMask)
	t.Run("T5-23_Inbound_TimeoutVsDrain_And_CloseShutdownCancellation", runT523InboundLifecycleAndClose)
	t.Run("T5-24_Conn_25msCoalescedBurst_ServerSpeaksFirst_And_LargeInitialSplit", runT524CoalescedBurstAndLargeInit)
	t.Run("T5-25_PacketConn_MidHeaderDeadlineRecovery_And_EmptyFQDNRejection", runT525PacketConnMidHeaderRecoveryAndEmptyFQDN)
	t.Run("T5-26_Conn_DataAfterCloseWriteRejected_PingPongChaffPreserved", runT526ConnDataAfterCloseWriteRejected)
	t.Run("T5-27_URLTest_PostStartConcurrentTouch_Race", runT527URLTestPostStartTouchRace)
}

// ---------------------------------------------------------------------------
// White-box helpers (prefixed t5* to prevent package e2e_test collisions)
// ---------------------------------------------------------------------------

var t5LowOrderCurve25519Hex = []string{
	"0000000000000000000000000000000000000000000000000000000000000000",
	"0000000000000000000000000000000000000000000000000000000000000080",
	"edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
	"edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
	"0100000000000000000000000000000000000000000000000000000000000000",
	"0100000000000000000000000000000000000000000000000000000000000080",
	"eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
	"eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
	"e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b800",
	"e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b880",
	"5f9c95bca3508c24b1d0b1559c83ef5b04445cc4581c8e86d8224eddd09f1157",
	"5f9c95bca3508c24b1d0b1559c83ef5b04445cc4581c8e86d8224eddd09f11d7",
	"ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
	"ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
}

func t5DecodeHex32(t testing.TB, s string) [32]byte {
	t.Helper()
	var out [32]byte
	require.Len(t, s, 64)
	for i := range 32 {
		hi := t5HexNibble(t, s[2*i])
		lo := t5HexNibble(t, s[2*i+1])
		out[i] = (hi << 4) | lo
	}
	return out
}

func t5HexNibble(t testing.TB, b byte) byte {
	t.Helper()
	switch {
	case b >= '0' && b <= '9':
		return b - '0'
	case b >= 'a' && b <= 'f':
		return b - 'a' + 10
	case b >= 'A' && b <= 'F':
		return b - 'A' + 10
	default:
		t.Fatalf("invalid hex byte %q", b)
		return 0
	}
}

func t5RandomKeyB64(t testing.TB) string {
	t.Helper()
	var raw [32]byte
	_, err := io.ReadFull(rand.Reader, raw[:])
	require.NoError(t, err)
	raw[0] |= 0x01 // ensure non-zero
	return base64.StdEncoding.EncodeToString(raw[:])
}

func t5TCPPair(t testing.TB) (net.Conn, net.Conn) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = ln.Close() })

	type acceptRes struct {
		conn net.Conn
		err  error
	}
	ch := make(chan acceptRes, 1)
	go func() {
		c, aErr := ln.Accept()
		ch <- acceptRes{conn: c, err: aErr}
	}()

	cConn, err := net.DialTimeout("tcp", ln.Addr().String(), 5*time.Second)
	require.NoError(t, err)
	t.Cleanup(func() { _ = cConn.Close() })

	res := <-ch
	require.NoError(t, res.err)
	t.Cleanup(func() { _ = res.conn.Close() })
	return cConn, res.conn
}

type t5SpyRawConn struct {
	net.Conn
	mu     sync.Mutex
	writes [][]byte
}

func (s *t5SpyRawConn) Write(p []byte) (int, error) {
	cp := make([]byte, len(p))
	copy(cp, p)
	s.mu.Lock()
	s.writes = append(s.writes, cp)
	s.mu.Unlock()
	return s.Conn.Write(p)
}

func (s *t5SpyRawConn) snapshotWrites() [][]byte {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([][]byte, len(s.writes))
	copy(out, s.writes)
	return out
}

type t5CountingLogger struct {
	mu      sync.Mutex
	warns   int
	entries []string
}

func (l *t5CountingLogger) Trace(...any)                            {}
func (l *t5CountingLogger) Debug(...any)                            {}
func (l *t5CountingLogger) Info(...any)                             {}
func (l *t5CountingLogger) Warn(args ...any)                        { l.record(args...) }
func (l *t5CountingLogger) Error(...any)                            {}
func (l *t5CountingLogger) Fatal(...any)                            {}
func (l *t5CountingLogger) Panic(...any)                            {}
func (l *t5CountingLogger) TraceContext(context.Context, ...any)    {}
func (l *t5CountingLogger) DebugContext(context.Context, ...any)    {}
func (l *t5CountingLogger) InfoContext(context.Context, ...any)     {}
func (l *t5CountingLogger) WarnContext(_ context.Context, a ...any) { l.record(a...) }
func (l *t5CountingLogger) ErrorContext(context.Context, ...any)    {}
func (l *t5CountingLogger) FatalContext(context.Context, ...any)    {}
func (l *t5CountingLogger) PanicContext(context.Context, ...any)    {}

func (l *t5CountingLogger) record(args ...any) {
	l.mu.Lock()
	l.warns++
	l.entries = append(l.entries, fmt.Sprint(args...))
	l.mu.Unlock()
}

func (l *t5CountingLogger) warnCount() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.warns
}

var _ logger.ContextLogger = (*t5CountingLogger)(nil)

type t5StubRouter struct {
	adapter.Router
	onConn   func(ctx context.Context, conn net.Conn, metadata adapter.InboundContext, onClose N.CloseHandlerFunc)
	onPacket func(ctx context.Context, conn N.PacketConn, metadata adapter.InboundContext, onClose N.CloseHandlerFunc)
}

func (r *t5StubRouter) RouteConnectionEx(ctx context.Context, conn net.Conn, metadata adapter.InboundContext, onClose N.CloseHandlerFunc) {
	if r.onConn != nil {
		r.onConn(ctx, conn, metadata, onClose)
		return
	}
	_ = conn.Close()
	if onClose != nil {
		onClose(nil)
	}
}

func (r *t5StubRouter) RoutePacketConnectionEx(ctx context.Context, conn N.PacketConn, metadata adapter.InboundContext, onClose N.CloseHandlerFunc) {
	if r.onPacket != nil {
		r.onPacket(ctx, conn, metadata, onClose)
		return
	}
	_ = conn.Close()
	if onClose != nil {
		onClose(nil)
	}
}

func t5CreateAetherPair(
	t testing.TB,
	clientOpts aether.ClientConnOptions,
	serverOpts aether.ServerConnOptions,
	rawClient net.Conn,
	rawServer net.Conn,
) (*aether.Conn, *aether.ServerAcceptResult) {
	t.Helper()
	if clientOpts.Command == 0 {
		clientOpts.Command = aether.CommandTCP
	}
	if clientOpts.CipherSuite == 0 {
		clientOpts.CipherSuite = aether.CipherAES256GCM
	}
	if !clientOpts.TargetAddr.IsValid() {
		clientOpts.TargetAddr = M.ParseSocksaddrHostPort("127.0.0.1", 8080)
	}
	clientConn, err := aether.DialEarlyConnContext(context.Background(), rawClient, clientOpts)
	require.NoError(t, err)

	type srvRes struct {
		res *aether.ServerAcceptResult
		err error
	}
	ch := make(chan srvRes, 1)
	go func() {
		r, sErr := aether.AcceptServerConn(context.Background(), rawServer, serverOpts)
		ch <- srvRes{res: r, err: sErr}
	}()

	// Trigger ClientInitialBurst if caller wants immediate accept.
	return clientConn, <-func() <-chan *aether.ServerAcceptResult {
		out := make(chan *aether.ServerAcceptResult, 1)
		go func() {
			sr := <-ch
			require.NoError(t, sr.err)
			out <- sr.res
		}()
		return out
	}()
}

// t5EstablishedPair connects a client & server Aether Conn over real loopback TCP
// and completes the handshake via a 1-byte ping/echo exchange so both sides hold live ciphers.
func t5EstablishedPair(
	t testing.TB,
	command uint8,
	cipherSuite uint8,
	hbInterval time.Duration,
	disableShaping bool,
) (*aether.Conn, *aether.Conn, *t5SpyRawConn, *t5SpyRawConn) {
	t.Helper()
	rawC, rawS := t5TCPPair(t)
	spyC := &t5SpyRawConn{Conn: rawC}
	spyS := &t5SpyRawConn{Conn: rawS}

	secret := t5RandomKeyB64(t)
	creds, err := aether.ParseOutboundCredentials(secret)
	require.NoError(t, err)
	auth, err := aether.NewServerAuthenticator(secret, nil, "")
	require.NoError(t, err)
	replay := aether.NewSlidingBloomFilter(aether.DefaultTimeWindow, nil)

	clientConn, err := aether.DialEarlyConnContext(context.Background(), spyC, aether.ClientConnOptions{
		Credentials:       creds,
		Command:           command,
		CipherSuite:       cipherSuite,
		TargetAddr:        M.ParseSocksaddrHostPort("127.0.0.1", 443),
		HeartbeatInterval: hbInterval,
		DisableShaping:    disableShaping,
	})
	require.NoError(t, err)

	type srvRes struct {
		res *aether.ServerAcceptResult
		err error
	}
	ch := make(chan srvRes, 1)
	go func() {
		r, aErr := aether.AcceptServerConn(context.Background(), spyS, aether.ServerConnOptions{
			Authenticator:     auth,
			ReplayFilter:      replay,
			HeartbeatInterval: hbInterval,
			DisableShaping:    disableShaping,
		})
		ch <- srvRes{res: r, err: aErr}
	}()

	// Flush 0-RTT handshake + initial byte and receive coalesced ServerRespPrefix + ack byte.
	_, err = clientConn.Write([]byte("X"))
	require.NoError(t, err)

	sr := <-ch
	require.NoError(t, sr.err)
	srvConn := sr.res.Conn

	var initByte [1]byte
	_, err = io.ReadFull(srvConn, initByte[:])
	require.NoError(t, err)
	require.Equal(t, byte('X'), initByte[0])

	_, err = srvConn.Write([]byte("Y"))
	require.NoError(t, err)

	var ackByte [1]byte
	_, err = io.ReadFull(clientConn, ackByte[:])
	require.NoError(t, err)
	require.Equal(t, byte('Y'), ackByte[0])

	t.Cleanup(func() {
		_ = clientConn.Close()
		_ = srvConn.Close()
	})
	return clientConn, srvConn, spyC, spyS
}

// ---------------------------------------------------------------------------
// T5-01..T5-24
// ---------------------------------------------------------------------------

func runT501SelectCipherSuite(t *testing.T) {
	expectedCurrent := aether.CipherChaCha20Poly1305
	if aether.HasAESGCMHardware() {
		expectedCurrent = aether.CipherAES256GCM
	}
	suiteAuto, err := aether.SelectCipherSuite("auto")
	require.NoError(t, err)
	require.Equal(t, expectedCurrent, suiteAuto)

	suiteEmpty, err := aether.SelectCipherSuite("")
	require.NoError(t, err)
	require.Equal(t, expectedCurrent, suiteEmpty)

	sAES, err := aether.SelectCipherSuite("aes-256-gcm")
	require.NoError(t, err)
	require.Equal(t, aether.CipherAES256GCM, sAES)

	sChaCha, err := aether.SelectCipherSuite("chacha20-poly1305")
	require.NoError(t, err)
	require.Equal(t, aether.CipherChaCha20Poly1305, sChaCha)

	_, err = aether.SelectCipherSuite("aes-128-gcm")
	require.Error(t, err)
	_, err = aether.SelectCipherSuite("AUTO")
	require.Error(t, err)

	// Explicitly verify both AES-capable and non-AES fallback branches of SelectCipherSuite("auto").
	switch runtime.GOARCH {
	case "arm64":
		origAES, origPMULL := cpu.ARM64.HasAES, cpu.ARM64.HasPMULL
		defer func() {
			cpu.ARM64.HasAES = origAES
			cpu.ARM64.HasPMULL = origPMULL
		}()
		cpu.ARM64.HasAES = true
		cpu.ARM64.HasPMULL = true
		require.True(t, aether.HasAESGCMHardware())
		s, sErr := aether.SelectCipherSuite("auto")
		require.NoError(t, sErr)
		require.Equal(t, aether.CipherAES256GCM, s)

		cpu.ARM64.HasAES = false
		cpu.ARM64.HasPMULL = false
		require.False(t, aether.HasAESGCMHardware())
		s, sErr = aether.SelectCipherSuite("auto")
		require.NoError(t, sErr)
		require.Equal(t, aether.CipherChaCha20Poly1305, s)

		cpu.ARM64.HasAES = true
		cpu.ARM64.HasPMULL = false
		require.False(t, aether.HasAESGCMHardware())
		s, sErr = aether.SelectCipherSuite("auto")
		require.NoError(t, sErr)
		require.Equal(t, aether.CipherChaCha20Poly1305, s)
	case "amd64":
		origAES, origPCLMUL := cpu.X86.HasAES, cpu.X86.HasPCLMULQDQ
		origSSE41, origSSSE3 := cpu.X86.HasSSE41, cpu.X86.HasSSSE3
		defer func() {
			cpu.X86.HasAES = origAES
			cpu.X86.HasPCLMULQDQ = origPCLMUL
			cpu.X86.HasSSE41 = origSSE41
			cpu.X86.HasSSSE3 = origSSSE3
		}()
		cpu.X86.HasAES = true
		cpu.X86.HasPCLMULQDQ = true
		cpu.X86.HasSSE41 = true
		cpu.X86.HasSSSE3 = true
		require.True(t, aether.HasAESGCMHardware())
		s, sErr := aether.SelectCipherSuite("auto")
		require.NoError(t, sErr)
		require.Equal(t, aether.CipherAES256GCM, s)

		cpu.X86.HasAES = false
		require.False(t, aether.HasAESGCMHardware())
		s, sErr = aether.SelectCipherSuite("auto")
		require.NoError(t, sErr)
		require.Equal(t, aether.CipherChaCha20Poly1305, s)
	}

	// Wire-level cipher negotiation mismatch: client asks AES-256-GCM, server echoes ChaCha20-Poly1305.
	secret := t5RandomKeyB64(t)
	creds, err := aether.ParseOutboundCredentials(secret)
	require.NoError(t, err)
	fh := aether.FixedHeader{
		Version:      aether.ProtocolVersion,
		Command:      aether.CommandTCP,
		CipherSuite:  aether.CipherAES256GCM,
		TimestampSec: time.Now().Unix(),
		NoiseLen:     32,
		VarHeaderLen: 64,
	}
	fixedPlain, err := aether.EncodeFixedHeader(fh)
	require.NoError(t, err)

	clientHS, prefix, err := aether.StartClientHandshake(creds, nil, fixedPlain)
	require.NoError(t, err)

	auth, err := aether.NewServerAuthenticator(secret, nil, "")
	require.NoError(t, err)
	srvHS, _, err := auth.OpenClientFixedPrefix(prefix)
	require.NoError(t, err)

	badRespPlain, err := aether.EncodeRespHeader(aether.CipherChaCha20Poly1305)
	require.NoError(t, err)
	badRespPrefix, _, _, err := srvHS.Complete(aether.CipherChaCha20Poly1305, badRespPlain)
	require.NoError(t, err)

	_, _, _, err = clientHS.Complete(badRespPrefix[:], aether.CipherAES256GCM)
	require.ErrorIs(t, err, aether.ErrInvalidRespHeader)

	// Invalid RespHeader fields.
	for _, raw := range [][4]byte{
		{0x01, 0x00, aether.CipherAES256GCM, 0x00},
		{aether.ProtocolVersion, 0x01, aether.CipherAES256GCM, 0x00},
		{aether.ProtocolVersion, 0x00, aether.CipherAES256GCM, 0x02},
		{aether.ProtocolVersion, 0x00, aether.CipherChaCha20Poly1305, 0x00},
	} {
		err = aether.DecodeAndValidateRespHeader(raw[:], aether.CipherAES256GCM)
		require.ErrorIs(t, err, aether.ErrInvalidRespHeader)
	}
}

func runT502SecretsAndEIH(t *testing.T) {
	t.Parallel()

	// ResolveSecret matrix.
	s, err := option.ResolveSecret("", "")
	require.NoError(t, err)
	require.Empty(t, s)
	s, err = option.ResolveSecret("same-secret-16chr", "same-secret-16chr")
	require.NoError(t, err)
	require.Equal(t, "same-secret-16chr", s)
	s, err = option.ResolveSecret("pw-only-secret-16", "")
	require.NoError(t, err)
	require.Equal(t, "pw-only-secret-16", s)
	s, err = option.ResolveSecret("", "key-only-secret-1")
	require.NoError(t, err)
	require.Equal(t, "key-only-secret-1", s)
	_, err = option.ResolveSecret("alpha-secret-16ch", "beta-secret-16chr")
	require.Error(t, err)

	// DerivePSK boundaries: empty, <16 chars (1..15), exact 16 chars Argon2id, all-zero Base64.
	_, err = aether.DerivePSK("")
	require.ErrorIs(t, err, aether.ErrEmptySecret)
	for length := 1; length < aether.MinPassphraseLength; length++ {
		_, err = aether.DerivePSK(strings.Repeat("a", length))
		require.ErrorIs(t, err, aether.ErrWeakPassword, "len=%d", length)
	}

	pw16 := "exactly-16-chars"
	psk16, err := aether.DerivePSK(pw16)
	require.NoError(t, err)
	want16 := argon2.IDKey([]byte(pw16), []byte(aether.KDFSaltArgon2id), aether.Argon2Time, aether.Argon2MemoryKiB, aether.Argon2Threads, aether.PSKSize)
	require.Equal(t, want16, psk16[:])

	var zero32 [32]byte
	for _, enc := range []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding} {
		_, zErr := aether.DerivePSK(enc.EncodeToString(zero32[:]))
		require.ErrorIs(t, zErr, aether.ErrAllZeroKey)
	}

	// Non-canonical padding bit or CR/LF must NOT trigger Base64 fast-path.
	var sample32 [32]byte
	for i := range sample32 {
		sample32[i] = byte(i + 1)
	}
	stdB64 := base64.StdEncoding.EncodeToString(sample32[:])
	// Flip unused low bit in 43rd char ('B' instead of 'A'/'Q'/'g'/'w' etc.) -> Strict rejects.
	nonCanon := stdB64[:42] + string(stdB64[42]^0x01) + "="
	fastKey, err := aether.DerivePSK(stdB64)
	require.NoError(t, err)
	require.Equal(t, sample32, fastKey)
	argonFallback, err := aether.DerivePSK(nonCanon)
	require.NoError(t, err)
	require.NotEqual(t, sample32, argonFallback)

	// CR/LF injection inside 44-char string also falls back instead of matching Base64 fast-path.
	_, err = aether.DerivePSK(stdB64[:42] + "\n=")
	require.NoError(t, err)
	// Same length as 43 raw URL + \r\n -> >=16, does NOT decode to sample32.
	crlfKey, err := aether.DerivePSK(stdB64[:20] + "\n" + stdB64[21:])
	require.NoError(t, err)
	require.NotEqual(t, sample32, crlfKey)

	// ParseOutboundCredentials EIH ':' splitting edges.
	_, err = aether.ParseOutboundCredentials("")
	require.ErrorIs(t, err, aether.ErrEmptySecret)

	srvB64 := t5RandomKeyB64(t)
	usrB64 := t5RandomKeyB64(t)
	dual, err := aether.ParseOutboundCredentials(srvB64 + ":" + usrB64)
	require.NoError(t, err)
	require.True(t, dual.HasServerPSK)
	srvPSK, _ := aether.DerivePSK(srvB64)
	usrPSK, _ := aether.DerivePSK(usrB64)
	require.Equal(t, srvPSK, dual.IPSK)
	require.Equal(t, usrPSK, dual.UPSK)
	require.Equal(t, aether.DeriveUserID(usrPSK), dual.UserID)

	// Reject "<b64>:weak" and "weak:<b64>" and "<b64>:<all_zero>".
	_, err = aether.ParseOutboundCredentials(srvB64 + ":shortpw")
	require.ErrorIs(t, err, aether.ErrWeakPassword)
	_, err = aether.ParseOutboundCredentials("shortpw:" + usrB64)
	require.ErrorIs(t, err, aether.ErrWeakPassword)
	_, err = aether.ParseOutboundCredentials(srvB64 + ":" + base64.StdEncoding.EncodeToString(zero32[:]))
	require.ErrorIs(t, err, aether.ErrAllZeroKey)

	// Single passphrase containing ':' where left < 16 is treated as single-user secret.
	singleColon, err := aether.ParseOutboundCredentials("short:passphrase16chars")
	require.NoError(t, err)
	require.False(t, singleColon.HasServerPSK)
	expectedSingle, err := aether.DerivePSK("short:passphrase16chars")
	require.NoError(t, err)
	require.Equal(t, expectedSingle, singleColon.UPSK)

	// Dual passphrase (>=16 on both sides).
	dualPass, err := aether.ParseOutboundCredentials("server-pass-16ch:user-pass-16char")
	require.NoError(t, err)
	require.True(t, dualPass.HasServerPSK)

	// Multiple colons with Base64 on left or right disambiguates cleanly.
	multiLeft, err := aether.ParseOutboundCredentials(srvB64 + ":user:pass:16chars")
	require.NoError(t, err)
	require.True(t, multiLeft.HasServerPSK)
	require.Equal(t, srvPSK, multiLeft.IPSK)

	multiRight, err := aether.ParseOutboundCredentials("srv:pass:16chars:" + usrB64)
	require.NoError(t, err)
	require.True(t, multiRight.HasServerPSK)
	require.Equal(t, usrPSK, multiRight.UPSK)

	// Multiple colons where >1 split has >=16 chars on both sides -> ErrAmbiguousCredentials.
	_, err = aether.ParseOutboundCredentials("alpha-passphrase1:beta-passphrase22:gamma-passphrase3")
	require.ErrorIs(t, err, aether.ErrAmbiguousCredentials)

	// Multiple colons where exactly ONE split has >=16 chars on both sides succeeds deterministically.
	unambig, err := aether.ParseOutboundCredentials("short:middle-part-16ch:right-secret-16ch")
	require.NoError(t, err)
	require.True(t, unambig.HasServerPSK)
	wantLeft, _ := aether.DerivePSK("short:middle-part-16ch")
	wantRight, _ := aether.DerivePSK("right-secret-16ch")
	require.Equal(t, wantLeft, unambig.IPSK)
	require.Equal(t, wantRight, unambig.UPSK)
}

func runT503BloomBoundaries(t *testing.T) {
	t.Parallel()

	var curNs atomic.Int64
	base := time.Unix(1750000000, 0)
	curNs.Store(base.UnixNano())

	f := aether.NewSlidingBloomFilter(30*time.Second, func() time.Time {
		return time.Unix(0, curNs.Load())
	})
	require.Equal(t, 30*time.Second, f.Window())
	require.Equal(t, 60*time.Second, f.RotationInterval())

	var saltA, saltB, saltC, saltD [32]byte
	saltA[0] = 0x11
	saltB[0] = 0x22
	saltC[0] = 0x33
	saltD[0] = 0x44

	// t = 0: insert saltA into gen 0.
	require.NoError(t, f.ValidateAndRecord(saltA, base.Unix()))
	require.ErrorIs(t, f.ValidateAndRecord(saltA, base.Unix()), aether.ErrSaltReplayed)

	// t = +59.999s (still < 2*TimeWindow = 60s): no rotation yet, saltA rejected.
	curNs.Store(base.Add(59*time.Second + 999*time.Millisecond).UnixNano())
	require.False(t, f.CheckAndAdd(saltA, time.Unix(0, curNs.Load())))
	require.True(t, f.CheckAndAdd(saltB, time.Unix(0, curNs.Load())))

	// t = +60.000s (exact rotation boundary #1): gen 1 cleared & active, gen 0 becomes prev.
	// saltA & saltB remain blocked because they live in prev.
	curNs.Store(base.Add(60 * time.Second).UnixNano())
	require.False(t, f.CheckAndAdd(saltA, time.Unix(0, curNs.Load())))
	require.False(t, f.CheckAndAdd(saltB, time.Unix(0, curNs.Load())))
	require.True(t, f.CheckAndAdd(saltC, time.Unix(0, curNs.Load())))

	// Backward NTP clock jump (60s -> 45s): MUST preserve both current (saltC) and prev (saltA, saltB)
	// and re-anchor lastRotate to 45s so rotation #2 happens at 45s + 60s = 105s.
	curNs.Store(base.Add(45 * time.Second).UnixNano())
	require.False(t, f.CheckAndAdd(saltA, time.Unix(0, curNs.Load())))
	require.False(t, f.CheckAndAdd(saltC, time.Unix(0, curNs.Load())))

	// At 104s (elapsed 59s since re-anchored 45s): saltA must STILL be blocked!
	curNs.Store(base.Add(104 * time.Second).UnixNano())
	require.False(t, f.CheckAndAdd(saltA, time.Unix(0, curNs.Load())))

	// At 105s (elapsed 60s since re-anchored 45s): rotation #2 clears gen 0 (saltA/saltB evicted),
	// while gen 1 (saltC) becomes prev and stays blocked!
	curNs.Store(base.Add(105 * time.Second).UnixNano())
	require.False(t, f.CheckAndAdd(saltC, time.Unix(0, curNs.Load())))
	require.True(t, f.CheckAndAdd(saltD, time.Unix(0, curNs.Load())))
	require.True(t, f.CheckAndAdd(saltA, time.Unix(0, curNs.Load())))

	// Jump >= 2 * rotationInterval (120s): clears BOTH generations.
	curNs.Store(base.Add(225 * time.Second).UnixNano())
	require.True(t, f.CheckAndAdd(saltC, time.Unix(0, curNs.Load())))
	require.True(t, f.CheckAndAdd(saltD, time.Unix(0, curNs.Load())))

	// NTP timestamp boundaries: exact +/- 30s allowed, +/- 31s rejected WITHOUT polluting Bloom.
	nowT := time.Unix(0, curNs.Load())
	var saltSkew [32]byte
	saltSkew[0] = 0x55
	require.ErrorIs(t, f.ValidateAndRecord(saltSkew, nowT.Unix()+31), aether.ErrTimestampOutOfWindow)
	require.ErrorIs(t, f.ValidateAndRecord(saltSkew, nowT.Unix()-31), aether.ErrTimestampOutOfWindow)
	require.ErrorIs(t, f.ValidateAndRecord(saltSkew, math.MaxInt64), aether.ErrTimestampOutOfWindow)
	require.ErrorIs(t, f.ValidateAndRecord(saltSkew, math.MinInt64), aether.ErrTimestampOutOfWindow)
	// Confirm expired rejections did NOT pollute Bloom!
	require.NoError(t, f.ValidateAndRecord(saltSkew, nowT.Unix()+30))

	var saltSkewNeg [32]byte
	saltSkewNeg[0] = 0x56
	require.NoError(t, f.ValidateAndRecord(saltSkewNeg, nowT.Unix()-30))

	// Sub-second window clamps maxSkewSec to 1s.
	require.NoError(t, aether.ValidateTimestamp(nowT.Unix()-1, nowT, 500*time.Millisecond))
	require.ErrorIs(t, aether.ValidateTimestamp(nowT.Unix()-2, nowT, 500*time.Millisecond), aether.ErrTimestampOutOfWindow)
}

type t5TimeService struct {
	fn func() time.Time
}

func (s t5TimeService) TimeFunc() func() time.Time {
	return s.fn
}

func runT504BloomRace(t *testing.T) {
	t.Parallel()

	// Verify NTP TimeFunc resolution from context and nil fallback.
	fixed := time.Unix(1800000000, 0)
	ntpCtx := service.ContextWith[ntp.TimeService](context.Background(), t5TimeService{fn: func() time.Time { return fixed }})
	fCtx := aether.NewSlidingBloomFilterFromContext(ntpCtx, 10*time.Second)
	require.Equal(t, fixed, fCtx.Now())

	//nolint:staticcheck
	fNil := aether.NewSlidingBloomFilterFromContext(nil, 0)
	require.Equal(t, aether.DefaultTimeWindow, fNil.Window())
	require.WithinDuration(t, time.Now(), fNil.Now(), 5*time.Second)

	// Phase 1: 16 concurrent workers hammer ValidateAndRecord & replay detection while clock jitters within ±2s of 10s window.
	var clockNs atomic.Int64
	clockNs.Store(fixed.UnixNano())
	f := aether.NewSlidingBloomFilter(10*time.Second, func() time.Time {
		return time.Unix(0, clockNs.Load())
	})

	const workers = 16
	const iters = 150
	var stopJitter atomic.Bool
	var jitterWg sync.WaitGroup
	jitterWg.Add(1)
	go func() {
		defer jitterWg.Done()
		step := int64(0)
		for !stopJitter.Load() {
			delta := time.Duration((step%5)-2) * time.Second // -2s..+2s around fixed; total spread <=4s << 10s window
			clockNs.Store(fixed.Add(delta).UnixNano())
			step++
			runtime.Gosched()
		}
	}()

	var wg sync.WaitGroup
	var accepted atomic.Int64
	for w := range workers {
		wg.Add(1)
		go func(workerID int) {
			defer wg.Done()
			for i := range iters {
				var salt [32]byte
				binary.BigEndian.PutUint32(salt[0:4], uint32(workerID))
				binary.BigEndian.PutUint32(salt[4:8], uint32(i))
				ts := fixed.Unix() + int64(i%3) - 1 // within [-1s, +1s] of fixed -> always within ±10s of clockNs
				if err := f.ValidateAndRecord(salt, ts); err == nil {
					accepted.Add(1)
				}
				// Replay same salt immediately: must fail with ErrSaltReplayed.
				err2 := f.ValidateAndRecord(salt, ts)
				require.ErrorIs(t, err2, aether.ErrSaltReplayed)
			}
		}(w)
	}
	wg.Wait()
	stopJitter.Store(true)
	jitterWg.Wait()
	require.Equal(t, int64(workers*iters), accepted.Load())

	// Phase 2: Concurrent generation rotation + NTP skew stress (race check on maybeRotateLocked).
	var rotNs atomic.Int64
	rotNs.Store(fixed.UnixNano())
	fRot := aether.NewSlidingBloomFilter(2*time.Second, func() time.Time {
		return time.Unix(0, rotNs.Load())
	})
	var rotWg sync.WaitGroup
	for w := range 8 {
		rotWg.Add(1)
		go func(workerID int) {
			defer rotWg.Done()
			for i := range 80 {
				if i%10 == 0 {
					rotNs.Add(int64(3 * time.Second))
				}
				nowSec := time.Unix(0, rotNs.Load()).Unix()
				var salt [32]byte
				salt[0] = byte(workerID + 100)
				binary.BigEndian.PutUint32(salt[4:8], uint32(i))
				err := fRot.ValidateAndRecord(salt, nowSec)
				if err != nil {
					require.ErrorIs(t, err, aether.ErrTimestampOutOfWindow)
				}
			}
		}(w)
	}
	rotWg.Wait()
}

func runT505InvalidAEADNoBloomPollution(t *testing.T) {
	t.Parallel()

	for _, eihMode := range []bool{false, true} {
		name := "single_user_96B"
		if eihMode {
			name = "multi_user_eih_112B"
		}
		t.Run(name, func(t *testing.T) {
			srvSecret := t5RandomKeyB64(t)
			usrSecret := t5RandomKeyB64(t)
			var (
				auth  *aether.ServerAuthenticator
				creds aether.ClientCredentials
				err   error
			)
			if eihMode {
				auth, err = aether.NewServerAuthenticator(srvSecret, []option.AetherUser{{Name: "alice", Password: usrSecret}}, "")
				require.NoError(t, err)
				creds, err = aether.ParseOutboundCredentials(srvSecret + ":" + usrSecret)
				require.NoError(t, err)
			} else {
				auth, err = aether.NewServerAuthenticator(srvSecret, nil, "")
				require.NoError(t, err)
				creds, err = aether.ParseOutboundCredentials(srvSecret)
				require.NoError(t, err)
			}

			replay := aether.NewSlidingBloomFilter(aether.DefaultTimeWindow, nil)

			varPlain, err := aether.EncodeVarHeader(nil, 32, M.ParseSocksaddrHostPort("127.0.0.1", 80), []byte("hello"))
			require.NoError(t, err)

			fh := aether.FixedHeader{
				Version:      aether.ProtocolVersion,
				Command:      aether.CommandTCP,
				CipherSuite:  aether.CipherAES256GCM,
				TimestampSec: time.Now().Unix(),
				NoiseLen:     32,
				VarHeaderLen: uint16(len(varPlain)),
			}
			fixedPlain, err := aether.EncodeFixedHeader(fh)
			require.NoError(t, err)

			clientHS, validPrefix, err := aether.StartClientHandshake(creds, nil, fixedPlain)
			require.NoError(t, err)
			encVar := clientHS.SealVarHeader(nil, varPlain)

			// 1. Send multiple invalid AEAD fixed headers reusing the EXACT SAME ClientSalt (bytes 0..31).
			for _, tamperOffset := range []int{32, 63, len(validPrefix) - 1, len(validPrefix) - 20} {
				badPrefix := append([]byte(nil), validPrefix...)
				badPrefix[tamperOffset] ^= 0x80
				rawC, rawS := t5TCPPair(t)
				go func() {
					_, _ = rawC.Write(badPrefix)
					_ = rawC.Close()
				}()
				_, acceptErr := aether.AcceptServerConn(context.Background(), rawS, aether.ServerConnOptions{
					Authenticator: auth,
					ReplayFilter:  replay,
				})
				require.ErrorIs(t, acceptErr, aether.ErrAuthenticationFailed)
			}

			// 2. Also probe with wrong password + same ClientSalt via raw AcceptServerConn.
			wrongCreds, err := aether.ParseOutboundCredentials(t5RandomKeyB64(t))
			require.NoError(t, err)
			initAEADWrong, err := aether.DeriveClientInitAEAD(wrongCreds.UPSK, clientHS.ClientSalt(), nil)
			require.NoError(t, err)
			wrongPrefix := append([]byte(nil), validPrefix...)
			var nonce0 [aether.AEADNonceSize]byte
			aether.EncodeNonce(0, &nonce0)
			aadLen := len(validPrefix) - aether.EncryptedFixedHdrSize
			initAEADWrong.Seal(wrongPrefix[aadLen:aadLen], nonce0[:], fixedPlain[:], wrongPrefix[:aadLen])
			rawC2, rawS2 := t5TCPPair(t)
			go func() {
				_, _ = rawC2.Write(wrongPrefix)
				_ = rawC2.Close()
			}()
			_, acceptErr := aether.AcceptServerConn(context.Background(), rawS2, aether.ServerConnOptions{
				Authenticator: auth,
				ReplayFilter:  replay,
			})
			require.ErrorIs(t, acceptErr, aether.ErrAuthenticationFailed)

			// 3. Now send the GENUINE handshake with the exact same ClientSalt: MUST succeed!
			rawC3, rawS3 := t5TCPPair(t)
			go func() {
				_, _ = rawC3.Write(append(append([]byte(nil), validPrefix...), encVar...))
			}()
			res, err := aether.AcceptServerConn(context.Background(), rawS3, aether.ServerConnOptions{
				Authenticator: auth,
				ReplayFilter:  replay,
			})
			require.NoError(t, err, "invalid AEAD probes must NEVER pollute Bloom filter")
			_ = res.Conn.Close()

			// 4. Replaying the valid handshake a second time MUST trigger ErrSaltReplayed.
			rawC4, rawS4 := t5TCPPair(t)
			go func() {
				_, _ = rawC4.Write(append(append([]byte(nil), validPrefix...), encVar...))
				_ = rawC4.Close()
			}()
			_, replayErr := aether.AcceptServerConn(context.Background(), rawS4, aether.ServerConnOptions{
				Authenticator: auth,
				ReplayFilter:  replay,
			})
			require.ErrorIs(t, replayErr, aether.ErrSaltReplayed)
		})
	}
}

func runT506HandshakeAADAndLowOrder(t *testing.T) {
	t.Parallel()

	srvSecret := t5RandomKeyB64(t)
	usrSecret := t5RandomKeyB64(t)
	authEIH, err := aether.NewServerAuthenticator(srvSecret, []option.AetherUser{{Name: "u1", Password: usrSecret}}, "")
	require.NoError(t, err)
	credsEIH, err := aether.ParseOutboundCredentials(srvSecret + ":" + usrSecret)
	require.NoError(t, err)

	fh := aether.FixedHeader{
		Version:      aether.ProtocolVersion,
		Command:      aether.CommandTCP,
		CipherSuite:  aether.CipherAES256GCM,
		TimestampSec: time.Now().Unix(),
		NoiseLen:     32,
		VarHeaderLen: 64,
	}
	fixedPlain, err := aether.EncodeFixedHeader(fh)
	require.NoError(t, err)

	clientHS, prefix112, err := aether.StartClientHandshake(credsEIH, nil, fixedPlain)
	require.NoError(t, err)
	require.Len(t, prefix112, aether.ClientPrefixEIHSize)

	// Test every AAD/tag region of 112B EIH prefix: ClientSalt(0..31), MaskedEPK(32..63), EIH(64..79), FixedCiphertext+Tag(80..111).
	for _, idx := range []int{0, 31, 32, 63, 64, 79, 80, 96, 111} {
		tampered := append([]byte(nil), prefix112...)
		tampered[idx] ^= 0x01
		_, _, openErr := authEIH.OpenClientFixedPrefix(tampered)
		require.ErrorIs(t, openErr, aether.ErrAuthenticationFailed, "byte %d", idx)
	}
	// Truncated/oversized prefix rejected.
	_, _, err = authEIH.OpenClientFixedPrefix(prefix112[:96])
	require.ErrorIs(t, err, aether.ErrAuthenticationFailed)

	// Open valid prefix and check VarHeader AAD/nonce separation.
	srvHS, _, err := authEIH.OpenClientFixedPrefix(prefix112)
	require.NoError(t, err)
	// Passing nonce=0 ciphertext (EncryptedFixedHeader) into OpenVarHeader (nonce=1) MUST fail!
	_, err = srvHS.OpenVarHeader(nil, prefix112[80:112])
	require.ErrorIs(t, err, aether.ErrAuthenticationFailed)

	// Seal valid VarHeader, tamper 1 byte -> rejected.
	varPlain, err := aether.EncodeVarHeader(nil, 32, M.ParseSocksaddrHostPort("127.0.0.1", 443), []byte("0rtt"))
	require.NoError(t, err)
	encVar := clientHS.SealVarHeader(nil, varPlain)
	badVar := append([]byte(nil), encVar...)
	badVar[len(badVar)-1] ^= 0x01
	_, err = srvHS.OpenVarHeader(nil, badVar)
	require.ErrorIs(t, err, aether.ErrAuthenticationFailed)

	gotVar, err := srvHS.OpenVarHeader(nil, encVar)
	require.NoError(t, err)
	require.Equal(t, varPlain, gotVar)

	// Complete server response -> tamper AAD (ServerSalt[0..31], MaskedServerEPK[32..63]) and tag[64..83].
	respPlain, err := aether.EncodeRespHeader(aether.CipherAES256GCM)
	require.NoError(t, err)
	respPrefix, _, _, err := srvHS.Complete(aether.CipherAES256GCM, respPlain)
	require.NoError(t, err)
	for _, idx := range []int{0, 31, 32, 63, 64, 83} {
		badResp := respPrefix
		badResp[idx] ^= 0x01
		_, _, _, cErr := clientHS.Complete(badResp[:], aether.CipherAES256GCM)
		require.Error(t, cErr, "resp byte %d", idx)
	}

	// Reject all 14 low-order Curve25519 points in ParseX25519PublicKey, ComputeECDH, and MaskedEPK handshakes.
	localPriv, err := ecdh.X25519().GenerateKey(rand.Reader)
	require.NoError(t, err)
	for _, hexPt := range t5LowOrderCurve25519Hex {
		pt := t5DecodeHex32(t, hexPt)
		_, parseErr := aether.ParseX25519PublicKey(base64.StdEncoding.EncodeToString(pt[:]))
		require.ErrorIs(t, parseErr, aether.ErrLowOrderX25519Point, "point=%s", hexPt)

		// Also inject low-order point masked as MaskedClientEPK into ServerHandshakeState.Complete!
		var salt [32]byte
		_, _ = io.ReadFull(rand.Reader, salt[:])
		maskedLow := aether.MaskEPK(credsEIH.UPSK, salt, pt)
		_, ecdhErr := aether.UnmaskAndECDH(localPriv, credsEIH.UPSK, salt, maskedLow)
		require.ErrorIs(t, ecdhErr, aether.ErrLowOrderX25519Point, "masked point=%s", hexPt)
	}

	// Clamped-zero X25519 private keys (low 3 bits or high bit set, variable bits zero) rejected.
	var clampedZeroPriv [32]byte
	clampedZeroPriv[0] = 0x07
	clampedZeroPriv[31] = 0xc0
	_, err = aether.ParseX25519PrivateKey(base64.StdEncoding.EncodeToString(clampedZeroPriv[:]))
	require.ErrorIs(t, err, aether.ErrAllZeroKey)
}

func runT507WireHeaderBoundaries(t *testing.T) {
	t.Parallel()

	// Exact NoiseLen [32..384] and VarHeaderLen (NoiseLen..16384] boundaries.
	valid := aether.FixedHeader{
		Version:      aether.ProtocolVersion,
		Command:      aether.CommandTCP,
		CipherSuite:  aether.CipherAES256GCM,
		Reserved:     0,
		TimestampSec: 1700000000,
		NoiseLen:     aether.MinNoiseLen,
		VarHeaderLen: aether.MinNoiseLen + 1,
	}
	_, err := aether.EncodeFixedHeader(valid)
	require.NoError(t, err)

	validMax := valid
	validMax.NoiseLen = aether.MaxNoiseLen
	validMax.VarHeaderLen = aether.MaxVarHeaderLen
	_, err = aether.EncodeFixedHeader(validMax)
	require.NoError(t, err)

	invalidHeaders := []struct {
		name string
		mod  func(*aether.FixedHeader)
		want error
	}{
		{"version_0x01", func(h *aether.FixedHeader) { h.Version = 0x01 }, aether.ErrInvalidVersion},
		{"version_0x03", func(h *aether.FixedHeader) { h.Version = 0x03 }, aether.ErrInvalidVersion},
		{"command_0x00", func(h *aether.FixedHeader) { h.Command = 0x00 }, aether.ErrInvalidCommand},
		{"command_0x05", func(h *aether.FixedHeader) { h.Command = 0x05 }, aether.ErrInvalidCommand},
		{"suite_0x00", func(h *aether.FixedHeader) { h.CipherSuite = 0x00 }, aether.ErrUnsupportedCipherSuite},
		{"suite_0x03", func(h *aether.FixedHeader) { h.CipherSuite = 0x03 }, aether.ErrUnsupportedCipherSuite},
		{"reserved_0x01", func(h *aether.FixedHeader) { h.Reserved = 0x01 }, aether.ErrInvalidReserved},
		{"noise_31", func(h *aether.FixedHeader) { h.NoiseLen = 31; h.VarHeaderLen = 64 }, aether.ErrInvalidNoiseLength},
		{"noise_385", func(h *aether.FixedHeader) { h.NoiseLen = 385; h.VarHeaderLen = 500 }, aether.ErrInvalidNoiseLength},
		{"var_equal_noise", func(h *aether.FixedHeader) { h.NoiseLen = 32; h.VarHeaderLen = 32 }, aether.ErrInvalidVarHeaderLen},
		{"var_less_noise", func(h *aether.FixedHeader) { h.NoiseLen = 32; h.VarHeaderLen = 31 }, aether.ErrInvalidVarHeaderLen},
		{"var_16385", func(h *aether.FixedHeader) { h.NoiseLen = 32; h.VarHeaderLen = 16385 }, aether.ErrInvalidVarHeaderLen},
	}
	for _, tc := range invalidHeaders {
		h := valid
		tc.mod(&h)
		_, e := aether.EncodeFixedHeader(h)
		require.ErrorIs(t, e, tc.want, tc.name)
	}

	// DecodeVarHeader invalid NoiseLen, VarHeaderLen, truncated Socksaddr (VarHeaderLen = NoiseLen + 1), bad family, empty FQDN.
	_, _, err = aether.DecodeVarHeader(make([]byte, 64), 31)
	require.ErrorIs(t, err, aether.ErrInvalidNoiseLength)
	_, _, err = aether.DecodeVarHeader(make([]byte, 64), 385)
	require.ErrorIs(t, err, aether.ErrInvalidNoiseLength)
	_, _, err = aether.DecodeVarHeader(make([]byte, 32), 32)
	require.ErrorIs(t, err, aether.ErrInvalidVarHeaderLen)
	_, _, err = aether.DecodeVarHeader(make([]byte, aether.MaxVarHeaderLen+1), 32)
	require.ErrorIs(t, err, aether.ErrInvalidVarHeaderLen)

	// VarHeaderLen == NoiseLen + 1 (cannot hold valid Socksaddr).
	_, _, err = aether.DecodeVarHeader(make([]byte, 33), 32)
	require.ErrorIs(t, err, aether.ErrInvalidVarHeader)

	// Invalid Socksaddr family 0x7f.
	badFam := make([]byte, 48)
	badFam[32] = 0x7f
	_, _, err = aether.DecodeVarHeader(badFam, 32)
	require.ErrorIs(t, err, aether.ErrInvalidVarHeader)

	// Empty FQDN (0x03, len=0) -> !IsValid().
	emptyFQDN := make([]byte, 40)
	emptyFQDN[32] = 0x03
	emptyFQDN[33] = 0x00
	_, _, err = aether.DecodeVarHeader(emptyFQDN, 32)
	require.ErrorIs(t, err, aether.ErrInvalidVarHeader)

	// EncodeVarHeader rejecting invalid TargetAddr and payload > MaxInitialPayloadLen.
	addr := M.ParseSocksaddrHostPort("127.0.0.1", 443)
	maxInit := aether.MaxInitialPayloadLen(64, addr)
	_, err = aether.EncodeVarHeader(nil, 64, M.Socksaddr{}, []byte("x"))
	require.ErrorIs(t, err, aether.ErrInvalidVarHeader)
	_, err = aether.EncodeVarHeader(nil, 64, addr, make([]byte, maxInit+1))
	require.ErrorIs(t, err, aether.ErrInvalidVarHeaderLen)
}

// t5OpenTestSession performs a raw wire client handshake against AcceptServerConn
// while returning the raw client-side keys so tests can inject adversarial wire frames.
func t5OpenTestSession(t *testing.T, suite uint8) (net.Conn, *aether.Conn, [32]byte, [32]byte, *aether.DirectionalCipher) {
	t.Helper()
	rawC, rawS := t5TCPPair(t)

	secret := t5RandomKeyB64(t)
	creds, err := aether.ParseOutboundCredentials(secret)
	require.NoError(t, err)
	auth, err := aether.NewServerAuthenticator(secret, nil, "")
	require.NoError(t, err)
	replay := aether.NewSlidingBloomFilter(aether.DefaultTimeWindow, nil)

	type srvRes struct {
		res *aether.ServerAcceptResult
		err error
	}
	srvCh := make(chan srvRes, 1)
	go func() {
		r, aErr := aether.AcceptServerConn(context.Background(), rawS, aether.ServerConnOptions{
			Authenticator:     auth,
			ReplayFilter:      replay,
			HeartbeatInterval: -1,
			DisableShaping:    true,
		})
		srvCh <- srvRes{res: r, err: aErr}
	}()

	addr := M.ParseSocksaddrHostPort("127.0.0.1", 80)
	varPlain, err := aether.EncodeVarHeader(nil, 32, addr, nil)
	require.NoError(t, err)
	fh := aether.FixedHeader{
		Version:      aether.ProtocolVersion,
		Command:      aether.CommandTCP,
		CipherSuite:  suite,
		TimestampSec: time.Now().Unix(),
		NoiseLen:     32,
		VarHeaderLen: uint16(len(varPlain)),
	}
	fixedPlain, err := aether.EncodeFixedHeader(fh)
	require.NoError(t, err)

	clientSalt, err := aether.GenerateRandomSalt()
	require.NoError(t, err)
	ekC, maskedClientEPK, err := aether.GenerateMaskedEPK(creds.UPSK, clientSalt)
	require.NoError(t, err)
	initAEAD, err := aether.DeriveClientInitAEAD(creds.UPSK, clientSalt, nil)
	require.NoError(t, err)

	var nonce0, nonce1 [aether.AEADNonceSize]byte
	aether.EncodeNonce(0, &nonce0)
	aether.EncodeNonce(1, &nonce1)

	prefix := make([]byte, aether.ClientPrefixNoEIHSize)
	copy(prefix[0:32], clientSalt[:])
	copy(prefix[32:64], maskedClientEPK[:])
	initAEAD.Seal(prefix[64:64], nonce0[:], fixedPlain[:], prefix[0:64])
	encVar := initAEAD.Seal(nil, nonce1[:], varPlain, fixedPlain[:])

	_, err = rawC.Write(append(prefix, encVar...))
	require.NoError(t, err)

	sr := <-srvCh
	require.NoError(t, sr.err)
	srvConn := sr.res.Conn

	// Trigger server's ServerRespPrefix coalesced frame (or wait 100ms timer).
	_, err = srvConn.Write([]byte("S"))
	require.NoError(t, err)

	var respPrefix [aether.ServerRespPrefixSize]byte
	_, err = io.ReadFull(rawC, respPrefix[:])
	require.NoError(t, err)

	var serverSalt, maskedSrvEPK [32]byte
	copy(serverSalt[:], respPrefix[0:32])
	copy(maskedSrvEPK[:], respPrefix[32:64])
	ssEph, err := aether.UnmaskAndECDH(ekC, creds.UPSK, serverSalt, maskedSrvEPK)
	require.NoError(t, err)
	keys, err := aether.DeriveSessionKeys(creds.UPSK, ssEph, nil, clientSalt, serverSalt)
	require.NoError(t, err)

	recvCipher, err := aether.NewDirectionalCipher(suite, keys.S2CHeaderKey, keys.S2CPayloadKey)
	require.NoError(t, err)

	var lenHdr [aether.EncryptedLengthSize]byte
	_, err = io.ReadFull(rawC, lenHdr[:])
	require.NoError(t, err)
	plainLen, err := recvCipher.OpenLengthHeader(lenHdr[:])
	require.NoError(t, err)
	encBody := make([]byte, int(plainLen)+aether.AEADTagSize)
	_, err = io.ReadFull(rawC, encBody)
	require.NoError(t, err)
	plainBody, err := recvCipher.OpenPayloadBody(nil, encBody)
	require.NoError(t, err)
	ft, data, err := aether.ParseFrameBody(plainBody)
	require.NoError(t, err)
	require.Equal(t, aether.FrameData, ft)
	require.Equal(t, []byte("S"), data)

	sendCipher, err := aether.NewDirectionalCipher(suite, keys.C2SHeaderKey, keys.C2SPayloadKey)
	require.NoError(t, err)
	return rawC, srvConn, keys.C2SHeaderKey, keys.C2SPayloadKey, sendCipher
}

func t5SealRawCustomFrame(t testing.TB, suite uint8, hdrKey, payKey [32]byte, seq uint64, wirePlainLenField uint16, bodyPlain []byte) []byte {
	t.Helper()
	hdrAEAD, err := aether.NewDataAEAD(suite, hdrKey)
	require.NoError(t, err)
	payAEAD, err := aether.NewDataAEAD(suite, payKey)
	require.NoError(t, err)

	var nonce [aether.AEADNonceSize]byte
	aether.EncodeNonce(seq, &nonce)
	var lenPlain [2]byte
	binary.BigEndian.PutUint16(lenPlain[:], wirePlainLenField)
	out := hdrAEAD.Seal(nil, nonce[:], lenPlain[:], nil)
	if bodyPlain != nil {
		out = payAEAD.Seal(out, nonce[:], bodyPlain, nil)
	}
	return out
}

func runT508MalformedFramesAndChaff(t *testing.T) {
	t.Parallel()

	// 1. DirectionalCipher & ParseFrameBody unit-level boundaries across both AEAD suites.
	for _, suite := range []uint8{aether.CipherAES256GCM, aether.CipherChaCha20Poly1305} {
		var hdrKey, payKey [32]byte
		_, _ = io.ReadFull(rand.Reader, hdrKey[:])
		_, _ = io.ReadFull(rand.Reader, payKey[:])

		dcSend, err := aether.NewDirectionalCipher(suite, hdrKey, payKey)
		require.NoError(t, err)
		dcRecv, err := aether.NewDirectionalCipher(suite, hdrKey, payKey)
		require.NoError(t, err)

		// SealFrame rejects body < 2 or > 16641.
		_, err = dcSend.SealFrame(nil, []byte{0x01})
		require.ErrorIs(t, err, aether.ErrInvalidFrameLength)
		_, err = dcSend.SealFrame(nil, make([]byte, aether.MaxFramePlainSize+1))
		require.ErrorIs(t, err, aether.ErrInvalidFrameLength)

		// OpenLengthHeader rejects wrong slice length and does NOT advance seq on OpenPayloadBody failure.
		_, err = dcRecv.OpenLengthHeader(make([]byte, 17))
		require.ErrorIs(t, err, aether.ErrInvalidFrameLength)

		validBody, err := aether.AppendFrameBody(nil, aether.FrameData, 4, []byte("abc"))
		require.NoError(t, err)
		wireFrame, err := dcSend.SealFrame(nil, validBody)
		require.NoError(t, err)

		// Tamper length header -> fails without advancing seq.
		badHdr := append([]byte(nil), wireFrame[:aether.EncryptedLengthSize]...)
		badHdr[len(badHdr)-1] ^= 0x01
		_, err = dcRecv.OpenLengthHeader(badHdr)
		require.Error(t, err)
		require.Equal(t, uint64(0), dcRecv.Seq())

		// Open valid length header, tamper payload tag -> fails without advancing seq.
		pLen, err := dcRecv.OpenLengthHeader(wireFrame[:aether.EncryptedLengthSize])
		require.NoError(t, err)
		require.Equal(t, uint16(len(validBody)), pLen)
		badBody := append([]byte(nil), wireFrame[aether.EncryptedLengthSize:]...)
		badBody[len(badBody)-1] ^= 0x01
		_, err = dcRecv.OpenPayloadBody(nil, badBody)
		require.Error(t, err)
		require.Equal(t, uint64(0), dcRecv.Seq())

		// Re-opening at seq=0 with genuine ciphertext succeeds and advances seq to 1.
		pLen, err = dcRecv.OpenLengthHeader(wireFrame[:aether.EncryptedLengthSize])
		require.NoError(t, err)
		gotPlain, err := dcRecv.OpenPayloadBody(nil, wireFrame[aether.EncryptedLengthSize:])
		require.NoError(t, err)
		require.Equal(t, validBody, gotPlain)
		require.Equal(t, uint64(1), dcRecv.Seq())
		// Replaying frame 0 at seq=1 fails.
		_, err = dcRecv.OpenLengthHeader(wireFrame[:aether.EncryptedLengthSize])
		require.Error(t, err)
	}

	// 2. Live Conn wire injection: chaff skip, out-of-range PlainFrameLen, PadLen > PlainFrameLen-2, unknown FrameType, malformed control.
	t.Run("live_chaff_then_data", func(t *testing.T) {
		rawC, srvConn, hdrKey, payKey, _ := t5OpenTestSession(t, aether.CipherAES256GCM)
		defer srvConn.Close()
		defer rawC.Close()

		// Seq 0: valid 0-byte FrameData chaff with PadLen=16 -> Read must skip and NOT return (0, nil).
		chaffBody, err := aether.AppendFrameBody(nil, aether.FrameData, 16, nil)
		require.NoError(t, err)
		f0 := t5SealRawCustomFrame(t, aether.CipherAES256GCM, hdrKey, payKey, 0, uint16(len(chaffBody)), chaffBody)
		realBody, err := aether.AppendFrameBody(nil, aether.FrameData, 0, []byte("after-chaff"))
		require.NoError(t, err)
		f1 := t5SealRawCustomFrame(t, aether.CipherAES256GCM, hdrKey, payKey, 1, uint16(len(realBody)), realBody)

		_, err = rawC.Write(append(f0, f1...))
		require.NoError(t, err)

		bufOut := make([]byte, 32)
		n, err := srvConn.Read(bufOut)
		require.NoError(t, err)
		require.Equal(t, []byte("after-chaff"), bufOut[:n])
	})

	wireRejectCases := []struct {
		name      string
		plainLen  uint16
		bodyPlain []byte
		wantErr   error
	}{
		{"plainLen_1_lt_2", 1, nil, aether.ErrInvalidFrameLength},
		{"plainLen_0_lt_2", 0, nil, aether.ErrInvalidFrameLength},
		{"plainLen_16642_gt_16641", aether.MaxFramePlainSize + 1, nil, aether.ErrInvalidFrameLength},
		{"padLen_exceeds_plainLen", 2, []byte{aether.FrameData, 0x01}, aether.ErrInvalidFramePadding},
		{"unknown_frame_type_0x00", 2, []byte{0x00, 0x00}, aether.ErrInvalidFrameType},
		{"unknown_frame_type_0x05", 3, []byte{0x05, 0x00, 0xaa}, aether.ErrInvalidFrameType},
		{"ping_pad_31", 33, append([]byte{aether.FramePing, 31}, make([]byte, 31)...), aether.ErrMalformedControlFrame},
		{"pong_with_data", 35, append([]byte{aether.FramePong, 32}, make([]byte, 33)...), aether.ErrMalformedControlFrame},
		{"close_write_with_data", 3, []byte{aether.FrameCloseWrite, 0, 0x01}, aether.ErrMalformedControlFrame},
	}

	for _, tc := range wireRejectCases {
		t.Run("live_reject_"+tc.name, func(t *testing.T) {
			rawC, srvConn, hdrKey, payKey, _ := t5OpenTestSession(t, aether.CipherChaCha20Poly1305)
			defer srvConn.Close()
			defer rawC.Close()

			wireBytes := t5SealRawCustomFrame(t, aether.CipherChaCha20Poly1305, hdrKey, payKey, 0, tc.plainLen, tc.bodyPlain)
			_, err := rawC.Write(wireBytes)
			require.NoError(t, err)

			_ = srvConn.SetReadDeadline(time.Now().Add(2 * time.Second))
			var out [16]byte
			_, err = srvConn.Read(out[:])
			require.ErrorIs(t, err, tc.wantErr)
		})
	}
}

func runT509SemaphoreSaturation(t *testing.T) {
	t.Parallel()

	// Use production defaults: HandshakeLimit = 256, DrainLimit = 512.
	dg := aether.NewDrainGuard(aether.DrainGuardOptions{})
	require.Equal(t, 0, dg.HandshakeInFlight())
	require.Equal(t, 0, dg.DrainInFlight())

	// Saturate all 256 handshakeSem slots.
	releases := make([]func(), 0, aether.DefaultHandshakeLimit)
	for i := range aether.DefaultHandshakeLimit {
		rel, ok := dg.TryAcquireHandshake()
		require.True(t, ok, "slot %d", i)
		releases = append(releases, rel)
	}
	require.Equal(t, aether.DefaultHandshakeLimit, dg.HandshakeInFlight())

	// 257th TryAcquireHandshake fails immediately; AcquireHandshake respects ctx deadline.
	_, ok := dg.TryAcquireHandshake()
	require.False(t, ok)
	waitCtx, cancelWait := context.WithTimeout(context.Background(), 20*time.Millisecond)
	_, ok = dg.AcquireHandshake(waitCtx)
	cancelWait()
	require.False(t, ok)

	// Idempotent double-release only frees ONE slot!
	releases[0]()
	releases[0]()
	require.Equal(t, aether.DefaultHandshakeLimit-1, dg.HandshakeInFlight())

	// Re-acquire the freed slot, then release all.
	relExtra, ok := dg.TryAcquireHandshake()
	require.True(t, ok)
	require.Equal(t, aether.DefaultHandshakeLimit, dg.HandshakeInFlight())
	relExtra()
	for i := 1; i < len(releases); i++ {
		releases[i]()
	}
	require.Equal(t, 0, dg.HandshakeInFlight())

	// Saturate all 512 drainSem slots concurrently with live pipes/sockets, verify 513th sheds via clean FIN.
	drainCtx, cancelDrain := context.WithCancel(context.Background())
	defer cancelDrain()

	var wg sync.WaitGroup
	peerEnds := make([]net.Conn, 0, aether.DefaultDrainLimit)
	for range aether.DefaultDrainLimit {
		cEnd, sEnd := net.Pipe()
		peerEnds = append(peerEnds, cEnd)
		wg.Add(1)
		go func(srv net.Conn) {
			defer wg.Done()
			dg.StealthDrain(drainCtx, srv, "198.51.100.1", aether.ReasonAuthFailed, aether.ErrAuthenticationFailed, nil)
		}(sEnd)
	}

	deadline := time.Now().Add(3 * time.Second)
	for dg.DrainInFlight() < aether.DefaultDrainLimit && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	require.Equal(t, aether.DefaultDrainLimit, dg.DrainInFlight())

	// 513th StealthDrain over real TCP loopback must shed IMMEDIATELY via clean TCP FIN (never RST, never block).
	shedClient, shedServer := t5TCPPair(t)
	var shedClosed atomic.Bool
	var shedErr error
	start := time.Now()
	dg.StealthDrain(drainCtx, shedServer, "198.51.100.2", aether.ReasonAuthFailed, aether.ErrAuthenticationFailed, func(err error) {
		shedErr = err
		shedClosed.Store(true)
	})
	require.Less(t, time.Since(start), 500*time.Millisecond)
	require.True(t, shedClosed.Load())
	require.ErrorIs(t, shedErr, aether.ErrAuthenticationFailed)

	_ = shedClient.SetReadDeadline(time.Now().Add(time.Second))
	var b [1]byte
	_, readErr := shedClient.Read(b[:])
	require.True(t, IsCleanEOF(readErr), "expected clean TCP FIN EOF, got %v", readErr)
	require.False(t, IsConnReset(readErr))

	cancelDrain()
	for _, cEnd := range peerEnds {
		_ = cEnd.Close()
	}
	wg.Wait()
	require.Equal(t, 0, dg.DrainInFlight())
}

func runT510StealthDrainFINAndCancel(t *testing.T) {
	t.Parallel()

	// 1. Production [3s, 10s] defaults on early client FIN: server must hold socket open for [3s, 10s]
	// and close cleanly with TCP FIN (never RST).
	dg := aether.NewDrainGuard(aether.DrainGuardOptions{})
	rawC, rawS := t5TCPPair(t)

	// Client sends 96B garbage and immediately half-closes (TCP FIN) at t=0.
	garbage := make([]byte, 96)
	_, _ = io.ReadFull(rand.Reader, garbage)
	_, err := rawC.Write(garbage)
	require.NoError(t, err)
	tcpC := rawC.(*net.TCPConn)
	require.NoError(t, tcpC.CloseWrite())

	var onCloseCalled atomic.Bool
	start := time.Now()
	drainDone := make(chan struct{})
	go func() {
		dg.StealthDrain(context.Background(), rawS, "203.0.113.10", aether.ReasonAuthFailed, aether.ErrAuthenticationFailed, func(e error) {
			onCloseCalled.Store(errors.Is(e, aether.ErrAuthenticationFailed))
		})
		close(drainDone)
	}()

	_ = tcpC.SetReadDeadline(time.Now().Add(12 * time.Second))
	var rbuf [16]byte
	_, readErr := tcpC.Read(rbuf[:])
	elapsed := time.Since(start)
	<-drainDone

	require.True(t, onCloseCalled.Load())
	require.True(t, IsCleanEOF(readErr), "expected clean TCP FIN EOF, got %v", readErr)
	require.False(t, IsConnReset(readErr))
	require.GreaterOrEqual(t, elapsed, 2900*time.Millisecond, "early FIN bypassed [3s, 10s] StealthDrain")
	require.LessOrEqual(t, elapsed, 10800*time.Millisecond, "StealthDrain exceeded 10s bound")

	// 2. Context cancellation immediately aborts an active [3s, 10s] StealthDrain.
	rawC2, rawS2 := t5TCPPair(t)
	ctx, cancel := context.WithCancel(context.Background())
	var done2 atomic.Bool
	ch2 := make(chan struct{})
	start2 := time.Now()
	go func() {
		dg.StealthDrain(ctx, rawS2, "203.0.113.11", aether.ReasonMalformed, aether.ErrInvalidVarHeader, func(_ error) {
			done2.Store(true)
		})
		close(ch2)
	}()
	time.Sleep(50 * time.Millisecond)
	cancel()
	<-ch2
	require.Less(t, time.Since(start2), 1*time.Second)
	require.True(t, done2.Load())

	_ = rawC2.SetReadDeadline(time.Now().Add(time.Second))
	_, err2 := rawC2.Read(rbuf[:])
	require.True(t, IsCleanEOF(err2), "expected clean FIN on ctx cancel, got %v", err2)
}

func runT511RateLimitConcurrency(t *testing.T) {
	t.Parallel()

	var nowNs atomic.Int64
	base := time.Unix(1750000000, 0)
	nowNs.Store(base.UnixNano())
	logSpy := &t5CountingLogger{}

	dg := aether.NewDrainGuard(aether.DrainGuardOptions{
		LogInterval: 10 * time.Second,
		Logger:      logSpy,
		NowFunc:     func() time.Time { return time.Unix(0, nowNs.Load()) },
	})

	// Same IP within 10s logs once; after +10s logs a second time.
	dg.CloseTimeout(context.Background(), nil, "192.0.2.50", aether.ReasonTimeout, context.DeadlineExceeded, nil)
	dg.CloseTimeout(context.Background(), nil, "192.0.2.50", aether.ReasonTimeout, context.DeadlineExceeded, nil)
	require.Equal(t, 1, logSpy.warnCount())

	nowNs.Store(base.Add(10 * time.Second).UnixNano())
	dg.CloseTimeout(context.Background(), nil, "192.0.2.50", aether.ReasonTimeout, context.DeadlineExceeded, nil)
	require.Equal(t, 2, logSpy.warnCount())

	// Concurrent 10,000 distinct IPs stress test exceeding maxWarnMapEntries (4096).
	const goroutines = 16
	const perG = 625
	var wg sync.WaitGroup
	for g := range goroutines {
		wg.Add(1)
		go func(gid int) {
			defer wg.Done()
			for i := range perG {
				ip := fmt.Sprintf("10.%d.%d.%d", gid, i/250, i%250)
				dg.CloseTimeout(context.Background(), nil, ip, aether.ReasonAuthFailed, aether.ErrAuthenticationFailed, nil)
				if i%100 == 0 {
					nowNs.Add(int64(time.Second))
				}
			}
		}(g)
	}
	wg.Wait()
	require.Equal(t, 2+goroutines*perG, logSpy.warnCount())
}

func runT512ExtendedConnBuffers(t *testing.T) {
	t.Parallel()

	clientConn, srvConn, _, _ := t5EstablishedPair(t, aether.CommandTCP, aether.CipherAES256GCM, -1, false)

	// ExtendedConn & EarlyConn interface invariants.
	for _, c := range []*aether.Conn{clientConn, srvConn} {
		require.False(t, c.ReaderReplaceable())
		require.False(t, c.WriterReplaceable())
		require.Equal(t, aether.EncryptedLengthSize+aether.MinFramePlainSize, c.FrontHeadroom())
		require.Equal(t, aether.AEADTagSize, c.RearHeadroom())
		require.Equal(t, aether.MaxFrameDataSize, c.WriterMTU())
		require.NotNil(t, c.Upstream())
	}

	// WriteBuffer releases pooled buffer on success; ReadBuffer does NOT release caller buffer.
	wb := buf.New()
	_, err := wb.WriteString("zero-copy-payload")
	require.NoError(t, err)
	require.NoError(t, clientConn.WriteBuffer(wb))
	require.Zero(t, wb.Cap(), "WriteBuffer must release buffer on success")
	require.Zero(t, wb.RawCap())

	rb := buf.New()
	defer rb.Release()
	require.NoError(t, srvConn.ReadBuffer(rb))
	require.Equal(t, "zero-copy-payload", string(rb.Bytes()))
	require.Positive(t, rb.Cap(), "ReadBuffer must preserve caller buffer ownership")

	// ReadBuffer with 0 FreeLen returns io.ErrShortBuffer without losing unread buffered data.
	_, err = clientConn.Write([]byte("partial-check"))
	require.NoError(t, err)
	fullBuf := buf.With(make([]byte, 0))
	err = srvConn.ReadBuffer(fullBuf)
	require.ErrorIs(t, err, io.ErrShortBuffer)
	rb2 := buf.New()
	defer rb2.Release()
	require.NoError(t, srvConn.ReadBuffer(rb2))
	require.Equal(t, "partial-check", string(rb2.Bytes()))

	// WriteBuffer on writeBroken fuses error AND releases buffer.
	require.NoError(t, clientConn.SetWriteDeadline(time.Now().Add(-time.Second)))
	_, err = clientConn.Write([]byte("trigger-fuse"))
	require.ErrorIs(t, err, os.ErrDeadlineExceeded)

	wbBroken := buf.New()
	_, _ = wbBroken.WriteString("after-fuse")
	err = clientConn.WriteBuffer(wbBroken)
	require.ErrorIs(t, err, net.ErrClosed)
	require.Zero(t, wbBroken.Cap(), "WriteBuffer must release buffer on writeBroken")

	// WriteBuffer on closed Conn releases buffer too.
	require.NoError(t, clientConn.Close())
	wbClosed := buf.New()
	_, _ = wbClosed.WriteString("after-close")
	err = clientConn.WriteBuffer(wbClosed)
	require.ErrorIs(t, err, net.ErrClosed)
	require.Zero(t, wbClosed.Cap(), "WriteBuffer must release buffer on closed conn")

	// PacketConn invariants & buffer release on success + every error path.
	cPktConn, sPktConn, _, _ := t5EstablishedPair(t, aether.CommandUDP, aether.CipherChaCha20Poly1305, -1, true)
	cp := aether.NewClientPacketConn(cPktConn)
	sp := aether.NewServerPacketConn(sPktConn)
	for _, pc := range []interface {
		ReaderReplaceable() bool
		WriterReplaceable() bool
		FrontHeadroom() int
		RearHeadroom() int
		Upstream() any
	}{cp, sp} {
		require.False(t, pc.ReaderReplaceable())
		require.False(t, pc.WriterReplaceable())
		require.Zero(t, pc.FrontHeadroom())
		require.Zero(t, pc.RearHeadroom())
		require.NotNil(t, pc.Upstream())
	}

	dest := M.ParseSocksaddrHostPort("198.51.100.1", 5353)
	pbOK := buf.NewPacket()
	_, _ = pbOK.WriteString("udp-ok")
	require.NoError(t, cp.WritePacket(pbOK, dest))
	require.Zero(t, pbOK.Cap(), "WritePacket must release buffer on success")

	rpBuf := buf.NewPacket()
	defer rpBuf.Release()
	gotDest, err := sp.ReadPacket(rpBuf)
	require.NoError(t, err)
	require.Equal(t, dest.String(), gotDest.String())
	require.Equal(t, "udp-ok", string(rpBuf.Bytes()))
	require.Positive(t, rpBuf.Cap(), "ReadPacket must preserve caller buffer ownership")

	// WritePacket error paths still release buffer.
	pbBadDest := buf.NewPacket()
	_, _ = pbBadDest.WriteString("x")
	err = cp.WritePacket(pbBadDest, M.Socksaddr{})
	require.ErrorIs(t, err, aether.ErrInvalidVarHeader)
	require.Zero(t, pbBadDest.Cap())

	pbTooBig := buf.NewSize(65536)
	pbTooBig.Extend(65536)
	err = cp.WritePacket(pbTooBig, dest)
	require.ErrorIs(t, err, aether.ErrPacketTooLarge)
	// buf.NewSize(65536) may or may not be pool-managed; nil-conn PacketConn with managed buf.NewPacket():
	nilPC := aether.NewClientPacketConn(nil)
	pbNilConn := buf.NewPacket()
	_, _ = pbNilConn.WriteString("z")
	err = nilPC.WritePacket(pbNilConn, dest)
	require.ErrorIs(t, err, net.ErrClosed)
	require.Zero(t, pbNilConn.Cap())
}

func runT513WriteBrokenAndDeadlines(t *testing.T) {
	t.Parallel()

	// 1. ReadDeadline timeout does NOT kill background readLoop or control-plane Ping/Pong.
	clientConn, srvConn, _, _ := t5EstablishedPair(t, aether.CommandTCP, aether.CipherAES256GCM, 80*time.Millisecond, true)

	require.NoError(t, clientConn.SetReadDeadline(time.Now().Add(30*time.Millisecond)))
	var tmp [32]byte
	_, err := clientConn.Read(tmp[:])
	require.ErrorIs(t, err, os.ErrDeadlineExceeded)

	// Clear read deadline and let heartbeat run for >200ms while checking connection stays healthy!
	require.NoError(t, clientConn.SetReadDeadline(time.Time{}))
	time.Sleep(220 * time.Millisecond)

	_, err = srvConn.Write([]byte("still-alive-after-read-timeout"))
	require.NoError(t, err)
	n, err := io.ReadFull(clientConn, tmp[:len("still-alive-after-read-timeout")])
	require.NoError(t, err)
	require.Equal(t, "still-alive-after-read-timeout", string(tmp[:n]))

	// 2. WriteDeadline expiration permanently fuses writeBroken even after SetWriteDeadline(zero).
	require.NoError(t, clientConn.SetWriteDeadline(time.Now().Add(-time.Millisecond)))
	_, err = clientConn.Write([]byte("expired"))
	require.ErrorIs(t, err, os.ErrDeadlineExceeded)

	require.NoError(t, clientConn.SetWriteDeadline(time.Time{}))
	_, err = clientConn.Write([]byte("must-stay-broken"))
	require.ErrorIs(t, err, net.ErrClosed)
	err = clientConn.CloseWrite()
	require.ErrorIs(t, err, net.ErrClosed)

	// 3. Physical rawConn write failure fuses writeBroken and closes socket.
	c2, s2, rawSpyC2, _ := t5EstablishedPair(t, aether.CommandTCP, aether.CipherChaCha20Poly1305, -1, true)
	_ = rawSpyC2.Conn.Close()
	_, err = c2.Write([]byte("physical-error"))
	require.Error(t, err)
	_, err = c2.Write([]byte("fused"))
	require.ErrorIs(t, err, net.ErrClosed)
	_ = s2.Close()
}

func runT514CloseWriteRaceStress(t *testing.T) {
	t.Parallel()

	// 1. Deterministic half-close semantics: client CloseWrite -> server drains data + gets io.EOF,
	// while server writes response and client reads it cleanly before server CloseWrite.
	clientConn, srvConn, _, _ := t5EstablishedPair(t, aether.CommandTCP, aether.CipherAES256GCM, -1, false)
	_, err := clientConn.Write([]byte("request-body"))
	require.NoError(t, err)
	require.NoError(t, clientConn.CloseWrite())
	// Second CloseWrite is idempotent.
	require.NoError(t, clientConn.CloseWrite())
	// Write after CloseWrite returns net.ErrClosed.
	_, err = clientConn.Write([]byte("after-close-write"))
	require.ErrorIs(t, err, net.ErrClosed)

	gotReq, err := io.ReadAll(srvConn)
	require.NoError(t, err)
	require.Equal(t, []byte("request-body"), gotReq)

	_, err = srvConn.Write([]byte("response-after-client-fin"))
	require.NoError(t, err)
	require.NoError(t, srvConn.CloseWrite())

	gotResp, err := io.ReadAll(clientConn)
	require.NoError(t, err)
	require.Equal(t, []byte("response-after-client-fin"), gotResp)

	// 2. Concurrent -race stress across Read, ReadBuffer, Write, WriteBuffer, CloseWrite, Set*Deadline, Close.
	for round := range 8 {
		c, s, _, _ := t5EstablishedPair(t, aether.CommandTCP, aether.CipherAES256GCM, 35*time.Millisecond, false)
		var wg sync.WaitGroup
		startGate := make(chan struct{})

		wg.Add(6)
		go func() {
			defer wg.Done()
			<-startGate
			var b [128]byte
			for range 40 {
				if _, rErr := c.Read(b[:]); rErr != nil && !errors.Is(rErr, os.ErrDeadlineExceeded) {
					return
				}
			}
		}()
		go func() {
			defer wg.Done()
			<-startGate
			for range 40 {
				rb := buf.New()
				rErr := c.ReadBuffer(rb)
				rb.Release()
				if rErr != nil && !errors.Is(rErr, os.ErrDeadlineExceeded) {
					return
				}
			}
		}()
		go func() {
			defer wg.Done()
			<-startGate
			for i := range 30 {
				wb := buf.New()
				_, _ = wb.WriteString("stress-msg")
				if wErr := c.WriteBuffer(wb); wErr != nil {
					return
				}
				if i == 15 {
					_ = c.CloseWrite()
				}
			}
		}()
		go func() {
			defer wg.Done()
			<-startGate
			for i := range 40 {
				if i%2 == 0 {
					_ = c.SetReadDeadline(time.Now().Add(5 * time.Millisecond))
					_ = c.SetWriteDeadline(time.Now().Add(200 * time.Millisecond))
				} else {
					_ = c.SetDeadline(time.Time{})
				}
				time.Sleep(time.Millisecond)
			}
		}()
		go func() {
			defer wg.Done()
			<-startGate
			var b [128]byte
			for range 40 {
				if _, rErr := s.Read(b[:]); rErr != nil {
					return
				}
				_, _ = s.Write([]byte("pong-data"))
			}
		}()
		go func() {
			defer wg.Done()
			<-startGate
			time.Sleep(time.Duration(10+round*2) * time.Millisecond)
			_ = c.Close()
			_ = s.Close()
		}()

		close(startGate)
		wg.Wait()
	}
}

func runT515HeadOnlyShapingFrames(t *testing.T) {
	t.Parallel()

	// Case 1: Frames 0..4 small Data + Frame 5 CloseWrite -> ALL 6 frames MUST carry PadLen in [16, 255].
	// Use server side after handshake (with DisableShaping=false) where initial 1B handshake ack was Frame 0,
	// OR construct fresh ServerConn right after AcceptServerConn before any write!
	rawC, rawS := t5TCPPair(t)
	spyS := &t5SpyRawConn{Conn: rawS}

	secret := t5RandomKeyB64(t)
	creds, err := aether.ParseOutboundCredentials(secret)
	require.NoError(t, err)
	auth, err := aether.NewServerAuthenticator(secret, nil, "")
	require.NoError(t, err)
	replay := aether.NewSlidingBloomFilter(aether.DefaultTimeWindow, nil)

	clientConn, err := aether.DialEarlyConnContext(context.Background(), rawC, aether.ClientConnOptions{
		Credentials:       creds,
		Command:           aether.CommandTCP,
		CipherSuite:       aether.CipherAES256GCM,
		TargetAddr:        M.ParseSocksaddrHostPort("127.0.0.1", 80),
		HeartbeatInterval: -1,
		DisableShaping:    false,
	})
	require.NoError(t, err)

	srvCh := make(chan *aether.ServerAcceptResult, 1)
	go func() {
		res, aErr := aether.AcceptServerConn(context.Background(), spyS, aether.ServerConnOptions{
			Authenticator:     auth,
			ReplayFilter:      replay,
			HeartbeatInterval: -1,
			DisableShaping:    false,
		})
		require.NoError(t, aErr)
		srvCh <- res
	}()

	_, err = clientConn.Write([]byte("init"))
	require.NoError(t, err)
	srvRes := <-srvCh
	srvConn := srvRes.Conn

	// Drain client's 4B initial payload so readLoop stays clear.
	var initGot [4]byte
	_, err = io.ReadFull(srvConn, initGot[:])
	require.NoError(t, err)

	// Send Frames 0..4 (each 10B FrameData), then Frame 5 (FrameCloseWrite).
	for range 5 {
		_, wErr := srvConn.Write([]byte("0123456789"))
		require.NoError(t, wErr)
	}
	require.NoError(t, srvConn.CloseWrite())

	// Client drains all 50B + EOF.
	gotAll, err := io.ReadAll(clientConn)
	require.NoError(t, err)
	require.Equal(t, bytes.Repeat([]byte("0123456789"), 5), gotAll)

	srvWrites := spyS.snapshotWrites()
	require.Len(t, srvWrites, 6, "expected exactly 6 wire writes for Frames 0..5")
	for idx, w := range srvWrites {
		frameLen := len(w)
		if idx == 0 {
			require.Greater(t, frameLen, aether.ServerRespPrefixSize)
			frameLen -= aether.ServerRespPrefixSize
		}
		dataLen := 10
		if idx == 5 {
			dataLen = 0 // FrameCloseWrite
		}
		padLen := frameLen - 36 - dataLen
		require.GreaterOrEqual(t, padLen, aether.ShapingPadMin, "frame %d padLen=%d", idx, padLen)
		require.LessOrEqual(t, padLen, aether.ShapingPadMax, "frame %d padLen=%d", idx, padLen)
	}
	_ = clientConn.Close()
	_ = srvConn.Close()

	// Case 2: Frames 0..5 with >1200B split chunks -> Frame 6 (16384B unpadded) + Frame 7 CloseWrite (unpadded 36B).
	c2, s2, _, spyS2 := t5EstablishedPair(t, aether.CommandTCP, aether.CipherAES256GCM, -1, false)
	//Note: t5EstablishedPair sent 1 FrameData on s2 (Frame 0, 1B). Send 5 more 200B writes (Frames 1..5).
	for range 5 {
		_, wErr := s2.Write(make([]byte, 200))
		require.NoError(t, wErr)
	}
	// Now sendFrameIdx == 6! Writing 16384B MUST emit ONE single 16384B FrameData with PadLen == 0 (36 + 16384 = 16420B).
	bigPayload := DeterministicBytes(515, aether.MaxFrameDataSize)
	_, err = s2.Write(bigPayload)
	require.NoError(t, err)
	// Frame 7: CloseWrite -> PadLen == 0 -> exact 36B!
	require.NoError(t, s2.CloseWrite())

	// Also verify >1200B splitting inside Frames 0..5 via NextDataChunk.
	chunkLen, padLen, err := aether.NextDataChunk(2500, 0, false)
	require.NoError(t, err)
	require.GreaterOrEqual(t, chunkLen, aether.ShapingSplitMin)
	require.LessOrEqual(t, chunkLen, aether.ShapingSplitMax)
	require.GreaterOrEqual(t, int(padLen), aether.ShapingPadMin)
	require.LessOrEqual(t, int(padLen), aether.ShapingPadMax)

	gotBig, err := io.ReadAll(c2)
	require.NoError(t, err)
	require.Equal(t, bigPayload, gotBig[1000:])

	writes2 := spyS2.snapshotWrites()
	require.Len(t, writes2, 8)
	require.Equal(t, 36+aether.MaxFrameDataSize, len(writes2[6]), "Frame 6 must be unpadded (36B overhead)")
	require.Equal(t, 36, len(writes2[7]), "Frame 7 CloseWrite must be unpadded (36B)")
}

func runT516PacketConnBoundaries(t *testing.T) {
	t.Parallel()

	// 1. Live CommandUDP 0B, 65535B max jumbo datagram, and 65536B overflow.
	cConn, sConn, _, _ := t5EstablishedPair(t, aether.CommandUDP, aether.CipherAES256GCM, -1, true)
	cp := aether.NewClientPacketConn(cConn)
	sp := aether.NewServerPacketConn(sConn)

	dest := M.ParseSocksaddrHostPort("2001:db8::42", 9999)

	// 0-byte UDP payload.
	b0 := buf.NewPacket()
	require.NoError(t, cp.WritePacket(b0, dest))
	r0 := buf.NewPacket()
	defer r0.Release()
	d0, err := sp.ReadPacket(r0)
	require.NoError(t, err)
	require.Equal(t, dest.String(), d0.String())
	require.Zero(t, r0.Len())

	// Exact 65535B max jumbo UDP payload spanning multiple 16384B frames.
	jumbo := DeterministicBytes(516, 65535)
	nWritten, err := cp.WriteTo(jumbo, dest.UDPAddr())
	require.NoError(t, err)
	require.Equal(t, 65535, nWritten)

	jumboRecv := make([]byte, 65535)
	nRead, rAddr, err := sp.ReadFrom(jumboRecv)
	require.NoError(t, err)
	require.Equal(t, 65535, nRead)
	require.Equal(t, dest.UDPAddr().String(), rAddr.String())
	require.Equal(t, jumbo, jumboRecv)

	// 65536B payload exceeds uint16 max -> ErrPacketTooLarge.
	over := buf.As(make([]byte, 65536))
	err = cp.WritePacket(over, dest)
	require.ErrorIs(t, err, aether.ErrPacketTooLarge)

	// FQDN > 255 bytes rejected cleanly.
	longDomain := M.ParseSocksaddrHostPort(strings.Repeat("a", 256), 443)
	bDomain := buf.NewPacket()
	_, _ = bDomain.WriteString("x")
	err = cp.WritePacket(bDomain, longDomain)
	require.Error(t, err)
	require.Zero(t, bDomain.Cap())

	// 2. Partial payload timeout recovery + io.ErrShortBuffer preservation.
	splitPayload := DeterministicBytes(99, 4000)
	var hdr [7]byte
	hdr[0] = 0x01 // IPv4
	copy(hdr[1:5], net.IPv4(192, 0, 2, 1).To4())
	binary.BigEndian.PutUint16(hdr[5:7], 8080)
	var lenBE [2]byte
	binary.BigEndian.PutUint16(lenBE[:], uint16(len(splitPayload)))

	// Write header + first 1000B of payload, stall before remaining 3000B.
	part1 := append(append(hdr[:], lenBE[:]...), splitPayload[:1000]...)
	_, err = cConn.Write(part1)
	require.NoError(t, err)

	require.NoError(t, sp.SetReadDeadline(time.Now().Add(40*time.Millisecond)))
	rpPart := buf.NewPacket()
	defer rpPart.Release()
	_, err = sp.ReadPacket(rpPart)
	require.ErrorIs(t, err, os.ErrDeadlineExceeded)

	require.NoError(t, sp.SetReadDeadline(time.Time{}))
	_, err = cConn.Write(splitPayload[1000:])
	require.NoError(t, err)
	gotD, err := sp.ReadPacket(rpPart)
	require.NoError(t, err)
	require.Equal(t, "192.0.2.1:8080", gotD.String())
	require.Equal(t, splitPayload, rpPart.Bytes())

	// Short caller buffer returns io.ErrShortBuffer and discards cleanly so next datagram parses intact.
	_, err = cp.WriteTo([]byte("0123456789"), dest.UDPAddr())
	require.NoError(t, err)
	tiny := buf.With(make([]byte, 4))
	_, err = sp.ReadPacket(tiny)
	require.ErrorIs(t, err, io.ErrShortBuffer)

	_, err = cp.WriteTo([]byte("ok"), dest.UDPAddr())
	require.NoError(t, err)
	rpOK := buf.NewPacket()
	defer rpOK.Release()
	_, err = sp.ReadPacket(rpOK)
	require.NoError(t, err)
	require.Equal(t, []byte("ok"), rpOK.Bytes())

	// 3. Truncated / unknown-family Socksaddr and truncated PayloadLen / truncated payload.
	malformedStreams := []struct {
		name string
		raw  []byte
	}{
		{"unknown_af_0x7f", []byte{0x7f, 0x01, 0x02}},
		{"truncated_ipv4", []byte{0x01, 127, 0}},
		{"truncated_len_1B", append(hdr[:], 0x00)},
		{"truncated_payload", append(append(hdr[:], 0x00, 0x10), []byte("short")...)},
	}
	for _, tc := range malformedStreams {
		t.Run(tc.name, func(t *testing.T) {
			mc, ms, _, _ := t5EstablishedPair(t, aether.CommandUDP, aether.CipherAES256GCM, -1, true)
			msp := aether.NewServerPacketConn(ms)
			_, wErr := mc.Write(tc.raw)
			require.NoError(t, wErr)
			require.NoError(t, mc.CloseWrite())

			out := buf.NewPacket()
			defer out.Release()
			_, rErr := msp.ReadPacket(out)
			require.Error(t, rErr)
		})
	}
}

func runT517OutboundPrecedence(t *testing.T) {
	t.Parallel()

	secret := t5RandomKeyB64(t)
	nopLog := log.NewNOPFactory().Logger()

	startDummyServer := func(t *testing.T, muxEnabled bool) (uint16, chan uint8, chan net.Conn) {
		t.Helper()
		cmds := make(chan uint8, 8)
		conns := make(chan net.Conn, 8)
		auth, err := aether.NewServerAuthenticator(secret, nil, "")
		require.NoError(t, err)
		replay := aether.NewSlidingBloomFilter(aether.DefaultTimeWindow, nil)

		ln, err := net.Listen("tcp", "127.0.0.1:0")
		require.NoError(t, err)
		t.Cleanup(func() { _ = ln.Close() })

		go func() {
			for {
				c, aErr := ln.Accept()
				if aErr != nil {
					return
				}
				go func(nc net.Conn) {
					res, sErr := aether.AcceptServerConn(context.Background(), nc, aether.ServerConnOptions{
						Authenticator:     auth,
						ReplayFilter:      replay,
						HeartbeatInterval: -1,
						DisableShaping:    true,
					})
					if sErr != nil {
						_ = nc.Close()
						return
					}
					cmds <- res.Command
					if res.Command == aether.CommandMux && !muxEnabled {
						_ = res.Conn.Close()
						return
					}
					conns <- res.Conn
				}(c)
			}
		}()
		return uint16(ln.Addr().(*net.TCPAddr).Port), cmds, conns
	}

	// Case 1: Simultaneous Multiplex + UDPOverTCP + CommandUDP -> Multiplex wins for TCP, UDP DialContext, and ListenPacket!
	port1, cmds1, conns1 := startDummyServer(t, false)
	outBoth, err := aether.NewOutbound(context.Background(), nil, nopLog, "both", option.AetherOutboundOptions{
		ServerOptions: option.ServerOptions{Server: "127.0.0.1", ServerPort: port1},
		Password:      secret,
		Cipher:        "aes-256-gcm",
		Multiplex:     &option.OutboundMultiplexOptions{Enabled: true, Protocol: "smux"},
		UDPOverTCP:    &option.UDPOverTCPOptions{Enabled: true, Version: 2},
	})
	require.NoError(t, err)
	scope1 := adapter.NewScope(context.Background(), nopLog)
	require.NoError(t, outBoth.(adapter.Lifecycle).Start(adapter.StartStateInitialize, scope1))
	t.Cleanup(func() { _ = outBoth.(io.Closer).Close() })
	require.True(t, outBoth.(adapter.OutboundWithMultiplex).MultiplexEnabled())

	// Exercising both ListenPacket and DialContext("udp") when Multiplex+UoT are enabled must dial CommandMux (not CommandUoT / CommandUDP).
	ctxDial, cancelDial := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancelDial()
	_, _ = outBoth.ListenPacket(ctxDial, M.ParseSocksaddrHostPort("127.0.0.1", 53))
	select {
	case cmd := <-cmds1:
		require.Equal(t, aether.CommandMux, cmd, "ListenPacket: Multiplex must take precedence over UoT and CommandUDP")
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for CommandMux dial via ListenPacket")
	}
	select {
	case c := <-conns1:
		_ = c.Close()
	default:
	}

	_, _ = outBoth.DialContext(ctxDial, N.NetworkUDP, M.ParseSocksaddrHostPort("127.0.0.1", 53))
	select {
	case cmd := <-cmds1:
		require.Equal(t, aether.CommandMux, cmd, "DialContext(udp): Multiplex must take precedence over UoT and CommandUDP")
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for CommandMux dial via DialContext(udp)")
	}
	select {
	case c := <-conns1:
		_ = c.Close()
	default:
	}

	// InterfaceUpdated / IdleConnectionKeeper / Close must not panic or race.
	ifaceListener := outBoth.(adapter.InterfaceUpdateListener)
	idleKeeper := outBoth.(adapter.IdleConnectionKeeper)
	var wg sync.WaitGroup
	for range 4 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ifaceListener.InterfaceUpdated(context.Background())
			idleKeeper.SetKeepIdleConnections(true)
			idleKeeper.CloseIdleConnections()
		}()
	}
	wg.Wait()

	// Case 2: Multiplex disabled + UDPOverTCP enabled -> UDP takes CommandUoT, TCP takes CommandTCP.
	port2, cmds2, conns2 := startDummyServer(t, false)
	outUoT, err := aether.NewOutbound(context.Background(), nil, nopLog, "uot", option.AetherOutboundOptions{
		ServerOptions: option.ServerOptions{Server: "127.0.0.1", ServerPort: port2},
		Password:      secret,
		UDPOverTCP:    &option.UDPOverTCPOptions{Enabled: true, Version: 2},
	})
	require.NoError(t, err)
	t.Cleanup(func() { _ = outUoT.(io.Closer).Close() })
	require.False(t, outUoT.(adapter.OutboundWithMultiplex).MultiplexEnabled())

	pcUoT, err := outUoT.ListenPacket(context.Background(), M.ParseSocksaddrHostPort("127.0.0.1", 53))
	require.NoError(t, err)
	// Write triggers 0-RTT CommandUoT dial.
	_, _ = pcUoT.WriteTo([]byte("u"), &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 53})
	require.Equal(t, aether.CommandUoT, <-cmds2)
	_ = pcUoT.Close()
	_ = (<-conns2).Close()

	tcpUoT, err := outUoT.DialContext(context.Background(), N.NetworkTCP, M.ParseSocksaddrHostPort("127.0.0.1", 80))
	require.NoError(t, err)
	_, _ = tcpUoT.Write([]byte("t"))
	require.Equal(t, aether.CommandTCP, <-cmds2)
	_ = tcpUoT.Close()
	_ = (<-conns2).Close()

	// Case 3: Neither Multiplex nor UoT -> ListenPacket and UDP DialContext use Native CommandUDP.
	port3, cmds3, conns3 := startDummyServer(t, false)
	outNative, err := aether.NewOutbound(context.Background(), nil, nopLog, "native", option.AetherOutboundOptions{
		ServerOptions: option.ServerOptions{Server: "127.0.0.1", ServerPort: port3},
		Password:      secret,
	})
	require.NoError(t, err)
	t.Cleanup(func() { _ = outNative.(io.Closer).Close() })

	pcNat, err := outNative.ListenPacket(context.Background(), M.ParseSocksaddrHostPort("127.0.0.1", 53))
	require.NoError(t, err)
	_, _ = pcNat.WriteTo([]byte("n"), &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 53})
	require.Equal(t, aether.CommandUDP, <-cmds3)
	_ = pcNat.Close()
	_ = (<-conns3).Close()

	// Case 4: Network=["tcp"] rejects UDP DialContext and ListenPacket.
	outTCPOnly, err := aether.NewOutbound(context.Background(), nil, nopLog, "tcponly", option.AetherOutboundOptions{
		ServerOptions: option.ServerOptions{Server: "127.0.0.1", ServerPort: port3},
		Network:       option.NetworkList(N.NetworkTCP),
		Password:      secret,
	})
	require.NoError(t, err)
	t.Cleanup(func() { _ = outTCPOnly.(io.Closer).Close() })
	_, err = outTCPOnly.DialContext(context.Background(), N.NetworkUDP, M.ParseSocksaddrHostPort("127.0.0.1", 53))
	require.ErrorIs(t, err, N.ErrUnknownNetwork)
	_, err = outTCPOnly.ListenPacket(context.Background(), M.ParseSocksaddrHostPort("127.0.0.1", 53))
	require.ErrorIs(t, err, N.ErrUnknownNetwork)
}

type t5MockOutbound struct {
	tag      string
	networks []string
}

func (m *t5MockOutbound) Type() string           { return "direct" }
func (m *t5MockOutbound) Tag() string            { return m.tag }
func (m *t5MockOutbound) Network() []string      { return m.networks }
func (m *t5MockOutbound) Dependencies() []string { return nil }
func (m *t5MockOutbound) DialContext(context.Context, string, M.Socksaddr) (net.Conn, error) {
	return nil, errors.New("mock dial disabled")
}
func (m *t5MockOutbound) ListenPacket(context.Context, M.Socksaddr) (net.PacketConn, error) {
	return nil, errors.New("mock packet disabled")
}

type t5MockOutboundManager struct {
	adapter.OutboundManager
	byTag map[string]adapter.Outbound
}

func (m *t5MockOutboundManager) Outbound(tag string) (adapter.Outbound, bool) {
	o, ok := m.byTag[tag]
	return o, ok
}

func runT518URLTestRace(t *testing.T) {
	t.Parallel()

	nopLog := log.NewNOPFactory().Logger()
	history := urltest.NewHistoryStorage()
	defer history.Close()

	out1 := &t5MockOutbound{tag: "aether-1", networks: []string{N.NetworkTCP, N.NetworkUDP}}
	out2 := &t5MockOutbound{tag: "aether-2", networks: []string{N.NetworkTCP, N.NetworkUDP}}
	out3 := &t5MockOutbound{tag: "aether-3", networks: []string{N.NetworkTCP}}

	mgr := &t5MockOutboundManager{
		byTag: map[string]adapter.Outbound{
			out1.tag: out1,
			out2.tag: out2,
			out3.tag: out3,
		},
	}

	ctx := pause.WithDefaultManager(context.Background())
	ctx = service.ContextWith[adapter.OutboundManager](ctx, mgr)
	ctx = service.ContextWithPtr(ctx, history)

	history.StoreURLTestHistory("aether-1", &adapter.URLTestHistory{Time: time.Now(), Delay: 40})
	history.StoreURLTestHistory("aether-2", &adapter.URLTestHistory{Time: time.Now(), Delay: 120})
	history.StoreURLTestHistory("aether-3", &adapter.URLTestHistory{Time: time.Now(), Delay: 15})

	rawUT, err := group.NewURLTest(ctx, nil, nopLog, "ut-race", option.URLTestOutboundOptions{
		Outbounds:                 []string{"aether-1", "aether-2", "aether-3"},
		Tolerance:                 20,
		InterruptExistConnections: true,
	})
	require.NoError(t, err)
	ut := rawUT.(*group.URLTest)

	scope := adapter.NewScope(ctx, nopLog)
	defer scope.Close()
	require.NoError(t, ut.Start(adapter.StartStateStart, scope))
	require.NoError(t, ut.Start(adapter.StartStateStarted, scope))

	// Allow PostStart's initial async CheckOutbounds to settle so we isolate References/Select/PerformUpdateCheck stress.
	time.Sleep(30 * time.Millisecond)

	const workers = 12
	const iters = 200
	var wg sync.WaitGroup
	for w := range workers {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for i := range iters {
				switch (id + i) % 5 {
				case 0:
					refs := ut.References()
					for _, r := range refs {
						require.Contains(t, []string{"aether-1", "aether-2", "aether-3"}, r)
					}
				case 1:
					selTCP := ut.Selected(N.NetworkTCP)
					require.NotNil(t, selTCP)
					selUDP := ut.Selected(N.NetworkUDP)
					require.NotNil(t, selUDP)
					require.NotEqual(t, "aether-3", selUDP.Tag(), "TCP-only outbound must never be selected for UDP")
				case 2:
					ut.PerformUpdateCheck()
				case 3:
					d1 := uint16(10 + (i % 150))
					d2 := uint16(150 - (i % 140))
					history.StoreURLTestHistory("aether-1", &adapter.URLTestHistory{Time: time.Now(), Delay: d1})
					history.StoreURLTestHistory("aether-2", &adapter.URLTestHistory{Time: time.Now(), Delay: d2})
				case 4:
					detach := ut.AttachConnection(io.NopCloser(nil))
					detach()
				}
			}
		}(w)
	}
	wg.Wait()

	ut.PerformUpdateCheck()
	refs := ut.References()
	require.NotEmpty(t, refs)
}

func runT519WorkflowContract(t *testing.T) {
	t.Parallel()

	root, err := RepoRoot()
	require.NoError(t, err)
	wfPath := filepath.Join(root, ".github", "workflows", "upstream-sync-release.yml")
	rawBytes, err := os.ReadFile(wfPath)
	require.NoError(t, err)
	wf := string(rawBytes)

	// 1. Trigger & literal permissions.
	require.Regexp(t, `(?m)^on:\s*\n\s+schedule:\s*\n\s+-\s+cron:\s*['"]0 2 \* \* 1['"]`, wf)
	require.Regexp(t, `(?m)^\s+workflow_dispatch:\s*$`, wf)
	require.Regexp(t, `(?m)^permissions:\s*\n\s+contents:\s*write\s*$`, wf)
	require.NotContains(t, wf, "workflows: write")
	require.NotContains(t, wf, "write-all")

	// 2. Single job under jobs: named sync-and-release.
	jobsIdx := strings.Index(wf, "\njobs:\n")
	require.Positive(t, jobsIdx)
	jobsBody := wf[jobsIdx+len("\njobs:\n"):]
	jobMatches := regexp.MustCompile(`(?m)^  ([A-Za-z0-9_-]+):\s*$`).FindAllStringSubmatch(jobsBody, -1)
	require.Len(t, jobMatches, 1, "must contain exactly one job under jobs:")
	require.Equal(t, "sync-and-release", jobMatches[0][1])

	// 3. Upstream latest stable tag check (rejects draft, prerelease, non-semver).
	require.Contains(t, wf, "https://api.github.com/repos/SagerNet/sing-box/releases/latest")
	require.Contains(t, wf, `[ "${IS_DRAFT}" != "false" ] || [ "${IS_PRERELEASE}" != "false" ]`)
	require.Contains(t, wf, `^v[0-9]+\.[0-9]+\.[0-9]+$`)

	// 4. .github/workflows/ preservation guard both during merge and pre-commit.
	require.Contains(t, wf, "git reset -q HEAD -- .github/workflows/")
	require.Contains(t, wf, "git checkout HEAD -- .github/workflows/")
	require.Contains(t, wf, "git clean -fd .github/workflows/")
	require.Contains(t, wf, "git diff HEAD --name-only -- .github/workflows/")

	// 5. Mandatory CGO_ENABLED=1 -race test gate and official pure-Go build tags.
	require.Contains(t, wf, "CGO_ENABLED=1 go test -race -count=1 ./cmd/sing-box/... ./option/... ./schema/... ./protocol/aether/...")
	require.Equal(t, 2, strings.Count(wf, "release/DEFAULT_BUILD_TAGS_OTHERS"), "release/DEFAULT_BUILD_TAGS_OTHERS must be used in both schema gen and multi-arch builds")
	require.Equal(t, 2, strings.Count(wf, DefaultOfficialPureGoBuildTags), "official pure-Go fallback tags must be present in both schema gen and multi-arch builds")
	require.Contains(t, wf, "for ARCH in amd64 arm64; do")

	// 6. Bash syntax check (`bash -n`) on every embedded run: script block.
	if bashBin, lookErr := exec.LookPath("bash"); lookErr == nil {
		reRun := regexp.MustCompile(`(?m)^      - name: ([^\n]+)(?:\n(?:        [^\n]*|))*?\n        run: \|\n((?:          [^\n]*\n|\s*\n)*)`)
		blocks := reRun.FindAllStringSubmatch(wf, -1)
		require.GreaterOrEqual(t, len(blocks), 5)
		for _, blk := range blocks {
			stepName := blk[1]
			lines := strings.Split(blk[2], "\n")
			for i := range lines {
				lines[i] = strings.TrimPrefix(lines[i], "          ")
			}
			cmd := exec.Command(bashBin, "-n")
			cmd.Stdin = strings.NewReader(strings.Join(lines, "\n"))
			out, bashErr := cmd.CombinedOutput()
			require.NoError(t, bashErr, "bash -n failed for step %q: %s", stepName, string(out))
		}
	}
}

func runT520AuthenticatorModes(t *testing.T) {
	t.Parallel()

	rawKey := make([]byte, 32)
	_, err := io.ReadFull(rand.Reader, rawKey)
	require.NoError(t, err)
	stdKey := base64.StdEncoding.EncodeToString(rawKey)
	rawURLKey := base64.RawURLEncoding.EncodeToString(rawKey)

	// NewUserTable validations.
	_, err = aether.NewUserTable(nil)
	require.ErrorIs(t, err, aether.ErrEmptyUserTable)
	_, err = aether.NewUserTable([]option.AetherUser{
		{Name: "dup", Password: t5RandomKeyB64(t)},
		{Name: "dup", Password: t5RandomKeyB64(t)},
	})
	require.ErrorIs(t, err, aether.ErrDuplicateUserName)
	_, err = aether.NewUserTable([]option.AetherUser{
		{Name: "u1", Password: stdKey},
		{Name: "u2", Key: rawURLKey}, // same decoded PSK across different Base64 encodings
	})
	require.ErrorIs(t, err, aether.ErrDuplicateUserKey)
	_, err = aether.NewUserTable([]option.AetherUser{
		{Name: "u1", Password: stdKey, Key: t5RandomKeyB64(t)},
	})
	require.Error(t, err)

	// No secret & no users -> ErrMissingInboundSecret.
	_, err = aether.NewServerAuthenticator("", nil, "")
	require.ErrorIs(t, err, aether.ErrMissingInboundSecret)

	// Users-Only mode (96B prefix, AuthModeMultiUserDirect) vs EIH mode (112B prefix, AuthModeMultiUserEIH).
	u1Key := t5RandomKeyB64(t)
	u2Key := t5RandomKeyB64(t)
	u3Key := t5RandomKeyB64(t)
	authDirect, err := aether.NewServerAuthenticator("", []option.AetherUser{
		{Name: "first", Password: u1Key},
		{Name: "middle", Password: u2Key},
		{Name: "last", Key: u3Key},
	}, "")
	require.NoError(t, err)
	require.Equal(t, aether.AuthModeMultiUserDirect, authDirect.Mode())
	require.Equal(t, aether.ClientPrefixNoEIHSize, authDirect.ClientPrefixSize())

	for _, tc := range []struct {
		name  string
		key   string
		index int
	}{
		{"first", u1Key, 0},
		{"last", u3Key, 2},
	} {
		creds, cErr := aether.ParseOutboundCredentials(tc.key)
		require.NoError(t, cErr)
		require.False(t, creds.HasServerPSK)
		fh, fErr := aether.EncodeFixedHeader(aether.FixedHeader{
			Version:      aether.ProtocolVersion,
			Command:      aether.CommandTCP,
			CipherSuite:  aether.CipherAES256GCM,
			TimestampSec: time.Now().Unix(),
			NoiseLen:     32,
			VarHeaderLen: 64,
		})
		require.NoError(t, fErr)
		_, pfx, sErr := aether.StartClientHandshake(creds, nil, fh)
		require.NoError(t, sErr)
		hs, _, oErr := authDirect.OpenClientFixedPrefix(pfx)
		require.NoError(t, oErr)
		require.Equal(t, tc.name, hs.UserName)
		require.Equal(t, tc.index, hs.UserIndex)
	}

	// EIH cross-user EIH tag swap rejected (because EIH is in AAD!).
	iPSK := t5RandomKeyB64(t)
	authEIH, err := aether.NewServerAuthenticator(iPSK, []option.AetherUser{
		{Name: "u1", Password: u1Key},
		{Name: "u2", Password: u2Key},
	}, "")
	require.NoError(t, err)
	require.Equal(t, aether.AuthModeMultiUserEIH, authEIH.Mode())
	require.Equal(t, aether.ClientPrefixEIHSize, authEIH.ClientPrefixSize())

	c1, _ := aether.ParseOutboundCredentials(iPSK + ":" + u1Key)
	c2, _ := aether.ParseOutboundCredentials(iPSK + ":" + u2Key)
	fh, _ := aether.EncodeFixedHeader(aether.FixedHeader{
		Version:      aether.ProtocolVersion,
		Command:      aether.CommandTCP,
		CipherSuite:  aether.CipherAES256GCM,
		TimestampSec: time.Now().Unix(),
		NoiseLen:     32,
		VarHeaderLen: 64,
	})
	_, pfx1, _ := aether.StartClientHandshake(c1, nil, fh)
	_, pfx2, _ := aether.StartClientHandshake(c2, nil, fh)
	swapped := append([]byte(nil), pfx1...)
	copy(swapped[64:80], pfx2[64:80])
	_, _, err = authEIH.OpenClientFixedPrefix(swapped)
	require.ErrorIs(t, err, aether.ErrAuthenticationFailed)
}

func runT521StaticPFSMismatch(t *testing.T) {
	t.Parallel()

	priv1, err := ecdh.X25519().GenerateKey(rand.Reader)
	require.NoError(t, err)
	priv2, err := ecdh.X25519().GenerateKey(rand.Reader)
	require.NoError(t, err)

	priv1B64 := base64.StdEncoding.EncodeToString(priv1.Bytes())
	pub1B64 := base64.StdEncoding.EncodeToString(priv1.PublicKey().Bytes())
	pub2B64 := base64.StdEncoding.EncodeToString(priv2.PublicKey().Bytes())
	secret := t5RandomKeyB64(t)

	creds, err := aether.ParseOutboundCredentials(secret)
	require.NoError(t, err)
	fh, err := aether.EncodeFixedHeader(aether.FixedHeader{
		Version:      aether.ProtocolVersion,
		Command:      aether.CommandTCP,
		CipherSuite:  aether.CipherAES256GCM,
		TimestampSec: time.Now().Unix(),
		NoiseLen:     32,
		VarHeaderLen: 64,
	})
	require.NoError(t, err)

	authWithStatic, err := aether.NewServerAuthenticator(secret, nil, priv1B64)
	require.NoError(t, err)
	require.True(t, authWithStatic.HasStaticKey())
	authNoStatic, err := aether.NewServerAuthenticator(secret, nil, "")
	require.NoError(t, err)
	require.False(t, authNoStatic.HasStaticKey())

	// 1. Client has pub1, server has priv1 -> succeeds.
	pub1, err := aether.ParseX25519PublicKey(pub1B64)
	require.NoError(t, err)
	_, pfx1, err := aether.StartClientHandshake(creds, pub1, fh)
	require.NoError(t, err)
	_, _, err = authWithStatic.OpenClientFixedPrefix(pfx1)
	require.NoError(t, err)

	// 2. Client has pub1, server has NO static key -> fails.
	_, _, err = authNoStatic.OpenClientFixedPrefix(pfx1)
	require.ErrorIs(t, err, aether.ErrAuthenticationFailed)

	// 3. Client has NO static key, server has priv1 -> fails.
	_, pfxNoStatic, err := aether.StartClientHandshake(creds, nil, fh)
	require.NoError(t, err)
	_, _, err = authWithStatic.OpenClientFixedPrefix(pfxNoStatic)
	require.ErrorIs(t, err, aether.ErrAuthenticationFailed)

	// 4. Client has wrong pub2, server has priv1 -> fails.
	pub2, err := aether.ParseX25519PublicKey(pub2B64)
	require.NoError(t, err)
	_, pfx2, err := aether.StartClientHandshake(creds, pub2, fh)
	require.NoError(t, err)
	_, _, err = authWithStatic.OpenClientFixedPrefix(pfx2)
	require.ErrorIs(t, err, aether.ErrAuthenticationFailed)
}

func runT522SingleUseAndEPKMask(t *testing.T) {
	t.Parallel()

	secret := t5RandomKeyB64(t)
	creds, err := aether.ParseOutboundCredentials(secret)
	require.NoError(t, err)
	auth, err := aether.NewServerAuthenticator(secret, nil, "")
	require.NoError(t, err)

	fh, err := aether.EncodeFixedHeader(aether.FixedHeader{
		Version:      aether.ProtocolVersion,
		Command:      aether.CommandTCP,
		CipherSuite:  aether.CipherAES256GCM,
		TimestampSec: time.Now().Unix(),
		NoiseLen:     32,
		VarHeaderLen: 64,
	})
	require.NoError(t, err)
	cHS, pfx, err := aether.StartClientHandshake(creds, nil, fh)
	require.NoError(t, err)
	varPlain, err := aether.EncodeVarHeader(nil, 32, M.ParseSocksaddrHostPort("127.0.0.1", 80), nil)
	require.NoError(t, err)
	encVar := cHS.SealVarHeader(nil, varPlain)

	sHS, _, err := auth.OpenClientFixedPrefix(pfx)
	require.NoError(t, err)
	_, err = sHS.OpenVarHeader(nil, encVar)
	require.NoError(t, err)
	// Second OpenVarHeader on same ServerHandshakeState must be rejected.
	_, err = sHS.OpenVarHeader(nil, encVar)
	require.ErrorIs(t, err, aether.ErrAuthenticationFailed)

	// Statistical check: MaskedEPK bit 255 (byte[31]&0x80) is ~50% (not 0% like raw X25519).
	var msbSet int
	const samples = 1000
	for range samples {
		salt, gErr := aether.GenerateRandomSalt()
		require.NoError(t, gErr)
		_, masked, gErr := aether.GenerateMaskedEPK(creds.UPSK, salt)
		require.NoError(t, gErr)
		if masked[31]&0x80 != 0 {
			msbSet++
		}
	}
	require.Greater(t, msbSet, 400, "masked EPK MSB must not be biased to 0")
	require.Less(t, msbSet, 600, "masked EPK MSB must be uniform")
}

func runT523InboundLifecycleAndClose(t *testing.T) {
	t.Parallel()

	secret := t5RandomKeyB64(t)
	nopLog := log.NewNOPFactory().Logger()

	var routedCount atomic.Int64
	router := &t5StubRouter{
		onConn: func(_ context.Context, conn net.Conn, metadata adapter.InboundContext, onClose N.CloseHandlerFunc) {
			routedCount.Add(1)
			require.Equal(t, "aether-in", metadata.Inbound)
			require.Equal(t, C.TypeAether, metadata.InboundType)
			_, _ = io.Copy(conn, conn)
			_ = conn.Close()
			if onClose != nil {
				onClose(nil)
			}
		},
	}

	listenAddr := badoption.Addr(netip.IPv4Unspecified())
	rawIn, err := aether.NewInbound(context.Background(), router, nopLog, "aether-in", option.AetherInboundOptions{
		ListenOptions: option.ListenOptions{
			Listen:     &listenAddr,
			ListenPort: 0,
		},
		Password:         secret,
		HandshakeTimeout: badoption.Duration(100 * time.Millisecond),
	})
	require.NoError(t, err)
	in := rawIn.(*aether.Inbound)

	// 1. Slowloris incomplete prefix (<96B) closes quickly at HandshakeTimeout via TCP FIN (not 3s..10s drain).
	c1, s1 := t5TCPPair(t)
	var onClose1 atomic.Bool
	closed1 := make(chan error, 1)
	go in.NewConnectionEx(context.Background(), s1, M.ParseSocksaddrHostPort("127.0.0.1", 11111), M.Socksaddr{}, func(e error) {
		onClose1.Store(true)
		closed1 <- e
	})

	_, err = c1.Write(bytes.Repeat([]byte{0x41}, 50))
	require.NoError(t, err)
	start := time.Now()
	_ = c1.SetReadDeadline(time.Now().Add(2 * time.Second))
	var b [1]byte
	_, rErr := c1.Read(b[:])
	elapsed := time.Since(start)
	require.Less(t, elapsed, 1500*time.Millisecond, "incomplete prefix timeout must not enter 3s..10s StealthDrain")
	require.True(t, IsCleanEOF(rErr), "expected clean FIN EOF, got %v", rErr)
	require.Error(t, <-closed1)
	require.True(t, onClose1.Load())

	// 2. Zero-byte immediate client FIN closes immediately.
	c2, s2 := t5TCPPair(t)
	closed2 := make(chan error, 1)
	go in.NewConnection(context.Background(), s2, adapter.InboundContext{
		Source: M.ParseSocksaddrHostPort("127.0.0.1", 22222),
	}, func(e error) { closed2 <- e })
	_ = c2.Close()
	select {
	case e := <-closed2:
		require.Error(t, e)
	case <-time.After(time.Second):
		t.Fatal("0-byte EOF stalled")
	}

	// 3. Valid TCP echo via NewConnectionEx.
	c3, s3 := t5TCPPair(t)
	closed3 := make(chan error, 1)
	go in.NewConnectionEx(context.Background(), s3, M.ParseSocksaddrHostPort("127.0.0.1", 33333), M.Socksaddr{}, func(e error) {
		closed3 <- e
	})
	creds, _ := aether.ParseOutboundCredentials(secret)
	dialC, err := aether.DialEarlyConnContext(context.Background(), c3, aether.ClientConnOptions{
		Credentials:       creds,
		Command:           aether.CommandTCP,
		CipherSuite:       aether.CipherAES256GCM,
		TargetAddr:        M.ParseSocksaddrHostPort("127.0.0.1", 80),
		HeartbeatInterval: -1,
	})
	require.NoError(t, err)
	_, err = dialC.Write([]byte("echo-ok"))
	require.NoError(t, err)
	require.NoError(t, dialC.CloseWrite())
	echoed, err := io.ReadAll(dialC)
	require.NoError(t, err)
	require.Equal(t, []byte("echo-ok"), echoed)
	_ = dialC.Close()
	<-closed3
	require.Equal(t, int64(1), routedCount.Load())

	// 4. Active 3s..10s StealthDrain aborts immediately when Inbound.Close() cancels in.ctx.
	c4, s4 := t5TCPPair(t)
	closed4 := make(chan error, 1)
	go in.NewConnectionEx(context.Background(), s4, M.ParseSocksaddrHostPort("127.0.0.1", 44444), M.Socksaddr{}, func(e error) {
		closed4 <- e
	})
	_, err = c4.Write(bytes.Repeat([]byte{0x99}, 96))
	require.NoError(t, err)
	time.Sleep(50 * time.Millisecond)

	closeStart := time.Now()
	require.NoError(t, in.Close())
	select {
	case <-closed4:
		require.Less(t, time.Since(closeStart), time.Second)
	case <-time.After(2 * time.Second):
		t.Fatal("Inbound.Close did not cancel active StealthDrain")
	}
}

func runT524CoalescedBurstAndLargeInit(t *testing.T) {
	t.Parallel()

	// 1. Server-speaks-first: Client calls Read() without calling Write() -> 25ms grace expires,
	// Client flushes 0B ClientInitialBurst, Server accepts and sends banner!
	rawC, rawS := t5TCPPair(t)
	spyC := &t5SpyRawConn{Conn: rawC}
	secret := t5RandomKeyB64(t)
	creds, _ := aether.ParseOutboundCredentials(secret)
	auth, _ := aether.NewServerAuthenticator(secret, nil, "")
	replay := aether.NewSlidingBloomFilter(aether.DefaultTimeWindow, nil)

	clientConn, err := aether.DialEarlyConnContext(context.Background(), spyC, aether.ClientConnOptions{
		Credentials:       creds,
		Command:           aether.CommandTCP,
		CipherSuite:       aether.CipherAES256GCM,
		TargetAddr:        M.ParseSocksaddrHostPort("127.0.0.1", 22),
		HeartbeatInterval: -1,
	})
	require.NoError(t, err)
	require.True(t, clientConn.NeedHandshakeForWrite())
	require.True(t, clientConn.NeedHandshakeForRead())
	require.True(t, clientConn.NeedHandshake())

	srvDone1 := make(chan struct{})
	go func() {
		defer close(srvDone1)
		res, aErr := aether.AcceptServerConn(context.Background(), rawS, aether.ServerConnOptions{
			Authenticator:     auth,
			ReplayFilter:      replay,
			HeartbeatInterval: -1,
		})
		require.NoError(t, aErr)
		defer func() { _ = res.Conn.Close() }()
		_, wErr := res.Conn.Write([]byte("SSH-2.0-AetherBanner\r\n"))
		require.NoError(t, wErr)
		require.NoError(t, res.Conn.CloseWrite())
		_, _ = io.ReadAll(res.Conn)
	}()

	gotBanner, err := io.ReadAll(clientConn)
	require.NoError(t, err)
	require.Equal(t, []byte("SSH-2.0-AetherBanner\r\n"), gotBanner)
	require.False(t, clientConn.NeedHandshakeForWrite())
	require.False(t, clientConn.NeedHandshakeForRead())
	require.False(t, clientConn.NeedHandshake())
	_ = clientConn.Close()
	<-srvDone1

	// 2. Large initial Write (> MaxInitialPayloadLen = 16384): splits 0-RTT VarHeader + subsequent FrameData!
	rawC2, rawS2 := t5TCPPair(t)
	spyC2 := &t5SpyRawConn{Conn: rawC2}
	clientConn2, err := aether.DialEarlyConnContext(context.Background(), spyC2, aether.ClientConnOptions{
		Credentials:       creds,
		Command:           aether.CommandTCP,
		CipherSuite:       aether.CipherChaCha20Poly1305,
		TargetAddr:        M.ParseSocksaddrHostPort("127.0.0.1", 8080),
		HeartbeatInterval: -1,
		DisableShaping:    true,
	})
	require.NoError(t, err)

	srvDone := make(chan []byte, 1)
	go func() {
		res, aErr := aether.AcceptServerConn(context.Background(), rawS2, aether.ServerConnOptions{
			Authenticator:     auth,
			ReplayFilter:      replay,
			HeartbeatInterval: -1,
			DisableShaping:    true,
		})
		require.NoError(t, aErr)
		// Send empty FrameData or Write to emit ServerResponsePrefix so client Write completes tail chunks.
		_, _ = res.Conn.Write([]byte("OK"))
		_ = res.Conn.CloseWrite()
		data, rErr := io.ReadAll(res.Conn)
		require.NoError(t, rErr)
		_ = res.Conn.Close()
		srvDone <- data
	}()

	large20K := DeterministicBytes(524, 20000)
	n, err := clientConn2.Write(large20K)
	require.NoError(t, err)
	require.Equal(t, 20000, n)
	require.NoError(t, clientConn2.CloseWrite())

	var ack [2]byte
	_, err = io.ReadFull(clientConn2, ack[:])
	require.NoError(t, err)
	require.Equal(t, []byte("OK"), ack[:])
	_ = clientConn2.Close()

	require.Equal(t, large20K, <-srvDone)
	// First raw write must be coalesced ClientPrefix(96) + EncryptedVarHeader(VarHeaderLen<=16384 + 16), NOT exceeding 96+16384+16!
	cWrites := spyC2.snapshotWrites()
	require.GreaterOrEqual(t, len(cWrites), 2)
	require.LessOrEqual(t, len(cWrites[0]), aether.ClientPrefixNoEIHSize+aether.MaxVarHeaderLen+aether.AEADTagSize)
}

func runT525PacketConnMidHeaderRecoveryAndEmptyFQDN(t *testing.T) {
	t.Parallel()

	// 1. Mid-header SetReadDeadline timeout recovery across AF, FQDN, and 2-byte PayloadLen splits.
	cConn, sConn, _, _ := t5EstablishedPair(t, aether.CommandUDP, aether.CipherAES256GCM, -1, true)
	sp := aether.NewServerPacketConn(sConn)

	// Target wire header: af=0x03, len=11, "example.com", port=443 (0x01,0xbb), payloadLen=5 (0x00,0x05), payload="hello"
	chunks := [][]byte{
		{0x03},                        // Split after AddressFamily byte
		{11, 'e', 'x', 'a', 'm'},      // Split mid-FQDN
		[]byte("ple.com\x01\xbb\x00"), // Split right inside 2-byte PayloadLen!
	}

	rp := buf.NewPacket()
	defer rp.Release()

	for idx, chunk := range chunks {
		_, err := cConn.Write(chunk)
		require.NoError(t, err, "write chunk %d", idx)
		require.NoError(t, sp.SetReadDeadline(time.Now().Add(40*time.Millisecond)))
		_, rErr := sp.ReadPacket(rp)
		require.ErrorIs(t, rErr, os.ErrDeadlineExceeded, "chunk %d must trigger read deadline without losing partial header", idx)
	}

	// Complete final PayloadLen byte + payload and follow-up packet to prove framing stays synced.
	require.NoError(t, sp.SetReadDeadline(time.Now().Add(2*time.Second)))
	_, err := cConn.Write(append([]byte{0x05}, []byte("hello")...))
	require.NoError(t, err)

	dest, err := sp.ReadPacket(rp)
	require.NoError(t, err)
	require.Equal(t, "example.com:443", dest.String())
	require.Equal(t, []byte("hello"), rp.Bytes())

	// Next packet on same PacketConn must decode cleanly with zero header desync.
	nextDest := M.ParseSocksaddrHostPort("127.0.0.1", 53)
	wp := buf.NewPacket()
	_, _ = wp.WriteString("next")
	require.NoError(t, aether.NewClientPacketConn(cConn).WritePacket(wp, nextDest))

	rpNext := buf.NewPacket()
	defer rpNext.Release()
	gotNext, err := sp.ReadPacket(rpNext)
	require.NoError(t, err)
	require.Equal(t, nextDest.String(), gotNext.String())
	require.Equal(t, []byte("next"), rpNext.Bytes())

	// 2. Empty FQDN (af=0x03, strLen=0) MUST be explicitly rejected with ErrInvalidVarHeader.
	cConn2, sConn2, _, _ := t5EstablishedPair(t, aether.CommandUDP, aether.CipherChaCha20Poly1305, -1, true)
	sp2 := aether.NewServerPacketConn(sConn2)
	_, err = cConn2.Write([]byte{0x03, 0x00, 0x00, 53, 0x00, 0x02, 'o', 'k'})
	require.NoError(t, err)

	rpBad := buf.NewPacket()
	defer rpBad.Release()
	_, err = sp2.ReadPacket(rpBad)
	require.ErrorIs(t, err, aether.ErrInvalidVarHeader)
	require.Contains(t, err.Error(), "empty UDP FQDN")
}

func runT526ConnDataAfterCloseWriteRejected(t *testing.T) {
	t.Parallel()

	// Case 1: FramePing, FramePong, and 0-byte FrameData chaff after FrameCloseWrite keep connection healthy;
	// subsequent non-empty FrameData triggers protocol rejection and aborts connection without leaking data.
	rawC, srvConn, hdrKey, payKey, _ := t5OpenTestSession(t, aether.CipherAES256GCM)
	defer srvConn.Close()
	defer rawC.Close()

	body0, err := aether.AppendFrameBody(nil, aether.FrameData, 0, []byte("before-eof"))
	require.NoError(t, err)
	f0 := t5SealRawCustomFrame(t, aether.CipherAES256GCM, hdrKey, payKey, 0, uint16(len(body0)), body0)

	body1, err := aether.AppendFrameBody(nil, aether.FrameCloseWrite, 0, nil)
	require.NoError(t, err)
	f1 := t5SealRawCustomFrame(t, aether.CipherAES256GCM, hdrKey, payKey, 1, uint16(len(body1)), body1)

	body2, err := aether.AppendFrameBody(nil, aether.FramePing, 32, nil)
	require.NoError(t, err)
	f2 := t5SealRawCustomFrame(t, aether.CipherAES256GCM, hdrKey, payKey, 2, uint16(len(body2)), body2)

	body3, err := aether.AppendFrameBody(nil, aether.FramePong, 32, nil)
	require.NoError(t, err)
	f3 := t5SealRawCustomFrame(t, aether.CipherAES256GCM, hdrKey, payKey, 3, uint16(len(body3)), body3)

	body4, err := aether.AppendFrameBody(nil, aether.FrameData, 16, nil) // 0B chaff
	require.NoError(t, err)
	f4 := t5SealRawCustomFrame(t, aether.CipherAES256GCM, hdrKey, payKey, 4, uint16(len(body4)), body4)

	var batch []byte
	batch = append(batch, f0...)
	batch = append(batch, f1...)
	batch = append(batch, f2...)
	batch = append(batch, f3...)
	batch = append(batch, f4...)
	_, err = rawC.Write(batch)
	require.NoError(t, err)

	_ = srvConn.SetReadDeadline(time.Now().Add(2 * time.Second))
	gotAll, err := io.ReadAll(srvConn)
	require.NoError(t, err)
	require.Equal(t, []byte("before-eof"), gotAll)

	// Half-closed connection remains writable after Ping/Pong/chaff!
	_, err = srvConn.Write([]byte("half-open-ok"))
	require.NoError(t, err)

	// Now inject forbidden non-empty FrameData AFTER FrameCloseWrite: must abort conn and NEVER return data.
	body5, err := aether.AppendFrameBody(nil, aether.FrameData, 0, []byte("after-eof"))
	require.NoError(t, err)
	f5 := t5SealRawCustomFrame(t, aether.CipherAES256GCM, hdrKey, payKey, 5, uint16(len(body5)), body5)
	_, err = rawC.Write(f5)
	require.NoError(t, err)

	// Peer TCP socket must be closed by readLoop's closeInternal(false).
	_ = rawC.SetReadDeadline(time.Now().Add(2 * time.Second))
	drainBuf := make([]byte, 256)
	for {
		_, rawErr := rawC.Read(drainBuf)
		if rawErr != nil {
			require.False(t, errors.Is(rawErr, os.ErrDeadlineExceeded), "server must close conn after FrameData following FrameCloseWrite")
			break
		}
	}

	var postRead [32]byte
	n, rErr := srvConn.Read(postRead[:])
	require.Zero(t, n)
	require.Error(t, rErr)

	// Case 2: Non-empty FrameData coalesced right behind FrameCloseWrite before any Read -> never leaks post-EOF bytes.
	rawC2, srvConn2, hdrKey2, payKey2, _ := t5OpenTestSession(t, aether.CipherChaCha20Poly1305)
	defer srvConn2.Close()
	defer rawC2.Close()

	cwBody, err := aether.AppendFrameBody(nil, aether.FrameCloseWrite, 0, nil)
	require.NoError(t, err)
	cwFrame := t5SealRawCustomFrame(t, aether.CipherChaCha20Poly1305, hdrKey2, payKey2, 0, uint16(len(cwBody)), cwBody)

	badBody, err := aether.AppendFrameBody(nil, aether.FrameData, 0, []byte("smuggled-after-eof"))
	require.NoError(t, err)
	badFrame := t5SealRawCustomFrame(t, aether.CipherChaCha20Poly1305, hdrKey2, payKey2, 1, uint16(len(badBody)), badBody)

	_, err = rawC2.Write(append(cwFrame, badFrame...))
	require.NoError(t, err)

	_ = srvConn2.SetReadDeadline(time.Now().Add(2 * time.Second))
	out2, err := io.ReadAll(srvConn2)
	require.NoError(t, err)
	require.Empty(t, out2, "non-empty FrameData after FrameCloseWrite must NEVER be returned")

	_ = rawC2.SetReadDeadline(time.Now().Add(2 * time.Second))
	for {
		_, rawErr := rawC2.Read(drainBuf)
		if rawErr != nil {
			require.False(t, errors.Is(rawErr, os.ErrDeadlineExceeded), "server must close conn on coalesced FrameData after FrameCloseWrite")
			break
		}
	}
}

func runT527URLTestPostStartTouchRace(t *testing.T) {
	t.Parallel()

	nopLog := log.NewNOPFactory().Logger()
	history := urltest.NewHistoryStorage()
	baseCtx := pause.WithDefaultManager(context.Background())
	baseCtx = service.ContextWithPtr(baseCtx, history)

	outbounds := []adapter.Outbound{
		&t5MockOutbound{tag: "aether-1", networks: []string{N.NetworkTCP, N.NetworkUDP}},
		&t5MockOutbound{tag: "aether-2", networks: []string{N.NetworkTCP}},
	}
	mgr := &t5MockOutboundManager{
		byTag: map[string]adapter.Outbound{
			"aether-1": outbounds[0],
			"aether-2": outbounds[1],
		},
	}
	baseCtx = service.ContextWith[adapter.OutboundManager](baseCtx, mgr)

	// Hammer concurrent Touch() calls directly across PostStart() transitions under -race.
	for round := range 40 {
		ctx, cancel := context.WithCancel(baseCtx)
		g, err := group.NewURLTestGroup(ctx, mgr, nopLog, outbounds, "", time.Minute, 50, 2*time.Minute, false)
		require.NoError(t, err)

		startGate := make(chan struct{})
		var wg sync.WaitGroup
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-startGate
			g.PostStart()
		}()
		for range 8 {
			wg.Add(1)
			go func() {
				defer wg.Done()
				<-startGate
				for range 64 {
					g.Touch()
				}
			}()
		}
		if round%2 == 0 {
			g.Touch() // Touch before PostStart must be a clean no-op
		}

		close(startGate)
		wg.Wait()

		// Confirm started transition completes and Select/Touch work after PostStart, then clean up ticker.
		g.Touch()
		sel, _ := g.Select(N.NetworkTCP)
		require.NotNil(t, sel)
		require.NoError(t, g.Close())
		cancel()
	}
}

// Keep unused-import guard clean across build variations.
var _ = bufio.ErrBufferFull
var _ = aes.BlockSize
var _ = cipher.AEAD(nil)
var _ = chacha20poly1305.KeySize
