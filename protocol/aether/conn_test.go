package aether

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"io"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/buf"
	"github.com/sagernet/sing/common/bufio"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

type spyConn struct {
	net.Conn
	mu          sync.Mutex
	writes      []int
	dropReads   atomic.Bool
	dropWrites  atomic.Bool
	failWriteAt atomic.Int32 // 1-based write index to fail with error (0 = disabled)
	shortWrite  atomic.Bool  // return n-1, nil on next write
	writeCount  atomic.Int32
	onWrite     func(int)
}

func newSpyConn(c net.Conn) *spyConn {
	return &spyConn{Conn: c}
}

func (s *spyConn) Write(p []byte) (int, error) {
	idx := s.writeCount.Add(1)
	if s.dropWrites.Load() {
		s.mu.Lock()
		s.writes = append(s.writes, len(p))
		s.mu.Unlock()
		return len(p), nil
	}
	if failAt := s.failWriteAt.Load(); failAt > 0 && idx == failAt {
		return 0, errors.New("injected write error")
	}
	if s.shortWrite.CompareAndSwap(true, false) && len(p) > 1 {
		n, err := s.Conn.Write(p[:len(p)-1])
		return n, err
	}

	s.mu.Lock()
	s.writes = append(s.writes, len(p))
	cb := s.onWrite
	s.mu.Unlock()
	if cb != nil {
		cb(len(p))
	}
	return s.Conn.Write(p)
}

func (s *spyConn) Read(p []byte) (int, error) {
	n, err := s.Conn.Read(p)
	for err == nil && s.dropReads.Load() {
		n, err = s.Conn.Read(p)
	}
	return n, err
}

func (s *spyConn) recordedWrites() []int {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]int, len(s.writes))
	copy(out, s.writes)
	return out
}

type aetherTestEnv struct {
	priv   *ecdh.PrivateKey
	pub    *ecdh.PublicKey
	creds  ClientCredentials
	auth   *ServerAuthenticator
	replay *SlidingBloomFilter
	target M.Socksaddr
}

func newAetherTestEnv(t *testing.T, multiUser bool) *aetherTestEnv {
	t.Helper()
	var rawServerKey [PSKSize]byte
	if _, err := io.ReadFull(rand.Reader, rawServerKey[:]); err != nil {
		t.Fatal(err)
	}
	serverSecret := base64.StdEncoding.EncodeToString(rawServerKey[:])

	priv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pub := priv.PublicKey()
	privB64 := base64.StdEncoding.EncodeToString(priv.Bytes())

	var users []option.AetherUser
	var creds ClientCredentials
	if multiUser {
		u1 := "11111111-2222-3333-4444-555555555555"
		u2 := "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
		users = []option.AetherUser{
			{Name: "alice", Password: u1},
			{Name: "bob", Password: u2},
		}
		creds, err = ParseOutboundCredentials(serverSecret + ":" + u1)
		if err != nil {
			t.Fatal(err)
		}
	} else {
		creds, err = ParseOutboundCredentials(serverSecret)
		if err != nil {
			t.Fatal(err)
		}
	}

	auth, err := NewServerAuthenticator(serverSecret, users, privB64)
	if err != nil {
		t.Fatal(err)
	}
	replay := NewSlidingBloomFilter(DefaultTimeWindow, time.Now)

	return &aetherTestEnv{
		priv:   priv,
		pub:    pub,
		creds:  creds,
		auth:   auth,
		replay: replay,
		target: M.ParseSocksaddrHostPort("93.184.216.34", 443),
	}
}

func tcpLoopbackPair(t *testing.T) (net.Conn, net.Conn) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	type dialRes struct {
		c   net.Conn
		err error
	}
	ch := make(chan dialRes, 1)
	go func() {
		c, err := net.Dial("tcp", ln.Addr().String())
		ch <- dialRes{c: c, err: err}
	}()

	srv, err := ln.Accept()
	if err != nil {
		t.Fatal(err)
	}
	cliRes := <-ch
	if cliRes.err != nil {
		srv.Close()
		t.Fatal(cliRes.err)
	}
	t.Cleanup(func() {
		_ = cliRes.c.Close()
		_ = srv.Close()
	})
	return cliRes.c, srv
}

func TestClientZeroRTTCoalescingBeforeServerBytes(t *testing.T) {
	for _, multiUser := range []bool{false, true} {
		name := "single_user"
		if multiUser {
			name = "multi_user_eih"
		}
		t.Run(name, func(t *testing.T) {
			env := newAetherTestEnv(t, multiUser)
			rawCli, rawSrv := tcpLoopbackPair(t)
			cliSpy := newSpyConn(rawCli)
			srvSpy := newSpyConn(rawSrv)

			cc, err := DialEarlyConn(cliSpy, ClientConnOptions{
				Credentials:       env.creds,
				ServerStaticPub:   env.pub,
				Command:           CommandTCP,
				CipherSuite:       CipherAES256GCM,
				TargetAddr:        env.target,
				HeartbeatInterval: -1,
			})
			if err != nil {
				t.Fatal(err)
			}
			defer cc.Close()

			if !cc.NeedHandshakeForWrite() || !cc.NeedHandshakeForRead() || !cc.NeedHandshake() {
				t.Fatal("expected initial NeedHandshake flags true")
			}

			// Write 500B BEFORE server has read or replied a single byte!
			payload := bytes.Repeat([]byte{0x3c}, 500)
			n, err := cc.Write(payload)
			if err != nil || n != len(payload) {
				t.Fatalf("0-RTT Write returned (%d, %v)", n, err)
			}
			if cc.NeedHandshakeForWrite() || cc.NeedHandshake() {
				t.Fatal("NeedHandshakeForWrite/NeedHandshake must become false after InitialBurst")
			}

			writes := cliSpy.recordedWrites()
			if len(writes) != 1 {
				t.Fatalf("expected exactly 1 coalesced rawConn.Write for 0-RTT burst, got %d (%v)", len(writes), writes)
			}
			expectedPrefix := env.auth.ClientPrefixSize()
			minSize := expectedPrefix + MinNoiseLen + 7 + len(payload) + AEADTagSize
			if writes[0] < minSize {
				t.Fatalf("coalesced burst too small: %d < %d", writes[0], minSize)
			}

			// Server accepts WITHOUT sending anything back yet and reads the 500B 0-RTT payload!
			srvRes, err := AcceptServerConn(context.Background(), srvSpy, ServerConnOptions{
				Authenticator:     env.auth,
				ReplayFilter:      env.replay,
				HeartbeatInterval: -1,
			})
			if err != nil {
				t.Fatal(err)
			}
			defer srvRes.Conn.Close()
			if srvRes.Command != CommandTCP || srvRes.TargetAddr.String() != env.target.String() {
				t.Fatalf("unexpected accept metadata: %+v", srvRes)
			}
			if len(srvSpy.recordedWrites()) != 0 {
				t.Fatalf("server unexpectedly wrote bytes on AcceptServerConn: %v", srvSpy.recordedWrites())
			}

			got := make([]byte, len(payload))
			if _, err := io.ReadFull(srvRes.Conn, got); err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(got, payload) {
				t.Fatal("0-RTT payload mismatch on server")
			}
		})
	}
}

func TestServerResponseCoalescingFirstFrame(t *testing.T) {
	firstFrameModes := []struct {
		name string
		fn   func(*Conn) error
	}{
		{"first_frame_data", func(sc *Conn) error {
			_, err := sc.Write([]byte("hello client"))
			return err
		}},
		{"first_frame_ping", func(sc *Conn) error {
			return sc.sendControlFrame(FramePing)
		}},
		{"first_frame_close_write", func(sc *Conn) error {
			return sc.CloseWrite()
		}},
	}

	for _, tc := range firstFrameModes {
		t.Run(tc.name, func(t *testing.T) {
			env := newAetherTestEnv(t, false)
			rawCli, rawSrv := tcpLoopbackPair(t)
			cliSpy := newSpyConn(rawCli)
			srvSpy := newSpyConn(rawSrv)

			cc, err := DialEarlyConn(cliSpy, ClientConnOptions{
				Credentials:       env.creds,
				ServerStaticPub:   env.pub,
				Command:           CommandTCP,
				CipherSuite:       CipherChaCha20Poly1305,
				TargetAddr:        env.target,
				HeartbeatInterval: -1,
			})
			if err != nil {
				t.Fatal(err)
			}
			defer cc.Close()

			if _, err := cc.Write([]byte("req")); err != nil {
				t.Fatal(err)
			}

			srvRes, err := AcceptServerConn(context.Background(), srvSpy, ServerConnOptions{
				Authenticator:     env.auth,
				ReplayFilter:      env.replay,
				HeartbeatInterval: -1,
			})
			if err != nil {
				t.Fatal(err)
			}
			defer srvRes.Conn.Close()

			if err := tc.fn(srvRes.Conn); err != nil {
				t.Fatal(err)
			}
			writes := srvSpy.recordedWrites()
			if len(writes) != 1 {
				t.Fatalf("expected 1 coalesced S2C write (84B + frame), got %d (%v)", len(writes), writes)
			}
			// Minimum size: 84 (ServerRespPrefix) + 18 (EncLen) + 2 (Type+Pad) + 0 (data) + 16 (Tag) = 120.
			if writes[0] < 120 {
				t.Fatalf("coalesced first S2C write %d < 120", writes[0])
			}
			if err := cc.ensureClientHandshakeRead(); err != nil {
				t.Fatalf("client failed to read coalesced server response: %v", err)
			}
			if cc.NeedHandshakeForRead() {
				t.Fatal("NeedHandshakeForRead should be false after reading 84B ServerResponsePrefix")
			}
		})
	}
}

func TestClientOverflowGreaterThanVarHeaderAndServerSpeaksFirst(t *testing.T) {
	t.Run("overflow_32k_0rtt", func(t *testing.T) {
		env := newAetherTestEnv(t, false)
		rawCli, rawSrv := tcpLoopbackPair(t)
		cliSpy := newSpyConn(rawCli)
		srvSpy := newSpyConn(rawSrv)

		cc, err := DialEarlyConn(cliSpy, ClientConnOptions{
			Credentials:       env.creds,
			ServerStaticPub:   env.pub,
			Command:           CommandTCP,
			CipherSuite:       CipherAES256GCM,
			TargetAddr:        env.target,
			HeartbeatInterval: -1,
		})
		if err != nil {
			t.Fatal(err)
		}
		defer cc.Close()

		payload := make([]byte, 32768)
		for i := range payload {
			payload[i] = byte(i * 13)
		}

		// Server accepts initial 0-RTT prefix, reads initial chunk, replies ACK (delivering 84B),
		// then reads remaining overflow bytes + follow-up write.
		srvErrCh := make(chan error, 1)
		go func() {
			srvRes, err := AcceptServerConn(context.Background(), srvSpy, ServerConnOptions{
				Authenticator:     env.auth,
				ReplayFilter:      env.replay,
				HeartbeatInterval: -1,
			})
			if err != nil {
				srvErrCh <- err
				return
			}
			defer srvRes.Conn.Close()
			if _, err := srvRes.Conn.Write([]byte("ACK")); err != nil {
				srvErrCh <- err
				return
			}
			got := make([]byte, len(payload)+64)
			if _, err := io.ReadFull(srvRes.Conn, got); err != nil {
				srvErrCh <- err
				return
			}
			if !bytes.Equal(got[:len(payload)], payload) || !bytes.Equal(got[len(payload):], bytes.Repeat([]byte{0x77}, 64)) {
				srvErrCh <- errors.New("server payload mismatch")
				return
			}
			srvErrCh <- nil
		}()

		n, err := cc.Write(payload)
		if err != nil || n != len(payload) {
			t.Fatalf("Write(32K) returned (%d, %v)", n, err)
		}
		if _, err := cc.Write(bytes.Repeat([]byte{0x77}, 64)); err != nil {
			t.Fatalf("follow-up write err: %v", err)
		}
		ack := make([]byte, 3)
		if _, err := io.ReadFull(cc, ack); err != nil || string(ack) != "ACK" {
			t.Fatalf("client ack read (%q, %v)", ack, err)
		}
		if err := <-srvErrCh; err != nil {
			t.Fatal(err)
		}
		// Ensure first rawConn write was <= ClientPrefix + MaxVarHeaderLen + Tag (single coalesced 0-RTT burst).
		writes := cliSpy.recordedWrites()
		if len(writes) < 2 || writes[0] > ClientPrefixNoEIHSize+MaxVarHeaderLen+AEADTagSize {
			t.Fatalf("unexpected write pattern %v", writes)
		}
	})

	t.Run("server_speaks_first_read_before_write", func(t *testing.T) {
		env := newAetherTestEnv(t, false)
		rawCli, rawSrv := tcpLoopbackPair(t)
		cliSpy := newSpyConn(rawCli)
		srvSpy := newSpyConn(rawSrv)

		cc, err := DialEarlyConn(cliSpy, ClientConnOptions{
			Credentials:       env.creds,
			ServerStaticPub:   env.pub,
			Command:           CommandTCP,
			CipherSuite:       CipherAES256GCM,
			TargetAddr:        env.target,
			HeartbeatInterval: -1,
		})
		if err != nil {
			t.Fatal(err)
		}
		defer cc.Close()

		doneCh := make(chan error, 1)
		go func() {
			srvRes, err := AcceptServerConn(context.Background(), srvSpy, ServerConnOptions{
				Authenticator:     env.auth,
				ReplayFilter:      env.replay,
				HeartbeatInterval: -1,
			})
			if err != nil {
				doneCh <- err
				return
			}
			defer srvRes.Conn.Close()
			if _, err := srvRes.Conn.Write([]byte("SSH-2.0-AetherBanner")); err != nil {
				doneCh <- err
				return
			}
			doneCh <- nil
		}()

		banner := make([]byte, len("SSH-2.0-AetherBanner"))
		if _, err := io.ReadFull(cc, banner); err != nil {
			t.Fatal(err)
		}
		if string(banner) != "SSH-2.0-AetherBanner" {
			t.Fatalf("banner=%q", banner)
		}
		if err := <-doneCh; err != nil {
			t.Fatal(err)
		}
	})

	t.Run("empty_writes_emit_zero_frames", func(t *testing.T) {
		env := newAetherTestEnv(t, false)
		rawCli, rawSrv := tcpLoopbackPair(t)
		cliSpy := newSpyConn(rawCli)
		cc, err := DialEarlyConn(cliSpy, ClientConnOptions{
			Credentials:       env.creds,
			ServerStaticPub:   env.pub,
			Command:           CommandTCP,
			TargetAddr:        env.target,
			HeartbeatInterval: -1,
		})
		if err != nil {
			t.Fatal(err)
		}
		defer cc.Close()
		defer rawSrv.Close()

		if n, err := cc.Write(nil); n != 0 || err != nil {
			t.Fatalf("Write(nil) = (%d, %v)", n, err)
		}
		if n, err := cc.Write([]byte{}); n != 0 || err != nil {
			t.Fatalf("Write([]) = (%d, %v)", n, err)
		}
		emptyBuf := buf.NewSize(128)
		if err := cc.WriteBuffer(emptyBuf); err != nil {
			t.Fatalf("WriteBuffer(empty) err = %v", err)
		}
		if emptyBuf.Cap() != 0 {
			t.Fatalf("empty WriteBuffer did not release caller buffer")
		}
		if len(cliSpy.recordedWrites()) != 0 {
			t.Fatalf("empty writes emitted wire data: %v", cliSpy.recordedWrites())
		}
	})
}

func TestHeadOnlyShapingCutoverWireSizes(t *testing.T) {
	env := newAetherTestEnv(t, false)
	rawCli, rawSrv := tcpLoopbackPair(t)
	cliSpy := newSpyConn(rawCli)
	srvSpy := newSpyConn(rawSrv)

	cc, err := DialEarlyConn(cliSpy, ClientConnOptions{
		Credentials:       env.creds,
		ServerStaticPub:   env.pub,
		Command:           CommandTCP,
		CipherSuite:       CipherAES256GCM,
		TargetAddr:        env.target,
		HeartbeatInterval: -1,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer cc.Close()

	srvCh := make(chan *Conn, 1)
	go func() {
		res, err := AcceptServerConn(context.Background(), srvSpy, ServerConnOptions{
			Authenticator:     env.auth,
			ReplayFilter:      env.replay,
			HeartbeatInterval: -1,
		})
		if err != nil {
			t.Error(err)
			return
		}
		srvCh <- res.Conn
	}()

	// Initial 0-RTT burst.
	if _, err := cc.Write([]byte("init")); err != nil {
		t.Fatal(err)
	}
	sc := <-srvCh
	defer sc.Close()
	bufInit := make([]byte, 4)
	if _, err := io.ReadFull(sc, bufInit); err != nil {
		t.Fatal(err)
	}
	// Trigger Server 84B + first reply frame so client sendCipher initializes cleanly.
	if _, err := sc.Write([]byte("srv0")); err != nil {
		t.Fatal(err)
	}
	bufSrv0 := make([]byte, 4)
	if _, err := io.ReadFull(cc, bufSrv0); err != nil {
		t.Fatal(err)
	}

	// Send 6 shaped chunks cleanly (6 x 1200B -> frames 0..5), then a 16384B unpadded frame (frame 6).
	baseWrites := len(cliSpy.recordedWrites())
	totalApp := 6*1200 + MaxFrameDataSize
	go func() {
		discard := make([]byte, 16384)
		remaining := totalApp
		for remaining > 0 {
			n, err := sc.Read(discard)
			if err != nil {
				return
			}
			remaining -= n
		}
	}()

	for i := 0; i < 6; i++ {
		if _, err := cc.Write(bytes.Repeat([]byte{byte(i)}, 1200)); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := cc.Write(bytes.Repeat([]byte{0xfe}, MaxFrameDataSize)); err != nil {
		t.Fatal(err)
	}

	writes := cliSpy.recordedWrites()[baseWrites:]
	if len(writes) != 7 {
		t.Fatalf("expected 7 writes after handshake (6 shaped + 1 steady), got %d (%v)", len(writes), writes)
	}
	for i := 0; i < 6; i++ {
		// Each 1200B frame 0..5 has wire size = 18 + 2 + [16..255] + 1200 + 16 = 1252..1491.
		if writes[i] < 1252 || writes[i] > 1491 {
			t.Fatalf("shaped frame %d wire len %d outside [1252,1491]", i, writes[i])
		}
	}
	// Frame 6 MUST have PadLen = 0: 18 + 2 + 0 + 16384 + 16 = 16420!
	if writes[6] != EncryptedLengthSize+MinFramePlainSize+MaxFrameDataSize+AEADTagSize {
		t.Fatalf("frame 6 wire len = %d, want %d (PadLen=0)", writes[6], EncryptedLengthSize+MinFramePlainSize+MaxFrameDataSize+AEADTagSize)
	}
}

func TestChaff100FramesAndBufioCopyAndTightBuffer(t *testing.T) {
	env := newAetherTestEnv(t, false)
	rawCli, rawSrv := tcpLoopbackPair(t)

	cc, err := DialEarlyConn(rawCli, ClientConnOptions{
		Credentials:       env.creds,
		ServerStaticPub:   env.pub,
		Command:           CommandTCP,
		TargetAddr:        env.target,
		HeartbeatInterval: -1,
		DisableShaping:    true,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer cc.Close()

	var sc *Conn
	accDone := make(chan error, 1)
	go func() {
		res, err := AcceptServerConn(context.Background(), rawSrv, ServerConnOptions{
			Authenticator:     env.auth,
			ReplayFilter:      env.replay,
			HeartbeatInterval: -1,
			DisableShaping:    true,
		})
		if err != nil {
			accDone <- err
			return
		}
		sc = res.Conn
		accDone <- nil
	}()

	if _, err := cc.Write([]byte("go")); err != nil {
		t.Fatal(err)
	}
	if err := <-accDone; err != nil {
		t.Fatal(err)
	}
	defer sc.Close()

	wantData := bytes.Repeat([]byte("AetherV2Payload!"), 256) // 4096B

	go func() {
		sc.writeMu.Lock()
		for i := 0; i < 100; i++ {
			if err := sc.writeSealedFrameLocked(FrameData, 16, nil, time.Now().Add(2*time.Second)); err != nil {
				sc.writeMu.Unlock()
				return
			}
		}
		sc.writeMu.Unlock()
		_, _ = sc.Write(wantData)
		_ = sc.CloseWrite()
	}()

	// First test ReadBuffer with a tight 64B buffer (T2-F23-04)!
	tight := buf.NewSize(64)
	defer tight.Release()
	if err := cc.ReadBuffer(tight); err != nil {
		t.Fatalf("tight ReadBuffer err: %v", err)
	}
	if tight.Len() != 64 || tight.Cap() != 64 {
		t.Fatalf("tight ReadBuffer len=%d cap=%d, want 64/64", tight.Len(), tight.Cap())
	}
	// Full buffer must return io.ErrShortBuffer WITHOUT releasing tight buffer.
	if err := cc.ReadBuffer(tight); !errors.Is(err, io.ErrShortBuffer) || tight.Cap() != 64 {
		t.Fatalf("full ReadBuffer err=%v cap=%d", err, tight.Cap())
	}

	// Drain remaining bytes through sing/common/bufio.Copy.
	var dst bytes.Buffer
	dst.Write(tight.Bytes())
	copied, err := bufio.Copy(&dst, cc)
	if err != nil {
		t.Fatalf("bufio.Copy after 100 chaff frames err: %v", err)
	}
	if copied != int64(len(wantData)-64) || !bytes.Equal(dst.Bytes(), wantData) {
		t.Fatalf("copied=%d len=%d mismatch", copied, dst.Len())
	}

	// Verify WriteBuffer releases buffer cleanly both on success and after Close().
	wb := buf.NewSize(256)
	_, _ = wb.Write([]byte("owned"))
	if err := cc.WriteBuffer(wb); err != nil {
		t.Fatalf("WriteBuffer err: %v", err)
	}
	if wb.Cap() != 0 {
		t.Fatal("WriteBuffer did not release caller buffer on success")
	}
	_ = cc.Close()
	wbClosed := buf.NewSize(256)
	_, _ = wbClosed.Write([]byte("closed"))
	if err := cc.WriteBuffer(wbClosed); err == nil {
		t.Fatal("expected error writing to closed conn")
	}
	if wbClosed.Cap() != 0 {
		t.Fatal("WriteBuffer did not release caller buffer on error")
	}

	// Static interface assertions for Sing-Box metadata checks.
	if cc.WriterMTU() != MaxFrameDataSize {
		t.Fatalf("WriterMTU=%d", cc.WriterMTU())
	}
	if cc.ReaderReplaceable() || cc.WriterReplaceable() {
		t.Fatal("ReaderReplaceable/WriterReplaceable must be false")
	}
	if cc.Upstream() != rawCli {
		t.Fatal("Upstream mismatch")
	}
	_ = N.EarlyConn(cc)
}

func TestControlPlaneDecouplingPingFlood(t *testing.T) {
	env := newAetherTestEnv(t, false)
	rawCli, rawSrv := tcpLoopbackPair(t)

	cc, err := DialEarlyConn(rawCli, ClientConnOptions{
		Credentials:       env.creds,
		ServerStaticPub:   env.pub,
		Command:           CommandTCP,
		TargetAddr:        env.target,
		HeartbeatInterval: -1,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer cc.Close()

	accCh := make(chan *Conn, 1)
	go func() {
		res, err := AcceptServerConn(context.Background(), rawSrv, ServerConnOptions{
			Authenticator:     env.auth,
			ReplayFilter:      env.replay,
			HeartbeatInterval: -1,
		})
		if err != nil {
			t.Error(err)
			return
		}
		accCh <- res.Conn
	}()

	if _, err := cc.Write([]byte("hello")); err != nil {
		t.Fatal(err)
	}
	sc := <-accCh
	defer sc.Close()

	// Saturate Ping->Pong concurrently with data writes to prove Read loop never touches writeMu.
	errCh := make(chan error, 2)
	go func() {
		for i := 0; i < 20; i++ {
			if err := sc.sendControlFrame(FramePing); err != nil {
				errCh <- err
				return
			}
		}
		_, err := sc.Write([]byte("done"))
		_ = sc.CloseWrite()
		errCh <- err
	}()
	go func() {
		for i := 0; i < 20; i++ {
			if _, err := cc.Write([]byte("uplink-chunk")); err != nil {
				errCh <- err
				return
			}
		}
		_ = cc.CloseWrite()
		errCh <- nil
	}()

	gotCli, err := io.ReadAll(cc)
	if err != nil || string(gotCli) != "done" {
		t.Fatalf("client ReadAll = (%q, %v)", gotCli, err)
	}
	gotSrv, err := io.ReadAll(sc)
	if err != nil {
		t.Fatalf("server ReadAll err: %v", err)
	}
	if len(gotSrv) != len("hello")+20*len("uplink-chunk") {
		t.Fatalf("server got len=%d", len(gotSrv))
	}
	for i := 0; i < 2; i++ {
		if e := <-errCh; e != nil {
			t.Fatal(e)
		}
	}
}

func TestWriteDeadlinePastNoDesyncAndWriteBrokenFuse(t *testing.T) {
	t.Run("past_write_deadline_fuses_writeBroken_preserves_read", func(t *testing.T) {
		env := newAetherTestEnv(t, false)
		rawCli, rawSrv := tcpLoopbackPair(t)

		cc, err := DialEarlyConn(rawCli, ClientConnOptions{
			Credentials:       env.creds,
			ServerStaticPub:   env.pub,
			Command:           CommandTCP,
			TargetAddr:        env.target,
			HeartbeatInterval: -1,
		})
		if err != nil {
			t.Fatal(err)
		}
		defer cc.Close()

		srvCh := make(chan *Conn, 1)
		go func() {
			res, err := AcceptServerConn(context.Background(), rawSrv, ServerConnOptions{
				Authenticator:     env.auth,
				ReplayFilter:      env.replay,
				HeartbeatInterval: -1,
			})
			if err == nil {
				srvCh <- res.Conn
			}
		}()

		if _, err := cc.Write([]byte("init")); err != nil {
			t.Fatal(err)
		}
		sc := <-srvCh
		defer sc.Close()
		if _, err := sc.Write([]byte("ok")); err != nil {
			t.Fatal(err)
		}
		ack := make([]byte, 2)
		if _, err := io.ReadFull(cc, ack); err != nil {
			t.Fatal(err)
		}

		// Set an already-expired write deadline; Write MUST fail, latch writeBroken, and preserve read side.
		if err := cc.SetWriteDeadline(time.Now().Add(-time.Second)); err != nil {
			t.Fatal(err)
		}
		if _, err := cc.Write([]byte("should-not-encrypt")); !errors.Is(err, os.ErrDeadlineExceeded) {
			t.Fatalf("expected ErrDeadlineExceeded, got %v", err)
		}
		if !cc.writeBroken.Load() || cc.closed.Load() {
			t.Fatalf("writeBroken=%v closed=%v, want true/false", cc.writeBroken.Load(), cc.closed.Load())
		}

		// Clear deadline: write side remains fused (net.ErrClosed), while S2C Read still works cleanly!
		if err := cc.SetWriteDeadline(time.Time{}); err != nil {
			t.Fatal(err)
		}
		if _, err := cc.Write([]byte("after-reset")); !errors.Is(err, net.ErrClosed) {
			t.Fatalf("Write after writeBroken fuse expected net.ErrClosed, got %v", err)
		}
		if _, err := sc.Write([]byte("srv-still-open")); err != nil {
			t.Fatalf("server Write failed: %v", err)
		}
		stillOpen := make([]byte, len("srv-still-open"))
		if _, err := io.ReadFull(cc, stillOpen); err != nil || string(stillOpen) != "srv-still-open" {
			t.Fatalf("client Read got (%q, %v)", stillOpen, err)
		}
		gotInit := make([]byte, 4)
		if _, err := io.ReadFull(sc, gotInit); err != nil || string(gotInit) != "init" {
			t.Fatalf("server got (%q, %v)", gotInit, err)
		}
	})

	t.Run("raw_write_failure_fuses_writeBroken_and_closes", func(t *testing.T) {
		env := newAetherTestEnv(t, false)
		rawCli, rawSrv := tcpLoopbackPair(t)
		cliSpy := newSpyConn(rawCli)

		cc, err := DialEarlyConn(cliSpy, ClientConnOptions{
			Credentials:       env.creds,
			ServerStaticPub:   env.pub,
			Command:           CommandTCP,
			TargetAddr:        env.target,
			HeartbeatInterval: -1,
		})
		if err != nil {
			t.Fatal(err)
		}
		defer rawSrv.Close()
		defer cc.Close()

		cliSpy.shortWrite.Store(true)
		if _, err := cc.Write([]byte("burst")); err == nil {
			t.Fatal("expected write failure on short write")
		}
		if !cc.writeBroken.Load() || !cc.closed.Load() {
			t.Fatalf("writeBroken=%v closed=%v, want both true", cc.writeBroken.Load(), cc.closed.Load())
		}
		if _, err := cc.Write([]byte("second")); !errors.Is(err, net.ErrClosed) {
			t.Fatalf("second Write expected net.ErrClosed, got %v", err)
		}
	})
}

func TestReadDeadlineMidFrameRecovery(t *testing.T) {
	env := newAetherTestEnv(t, false)
	rawCli, rawSrv := tcpLoopbackPair(t)

	cc, err := DialEarlyConn(rawCli, ClientConnOptions{
		Credentials:       env.creds,
		ServerStaticPub:   env.pub,
		Command:           CommandTCP,
		TargetAddr:        env.target,
		HeartbeatInterval: -1,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer cc.Close()

	srvCh := make(chan *Conn, 1)
	go func() {
		res, err := AcceptServerConn(context.Background(), rawSrv, ServerConnOptions{
			Authenticator:     env.auth,
			ReplayFilter:      env.replay,
			HeartbeatInterval: -1,
		})
		if err == nil {
			srvCh <- res.Conn
		}
	}()

	if _, err := cc.Write([]byte("hello")); err != nil {
		t.Fatal(err)
	}
	sc := <-srvCh
	defer sc.Close()

	// Complete server 84B + frame 0 cleanly first.
	if _, err := sc.Write([]byte("frame0")); err != nil {
		t.Fatal(err)
	}
	tmp := make([]byte, 6)
	if _, err := io.ReadFull(cc, tmp); err != nil {
		t.Fatal(err)
	}

	// Send ONLY the first 10 bytes of the next frame's 18B encrypted length header directly!
	sc.writeMu.Lock()
	plain, err := AppendFrameBody(nil, FrameData, 0, []byte("recovered-payload"))
	if err != nil {
		sc.writeMu.Unlock()
		t.Fatal(err)
	}
	wireFrame, err := sc.sendCipher.SealFrame(nil, plain)
	if err != nil {
		sc.writeMu.Unlock()
		t.Fatal(err)
	}
	sc.writeMu.Unlock()

	if _, err := rawSrv.Write(wireFrame[:10]); err != nil {
		t.Fatal(err)
	}

	// Trigger SetReadDeadline timeout mid-length-header, clear deadline, deliver remainder!
	if err := cc.SetReadDeadline(time.Now().Add(25 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	out := make([]byte, 64)
	if _, err := cc.Read(out); !isTimeoutError(err) {
		t.Fatalf("expected timeout reading partial frame, got %v", err)
	}
	if err := cc.SetReadDeadline(time.Time{}); err != nil {
		t.Fatal(err)
	}
	if _, err := rawSrv.Write(wireFrame[10:]); err != nil {
		t.Fatal(err)
	}
	if err := cc.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatal(err)
	}
	n, err := cc.Read(out)
	if err != nil || string(out[:n]) != "recovered-payload" {
		t.Fatalf("recovery Read = (%q, %v), want \"recovered-payload\"", out[:n], err)
	}
}

func TestHeartbeatSuppressionAndContinuousUplinkDPD(t *testing.T) {
	t.Run("active_echo_suppresses_idle_pings", func(t *testing.T) {
		env := newAetherTestEnv(t, false)
		rawCli, rawSrv := tcpLoopbackPair(t)
		cliSpy := newSpyConn(rawCli)

		cc, err := DialEarlyConn(cliSpy, ClientConnOptions{
			Credentials:       env.creds,
			ServerStaticPub:   env.pub,
			Command:           CommandTCP,
			TargetAddr:        env.target,
			HeartbeatInterval: 400 * time.Millisecond,
			DisableShaping:    true,
		})
		if err != nil {
			t.Fatal(err)
		}
		defer cc.Close()

		srvCh := make(chan *Conn, 1)
		go func() {
			res, err := AcceptServerConn(context.Background(), rawSrv, ServerConnOptions{
				Authenticator:     env.auth,
				ReplayFilter:      env.replay,
				HeartbeatInterval: 400 * time.Millisecond,
				DisableShaping:    true,
			})
			if err != nil {
				return
			}
			srvCh <- res.Conn
			_, _ = bufio.Copy(res.Conn, res.Conn)
		}()

		// Send initial echo, wait for server handle, then do 6 rounds every 80ms (~480ms > 400ms interval).
		if _, err := cc.Write([]byte("ping0")); err != nil {
			t.Fatal(err)
		}
		sc := <-srvCh
		defer sc.Close()
		buf5 := make([]byte, 5)
		if _, err := io.ReadFull(cc, buf5); err != nil {
			t.Fatal(err)
		}
		baseWrites := len(cliSpy.recordedWrites())
		for i := 0; i < 6; i++ {
			time.Sleep(80 * time.Millisecond)
			if _, err := cc.Write([]byte("echo!")); err != nil {
				t.Fatal(err)
			}
			if _, err := io.ReadFull(cc, buf5); err != nil {
				t.Fatal(err)
			}
		}
		writes := cliSpy.recordedWrites()[baseWrites:]
		// Exactly 6 app writes (no redundant Ping/Pong control frames emitted).
		if len(writes) != 6 {
			t.Fatalf("expected 6 writes without idle pings during active echo, got %d (%v)", len(writes), writes)
		}
	})

	t.Run("continuous_uplink_saved_by_pong_and_killed_on_s2c_blackhole", func(t *testing.T) {
		env := newAetherTestEnv(t, false)
		rawCli, rawSrv := tcpLoopbackPair(t)
		cliSpy := newSpyConn(rawCli)

		// Interval 200ms -> PongTimeout = max(100ms, 500ms) = 500ms.
		cc, err := DialEarlyConn(cliSpy, ClientConnOptions{
			Credentials:       env.creds,
			ServerStaticPub:   env.pub,
			Command:           CommandTCP,
			TargetAddr:        env.target,
			HeartbeatInterval: 200 * time.Millisecond,
			DisableShaping:    true,
		})
		if err != nil {
			t.Fatal(err)
		}
		defer cc.Close()

		go func() {
			res, err := AcceptServerConn(context.Background(), rawSrv, ServerConnOptions{
				Authenticator:     env.auth,
				ReplayFilter:      env.replay,
				HeartbeatInterval: 200 * time.Millisecond,
				DisableShaping:    true,
			})
			if err != nil {
				return
			}
			defer res.Conn.Close()
			// Drain client data forever WITHOUT writing any app bytes back (silent downlink)!
			// Server still answers client's FramePing with FramePong via coordinator.
			_, _ = io.Copy(io.Discard, res.Conn)
		}()

		// Prime Read goroutine in background so FramePong advances lastRead.
		readErrCh := make(chan error, 1)
		go func() {
			_, err := io.ReadAll(cc)
			readErrCh <- err
		}()

		// Phase 1 (~750ms): Healthy silent target; continuous uplink keeps lastWrite busy, FramePong keeps lastRead alive!
		for i := 0; i < 15; i++ {
			if _, err := cc.Write([]byte("uplink-only-data")); err != nil {
				t.Fatalf("healthy uplink iteration %d failed unexpectedly: %v", i, err)
			}
			time.Sleep(50 * time.Millisecond)
		}

		// Phase 2: Blackhole S->C while continuous uplink keeps lastWrite busy!
		cliSpy.dropReads.Store(true)
		deadline := time.Now().Add(2500 * time.Millisecond)
		for time.Now().Before(deadline) {
			if _, err := cc.Write([]byte("uplink-during-blackhole")); err != nil {
				// Expected: DPD closed rawConn because lastRead stopped advancing!
				select {
				case rErr := <-readErrCh:
					_ = rErr
				case <-time.After(time.Second):
					t.Fatal("reader did not unblock after DPD close")
				}
				return
			}
			time.Sleep(40 * time.Millisecond)
		}
		t.Fatal("DPD failed to close connection during continuous-uplink S2C blackhole")
	})
}

func TestPacketConnZeroToMaxPayloadConcurrentAndBufferOwnership(t *testing.T) {
	env := newAetherTestEnv(t, false)
	rawCli, rawSrv := tcpLoopbackPair(t)

	cliConn, err := DialEarlyConn(rawCli, ClientConnOptions{
		Credentials:       env.creds,
		ServerStaticPub:   env.pub,
		Command:           CommandUDP,
		TargetAddr:        M.Socksaddr{}, // Tests unspecified CommandUDP normalization
		HeartbeatInterval: -1,
	})
	if err != nil {
		t.Fatal(err)
	}
	cliPkt := NewClientPacketConn(cliConn)
	defer cliPkt.Close()

	srvCh := make(chan *ServerPacketConn, 1)
	go func() {
		res, err := AcceptServerConn(context.Background(), rawSrv, ServerConnOptions{
			Authenticator:     env.auth,
			ReplayFilter:      env.replay,
			HeartbeatInterval: -1,
		})
		if err != nil {
			t.Error(err)
			return
		}
		if res.Command != CommandUDP {
			t.Errorf("server Command = 0x%02x, want 0x02", res.Command)
		}
		srvCh <- NewServerPacketConn(res.Conn)
	}()

	// 1) Reject > 65535B cleanly AND verify caller buffer is released!
	oversized := buf.NewSize(65536)
	oversized.Extend(65536)
	if err := cliPkt.WritePacket(oversized, M.ParseSocksaddrHostPort("8.8.8.8", 53)); !errors.Is(err, ErrPacketTooLarge) {
		t.Fatalf("expected ErrPacketTooLarge for 65536B, got %v", err)
	}
	if oversized.Cap() != 0 {
		t.Fatal("WritePacket did not release oversized caller buffer")
	}

	// 2) Write 0B UDP datagram (also acts as 0-RTT trigger), 1200B FQDN, and 65507B / 65535B jumbo datagram!
	dZero := M.ParseSocksaddrHostPort("1.1.1.1", 53)
	bZero := buf.NewSize(64)
	if err := cliPkt.WritePacket(bZero, dZero); err != nil {
		t.Fatalf("0B WritePacket err: %v", err)
	}
	if bZero.Cap() != 0 {
		t.Fatal("WritePacket did not release 0B buffer")
	}

	srvPkt := <-srvCh
	defer srvPkt.Close()

	readDst := buf.NewSize(65535)
	defer readDst.Release()
	gotDest, err := srvPkt.ReadPacket(readDst)
	if err != nil || gotDest.String() != dZero.String() || readDst.Len() != 0 {
		t.Fatalf("0B ReadPacket got (%s, len=%d, %v)", gotDest, readDst.Len(), err)
	}

	// Server echoes 0B back so 84B ServerResponsePrefix coalesces and client completes keys.
	srvZeroReply := buf.NewSize(64)
	if err := srvPkt.WritePacket(srvZeroReply, dZero); err != nil {
		t.Fatalf("server 0B WritePacket err: %v", err)
	}
	cliZeroDst := buf.NewSize(64)
	defer cliZeroDst.Release()
	if replyDest, err := cliPkt.ReadPacket(cliZeroDst); err != nil || replyDest.String() != dZero.String() || cliZeroDst.Len() != 0 {
		t.Fatalf("client 0B ReadPacket got (%s, len=%d, %v)", replyDest, cliZeroDst.Len(), err)
	}

	// Test ReadPacket with too-small buffer -> MUST return io.ErrShortBuffer AND NOT release caller buffer!
	smallPkt := buf.NewSize(2048)
	_, _ = smallPkt.Write(bytes.Repeat([]byte{0x44}, 2048))
	if err := cliPkt.WritePacket(smallPkt, dZero); err != nil {
		t.Fatalf("WritePacket(2048) err: %v", err)
	}
	tooSmall := buf.NewSize(1024)
	if _, err := srvPkt.ReadPacket(tooSmall); !errors.Is(err, io.ErrShortBuffer) {
		t.Fatalf("short buffer ReadPacket err = %v, want io.ErrShortBuffer", err)
	}
	if tooSmall.Cap() != 1024 {
		t.Fatal("ReadPacket illegally released caller buffer on io.ErrShortBuffer")
	}
	tooSmall.Release()

	// Test jumbo 65535B across multiple 16384B FrameData frames and verify exact payload + FQDN target!
	jumbo := make([]byte, 65535)
	for i := range jumbo {
		jumbo[i] = byte(i ^ (i >> 8))
	}
	jumboDest := M.ParseSocksaddrHostPort("dns.google", 853)
	jb := buf.NewSize(len(jumbo))
	_, _ = jb.Write(jumbo)
	jumboWriteDone := make(chan struct{})
	go func() {
		defer close(jumboWriteDone)
		if err := cliPkt.WritePacket(jb, jumboDest); err != nil {
			t.Errorf("65535B WritePacket err: %v", err)
		}
		if jb.Cap() != 0 {
			t.Error("jumbo WritePacket did not release buffer")
		}
	}()
	readDst.Reset()
	gotJumboDest, err := srvPkt.ReadPacket(readDst)
	<-jumboWriteDone
	if err != nil || gotJumboDest.String() != jumboDest.String() || !bytes.Equal(readDst.Bytes(), jumbo) {
		t.Fatalf("65535B ReadPacket = (%s, len=%d, err=%v)", gotJumboDest, readDst.Len(), err)
	}

	// Now send 65507B IPv4 datagram via WriteTo / ReadFrom!
	d65507 := M.ParseSocksaddrHostPort("8.8.4.4", 53)
	p65507 := bytes.Repeat([]byte{0x9d}, 65507)
	if n, err := cliPkt.WriteTo(p65507, d65507.UDPAddr()); err != nil || n != len(p65507) {
		t.Fatalf("WriteTo 65507B = (%d, %v)", n, err)
	}
	rx := make([]byte, 65535)
	n, addr, err := srvPkt.ReadFrom(rx)
	if err != nil || n != 65507 || addr.String() != d65507.String() || !bytes.Equal(rx[:n], p65507) {
		t.Fatalf("ReadFrom 65507B = (%d, %v, %v)", n, addr, err)
	}

	// Concurrent WritePacket test (8 writers sending multi-frame 20KB datagrams with SHA256 verification).
	const workers = 8
	const perWorker = 4
	expectedHashes := make(map[[32]byte]bool)
	var mu sync.Mutex
	var wg sync.WaitGroup
	wg.Add(workers)
	for w := 0; w < workers; w++ {
		go func(id int) {
			defer wg.Done()
			for k := 0; k < perWorker; k++ {
				pktData := make([]byte, 20000)
				pktData[0] = byte(id)
				pktData[1] = byte(k)
				pktData[len(pktData)-1] = byte(id ^ k)
				sum := sha256.Sum256(pktData)
				mu.Lock()
				expectedHashes[sum] = true
				mu.Unlock()

				b := buf.NewSize(len(pktData))
				_, _ = b.Write(pktData)
				if err := srvPkt.WritePacket(b, dZero); err != nil {
					t.Errorf("concurrent WritePacket err: %v", err)
					return
				}
			}
		}(w)
	}

	received := 0
	cliRx := buf.NewSize(65535)
	defer cliRx.Release()
	for received < workers*perWorker {
		cliRx.Reset()
		if _, err := cliPkt.ReadPacket(cliRx); err != nil {
			t.Fatalf("concurrent ReadPacket %d err: %v", received, err)
		}
		sum := sha256.Sum256(cliRx.Bytes())
		mu.Lock()
		ok := expectedHashes[sum]
		delete(expectedHashes, sum)
		mu.Unlock()
		if !ok {
			t.Fatalf("unexpected or corrupted concurrent packet #%d (len=%d)", received, cliRx.Len())
		}
		received++
	}
	wg.Wait()
	if len(expectedHashes) != 0 {
		t.Fatalf("missing %d concurrent packets", len(expectedHashes))
	}

	// Check PacketConn metadata methods.
	if cliPkt.Upstream() != cliConn || cliPkt.ReaderReplaceable() || cliPkt.WriterReplaceable() {
		t.Fatal("PacketConn metadata check failed")
	}
}

func TestCloseWriteHalfCloseAndUsersOnlyMode(t *testing.T) {
	priv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pub := priv.PublicKey()
	privB64 := base64.StdEncoding.EncodeToString(priv.Bytes())
	uSecret := "11111111-2222-3333-4444-555555555555"
	users := []option.AetherUser{{Name: "alice", Password: uSecret}}

	auth, err := NewServerAuthenticator("", users, privB64)
	if err != nil {
		t.Fatal(err)
	}
	creds, err := ParseOutboundCredentials(uSecret)
	if err != nil {
		t.Fatal(err)
	}
	replay := NewSlidingBloomFilter(DefaultTimeWindow, time.Now)

	rawCli, rawSrv := tcpLoopbackPair(t)
	cc, err := DialEarlyConn(rawCli, ClientConnOptions{
		Credentials:       creds,
		ServerStaticPub:   pub,
		Command:           CommandTCP,
		TargetAddr:        M.ParseSocksaddrHostPort("127.0.0.1", 80),
		HeartbeatInterval: -1,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer cc.Close()

	srvCh := make(chan *ServerAcceptResult, 1)
	go func() {
		res, err := AcceptServerConn(context.Background(), rawSrv, ServerConnOptions{
			Authenticator:     auth,
			ReplayFilter:      replay,
			HeartbeatInterval: -1,
		})
		if err != nil {
			t.Error(err)
			return
		}
		srvCh <- res
	}()

	// Client writes query and half-closes BEFORE or AFTER server replies.
	if _, err := cc.Write([]byte("HALF_REQ")); err != nil {
		t.Fatal(err)
	}
	srvRes := <-srvCh
	sc := srvRes.Conn
	defer sc.Close()
	if srvRes.UserName != "alice" {
		t.Fatalf("UserName = %q, want alice", srvRes.UserName)
	}

	// Server must coalesce 84B + first reply frame so client CloseWrite completes cleanly.
	if _, err := sc.Write([]byte("PART1-")); err != nil {
		t.Fatal(err)
	}
	if err := cc.CloseWrite(); err != nil {
		t.Fatalf("client CloseWrite err: %v", err)
	}
	// Idempotent second CloseWrite should return nil; subsequent Write must fail with net.ErrClosed.
	if err := cc.CloseWrite(); err != nil {
		t.Fatalf("second CloseWrite err: %v", err)
	}
	if _, err := cc.Write([]byte("after-closewrite")); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("Write after CloseWrite err = %v, want net.ErrClosed", err)
	}

	reqBytes, err := io.ReadAll(sc)
	if err != nil || string(reqBytes) != "HALF_REQ" {
		t.Fatalf("server ReadAll after client CloseWrite = (%q, %v)", reqBytes, err)
	}
	// Server's write side remains open after receiving client's FrameCloseWrite!
	if _, err := sc.Write([]byte("PART2")); err != nil {
		t.Fatalf("server write after client CloseWrite err: %v", err)
	}
	if err := sc.CloseWrite(); err != nil {
		t.Fatalf("server CloseWrite err: %v", err)
	}

	respBytes, err := io.ReadAll(cc)
	if err != nil || string(respBytes) != "PART1-PART2" {
		t.Fatalf("client ReadAll = (%q, %v), want PART1-PART2", respBytes, err)
	}
}

func TestWireMalformedFramesRejectedOnConnRead(t *testing.T) {
	malformedBodies := []struct {
		name string
		body []byte
		want error
	}{
		{"frame_type_0x00", []byte{0x00, 0x00}, ErrInvalidFrameType},
		{"frame_type_0x05", []byte{0x05, 0x00, 0x01}, ErrInvalidFrameType},
		{"pad_exceeds_body", []byte{FrameData, 0xff, 0xaa}, ErrInvalidFramePadding},
		{"ping_pad_31", append([]byte{FramePing, 31}, make([]byte, 31)...), ErrMalformedControlFrame},
		{"ping_with_data", append([]byte{FramePing, 32}, make([]byte, 33)...), ErrMalformedControlFrame},
		{"closewrite_with_data", []byte{FrameCloseWrite, 0x00, 0x01}, ErrMalformedControlFrame},
	}

	for _, tc := range malformedBodies {
		t.Run(tc.name, func(t *testing.T) {
			env := newAetherTestEnv(t, false)
			rawCli, rawSrv := tcpLoopbackPair(t)

			cc, err := DialEarlyConn(rawCli, ClientConnOptions{
				Credentials:       env.creds,
				ServerStaticPub:   env.pub,
				Command:           CommandTCP,
				TargetAddr:        env.target,
				HeartbeatInterval: -1,
			})
			if err != nil {
				t.Fatal(err)
			}
			defer cc.Close()

			srvCh := make(chan *Conn, 1)
			go func() {
				res, err := AcceptServerConn(context.Background(), rawSrv, ServerConnOptions{
					Authenticator:     env.auth,
					ReplayFilter:      env.replay,
					HeartbeatInterval: -1,
				})
				if err == nil {
					srvCh <- res.Conn
				}
			}()

			if _, err := cc.Write([]byte("hi")); err != nil {
				t.Fatal(err)
			}
			sc := <-srvCh
			defer sc.Close()

			// Seal and transmit raw crafted invalid body over real DirectionalCipher + 84B prefix.
			sc.writeMu.Lock()
			wire, err := sc.sendCipher.SealFrame(nil, tc.body)
			if err != nil {
				sc.writeMu.Unlock()
				t.Fatal(err)
			}
			pkt := append(sc.serverRespPrefix[:], wire...)
			sc.writeMu.Unlock()

			if _, err := rawSrv.Write(pkt); err != nil {
				t.Fatal(err)
			}

			bufRead := make([]byte, 64)
			if _, err := cc.Read(bufRead); !errors.Is(err, tc.want) {
				t.Fatalf("Conn.Read err = %v, want %v", err, tc.want)
			}
		})
	}
}

func TestConcurrentReadBufferAndDelayedWriteZeroRTT(t *testing.T) {
	env := newAetherTestEnv(t, false)
	rawCli, rawSrv := tcpLoopbackPair(t)
	cliSpy := newSpyConn(rawCli)

	cc, err := DialEarlyConn(cliSpy, ClientConnOptions{
		Credentials:       env.creds,
		ServerStaticPub:   env.pub,
		Command:           CommandTCP,
		TargetAddr:        env.target,
		HeartbeatInterval: -1,
		DisableShaping:    true,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer cc.Close()

	srvErrCh := make(chan error, 1)
	go func() {
		srvRes, err := AcceptServerConn(context.Background(), rawSrv, ServerConnOptions{
			Authenticator:     env.auth,
			ReplayFilter:      env.replay,
			HeartbeatInterval: -1,
			DisableShaping:    true,
		})
		if err != nil {
			srvErrCh <- err
			return
		}
		defer srvRes.Conn.Close()
		// Echo only what arrives from client (server waits for client request first).
		got := make([]byte, 64)
		n, err := srvRes.Conn.Read(got)
		if err != nil {
			srvErrCh <- err
			return
		}
		_, err = srvRes.Conn.Write(got[:n])
		srvErrCh <- err
	}()

	// Simulate sing-box route.ConnectionManager launching download ReadBuffer slightly before upload Write.
	readBuf := buf.NewSize(256)
	defer readBuf.Release()
	readDone := make(chan error, 1)
	go func() {
		readDone <- cc.ReadBuffer(readBuf)
	}()

	time.Sleep(3 * time.Millisecond)
	want := []byte("delayed-0rtt-socks5-payload")
	if _, err := cc.Write(want); err != nil {
		t.Fatalf("client Write failed: %v", err)
	}

	if err := <-readDone; err != nil {
		t.Fatalf("client ReadBuffer failed: %v", err)
	}
	if !bytes.Equal(readBuf.Bytes(), want) {
		t.Fatalf("echo mismatch: got %q, want %q", readBuf.Bytes(), want)
	}
	if err := <-srvErrCh; err != nil {
		t.Fatalf("server error: %v", err)
	}
	// Entire client request must have coalesced into the single 0-RTT initial burst write.
	if writes := cliSpy.recordedWrites(); len(writes) != 1 {
		t.Fatalf("expected single coalesced 0-RTT write, got %d (%v)", len(writes), writes)
	}
}

func TestWriteDeadlineIsolationDuringServerRespRead(t *testing.T) {
	env := newAetherTestEnv(t, false)
	rawCli, rawSrv := tcpLoopbackPair(t)

	cc, err := DialEarlyConn(rawCli, ClientConnOptions{
		Credentials:       env.creds,
		ServerStaticPub:   env.pub,
		Command:           CommandTCP,
		TargetAddr:        env.target,
		HeartbeatInterval: -1,
		DisableShaping:    true,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer cc.Close()

	srvCh := make(chan *Conn, 1)
	go func() {
		res, err := AcceptServerConn(context.Background(), rawSrv, ServerConnOptions{
			Authenticator:     env.auth,
			ReplayFilter:      env.replay,
			HeartbeatInterval: -1,
			DisableShaping:    true,
		})
		if err == nil {
			srvCh <- res.Conn
		}
	}()

	if _, err := cc.Write([]byte("0rtt")); err != nil {
		t.Fatal(err)
	}
	sc := <-srvCh
	defer sc.Close()

	// Concurrent Read awaits 84B ServerResponsePrefix with no read deadline.
	readBuf := make([]byte, 32)
	type readResult struct {
		n   int
		err error
	}
	readDone := make(chan readResult, 1)
	go func() {
		n, rErr := cc.Read(readBuf)
		readDone <- readResult{n: n, err: rErr}
	}()

	// Let Read enter runRespReadAttempt first, then test bounded WriteDeadline on second write.
	time.Sleep(5 * time.Millisecond)
	if err := cc.SetWriteDeadline(time.Now().Add(25 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	if _, err := cc.Write([]byte("blocked-on-84b")); !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("expected os.ErrDeadlineExceeded on second Write, got %v", err)
	}
	if el := time.Since(start); el > 300*time.Millisecond {
		t.Fatalf("Write deadline blocked too long: %v", el)
	}
	if err := cc.SetWriteDeadline(time.Time{}); err != nil {
		t.Fatal(err)
	}

	// Verify Read was NOT poisoned by Write's deadline and completes normally when Server responds.
	if _, err := sc.Write([]byte("server-alive")); err != nil {
		t.Fatal(err)
	}
	rr := <-readDone
	if rr.err != nil || string(readBuf[:rr.n]) != "server-alive" {
		t.Fatalf("Read after Write deadline = (%q, %v), want \"server-alive\"", readBuf[:rr.n], rr.err)
	}
}

func TestSlowClientZeroByteGraceAndPendingServerRespFlush(t *testing.T) {
	for _, tc := range []struct {
		name              string
		heartbeatInterval time.Duration
		minWireLen        int
		maxWireLen        int
	}{
		{"heartbeat_disabled_chaff", -1, ServerRespPrefixSize + EncryptedLengthSize + 2 + AEADTagSize, ServerRespPrefixSize + EncryptedLengthSize + 2 + AEADTagSize},
		{"heartbeat_enabled_ping", 5 * time.Second, ServerRespPrefixSize + EncryptedLengthSize + 2 + MinPingPadLen + AEADTagSize, ServerRespPrefixSize + EncryptedLengthSize + 2 + MaxPingPadLen + AEADTagSize},
	} {
		t.Run(tc.name, func(t *testing.T) {
			env := newAetherTestEnv(t, false)
			rawCli, rawSrv := tcpLoopbackPair(t)
			srvSpy := newSpyConn(rawSrv)

			cc, err := DialEarlyConn(rawCli, ClientConnOptions{
				Credentials:       env.creds,
				ServerStaticPub:   env.pub,
				Command:           CommandTCP,
				TargetAddr:        env.target,
				HeartbeatInterval: tc.heartbeatInterval,
				DisableShaping:    true,
			})
			if err != nil {
				t.Fatal(err)
			}
			defer cc.Close()

			srvErrCh := make(chan error, 1)
			go func() {
				res, err := AcceptServerConn(context.Background(), srvSpy, ServerConnOptions{
					Authenticator:     env.auth,
					ReplayFilter:      env.replay,
					HeartbeatInterval: tc.heartbeatInterval,
					DisableShaping:    true,
				})
				if err != nil {
					srvErrCh <- err
					return
				}
				defer res.Conn.Close()
				// Server waits until slow client writes before echoing app data.
				bufIn := make([]byte, 32)
				n, rErr := res.Conn.Read(bufIn)
				if rErr != nil {
					srvErrCh <- rErr
					return
				}
				_, wErr := res.Conn.Write(bufIn[:n])
				srvErrCh <- wErr
			}()

			// Client starts ReadBuffer first and delays Write past the 25ms grace window.
			readDone := make(chan error, 1)
			readBuf := buf.NewSize(64)
			defer readBuf.Release()
			go func() {
				readDone <- cc.ReadBuffer(readBuf)
			}()

			time.Sleep(45 * time.Millisecond)
			want := []byte("late-client-msg")
			if _, err := cc.Write(want); err != nil {
				t.Fatalf("late client Write failed: %v", err)
			}
			if err := <-readDone; err != nil {
				t.Fatalf("client ReadBuffer failed: %v", err)
			}
			if !bytes.Equal(readBuf.Bytes(), want) {
				t.Fatalf("echo=%q, want %q", readBuf.Bytes(), want)
			}
			if err := <-srvErrCh; err != nil {
				t.Fatalf("server error: %v", err)
			}
			writes := srvSpy.recordedWrites()
			if len(writes) < 2 {
				t.Fatalf("expected coalesced flush + echo writes, got %v", writes)
			}
			if writes[0] < tc.minWireLen || writes[0] > tc.maxWireLen {
				t.Fatalf("first S2C coalesced flush len = %d, want in [%d, %d]", writes[0], tc.minWireLen, tc.maxWireLen)
			}
		})
	}
}

func TestClientBlackholedHandshakeDPD(t *testing.T) {
	env := newAetherTestEnv(t, false)
	rawCli, rawSrv := tcpLoopbackPair(t)
	defer rawSrv.Close()

	cc, err := DialEarlyConn(rawCli, ClientConnOptions{
		Credentials:       env.creds,
		ServerStaticPub:   env.pub,
		Command:           CommandTCP,
		TargetAddr:        env.target,
		HeartbeatInterval: 200 * time.Millisecond,
		DisableShaping:    true,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer cc.Close()

	// Drain client's C2S bytes silently (blackholed S2C 84B ServerResponsePrefix).
	go func() {
		_, _ = io.Copy(io.Discard, rawSrv)
	}()

	if _, err := cc.Write([]byte("trigger-handshake")); err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	_ = cc.SetReadDeadline(time.Now().Add(3 * time.Second))
	var out [16]byte
	_, rErr := cc.Read(out[:])
	elapsed := time.Since(start)
	if rErr == nil {
		t.Fatal("expected Read error on blackholed handshake")
	}
	if errors.Is(rErr, os.ErrDeadlineExceeded) {
		t.Fatalf("DPD should close conn before outer 3s read deadline (elapsed=%v, err=%v)", elapsed, rErr)
	}
	if elapsed > 2*time.Second {
		t.Fatalf("handshake DPD took too long: %v", elapsed)
	}
}

func TestIdleConnAndHalfCloseSurvivesShortHeartbeatWithoutActiveReader(t *testing.T) {
	t.Run("idle_tcp_conn_without_read", func(t *testing.T) {
		env := newAetherTestEnv(t, false)
		rawCli, rawSrv := tcpLoopbackPair(t)

		cc, err := DialEarlyConn(rawCli, ClientConnOptions{
			Credentials:       env.creds,
			ServerStaticPub:   env.pub,
			Command:           CommandTCP,
			TargetAddr:        env.target,
			HeartbeatInterval: 150 * time.Millisecond,
			DisableShaping:    true,
		})
		if err != nil {
			t.Fatal(err)
		}
		defer cc.Close()

		srvCh := make(chan *Conn, 1)
		go func() {
			res, err := AcceptServerConn(context.Background(), rawSrv, ServerConnOptions{
				Authenticator:     env.auth,
				ReplayFilter:      env.replay,
				HeartbeatInterval: 150 * time.Millisecond,
				DisableShaping:    true,
			})
			if err == nil {
				srvCh <- res.Conn
			}
		}()

		if _, err := cc.Write([]byte("warm")); err != nil {
			t.Fatal(err)
		}
		sc := <-srvCh
		defer sc.Close()

		buf := make([]byte, 16)
		if _, err := io.ReadFull(sc, buf[:4]); err != nil {
			t.Fatal(err)
		}
		if _, err := sc.Write(buf[:4]); err != nil {
			t.Fatal(err)
		}
		if _, err := io.ReadFull(cc, buf[:4]); err != nil {
			t.Fatal(err)
		}

		// Neither side calls Read() while multiple heartbeat+pongTimeout windows elapse (>500ms).
		time.Sleep(850 * time.Millisecond)

		if _, err := cc.Write([]byte("post-idle")); err != nil {
			t.Fatalf("client Write after idle failed: %v", err)
		}
		if _, err := io.ReadFull(sc, buf[:9]); err != nil {
			t.Fatalf("server Read after idle failed: %v", err)
		}
		if _, err := sc.Write(buf[:9]); err != nil {
			t.Fatalf("server Write after idle failed: %v", err)
		}
		if _, err := io.ReadFull(cc, buf[:9]); err != nil || string(buf[:9]) != "post-idle" {
			t.Fatalf("client Read after idle = (%q, %v), want post-idle", buf[:9], err)
		}
	})

	t.Run("idle_udp_packetconn_without_read", func(t *testing.T) {
		env := newAetherTestEnv(t, false)
		rawCli, rawSrv := tcpLoopbackPair(t)

		cc, err := DialEarlyConn(rawCli, ClientConnOptions{
			Credentials:       env.creds,
			ServerStaticPub:   env.pub,
			Command:           CommandUDP,
			TargetAddr:        env.target,
			HeartbeatInterval: 150 * time.Millisecond,
			DisableShaping:    true,
		})
		if err != nil {
			t.Fatal(err)
		}
		cp := NewClientPacketConn(cc)
		defer cp.Close()

		srvCh := make(chan *ServerPacketConn, 1)
		go func() {
			res, err := AcceptServerConn(context.Background(), rawSrv, ServerConnOptions{
				Authenticator:     env.auth,
				ReplayFilter:      env.replay,
				HeartbeatInterval: 150 * time.Millisecond,
				DisableShaping:    true,
			})
			if err == nil {
				srvCh <- NewServerPacketConn(res.Conn)
			}
		}()

		pkt := buf.NewPacket()
		_, _ = pkt.Write([]byte("udp-warm"))
		if err := cp.WritePacket(pkt, env.target); err != nil {
			t.Fatal(err)
		}
		sp := <-srvCh
		defer sp.Close()

		rBuf := buf.NewPacket()
		defer rBuf.Release()
		dest, err := sp.ReadPacket(rBuf)
		if err != nil {
			t.Fatal(err)
		}
		reply := buf.NewPacket()
		_, _ = reply.Write(rBuf.Bytes())
		if err := sp.WritePacket(reply, dest); err != nil {
			t.Fatal(err)
		}
		cBuf := buf.NewPacket()
		defer cBuf.Release()
		if _, err := cp.ReadPacket(cBuf); err != nil {
			t.Fatal(err)
		}

		// Neither PacketConn calls ReadPacket during idle > pongTimeout (500ms).
		time.Sleep(850 * time.Millisecond)

		pkt2 := buf.NewPacket()
		_, _ = pkt2.Write([]byte("udp-alive"))
		if err := cp.WritePacket(pkt2, env.target); err != nil {
			t.Fatalf("WritePacket after idle failed: %v", err)
		}
		rBuf.Reset()
		dest, err = sp.ReadPacket(rBuf)
		if err != nil || string(rBuf.Bytes()) != "udp-alive" {
			t.Fatalf("server ReadPacket after idle = (%q, %v)", rBuf.Bytes(), err)
		}
		reply2 := buf.NewPacket()
		_, _ = reply2.Write(rBuf.Bytes())
		if err := sp.WritePacket(reply2, dest); err != nil {
			t.Fatalf("server WritePacket after idle failed: %v", err)
		}
		cBuf.Reset()
		if _, err := cp.ReadPacket(cBuf); err != nil || string(cBuf.Bytes()) != "udp-alive" {
			t.Fatalf("client ReadPacket after idle = (%q, %v)", cBuf.Bytes(), err)
		}
	})

	t.Run("half_close_eof_keeps_ping_pong_alive", func(t *testing.T) {
		env := newAetherTestEnv(t, false)
		rawCli, rawSrv := tcpLoopbackPair(t)

		cc, err := DialEarlyConn(rawCli, ClientConnOptions{
			Credentials:       env.creds,
			ServerStaticPub:   env.pub,
			Command:           CommandTCP,
			TargetAddr:        env.target,
			HeartbeatInterval: 150 * time.Millisecond,
			DisableShaping:    true,
		})
		if err != nil {
			t.Fatal(err)
		}
		defer cc.Close()

		srvErrCh := make(chan error, 1)
		go func() {
			res, err := AcceptServerConn(context.Background(), rawSrv, ServerConnOptions{
				Authenticator:     env.auth,
				ReplayFilter:      env.replay,
				HeartbeatInterval: 150 * time.Millisecond,
				DisableShaping:    true,
			})
			if err != nil {
				srvErrCh <- err
				return
			}
			sc := res.Conn
			defer sc.Close()
			// Read until EOF (FrameCloseWrite), then sleep 850ms WITHOUT calling sc.Read() again.
			req, err := io.ReadAll(sc)
			if err != nil || string(req) != "half-close-req" {
				srvErrCh <- errors.New("server ReadAll mismatch: " + string(req))
				return
			}
			time.Sleep(850 * time.Millisecond)
			if _, err := sc.Write([]byte("delayed-trailer")); err != nil {
				srvErrCh <- err
				return
			}
			srvErrCh <- sc.CloseWrite()
		}()

		if _, err := cc.Write([]byte("half-close-req")); err != nil {
			t.Fatal(err)
		}
		if err := cc.CloseWrite(); err != nil {
			t.Fatal(err)
		}
		got, err := io.ReadAll(cc)
		if err != nil || string(got) != "delayed-trailer" {
			t.Fatalf("client ReadAll = (%q, %v), want delayed-trailer", got, err)
		}
		if err := <-srvErrCh; err != nil {
			t.Fatalf("server error: %v", err)
		}
	})
}

func TestAwaitServerRespWriteDeadlineFusesWriteBroken(t *testing.T) {
	env := newAetherTestEnv(t, false)
	rawCli, rawSrv := tcpLoopbackPair(t)

	cc, err := DialEarlyConn(rawCli, ClientConnOptions{
		Credentials:       env.creds,
		ServerStaticPub:   env.pub,
		Command:           CommandTCP,
		TargetAddr:        env.target,
		HeartbeatInterval: -1,
		DisableShaping:    true,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer cc.Close()

	srvCh := make(chan *Conn, 1)
	go func() {
		res, err := AcceptServerConn(context.Background(), rawSrv, ServerConnOptions{
			Authenticator:     env.auth,
			ReplayFilter:      env.replay,
			HeartbeatInterval: -1,
			DisableShaping:    true,
		})
		if err == nil {
			srvCh <- res.Conn
		}
	}()

	if _, err := cc.Write([]byte("init-req")); err != nil {
		t.Fatal(err)
	}
	sc := <-srvCh
	defer sc.Close()

	// Do not send server response yet; let second WriteBuffer time out in awaitServerRespForWrite.
	if err := cc.SetWriteDeadline(time.Now().Add(20 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	b1 := buf.NewSize(32)
	_, _ = b1.Write([]byte("blocked-write"))
	err = cc.WriteBuffer(b1)
	if !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("WriteBuffer expected os.ErrDeadlineExceeded, got %v", err)
	}

	// Clearing or extending deadline must NOT un-fuse writeBroken!
	if err := cc.SetWriteDeadline(time.Now().Add(3 * time.Second)); err != nil {
		t.Fatal(err)
	}
	b2 := buf.NewSize(32)
	_, _ = b2.Write([]byte("must-fail-fused"))
	err = cc.WriteBuffer(b2)
	if !errors.Is(err, net.ErrClosed) {
		t.Fatalf("WriteBuffer after timeout expected net.ErrClosed, got %v", err)
	}

	// Read path remained open so server can still push downlink reply.
	if _, err := sc.Write([]byte("downlink-ok")); err != nil {
		t.Fatalf("server Write failed: %v", err)
	}
	out := make([]byte, len("downlink-ok"))
	if _, err := io.ReadFull(cc, out); err != nil || string(out) != "downlink-ok" {
		t.Fatalf("client Read = (%q, %v), want downlink-ok", out, err)
	}
}

func TestCloseWriteShapedWhenShapingEnabled(t *testing.T) {
	env := newAetherTestEnv(t, false)
	rawCli, rawSrv := tcpLoopbackPair(t)
	srvSpy := newSpyConn(rawSrv)

	cc, err := DialEarlyConn(rawCli, ClientConnOptions{
		Credentials:       env.creds,
		ServerStaticPub:   env.pub,
		Command:           CommandTCP,
		TargetAddr:        env.target,
		HeartbeatInterval: -1,
		DisableShaping:    false,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer cc.Close()

	srvErrCh := make(chan error, 1)
	go func() {
		res, err := AcceptServerConn(context.Background(), srvSpy, ServerConnOptions{
			Authenticator:     env.auth,
			ReplayFilter:      env.replay,
			HeartbeatInterval: -1,
			DisableShaping:    false,
		})
		if err != nil {
			srvErrCh <- err
			return
		}
		sc := res.Conn
		defer sc.Close()
		buf := make([]byte, 4)
		if _, err := io.ReadFull(sc, buf); err != nil {
			srvErrCh <- err
			return
		}
		srvErrCh <- sc.CloseWrite()
	}()

	if _, err := cc.Write([]byte("ping")); err != nil {
		t.Fatal(err)
	}
	got, err := io.ReadAll(cc)
	if err != nil || len(got) != 0 {
		t.Fatalf("client ReadAll = (%d bytes, %v), want 0 bytes EOF", len(got), err)
	}
	if err := <-srvErrCh; err != nil {
		t.Fatalf("server err: %v", err)
	}

	writes := srvSpy.recordedWrites()
	minShapedCloseWrite := ServerRespPrefixSize + EncryptedLengthSize + 2 + ShapingPadMin + AEADTagSize
	if len(writes) != 1 || writes[0] < minShapedCloseWrite {
		t.Fatalf("server CloseWrite writes=%v, want 1 coalesced shaped write >= %d", writes, minShapedCloseWrite)
	}
}

func TestPacketConnMidHeaderDeadlineRecoveryAndInvalidFQDNRejection(t *testing.T) {
	t.Run("mid_fqdn_header_deadline_recovery", func(t *testing.T) {
		env := newAetherTestEnv(t, false)
		rawCli, rawSrv := tcpLoopbackPair(t)

		cc, err := DialEarlyConn(rawCli, ClientConnOptions{
			Credentials:       env.creds,
			ServerStaticPub:   env.pub,
			Command:           CommandUDP,
			TargetAddr:        env.target,
			HeartbeatInterval: -1,
			DisableShaping:    true,
		})
		if err != nil {
			t.Fatal(err)
		}
		cp := NewClientPacketConn(cc)
		defer cp.Close()

		srvCh := make(chan *Conn, 1)
		go func() {
			res, err := AcceptServerConn(context.Background(), rawSrv, ServerConnOptions{
				Authenticator:     env.auth,
				ReplayFilter:      env.replay,
				HeartbeatInterval: -1,
				DisableShaping:    true,
			})
			if err == nil {
				srvCh <- res.Conn
			}
		}()

		warm := buf.NewPacket()
		_, _ = warm.Write([]byte("w"))
		if err := cp.WritePacket(warm, env.target); err != nil {
			t.Fatal(err)
		}
		sc := <-srvCh
		defer sc.Close()
		sp := NewServerPacketConn(sc)
		warmIn := buf.NewPacket()
		defer warmIn.Release()
		if _, err := sp.ReadPacket(warmIn); err != nil {
			t.Fatal(err)
		}

		// Split raw UDP packet header mid-FQDN ("example.com":443, len=5, "hello").
		fullWire := []byte{
			0x03, 11, 'e', 'x', 'a', 'm', 'p', 'l', 'e', '.', 'c', 'o', 'm',
			0x01, 0xbb, // port 443
			0x00, 0x05, // payload len 5
			'h', 'e', 'l', 'l', 'o',
		}
		if _, err := sc.Write(fullWire[:6]); err != nil {
			t.Fatal(err)
		}

		out := buf.NewPacket()
		defer out.Release()
		_ = cp.SetReadDeadline(time.Now().Add(20 * time.Millisecond))
		if _, err := cp.ReadPacket(out); !isTimeoutError(err) {
			t.Fatalf("expected timeout on partial FQDN header, got %v", err)
		}
		_ = cp.SetReadDeadline(time.Time{})

		if _, err := sc.Write(fullWire[6:]); err != nil {
			t.Fatal(err)
		}
		dest, err := cp.ReadPacket(out)
		if err != nil {
			t.Fatalf("ReadPacket recovery failed: %v", err)
		}
		if dest.Fqdn != "example.com" || dest.Port != 443 || string(out.Bytes()) != "hello" {
			t.Fatalf("recovered=(%v, %q), want example.com:443 \"hello\"", dest, out.Bytes())
		}
	})

	t.Run("mid_payload_len_header_deadline_recovery", func(t *testing.T) {
		env := newAetherTestEnv(t, false)
		rawCli, rawSrv := tcpLoopbackPair(t)

		cc, err := DialEarlyConn(rawCli, ClientConnOptions{
			Credentials:       env.creds,
			ServerStaticPub:   env.pub,
			Command:           CommandUDP,
			TargetAddr:        env.target,
			HeartbeatInterval: -1,
			DisableShaping:    true,
		})
		if err != nil {
			t.Fatal(err)
		}
		cp := NewClientPacketConn(cc)
		defer cp.Close()

		srvCh := make(chan *Conn, 1)
		go func() {
			res, err := AcceptServerConn(context.Background(), rawSrv, ServerConnOptions{
				Authenticator:     env.auth,
				ReplayFilter:      env.replay,
				HeartbeatInterval: -1,
				DisableShaping:    true,
			})
			if err == nil {
				srvCh <- res.Conn
			}
		}()

		warm := buf.NewPacket()
		_, _ = warm.Write([]byte("w"))
		if err := cp.WritePacket(warm, env.target); err != nil {
			t.Fatal(err)
		}
		sc := <-srvCh
		defer sc.Close()
		sp := NewServerPacketConn(sc)
		warmIn := buf.NewPacket()
		defer warmIn.Release()
		if _, err := sp.ReadPacket(warmIn); err != nil {
			t.Fatal(err)
		}

		// Send IPv4 127.0.0.1:80 + first byte (0x00) of uint16 payloadLen only.
		fullWire := []byte{
			0x01, 127, 0, 0, 1,
			0x00, 80,
			0x00, 0x04,
			'p', 'o', 'n', 'g',
		}
		if _, err := sc.Write(fullWire[:8]); err != nil {
			t.Fatal(err)
		}

		out := buf.NewPacket()
		defer out.Release()
		_ = cp.SetReadDeadline(time.Now().Add(20 * time.Millisecond))
		if _, err := cp.ReadPacket(out); !isTimeoutError(err) {
			t.Fatalf("expected timeout on split 2B payloadLen, got %v", err)
		}
		_ = cp.SetReadDeadline(time.Time{})

		if _, err := sc.Write(fullWire[8:]); err != nil {
			t.Fatal(err)
		}
		dest, err := cp.ReadPacket(out)
		if err != nil {
			t.Fatalf("ReadPacket recovery failed: %v", err)
		}
		if dest.String() != "127.0.0.1:80" || string(out.Bytes()) != "pong" {
			t.Fatalf("recovered=(%v, %q), want 127.0.0.1:80 \"pong\"", dest, out.Bytes())
		}
	})

	t.Run("reject_empty_fqdn_len_zero", func(t *testing.T) {
		env := newAetherTestEnv(t, false)
		rawCli, rawSrv := tcpLoopbackPair(t)

		cc, err := DialEarlyConn(rawCli, ClientConnOptions{
			Credentials:       env.creds,
			ServerStaticPub:   env.pub,
			Command:           CommandUDP,
			TargetAddr:        env.target,
			HeartbeatInterval: -1,
			DisableShaping:    true,
		})
		if err != nil {
			t.Fatal(err)
		}
		cp := NewClientPacketConn(cc)
		defer cp.Close()

		srvCh := make(chan *Conn, 1)
		go func() {
			res, err := AcceptServerConn(context.Background(), rawSrv, ServerConnOptions{
				Authenticator:     env.auth,
				ReplayFilter:      env.replay,
				HeartbeatInterval: -1,
				DisableShaping:    true,
			})
			if err == nil {
				srvCh <- res.Conn
			}
		}()

		warm := buf.NewPacket()
		_, _ = warm.Write([]byte("w"))
		if err := cp.WritePacket(warm, env.target); err != nil {
			t.Fatal(err)
		}
		sc := <-srvCh
		defer sc.Close()
		sp := NewServerPacketConn(sc)
		warmIn := buf.NewPacket()
		defer warmIn.Release()
		if _, err := sp.ReadPacket(warmIn); err != nil {
			t.Fatal(err)
		}

		// af=0x03 with strLen=0 must be rejected cleanly with ErrInvalidVarHeader.
		if _, err := sc.Write([]byte{0x03, 0x00, 0x00, 0x50, 0x00, 0x00}); err != nil {
			t.Fatal(err)
		}
		out := buf.NewPacket()
		defer out.Release()
		if _, err := cp.ReadPacket(out); !errors.Is(err, ErrInvalidVarHeader) {
			t.Fatalf("ReadPacket empty FQDN err=%v, want ErrInvalidVarHeader", err)
		}
	})
}

func TestDataFrameAfterCloseWriteRejected(t *testing.T) {
	env := newAetherTestEnv(t, false)
	rawCli, rawSrv := tcpLoopbackPair(t)

	cc, err := DialEarlyConn(rawCli, ClientConnOptions{
		Credentials:       env.creds,
		ServerStaticPub:   env.pub,
		Command:           CommandTCP,
		TargetAddr:        env.target,
		HeartbeatInterval: -1,
		DisableShaping:    true,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer cc.Close()

	srvCh := make(chan *Conn, 1)
	go func() {
		res, err := AcceptServerConn(context.Background(), rawSrv, ServerConnOptions{
			Authenticator:     env.auth,
			ReplayFilter:      env.replay,
			HeartbeatInterval: -1,
			DisableShaping:    true,
		})
		if err == nil {
			srvCh <- res.Conn
		}
	}()

	if _, err := cc.Write([]byte("hello")); err != nil {
		t.Fatal(err)
	}
	sc := <-srvCh
	defer sc.Close()

	// Send normal data, CloseWrite, legal 0-byte chaff (still tolerated), then illegal post-EOF FrameData.
	if _, err := sc.Write([]byte("before-eof")); err != nil {
		t.Fatal(err)
	}
	if err := sc.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	sc.writeMu.Lock()
	chaffErr := sc.writeSealedFrameLocked(FrameData, 8, nil, time.Now().Add(time.Second))
	sc.writeMu.Unlock()
	if chaffErr != nil {
		t.Fatal(chaffErr)
	}

	got, err := io.ReadAll(cc)
	if err != nil || string(got) != "before-eof" {
		t.Fatalf("client ReadAll = (%q, %v), want before-eof", got, err)
	}

	// Peer violates protocol by injecting non-empty FrameData after FrameCloseWrite.
	sc.writeMu.Lock()
	injectErr := sc.writeSealedFrameLocked(FrameData, 0, []byte("after-eof"), time.Now().Add(time.Second))
	sc.writeMu.Unlock()
	if injectErr != nil {
		t.Fatal(injectErr)
	}

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if errors.Is(cc.getReadErr(), ErrInvalidFrameType) && cc.closed.Load() {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	if !errors.Is(cc.getReadErr(), ErrInvalidFrameType) || !cc.closed.Load() {
		t.Fatalf("expected ErrInvalidFrameType & closed=true on post-EOF FrameData, got readErr=%v closed=%v", cc.getReadErr(), cc.closed.Load())
	}
	extra := make([]byte, 16)
	n, rErr := cc.Read(extra)
	if n != 0 || !errors.Is(rErr, io.EOF) {
		t.Fatalf("post-EOF Read = (%d, %v), want (0, io.EOF)", n, rErr)
	}
}
