package aether

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/buf"
	"github.com/sagernet/sing/common/json/badoption"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/common/ntp"
	"github.com/sagernet/sing/service"
	"github.com/stretchr/testify/require"
)

type recordingRouteEvent struct {
	inbound     string
	inboundType string
	user        string
	network     string
	destination M.Socksaddr
}

type echoStressRouter struct {
	adapter.Router
	mu         sync.Mutex
	events     []recordingRouteEvent
	tcpHandler func(net.Conn)
}

func (r *echoStressRouter) record(evt recordingRouteEvent) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.events = append(r.events, evt)
}

func (r *echoStressRouter) snapshot() []recordingRouteEvent {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]recordingRouteEvent, len(r.events))
	copy(out, r.events)
	return out
}

func (r *echoStressRouter) RouteConnectionEx(ctx context.Context, conn net.Conn, metadata adapter.InboundContext, onClose N.CloseHandlerFunc) {
	r.record(recordingRouteEvent{
		inbound:     metadata.Inbound,
		inboundType: metadata.InboundType,
		user:        metadata.User,
		network:     N.NetworkTCP,
		destination: metadata.Destination,
	})
	go func() {
		if r.tcpHandler != nil {
			r.tcpHandler(conn)
			_ = conn.Close()
			if onClose != nil {
				onClose(nil)
			}
			return
		}
		var err error
		if _, copyErr := io.Copy(conn, conn); copyErr != nil {
			err = copyErr
		}
		_ = conn.Close()
		if onClose != nil {
			onClose(err)
		}
	}()
}

func (r *echoStressRouter) RoutePacketConnectionEx(ctx context.Context, conn N.PacketConn, metadata adapter.InboundContext, onClose N.CloseHandlerFunc) {
	r.record(recordingRouteEvent{
		inbound:     metadata.Inbound,
		inboundType: metadata.InboundType,
		user:        metadata.User,
		network:     N.NetworkUDP,
		destination: metadata.Destination,
	})
	go func() {
		var err error
		b := buf.NewPacket()
		defer b.Release()
		for {
			b.Reset()
			dest, rErr := conn.ReadPacket(b)
			if rErr != nil {
				err = rErr
				break
			}
			out := buf.NewPacket()
			out.Advance(1024)
			_, _ = out.Write(b.Bytes())
			if !dest.IsValid() {
				dest = metadata.Destination
			}
			if wErr := conn.WritePacket(out, dest); wErr != nil {
				out.Release()
				err = wErr
				break
			}
		}
		_ = conn.Close()
		if onClose != nil {
			onClose(err)
		}
	}()
}

func testX25519Keypair(t *testing.T) (privB64, pubB64 string) {
	t.Helper()
	priv, err := ecdh.X25519().GenerateKey(rand.Reader)
	require.NoError(t, err)
	return base64.StdEncoding.EncodeToString(priv.Bytes()),
		base64.StdEncoding.EncodeToString(priv.PublicKey().Bytes())
}

func startTestInboundAndOutbound(
	t *testing.T,
	ctx context.Context,
	inOpts option.AetherInboundOptions,
	outOpts option.AetherOutboundOptions,
) (*Inbound, *Outbound, *echoStressRouter, func()) {
	t.Helper()

	router := &echoStressRouter{}
	nopLogger := log.NewNOPFactory().Logger()

	listenAddr := badoption.Addr(netip.MustParseAddr("127.0.0.1"))
	inOpts.Listen = &listenAddr
	inOpts.ListenPort = 0

	inAny, err := NewInbound(ctx, router, nopLogger, "in-aether", inOpts)
	require.NoError(t, err)
	in := inAny.(*Inbound)

	scope := adapter.NewScope(ctx, nopLogger)
	require.NoError(t, in.Start(adapter.StartStateStart, scope))

	tcpAddr := in.listener.TCPListener().Addr().(*net.TCPAddr)
	outOpts.Server = tcpAddr.IP.String()
	outOpts.ServerPort = uint16(tcpAddr.Port)

	outAny, err := NewOutbound(ctx, router, nopLogger, "out-aether", outOpts)
	require.NoError(t, err)
	out := outAny.(*Outbound)
	require.NoError(t, out.Start(adapter.StartStateInitialize, scope))

	cleanup := func() {
		_ = out.Close()
		_ = scope.Close()
	}
	return in, out, router, cleanup
}

func TestStressBidirectionalTCPRace(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	priv, pub := testX25519Keypair(t)

	_, out, router, cleanup := startTestInboundAndOutbound(
		t, ctx,
		option.AetherInboundOptions{
			Users: []option.AetherUser{
				{Name: "alice", Password: "alice-stress-password"},
				{Name: "bob", Password: "bob-stress-password"},
			},
			ServerPrivateKey:  priv,
			HeartbeatInterval: badoption.Duration(250 * time.Millisecond),
		},
		option.AetherOutboundOptions{
			Password:          "alice-stress-password",
			ServerPublicKey:   pub,
			Cipher:            "auto",
			HeartbeatInterval: badoption.Duration(250 * time.Millisecond),
		},
	)
	defer cleanup()

	// Half-close echoed server streams cleanly and keep the peer TCP socket open
	// until all client workers finish draining ReadFull, preventing a server-side
	// TCP RST if a client heartbeat frame races with server close under -race CI load.
	done := make(chan struct{})
	defer close(done)
	router.tcpHandler = func(conn net.Conn) {
		_, _ = io.Copy(conn, conn)
		if cw, ok := conn.(interface{ CloseWrite() error }); ok {
			_ = cw.CloseWrite()
		}
		<-done
	}

	const workers = 16
	const payloadSize = 96 * 1024

	var wg sync.WaitGroup
	for w := 0; w < workers; w++ {
		w := w
		wg.Add(1)
		go func() {
			defer wg.Done()
			c, err := out.DialContext(ctx, "tcp", M.ParseSocksaddrHostPort("example.com", uint16(8000+w)))
			require.NoError(t, err)
			defer c.Close()

			payload := make([]byte, payloadSize)
			_, err = rand.Read(payload)
			require.NoError(t, err)
			wantSum := sha256.Sum256(payload)

			errCh := make(chan error, 1)
			go func() {
				// Half-close write direction once complete while reading concurrently.
				for off := 0; off < len(payload); {
					step := 4096
					if off+step > len(payload) {
						step = len(payload) - off
					}
					n, wErr := c.Write(payload[off : off+step])
					if wErr != nil {
						errCh <- wErr
						return
					}
					off += n
				}
				if cw, ok := c.(interface{ CloseWrite() error }); ok {
					errCh <- cw.CloseWrite()
					return
				}
				errCh <- nil
			}()

			got := make([]byte, payloadSize)
			_, rErr := io.ReadFull(c, got)
			require.NoError(t, rErr)
			require.NoError(t, <-errCh)
			require.Equal(t, wantSum, sha256.Sum256(got))
		}()
	}
	wg.Wait()

	events := router.snapshot()
	require.GreaterOrEqual(t, len(events), workers)
	for _, ev := range events {
		require.Equal(t, "in-aether", ev.inbound)
		require.Equal(t, "aether", ev.inboundType)
		require.Equal(t, "alice", ev.user)
		require.Equal(t, "example.com", ev.destination.Fqdn)
	}
}

func TestStressMultiplexAllBackendsAndIdleRaces(t *testing.T) {
	t.Parallel()

	for _, proto := range []string{"smux", "yamux", "h2mux"} {
		proto := proto
		t.Run(proto, func(t *testing.T) {
			t.Parallel()
			ctx := context.Background()
			_, out, _, cleanup := startTestInboundAndOutbound(
				t, ctx,
				option.AetherInboundOptions{
					Password: "mux-stress-password",
					Multiplex: &option.InboundMultiplexOptions{
						Enabled: true,
					},
				},
				option.AetherOutboundOptions{
					Password: "mux-stress-password",
					Multiplex: &option.OutboundMultiplexOptions{
						Enabled:        true,
						Protocol:       proto,
						MaxConnections: 4,
					},
					// R-5: enable both Multiplex and UDPOverTCP independently.
					UDPOverTCP: &option.UDPOverTCPOptions{
						Enabled: true,
						Version: 2,
					},
				},
			)
			defer cleanup()

			require.True(t, out.MultiplexEnabled())
			require.NotNil(t, out.multiplexDialer)
			require.NotNil(t, out.uotClient, "R-5: uotClient must still be initialized alongside multiplexDialer")

			var wg sync.WaitGroup
			for i := 0; i < 12; i++ {
				i := i
				wg.Add(1)
				go func() {
					defer wg.Done()
					c, err := out.DialContext(ctx, "tcp", M.ParseSocksaddrHostPort("mux.example.org", uint16(9000+i)))
					require.NoError(t, err)
					defer c.Close()

					msg := []byte(fmt.Sprintf("mux-%s-%d", proto, i))
					_, err = c.Write(msg)
					require.NoError(t, err)

					got := make([]byte, len(msg))
					_, err = io.ReadFull(c, got)
					require.NoError(t, err)
					require.Equal(t, msg, got)
				}()
			}

			// Test multiplexed UDP stream via ListenPacket.
			wg.Add(1)
			go func() {
				defer wg.Done()
				pc, err := out.ListenPacket(ctx, M.ParseSocksaddrHostPort("8.8.8.8", 53))
				require.NoError(t, err)
				defer pc.Close()

				_, err = pc.WriteTo([]byte("mux-udp-probe"), net.UDPAddrFromAddrPort(netip.MustParseAddrPort("8.8.8.8:53")))
				require.NoError(t, err)
				bufRead := make([]byte, 64)
				_ = pc.SetReadDeadline(time.Now().Add(10 * time.Second))
				n, _, err := pc.ReadFrom(bufRead)
				require.NoError(t, err)
				require.Equal(t, []byte("mux-udp-probe"), bufRead[:n])
			}()

			wg.Wait()

			// Exercise idle connection keeper and network interface reset, then verify fresh stream.
			out.SetKeepIdleConnections(true)
			out.CloseIdleConnections()
			out.InterfaceUpdated(ctx)

			c, err := out.DialContext(ctx, "tcp", M.ParseSocksaddrHostPort("mux.example.org", 9999))
			require.NoError(t, err)
			defer c.Close()
			_, err = c.Write([]byte("post-reset"))
			require.NoError(t, err)
			got := make([]byte, len("post-reset"))
			_, err = io.ReadFull(c, got)
			require.NoError(t, err)
			require.Equal(t, []byte("post-reset"), got)
		})
	}
}

func TestStressUDPAndUoTRace(t *testing.T) {
	t.Parallel()

	t.Run("native_udp", func(t *testing.T) {
		t.Parallel()
		ctx := context.Background()
		_, out, _, cleanup := startTestInboundAndOutbound(
			t, ctx,
			option.AetherInboundOptions{Password: "udp-native-secret"},
			option.AetherOutboundOptions{Password: "udp-native-secret"},
		)
		defer cleanup()

		// ListenPacket concurrency.
		var wg sync.WaitGroup
		for i := 0; i < 8; i++ {
			i := i
			wg.Add(1)
			go func() {
				defer wg.Done()
				dst := M.ParseSocksaddrHostPort("1.1.1.1", uint16(5300+i))
				pc, err := out.ListenPacket(ctx, dst)
				require.NoError(t, err)
				defer pc.Close()

				for j := 0; j < 5; j++ {
					payload := []byte(fmt.Sprintf("pkt-%d-%d", i, j))
					_, err = pc.WriteTo(payload, net.UDPAddrFromAddrPort(netip.MustParseAddrPort(fmt.Sprintf("1.1.1.1:%d", 5300+i))))
					require.NoError(t, err)
					bufRead := make([]byte, 128)
					n, _, err := pc.ReadFrom(bufRead)
					require.NoError(t, err)
					require.Equal(t, payload, bufRead[:n])
				}
			}()
		}

		// Bound UDP DialContext("udp", ...) path.
		wg.Add(1)
		go func() {
			defer wg.Done()
			conn, err := out.DialContext(ctx, "udp", M.ParseSocksaddrHostPort("9.9.9.9", 53))
			require.NoError(t, err)
			defer conn.Close()

			_, err = conn.Write([]byte("bound-udp-hello"))
			require.NoError(t, err)
			got := make([]byte, 32)
			n, err := conn.Read(got)
			require.NoError(t, err)
			require.Equal(t, []byte("bound-udp-hello"), got[:n])
		}()

		wg.Wait()
	})

	t.Run("uot_v2", func(t *testing.T) {
		t.Parallel()
		ctx := context.Background()
		_, out, _, cleanup := startTestInboundAndOutbound(
			t, ctx,
			option.AetherInboundOptions{Password: "uot-v2-stress-secret"},
			option.AetherOutboundOptions{
				Password:   "uot-v2-stress-secret",
				UDPOverTCP: &option.UDPOverTCPOptions{Enabled: true, Version: 2},
			},
		)
		defer cleanup()

		pc, err := out.ListenPacket(ctx, M.ParseSocksaddrHostPort("8.8.4.4", 53))
		require.NoError(t, err)
		defer pc.Close()

		_, err = pc.WriteTo([]byte("uot-hello"), net.UDPAddrFromAddrPort(netip.MustParseAddrPort("8.8.4.4:53")))
		require.NoError(t, err)

		got := make([]byte, 32)
		_ = pc.SetReadDeadline(time.Now().Add(10 * time.Second))
		n, _, err := pc.ReadFrom(got)
		require.NoError(t, err)
		require.Equal(t, []byte("uot-hello"), got[:n])

		// UoT connect-mode DialContext("udp", ...) path.
		c, err := out.DialContext(ctx, "udp", M.ParseSocksaddrHostPort("8.8.8.8", 53))
		require.NoError(t, err)
		defer c.Close()
		_, err = c.Write([]byte("uot-connect"))
		require.NoError(t, err)
		n, err = c.Read(got)
		require.NoError(t, err)
		require.Equal(t, []byte("uot-connect"), got[:n])
	})
}

func TestInboundMuxDisabledRejectsWithoutLeakingDestination(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	in, out, router, cleanup := startTestInboundAndOutbound(
		t, ctx,
		option.AetherInboundOptions{
			Password:  "nomux-stress-secret-v2",
			Multiplex: &option.InboundMultiplexOptions{Enabled: false},
		},
		option.AetherOutboundOptions{
			Password:  "nomux-stress-secret-v2",
			Multiplex: &option.OutboundMultiplexOptions{Enabled: true, Protocol: "smux"},
		},
	)
	defer cleanup()
	_ = in

	// Even when outbound sends CommandMux, inbound must reject cleanly without forwarding sp.mux.sing-box.arpa to router.
	c, err := out.DialContext(ctx, "tcp", M.ParseSocksaddrHostPort("blocked-mux.example", 443))
	if err == nil {
		buf := make([]byte, 16)
		_ = c.SetReadDeadline(time.Now().Add(2 * time.Second))
		_, rErr := c.Read(buf)
		require.Error(t, rErr)
		_ = c.Close()
	}

	// Router must have ZERO routes containing sp.mux.sing-box.arpa!
	for _, ev := range router.snapshot() {
		require.NotContains(t, ev.destination.Fqdn, "sp.mux.sing-box.arpa")
	}
}

func TestOutboundOptionValidationNetworkAndNTP(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	nopLogger := log.NewNOPFactory().Logger()

	// Missing server / port / cipher / secret validation.
	_, err := NewOutbound(ctx, nil, nopLogger, "bad", option.AetherOutboundOptions{
		ServerOptions: option.ServerOptions{ServerPort: 443},
		Password:      "validation-secret-v2",
	})
	require.Error(t, err)

	_, err = NewOutbound(ctx, nil, nopLogger, "bad", option.AetherOutboundOptions{
		ServerOptions: option.ServerOptions{Server: "127.0.0.1"},
		Password:      "validation-secret-v2",
	})
	require.Error(t, err)

	_, err = NewOutbound(ctx, nil, nopLogger, "bad", option.AetherOutboundOptions{
		ServerOptions: option.ServerOptions{Server: "127.0.0.1", ServerPort: 443},
		Password:      "validation-secret-v2",
		Cipher:        "rc4-md5",
	})
	require.Error(t, err)
	require.Contains(t, err.Error(), "unsupported aether cipher")

	// Network allowlist enforcement (tcp-only outbound rejects udp & icmp with ErrUnknownNetwork).
	_, tcpOnlyOut, _, cleanup := startTestInboundAndOutbound(
		t, ctx,
		option.AetherInboundOptions{Password: "net-filter-secret-v2"},
		option.AetherOutboundOptions{
			Password: "net-filter-secret-v2",
			Network:  option.NetworkList(N.NetworkTCP),
		},
	)
	defer cleanup()

	_, err = tcpOnlyOut.DialContext(ctx, "udp", M.ParseSocksaddrHostPort("8.8.8.8", 53))
	require.ErrorIs(t, err, N.ErrUnknownNetwork)
	_, err = tcpOnlyOut.DialContext(ctx, "icmp", M.ParseSocksaddrHostPort("8.8.8.8", 0))
	require.ErrorIs(t, err, N.ErrUnknownNetwork)
	_, err = tcpOnlyOut.ListenPacket(ctx, M.ParseSocksaddrHostPort("8.8.8.8", 53))
	require.ErrorIs(t, err, N.ErrUnknownNetwork)

	// NTP time synchronization via context: inbound & outbound both advance by +2 hours cleanly
	// despite host wall clock difference; unshifted outbound is rejected for clock skew!
	shiftedNow := time.Now().Add(2 * time.Hour)
	ntpCtx := service.ContextWith[ntp.TimeService](ctx, stressTimeService{fn: func() time.Time { return shiftedNow }})
	_, ntpOut, _, cleanupNTP := startTestInboundAndOutbound(
		t, ntpCtx,
		option.AetherInboundOptions{Password: "ntp-sync-stress-secret"},
		option.AetherOutboundOptions{Password: "ntp-sync-stress-secret"},
	)
	defer cleanupNTP()

	c, err := ntpOut.DialContext(ntpCtx, "tcp", M.ParseSocksaddrHostPort("ntp.example", 443))
	require.NoError(t, err)
	_, err = c.Write([]byte("ntp-sync-ok"))
	require.NoError(t, err)
	got := make([]byte, 11)
	_, err = io.ReadFull(c, got)
	require.NoError(t, err)
	require.Equal(t, []byte("ntp-sync-ok"), got)
	_ = c.Close()

	// Unshifted time context calling into the +2h shifted server must fail clock skew.
	unshiftedCtx := service.ContextWith[ntp.TimeService](ctx, stressTimeService{fn: time.Now})
	badConn, dErr := ntpOut.DialContext(unshiftedCtx, "tcp", M.ParseSocksaddrHostPort("ntp.example", 443))
	if dErr == nil {
		// Force write & read so server processes handshake and closes cleanly via StealthDrain/timeout.
		_ = badConn.SetReadDeadline(time.Now().Add(4 * time.Second))
		_, _ = badConn.Write([]byte("probe"))
		bufRead := make([]byte, 8)
		_, rErr := badConn.Read(bufRead)
		require.Error(t, rErr)
		_ = badConn.Close()
	}
	_ = bytes.Equal(got, got)
	_ = atomic.Int32{}
}

type stressTimeService struct {
	fn func() time.Time
}

func (s stressTimeService) TimeFunc() func() time.Time {
	return s.fn
}

func TestStressTLS13OverCommandTCP(t *testing.T) {
	t.Parallel()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	require.NoError(t, err)
	srvTLSConfig := &tls.Config{
		MinVersion: tls.VersionTLS13,
		MaxVersion: tls.VersionTLS13,
		Certificates: []tls.Certificate{{
			Certificate: [][]byte{der},
			PrivateKey:  key,
		}},
	}

	_, out, router, cleanup := startTestInboundAndOutbound(
		t, context.Background(),
		option.AetherInboundOptions{
			Password:          "tls13-command-tcp-secret",
			HeartbeatInterval: badoption.Duration(-time.Second),
		},
		option.AetherOutboundOptions{
			Password:          "tls13-command-tcp-secret",
			HeartbeatInterval: badoption.Duration(-time.Second),
		},
	)
	defer cleanup()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	router.tcpHandler = func(c net.Conn) {
		tc := tls.Server(c, srvTLSConfig)
		defer tc.Close()
		if hErr := tc.HandshakeContext(ctx); hErr != nil {
			return
		}
		_, _ = io.Copy(tc, tc)
	}

	c, err := out.DialContext(ctx, "tcp", M.ParseSocksaddrHostPort("127.0.0.1", 443))
	require.NoError(t, err)
	defer c.Close()

	cliTLS := tls.Client(c, &tls.Config{
		MinVersion:         tls.VersionTLS13,
		MaxVersion:         tls.VersionTLS13,
		ServerName:         "api.aether.internal",
		NextProtos:         []string{"h2", "http/1.1"},
		InsecureSkipVerify: true,
	})
	require.NoError(t, cliTLS.HandshakeContext(ctx))
	_, err = cliTLS.Write([]byte("tls13-ok"))
	require.NoError(t, err)
	got := make([]byte, 8)
	_, err = io.ReadFull(cliTLS, got)
	require.NoError(t, err)
	require.Equal(t, []byte("tls13-ok"), got)
}
