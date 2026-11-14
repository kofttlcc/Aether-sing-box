package e2e_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/sagernet/sing-box/adapter"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing/common/buf"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/stretchr/testify/require"
)

// TestTier3Combinations validates cross-feature Tier 3 combinations (T3-01..T3-32)
// through opaque-box box.Box, CLI, WireTapProxy, and SpecRefCodec harnesses.
func TestTier3Combinations(t *testing.T) {
	VerifyOpaqueImports(t)

	t.Run("T3-01_MultiUserEIH_StaticPFS_ChaCha20_H2MuxPadding", testT301MultiUserEIHStaticPFSChaChaH2Mux)
	t.Run("T3-02_UsersOnly_AES256GCM_UoTv2_DisableShaping", testT302UsersOnlyAESUoTv2DisableShaping)
	t.Run("T3-03_NativeCommandUDP_FullCone_HeartbeatDPD_Blackhole", testT303NativeUDPFullConeBlackholeDPD)
	t.Run("T3-04_ServerSpeaksFirst_EarlyWriter_Shaping6", testT304ServerSpeaksFirstEarlyWriter)
	t.Run("T3-05_CLIKeys_AutoCipher_Shaping6_HalfCloseDownlink", testT305CLIKeysAutoCipherHalfClose)
	t.Run("T3-06_MultiUserEIH_ClockSkew25s_ReplayStealthDrain", testT306ClockSkewAndReplayStealthDrain)
	t.Run("T3-07_Smux_ChaCha20_Shaping_Heartbeat200ms_ThrottledTap", testT307SmuxChaChaThrottled12Streams)
	t.Run("T3-08_StaticPFS_AES256GCM_JumboUDP_BloomRotation65s", testT308JumboUDPBloomRotation65s)
	t.Run("T3-09_UsersOnlyKeyAlias_YamuxPadding_IPv6AndLocalhost", testT309UsersOnlyKeyAliasYamuxIPv6)
	t.Run("T3-10_EPKMask_Coalesced84B_Shaping_AES_64Sessions_PCAP", testT310EPKMaskCoalesced64SessionsPCAP)
	t.Run("T3-11_MultiUserEIH_AuthUserRouteOverrides_TCPAndUDP", testT311MultiUserRouteOverridesTCPAndUDP)
	t.Run("T3-12_ClientInitialWrite128KiB_VarHeaderCapAndFrames", testT312ClientInitialWrite128KiB)
	t.Run("T3-13_Chaff_PingPong_Data_CloseWrite_Interop", testT313ChaffPingPongDataCloseWrite)
	t.Run("T3-14_WriteBuffer_WriteDeadline5ms_WriteBrokenLatch", testT314WriteBufferDeadlineWriteBroken)
	t.Run("T3-15_MultiUserEIH_200InvalidProbes_UnderLiveH2MuxLoad", testT315MultiUser200ProbesUnderH2MuxLoad)
	t.Run("T3-16_URLTest_Failover_PrimaryBlackhole_To_Backup", testT316URLTestFailoverOnPrimaryBlackhole)
	t.Run("T3-17_RawURLEncodingKey_StaticECDH_NTPSync20sSkew", testT317RawURLEncodingKeyAndNTPSync)
	t.Run("T3-18_AsymmetricShaping_ClientOff_ServerOn_UoTv1", testT318AsymmetricShapingUoTv1)
	t.Run("T3-19_H2MuxPool4_CloseIdleConnections_ResetNetwork", testT319H2MuxPoolIdleResetNetwork)
	t.Run("T3-20_ImmediateFIN_ZeroByteDownlink_CoalescedCloseWrite", testT320ImmediateFINCoalescedCloseWrite)
	t.Run("T3-21_TCPInjectableInbound_NetPipe_112BEIH_Route", testT321TCPInjectableInboundNetPipeEIH)
	t.Run("T3-22_NativeUDP_DialContext_CoalescedFirstDatagram", testT322NativeUDPDialContextCoalesced)
	t.Run("T3-23_CLIChain_KeygenSchemaCheckDaemonTrafficSIGTERM", testT323EndToEndCLIChain)
	t.Run("T3-24_UsersOnly_ConstantTimeStealthDrain_Across3Failures", testT324UniformStealthDrainAcross3Failures)
	t.Run("T3-25_MixedWrite_WriteBuffer_IOCopy_FrameCutover", testT325MixedWriteWriteBufferIOCopyCutover)
	t.Run("T3-26_RegressionR5_MuxAndUoT_ConfiguredSimultaneously", testT326RegressionR5MuxAndUoTSimultaneous)
	t.Run("T3-27_MaxNoise384_NativeUDP_10Packets_Frame6Cutover", testT327MaxNoise384UDP10PacketsCutover)
	t.Run("T3-28_ReleaseEngineeringConsistency_VersionLDFLAGSCI", testT328ReleaseEngineeringConsistency)
	t.Run("T3-29_StaticKeyServer_MixedCipherClients_20Sessions", testT329StaticKeyServerMixedCipherClients)
	t.Run("T3-30_HalfClose_IdleHeartbeatSurvival_DelayedDownlink", testT330HalfCloseIdleHeartbeatSurvival)
	t.Run("T3-31_NegativeHeartbeatDisablesPing_Yamux4MiBStream", testT331NegativeHeartbeatDisablesPingYamux4MiB)
	t.Run("T3-32_Interleaved150ValidAnd40Malformed_ZeroLeakBaseline", testT332Interleaved150Valid40BadZeroLeaks)
}

// ---------------------------------------------------------------------------
// Shared helpers for Tier 3 & Tier 4 (package e2e_test)
// ---------------------------------------------------------------------------

func mustSOCKS5EchoTCP(t testing.TB, topo *Topology, user, pass, targetAddr string, payload []byte) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	var (
		conn *SOCKS5StreamConn
		err  error
	)
	if user != "" || pass != "" {
		conn, err = topo.DialSOCKS5Auth(ctx, user, pass, targetAddr)
	} else {
		conn, err = topo.DialSOCKS5(ctx, targetAddr)
	}
	require.NoError(t, err)
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(15 * time.Second))
	echoStreamExact(t, conn, payload)
}

func echoStreamExact(t testing.TB, conn net.Conn, payload []byte) {
	t.Helper()
	wantSum := sha256.Sum256(payload)
	errCh := make(chan error, 1)
	go func() {
		_, wErr := conn.Write(payload)
		errCh <- wErr
	}()
	reply := make([]byte, len(payload))
	_, rErr := io.ReadFull(conn, reply)
	require.NoError(t, rErr)
	require.NoError(t, <-errCh)
	require.Equal(t, wantSum, sha256.Sum256(reply))
}

func echoExtendedConnHalfClose(t testing.TB, conn net.Conn, payload []byte) []byte {
	t.Helper()
	errCh := make(chan error, 1)
	go func() {
		if _, wErr := conn.Write(payload); wErr != nil {
			errCh <- wErr
			return
		}
		if wc, ok := conn.(N.WriteCloser); ok {
			errCh <- wc.CloseWrite()
			return
		}
		if tc, ok := conn.(*net.TCPConn); ok {
			errCh <- tc.CloseWrite()
			return
		}
		errCh <- N.CloseWrite(conn)
	}()
	got, rErr := io.ReadAll(conn)
	require.NoError(t, rErr)
	require.NoError(t, <-errCh)
	return got
}

func mustSOCKS5EchoUDP(t testing.TB, udpConn *SOCKS5UDPConn, targetAddr string, payload []byte) {
	t.Helper()
	_ = udpConn.SetDeadline(time.Now().Add(8 * time.Second))
	require.NoError(t, udpConn.WriteToHostPort(payload, targetAddr))
	bufReply := make([]byte, len(payload)+4096)
	n, _, err := udpConn.ReadFromHostPort(bufReply)
	require.NoError(t, err)
	require.Equal(t, len(payload), n)
	require.Equal(t, sha256.Sum256(payload), sha256.Sum256(bufReply[:n]))
}

func mustQueryDNSOverSOCKS5UDP(t testing.TB, udpConn *SOCKS5UDPConn, dnsAddr, fqdn string, qtype uint16) *dns.Msg {
	t.Helper()
	msg := new(dns.Msg)
	msg.SetQuestion(dns.Fqdn(fqdn), qtype)
	msg.RecursionDesired = true
	rawQ, err := msg.Pack()
	require.NoError(t, err)

	_ = udpConn.SetDeadline(time.Now().Add(8 * time.Second))
	require.NoError(t, udpConn.WriteToHostPort(rawQ, dnsAddr))

	respBuf := make([]byte, 4096)
	n, _, err := udpConn.ReadFromHostPort(respBuf)
	require.NoError(t, err)
	resp := new(dns.Msg)
	require.NoError(t, resp.Unpack(respBuf[:n]))
	require.Equal(t, msg.Id, resp.Id)
	return resp
}

func startHTTP204HealthServer(t testing.TB) *httptest.Server {
	t.Helper()
	var hits atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		w.Header().Set("X-Health-Hit", strconv.FormatInt(hits.Load(), 10))
		w.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(srv.Close)
	return srv
}

type dualAetherClientSpec struct {
	ProxyPort         uint16
	PrimaryAddr       string
	BackupAddr        string
	Password          string
	Cipher            string
	ServerPublicKey   string
	HeartbeatInterval string
	HealthURL         string
	Interval          string
	Tolerance         uint16
	Multiplex         *MultiplexClientSpec
	PrimaryTag        string
	BackupTag         string
}

func buildDualAetherURLTestClientJSON(t testing.TB, spec dualAetherClientSpec) []byte {
	t.Helper()
	primaryHost, primaryPortStr, err := net.SplitHostPort(spec.PrimaryAddr)
	require.NoError(t, err)
	primaryPort, err := strconv.Atoi(primaryPortStr)
	require.NoError(t, err)

	backupHost, backupPortStr, err := net.SplitHostPort(spec.BackupAddr)
	require.NoError(t, err)
	backupPort, err := strconv.Atoi(backupPortStr)
	require.NoError(t, err)

	pTag := spec.PrimaryTag
	if pTag == "" {
		pTag = "aether-primary"
	}
	bTag := spec.BackupTag
	if bTag == "" {
		bTag = "aether-backup"
	}

	makeAetherOut := func(tag, host string, port int) map[string]any {
		out := map[string]any{
			"type":            C.TypeAether,
			"tag":             tag,
			"server":          host,
			"server_port":     port,
			"password":        spec.Password,
			"connect_timeout": "900ms",
		}
		if spec.Cipher != "" {
			out["cipher"] = spec.Cipher
		}
		if spec.ServerPublicKey != "" {
			out["public_key"] = spec.ServerPublicKey
		}
		if spec.HeartbeatInterval != "" {
			out["heartbeat_interval"] = spec.HeartbeatInterval
		}
		if spec.Multiplex != nil && spec.Multiplex.Enabled {
			out["multiplex"] = spec.Multiplex
		}
		return out
	}

	interval := spec.Interval
	if interval == "" {
		interval = "400ms"
	}
	tolerance := spec.Tolerance
	if tolerance == 0 {
		tolerance = 5
	}

	root := map[string]any{
		"log": map[string]any{
			"disabled": true,
		},
		"inbounds": []any{
			map[string]any{
				"type":        C.TypeSOCKS,
				"tag":         "proxy-in",
				"listen":      "127.0.0.1",
				"listen_port": spec.ProxyPort,
				"reuse_addr":  true,
			},
		},
		"outbounds": []any{
			map[string]any{
				"type":                        C.TypeURLTest,
				"tag":                         "urltest-out",
				"outbounds":                   []string{pTag, bTag},
				"url":                         spec.HealthURL,
				"interval":                    interval,
				"tolerance":                   tolerance,
				"idle_timeout":                "30s",
				"interrupt_exist_connections": true,
			},
			makeAetherOut(pTag, primaryHost, primaryPort),
			makeAetherOut(bTag, backupHost, backupPort),
			map[string]any{
				"type": C.TypeDirect,
				"tag":  "direct-out",
			},
		},
		"route": map[string]any{
			"final": "urltest-out",
		},
	}
	raw, err := json.Marshal(root)
	require.NoError(t, err)
	return raw
}

func mustDialSOCKS5OnAddr(t testing.TB, proxyAddr, targetAddr string, payload []byte) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	conn, err := DialSOCKS5TCP(ctx, proxyAddr, targetAddr)
	require.NoError(t, err)
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
	echoStreamExact(t, conn, payload)
}

// assertExpectedStealthDrain verifies a raw probe timed out inside StealthDrain
// and exited with a clean EOF rather than a TCP RST.
func assertExpectedStealthDrain(t testing.TB, p ProbeResult) {
	t.Helper()
	require.Empty(t, p.BytesReceived, "server must emit 0 bytes to unauthorized probes")
	require.True(t, p.ClosedCleanEOF, "expected clean FIN/EOF drain closure, got err=%v rst=%v timedOut=%v", p.Err, p.ClosedByRST, p.TimedOut)
	require.False(t, p.ClosedByRST, "server must not emit TCP RST during stealth drain")
	require.GreaterOrEqual(t, p.Elapsed, 2700*time.Millisecond, "stealth drain too short: %v", p.Elapsed)
	require.LessOrEqual(t, p.Elapsed, 12*time.Second, "stealth drain exceeded upper bound: %v", p.Elapsed)
}

func isTimeoutError(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, os.ErrDeadlineExceeded) || errors.Is(err, context.DeadlineExceeded) {
		return true
	}
	var ne net.Error
	return errors.As(err, &ne) && ne.Timeout()
}

// ---------------------------------------------------------------------------
// Tier 3 Case Implementations (T3-01 .. T3-32)
// ---------------------------------------------------------------------------

func testT301MultiUserEIHStaticPFSChaChaH2Mux(t *testing.T) {
	privKey, pubKey := GenerateAetherKeyPairCLI(t)
	iPSK := GenerateAetherKeyCLI(t)
	aliceSecret := "alice-" + GenerateRandomKeyBase64(t)
	bobSecret := "bob-" + GenerateRandomKeyBase64(t)

	users := []UserSpec{
		{Name: "alice", Password: aliceSecret},
		{Name: "bob", Password: bobSecret},
	}

	topo := StartTopology(t, TopologyConfig{
		ServerPassword:        iPSK,
		ServerUsers:           users,
		ServerPrivateKey:      privKey,
		ServerMultiplex:       &MultiplexServerSpec{Enabled: true, Padding: true},
		ClientPassword:        iPSK + ":" + aliceSecret,
		ClientCipher:          "chacha20-poly1305",
		ClientServerPublicKey: pubKey,
		ClientMultiplex: &MultiplexClientSpec{
			Enabled:        true,
			Protocol:       "h2mux",
			MaxConnections: 2,
			Padding:        true,
		},
	})

	tcpTarget := StartTCPEchoTarget(t)
	udpTarget := StartUDPEchoTarget(t)

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		mustSOCKS5EchoTCP(t, topo, "", "", tcpTarget.Addr(), DeterministicBytes(3011, 32*1024))
	}()
	go func() {
		defer wg.Done()
		uc, err := topo.OpenSOCKS5UDP(ctx)
		require.NoError(t, err)
		defer uc.Close()
		mustSOCKS5EchoUDP(t, uc, udpTarget.Addr(), DeterministicBytes(3012, 1200))
	}()
	wg.Wait()

	sessions := topo.Tap.WaitForSessions(t, 1, 5*time.Second)
	require.NotEmpty(t, sessions)
	require.True(t, sessions[0].WaitBytes(DirC2S, int64(SpecClientPrefixEIHSize+48), 5*time.Second))

	info, err := SpecInspectClientBurst(sessions[0].Bytes(DirC2S), iPSK, "", users, privKey)
	require.NoError(t, err)
	require.True(t, info.HasEIH)
	require.Equal(t, "alice", info.UserName)
	require.Equal(t, SpecCipherChaCha20Poly1305, info.FixedHeader.CipherSuite)
	require.Equal(t, SpecCommandMux, info.FixedHeader.Command)
	require.NotEmpty(t, info.StaticSharedSecret)
}

func testT302UsersOnlyAESUoTv2DisableShaping(t *testing.T) {
	u1Pass := "Argon2id-User1-Pass18!"
	u2Pass := "Argon2id-User2-Pass18!"
	users := []UserSpec{
		{Name: "u1", Password: u1Pass},
		{Name: "u2", Password: u2Pass},
	}
	udpTarget := StartUDPEchoTarget(t)

	// Part A: Box-to-Box UoT v2 + DisableShaping + users-only (password: "")
	topo1 := StartTopology(t, TopologyConfig{
		ServerPassword:       "",
		ServerUsers:          users,
		ServerDisableShaping: true,
		ClientPassword:       u1Pass,
		ClientCipher:         "aes-256-gcm",
		ClientDisableShaping: true,
		ClientUDPOverTCP:     map[string]any{"enabled": true, "version": 2},
	})
	ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
	defer cancel()
	uc1, err := topo1.OpenSOCKS5UDP(ctx)
	require.NoError(t, err)
	mustSOCKS5EchoUDP(t, uc1, udpTarget.Addr(), DeterministicBytes(3021, 1400))
	_ = uc1.Close()

	sessions := topo1.Tap.WaitForSessions(t, 1, 5*time.Second)
	require.True(t, sessions[0].WaitBytes(DirC2S, int64(SpecClientPrefixNoEIHSize+48), 5*time.Second))
	info, err := SpecInspectClientBurst(sessions[0].Bytes(DirC2S), "", "", users, "")
	require.NoError(t, err)
	require.False(t, info.HasEIH)
	require.Equal(t, SpecCipherAES256GCM, info.FixedHeader.CipherSuite)
	require.Equal(t, SpecCommandUoT, info.FixedHeader.Command)

	// Verify second user u2 also authenticates and passes UoT v2 against Server.
	port2 := AllocFreeTCPPort(t)
	sHost, sPortStr, err := net.SplitHostPort(topo1.ServerAddr())
	require.NoError(t, err)
	sPort, err := strconv.Atoi(sPortStr)
	require.NoError(t, err)
	raw2, err := BuildClientJSON(TopologyConfig{
		ClientPassword:       u2Pass,
		ClientCipher:         "aes-256-gcm",
		ClientDisableShaping: true,
		ClientUDPOverTCP:     map[string]any{"enabled": true, "version": 2},
	}, port2, sHost, uint16(sPort), 0, "")
	require.NoError(t, err)
	cli2, err := StartBoxWithLog(t, raw2, "", port2)
	require.NoError(t, err)
	defer func() { _ = cli2.Close() }()
	uc2, err := DialSOCKS5UDP(ctx, cli2.ListenAddr)
	require.NoError(t, err)
	mustSOCKS5EchoUDP(t, uc2, udpTarget.Addr(), DeterministicBytes(3022, 900))
	_ = uc2.Close()

	// Part B: Verify PadLen == 0 from Frame 0 on BOTH Client (via SpecMockServer)
	// and Server (via DialSpecClient) when disable_shaping: true.
	echoTCP := StartTCPEchoTarget(t)
	mockSrv := StartSpecEchoRelayServer(t, "", "", users, "")
	mHost, mPortStr, err := net.SplitHostPort(mockSrv.Addr())
	require.NoError(t, err)
	mPort, err := strconv.Atoi(mPortStr)
	require.NoError(t, err)
	port3 := AllocFreeTCPPort(t)
	raw3, err := BuildClientJSON(TopologyConfig{
		ClientPassword:       u1Pass,
		ClientCipher:         "aes-256-gcm",
		ClientDisableShaping: true,
	}, port3, mHost, uint16(mPort), 0, "")
	require.NoError(t, err)
	cli3, err := StartBoxWithLog(t, raw3, "", port3)
	require.NoError(t, err)
	defer func() { _ = cli3.Close() }()
	conn3, err := DialSOCKS5TCP(ctx, cli3.ListenAddr, echoTCP.Addr())
	require.NoError(t, err)
	_ = conn3.SetDeadline(time.Now().Add(10 * time.Second))
	// First chunk arrives in VarHeader.InitialPayload via 25ms coalescing; second chunk
	// forces C2S Frame 0 (SpecFrameData) to prove PadLen == 0 from Frame 0.
	echoStreamExact(t, conn3, DeterministicBytes(3023, 512))
	echoStreamExact(t, conn3, DeterministicBytes(30230, 256))
	_ = conn3.Close()
	srvSess := mockSrv.WaitForSessions(t, 1, 5*time.Second)
	require.NotEmpty(t, srvSess[0].C2SDataFrames())
	require.Equal(t, byte(0), srvSess[0].C2SDataFrames()[0].PadLen, "C2S Frame 0 PadLen must be 0 when disable_shaping=true")

	// Server S2C Frame 0..3 verification via DialSpecClient.
	suite := SpecCipherAES256GCM
	sc, err := DialSpecClient(ctx, topo1.ServerAddr(), SpecDialOptions{
		Password:    u1Pass,
		CipherSuite: &suite,
		TargetAddr:  echoTCP.Addr(),
	})
	require.NoError(t, err)
	defer sc.Close()
	_, err = sc.ReadServerResp(5 * time.Second)
	require.NoError(t, err)
	for i := 0; i < 4; i++ {
		msg := DeterministicBytes(uint64(3024+i), 100+i*10)
		require.NoError(t, sc.WriteFrame(SpecFrameData, 0, msg))
		fr, rErr := sc.ReadNextDataFrame(5 * time.Second)
		require.NoError(t, rErr)
		require.Equal(t, byte(0), fr.PadLen, "Server S2C Frame %d PadLen must be 0 when disable_shaping=true", i)
		require.Equal(t, msg, fr.Data)
	}
}

func testT303NativeUDPFullConeBlackholeDPD(t *testing.T) {
	fullCone := StartFullConeUDPTargets(t)
	psk := GenerateRandomKeyBase64(t)

	topo := StartTopology(t, TopologyConfig{
		ServerPassword:          psk,
		ServerHeartbeatInterval: "350ms",
		ClientPassword:          psk,
		ClientHeartbeatInterval: "350ms",
		ClientMultiplex:         nil,
		ClientUDPOverTCP:        nil,
	})

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	// Use in-process Outbound.ListenPacket for direct Native CommandUDP association,
	// avoiding SOCKS5 local UDP socket masking DPD closure.
	out, ok := topo.Client.Box.Outbound().Outbound("aether-out")
	require.True(t, ok)
	pConn, err := out.ListenPacket(ctx, M.ParseSocksaddr(fullCone.PeerA.Addr()))
	require.NoError(t, err)
	defer pConn.Close()

	// Send/receive through PeerA and PeerB over the SAME CommandUDP association.
	p1 := DeterministicBytes(3031, 180)
	b1 := buf.As(append([]byte(nil), p1...))
	require.NoError(t, pConn.(N.PacketConn).WritePacket(b1, M.ParseSocksaddr(fullCone.PeerA.Addr())))
	rBuf := buf.NewPacket()
	defer rBuf.Release()
	src, err := pConn.(N.PacketConn).ReadPacket(rBuf)
	require.NoError(t, err)
	require.Equal(t, p1, rBuf.Bytes())
	require.Equal(t, fullCone.PeerA.Port(), src.Port)

	p2 := DeterministicBytes(3032, 220)
	rBuf.Reset()
	require.NoError(t, pConn.(N.PacketConn).WritePacket(buf.As(append([]byte(nil), p2...)), M.ParseSocksaddr(fullCone.PeerB.Addr())))
	src2, err := pConn.(N.PacketConn).ReadPacket(rBuf)
	require.NoError(t, err)
	require.Equal(t, p2, rBuf.Bytes())
	require.Equal(t, fullCone.PeerB.Port(), src2.Port)

	// Full-Cone check: PeerC sends an unsolicited packet to PeerA's observed server NAT address.
	natAddr := fullCone.PeerA.LastClientUDPAddr()
	require.NotNil(t, natAddr)
	unsolicited := DeterministicBytes(3033, 96)
	require.NoError(t, fullCone.PeerC.SendUnsolicitedTo(unsolicited, natAddr))
	rBuf.Reset()
	_ = pConn.SetReadDeadline(time.Now().Add(4 * time.Second))
	src3, err := pConn.(N.PacketConn).ReadPacket(rBuf)
	require.NoError(t, err)
	require.Equal(t, unsolicited, rBuf.Bytes())
	require.Equal(t, fullCone.PeerC.Port(), src3.Port)

	// Verify wire Command == SpecCommandUDP.
	sessions := topo.Tap.WaitForSessions(t, 1, 5*time.Second)
	require.True(t, sessions[0].WaitBytes(DirC2S, int64(SpecClientPrefixNoEIHSize+48), 5*time.Second))
	info, err := SpecInspectClientBurst(sessions[0].Bytes(DirC2S), psk, "", nil, "")
	require.NoError(t, err)
	require.Equal(t, SpecCommandUDP, info.FixedHeader.Command)

	// Idle 1s (> 2 heartbeats at 350ms) and verify association survives.
	time.Sleep(1050 * time.Millisecond)
	pAlive := DeterministicBytes(3034, 64)
	rBuf.Reset()
	_ = pConn.SetDeadline(time.Now().Add(5 * time.Second))
	require.NoError(t, pConn.(N.PacketConn).WritePacket(buf.As(append([]byte(nil), pAlive...)), M.ParseSocksaddr(fullCone.PeerA.Addr())))
	_, err = pConn.(N.PacketConn).ReadPacket(rBuf)
	require.NoError(t, err)
	require.Equal(t, pAlive, rBuf.Bytes())

	// Blackhole both directions -> DPD must close transport session within < 1.5s (allow 2s CI margin).
	blackholeStart := time.Now()
	topo.Tap.SetBlackhole(true, true)
	require.True(t, sessions[0].WaitClosed(2*time.Second), "DPD did not close CommandUDP session after blackhole within 2s")
	dpdElapsed := time.Since(blackholeStart)
	t.Logf("T3-03 CommandUDP DPD elapsed: %v", dpdElapsed)

	// Ensure consumer PacketConn ReadPacket also sees EOF/closed error swiftly.
	_ = pConn.SetReadDeadline(time.Now().Add(2 * time.Second))
	rBuf.Reset()
	_, readAfterErr := pConn.(N.PacketConn).ReadPacket(rBuf)
	require.Error(t, readAfterErr)
}

func testT304ServerSpeaksFirstEarlyWriter(t *testing.T) {
	banner := []byte("SSH-2.0-OpenSSH_9.6\r\n")
	sshTarget := StartServerSpeaksFirstTarget(t, banner)
	psk := GenerateRandomKeyBase64(t)

	topo := StartTopology(t, TopologyConfig{
		ServerPassword: psk,
		ClientPassword: psk,
	})

	ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
	defer cancel()

	out, ok := topo.Client.Box.Outbound().Outbound("aether-out")
	require.True(t, ok)
	conn, err := out.DialContext(ctx, N.NetworkTCP, M.ParseSocksaddr(sshTarget.Addr()))
	require.NoError(t, err)
	defer conn.Close()

	// Before any Write or Read, Aether DialConn implements EarlyWriter (0-RTT handshake deferred).
	require.True(t, N.NeedHandshakeForWrite(conn), "outbound DialContext conn must advertise EarlyWriter")

	// Server-speaks-first: Client calls Read FIRST without writing anything!
	_ = conn.SetDeadline(time.Now().Add(8 * time.Second))
	gotBanner := make([]byte, len(banner))
	_, err = io.ReadFull(conn, gotBanner)
	require.NoError(t, err)
	require.Equal(t, banner, gotBanner)

	// Verify WireTap saw 0B InitialPayload + NoiseLen in [32, 384] + coalesced S2C >= 84+36+16+banner.
	sessions := topo.Tap.WaitForSessions(t, 1, 5*time.Second)
	require.True(t, sessions[0].WaitBytes(DirS2C, int64(SpecServerRespPrefixSize+36+16+len(banner)), 5*time.Second))
	info, err := SpecInspectClientBurst(sessions[0].Bytes(DirC2S), psk, "", nil, "")
	require.NoError(t, err)
	require.Empty(t, info.VarHeader.InitialPayload)
	require.GreaterOrEqual(t, int(info.FixedHeader.NoiseLen), SpecNoiseMin)
	require.LessOrEqual(t, int(info.FixedHeader.NoiseLen), SpecNoiseMax)

	s2cFirst, hasS2C := sessions[0].FirstSegment(DirS2C)
	require.True(t, hasS2C)
	require.GreaterOrEqual(t, s2cFirst.Size, SpecServerRespPrefixSize+36+16+len(banner))

	// Now client speaks back and reads echo.
	clientBanner := []byte("SSH-2.0-AetherClient_1.0\r\n")
	echoStreamExact(t, conn, clientBanner)

	// Confirm via DialSpecClient exact Server S2C Frame 0 PadLen in [16, 255].
	sc, err := DialSpecClient(ctx, topo.ServerAddr(), SpecDialOptions{
		Password:   psk,
		TargetAddr: sshTarget.Addr(),
	})
	require.NoError(t, err)
	defer sc.Close()
	_, err = sc.ReadServerResp(5 * time.Second)
	require.NoError(t, err)
	fr0, err := sc.ReadNextDataFrame(5 * time.Second)
	require.NoError(t, err)
	require.Equal(t, banner, fr0.Data)
	require.GreaterOrEqual(t, int(fr0.PadLen), 16)
}

func testT305CLIKeysAutoCipherHalfClose(t *testing.T) {
	psk := GenerateAetherKeyCLI(t)
	privKey, pubKey := GenerateAetherKeyPairCLI(t)

	upPayload := DeterministicBytes(3051, 32*1024)
	downTrailer := DeterministicBytes(3052, 128*1024)
	hcTarget := StartTCPHalfCloseTarget(t, downTrailer)

	topo := StartTopology(t, TopologyConfig{
		ServerPassword:        psk,
		ServerPrivateKey:      privKey,
		ClientPassword:        psk,
		ClientCipher:          "auto",
		ClientServerPublicKey: pubKey,
	})

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	out, ok := topo.Client.Box.Outbound().Outbound("aether-out")
	require.True(t, ok)
	conn, err := out.DialContext(ctx, N.NetworkTCP, M.ParseSocksaddr(hcTarget.Addr()))
	require.NoError(t, err)
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(15 * time.Second))

	downGot := echoExtendedConnHalfClose(t, conn, upPayload)
	require.Equal(t, sha256.Sum256(downTrailer), sha256.Sum256(downGot))
	require.Eventually(t, func() bool { return hcTarget.EOFObserved.Load() }, 3*time.Second, 20*time.Millisecond)
	require.Equal(t, sha256.Sum256(upPayload), hcTarget.ReceivedHash)
	require.NoError(t, conn.Close())

	sessions := topo.Tap.WaitForSessions(t, 1, 5*time.Second)
	require.True(t, sessions[0].WaitClosed(5*time.Second))
	require.False(t, sessions[0].HasSegmentOfExactSize(DirC2S, 2))
	require.False(t, sessions[0].HasSegmentOfExactSize(DirS2C, 2))

	info, err := SpecInspectClientBurst(sessions[0].Bytes(DirC2S), psk, "", nil, privKey)
	require.NoError(t, err)
	require.Contains(t, []uint8{SpecCipherAES256GCM, SpecCipherChaCha20Poly1305}, info.FixedHeader.CipherSuite)

	// Verify Server 6-frame shaping cutover (Frame 0..5 PadLen >= 16, Frame 6+ PadLen == 0) via DialSpecClient.
	echoTarget := StartTCPEchoTarget(t)
	sc, err := DialSpecClient(ctx, topo.ServerAddr(), SpecDialOptions{
		Password:        psk,
		ServerPublicKey: pubKey,
		TargetAddr:      echoTarget.Addr(),
	})
	require.NoError(t, err)
	defer sc.Close()
	_, err = sc.ReadServerResp(5 * time.Second)
	require.NoError(t, err)
	for seq := 0; seq < 8; seq++ {
		msg := DeterministicBytes(uint64(3053+seq), 256)
		pad := byte(24)
		if seq >= 6 {
			pad = 0
		}
		require.NoError(t, sc.WriteFrame(SpecFrameData, pad, msg))
		fr, fErr := sc.ReadNextDataFrame(5 * time.Second)
		require.NoError(t, fErr)
		require.Equal(t, msg, fr.Data)
		if seq < 6 {
			require.GreaterOrEqual(t, int(fr.PadLen), 16, "Frame %d must be shaped", seq)
		} else {
			require.Equal(t, byte(0), fr.PadLen, "Frame %d must be unpadded post-window", seq)
		}
	}
}

func testT306ClockSkewAndReplayStealthDrain(t *testing.T) {
	iPSK := GenerateRandomKeyBase64(t)
	users := []UserSpec{
		{Name: "alice", Password: "alice-clock-skew-18ch"},
		{Name: "bob", Password: "bob-clock-skew-18ch!"},
	}
	skew := 25 * time.Second
	echoTarget := StartTCPEchoTarget(t)

	topo := StartTopology(t, TopologyConfig{
		ServerPassword:    iPSK,
		ServerUsers:       users,
		ServerTimeWindow:  "30s",
		ClientPassword:    iPSK + ":" + users[0].Password,
		ClientClockOffset: &skew,
	})

	// Valid connection within +-30s window succeeds at +25s client skew.
	mustSOCKS5EchoTCP(t, topo, "", "", echoTarget.Addr(), DeterministicBytes(3061, 4096))

	sessions := topo.Tap.WaitForSessions(t, 1, 5*time.Second)
	require.True(t, sessions[0].WaitBytes(DirC2S, int64(SpecClientPrefixEIHSize+48), 5*time.Second))
	c2sBytes := sessions[0].Bytes(DirC2S)
	info, err := SpecInspectClientBurst(c2sBytes, iPSK, "", users, "")
	require.NoError(t, err)
	require.True(t, info.HasEIH)
	replayBurst := append([]byte(nil), c2sBytes[:info.TotalInitialConsumed]...)

	// Replaying the captured 112B+ EIH burst directly against Server must trigger StealthDrain!
	probe, err := SendRawProbe(topo.ServerAddr(), replayBurst, true, 13*time.Second)
	require.NoError(t, err)
	assertExpectedStealthDrain(t, probe)
}

func testT307SmuxChaChaThrottled12Streams(t *testing.T) {
	psk := GenerateRandomKeyBase64(t)
	echoTarget := StartTCPEchoTarget(t)

	topo := StartTopology(t, TopologyConfig{
		ServerPassword:          psk,
		ServerHeartbeatInterval: "200ms",
		ServerMultiplex:         &MultiplexServerSpec{Enabled: true, Padding: true},
		ClientPassword:          psk,
		ClientCipher:            "chacha20-poly1305",
		ClientHeartbeatInterval: "200ms",
		ClientMultiplex: &MultiplexClientSpec{
			Enabled:        true,
			Protocol:       "smux",
			MaxConnections: 2,
			Padding:        true,
		},
	})
	topo.Tap.SetTCPWindowBytes(4096)
	topo.Tap.SetThrottle(1*time.Millisecond, 4096)

	var wg sync.WaitGroup
	for i := 0; i < 12; i++ {
		i := i
		wg.Add(1)
		go func() {
			defer wg.Done()
			payload := DeterministicBytes(uint64(3070+i), 64*1024)
			mustSOCKS5EchoTCP(t, topo, "", "", echoTarget.Addr(), payload)
		}()
	}
	wg.Wait()
}

func testT308JumboUDPBloomRotation65s(t *testing.T) {
	privKey, pubKey := GenerateAetherKeyPairCLI(t)
	psk := GenerateRandomKeyBase64(t)
	srvTS := NewMockTimeService(0)
	cliTS := NewMockTimeService(0)

	// Path A: Outbound.ListenPacket -> Server Box -> UDPEchoTarget (65507B on Linux, 8192B OS-safe max on macOS due to net.inet.udp.maxdgram=9216).
	udpTarget := StartUDPEchoTarget(t)
	topo := StartTopology(t, TopologyConfig{
		ServerPassword:        psk,
		ServerPrivateKey:      privKey,
		ServerTimeService:     srvTS,
		ClientPassword:        psk,
		ClientCipher:          "aes-256-gcm",
		ClientServerPublicKey: pubKey,
		ClientTimeService:     cliTS,
	})

	boxPayloadSize := 65507
	if runtime.GOOS == "darwin" {
		boxPayloadSize = 8192
	}

	out, ok := topo.Client.Box.Outbound().Outbound("aether-out")
	require.True(t, ok)

	sendBoxJumbo := func(seed uint64) {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		pc, err := out.ListenPacket(ctx, M.ParseSocksaddr(udpTarget.Addr()))
		require.NoError(t, err)
		defer pc.Close()
		_ = pc.SetDeadline(time.Now().Add(10 * time.Second))
		payload := DeterministicBytes(seed, boxPayloadSize)
		require.NoError(t, pc.(N.PacketConn).WritePacket(buf.As(append([]byte(nil), payload...)), M.ParseSocksaddr(udpTarget.Addr())))
		rb := buf.NewSize(boxPayloadSize + 256)
		defer rb.Release()
		_, err = pc.(N.PacketConn).ReadPacket(rb)
		require.NoError(t, err)
		require.Equal(t, sha256.Sum256(payload), sha256.Sum256(rb.Bytes()))
	}

	// Path B: Client Outbound.ListenPacket -> SpecEchoRelayServer in-memory UDP relay exercises full 65507B over Aether CommandUDP on ALL OSes (including darwin).
	mockSrv := StartSpecEchoRelayServer(t, psk, "", nil, privKey)
	mHost, mPortStr, err := net.SplitHostPort(mockSrv.Addr())
	require.NoError(t, err)
	mPort, err := strconv.Atoi(mPortStr)
	require.NoError(t, err)
	port2 := AllocFreeTCPPort(t)
	rawCli2, err := BuildClientJSON(TopologyConfig{
		ClientPassword:        psk,
		ClientCipher:          "aes-256-gcm",
		ClientServerPublicKey: pubKey,
	}, port2, mHost, uint16(mPort), 0, "")
	require.NoError(t, err)
	cli2, err := StartBoxWithLog(t, rawCli2, "", port2, cliTS)
	require.NoError(t, err)
	defer func() { _ = cli2.Close() }()
	out2, ok := cli2.Box.Outbound().Outbound("aether-out")
	require.True(t, ok)

	send65507OverAetherWire := func(seed uint64) {
		ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
		defer cancel()
		pc, err := out2.ListenPacket(ctx, M.ParseSocksaddr("127.0.0.1:9999"))
		require.NoError(t, err)
		defer pc.Close()
		_ = pc.SetDeadline(time.Now().Add(12 * time.Second))
		jumbo := DeterministicBytes(seed, 65507)
		require.NoError(t, pc.(N.PacketConn).WritePacket(buf.As(append([]byte(nil), jumbo...)), M.ParseSocksaddr("127.0.0.1:9999")))
		rb := buf.NewSize(65535)
		defer rb.Release()
		_, err = pc.(N.PacketConn).ReadPacket(rb)
		require.NoError(t, err)
		require.Equal(t, 65507, rb.Len())
		require.Equal(t, sha256.Sum256(jumbo), sha256.Sum256(rb.Bytes()))
	}

	sendBoxJumbo(3081)
	send65507OverAetherWire(3082)

	// Advance both MockTimeServices +65s across Bloom generation rotation.
	srvTS.Advance(65 * time.Second)
	cliTS.Advance(65 * time.Second)

	sendBoxJumbo(3083)
	send65507OverAetherWire(3084)
}

func testT309UsersOnlyKeyAliasYamuxIPv6(t *testing.T) {
	uPass := "user-key-alias-secret!"
	users := []UserSpec{{Name: "v6user", Key: uPass}}

	v6TCP := StartTCPEchoTargetOn(t, "tcp6", "[::1]:0")
	dualStackTCP := StartTCPEchoTargetOn(t, "tcp", ":0")
	v6UDP := StartUDPEchoTargetOn(t, "udp6", "[::1]:0")

	topo := StartTopology(t, TopologyConfig{
		ServerPassword:  "",
		ServerUsers:     users,
		ServerMultiplex: &MultiplexServerSpec{Enabled: true, Padding: true},
		ClientPassword:  "",
		ClientKey:       uPass,
		ClientMultiplex: &MultiplexClientSpec{
			Enabled:  true,
			Protocol: "yamux",
			Padding:  true,
		},
	})

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	var wg sync.WaitGroup
	wg.Add(3)
	go func() {
		defer wg.Done()
		mustSOCKS5EchoTCP(t, topo, "", "", v6TCP.Addr(), DeterministicBytes(3091, 8192))
	}()
	go func() {
		defer wg.Done()
		hostAddr := fmt.Sprintf("localhost:%d", dualStackTCP.Port())
		mustSOCKS5EchoTCP(t, topo, "", "", hostAddr, DeterministicBytes(3092, 4096))
	}()
	go func() {
		defer wg.Done()
		uc, err := topo.OpenSOCKS5UDP(ctx)
		require.NoError(t, err)
		defer uc.Close()
		mustSOCKS5EchoUDP(t, uc, v6UDP.Addr(), DeterministicBytes(3093, 1024))
	}()
	wg.Wait()
}

func testT310EPKMaskCoalesced64SessionsPCAP(t *testing.T) {
	psk := GenerateRandomKeyBase64(t)
	echoTarget := StartTCPEchoTarget(t)

	topo := StartTopology(t, TopologyConfig{
		ServerPassword: psk,
		ClientPassword: psk,
		ClientCipher:   "aes-256-gcm",
	})

	const numSessions = 64
	for i := 0; i < numSessions; i++ {
		mustSOCKS5EchoTCP(t, topo, "", "", echoTarget.Addr(), DeterministicBytes(uint64(3100+i), 512+(i%7)*32))
	}

	sessions := topo.Tap.WaitForSessions(t, numSessions, 10*time.Second)
	require.GreaterOrEqual(t, len(sessions), numSessions)
	for i, s := range sessions[:numSessions] {
		s2cFirst, ok := s.FirstSegment(DirS2C)
		require.True(t, ok, "session %d missing S2C segment", i)
		require.GreaterOrEqual(t, s2cFirst.Size, SpecServerRespPrefixSize+36, "session %d S2C prefix not coalesced", i)
		require.False(t, s.HasSegmentOfExactSize(DirC2S, 2), "session %d leaked 2B C2S segment", i)
		require.False(t, s.HasSegmentOfExactSize(DirS2C, 2), "session %d leaked 2B S2C segment", i)
	}

	pcapPath := filepath.Join(t.TempDir(), "t310_epkmask.pcap")
	require.NoError(t, topo.Tap.SavePCAP(pcapPath))
	pktCount, err := ValidatePCAPFile(pcapPath)
	require.NoError(t, err)
	require.GreaterOrEqual(t, pktCount, numSessions*2)

	_, _, c2sBitRatio := topo.Tap.EPKBit255Stats(DirC2S)
	_, _, s2cBitRatio := topo.Tap.EPKBit255Stats(DirS2C)
	require.InDelta(t, 0.5, c2sBitRatio, 0.25, "C2S MaskedEPK bit 255 skewed: %v", c2sBitRatio)
	require.InDelta(t, 0.5, s2cBitRatio, 0.25, "S2C MaskedEPK bit 255 skewed: %v", s2cBitRatio)

	entC2S := topo.Tap.AggregateShannonEntropy(DirC2S)
	entS2C := topo.Tap.AggregateShannonEntropy(DirS2C)
	require.Greater(t, entC2S, 7.95, "C2S entropy too low: %v", entC2S)
	require.Greater(t, entS2C, 7.95, "S2C entropy too low: %v", entS2C)
}

func testT311MultiUserRouteOverridesTCPAndUDP(t *testing.T) {
	iPSK := GenerateRandomKeyBase64(t)
	alicePass := "alice-route-secret"
	bobPass := "bob-route-secret-18!"
	malloryPass := "mallory-route-secret"
	users := []UserSpec{
		{Name: "alice", Password: alicePass},
		{Name: "bob", Password: bobPass},
		{Name: "mallory", Password: malloryPass},
	}

	echoA := StartTCPEchoTarget(t)
	echoB := StartTCPEchoTarget(t)
	udpA := StartUDPEchoTarget(t)
	udpB := StartUDPEchoTarget(t)

	srvPort := AllocFreeTCPPort(t)
	rawSrv, err := BuildServerJSON(TopologyConfig{
		ServerPassword: iPSK,
		ServerUsers:    users,
		ServerExtraRouteRules: []map[string]any{
			{"auth_user": []string{"alice"}, "network": "tcp", "action": C.RuleActionTypeRoute, "outbound": "direct-out", "override_address": "127.0.0.1", "override_port": echoA.Port()},
			{"auth_user": []string{"alice"}, "network": "udp", "action": C.RuleActionTypeRoute, "outbound": "direct-out", "override_address": "127.0.0.1", "override_port": udpA.Port()},
			{"auth_user": []string{"bob"}, "network": "tcp", "action": C.RuleActionTypeRoute, "outbound": "direct-out", "override_address": "127.0.0.1", "override_port": echoB.Port()},
			{"auth_user": []string{"bob"}, "network": "udp", "action": C.RuleActionTypeRoute, "outbound": "direct-out", "override_address": "127.0.0.1", "override_port": udpB.Port()},
			{"auth_user": []string{"mallory"}, "action": C.RuleActionTypeReject},
		},
	}, srvPort, 0, "")
	require.NoError(t, err)
	srvBox, err := StartBoxWithLog(t, rawSrv, "", srvPort)
	require.NoError(t, err)
	defer func() { _ = srvBox.Close() }()

	startClient := func(pass string) *BoxInstance {
		cPort := AllocFreeTCPPort(t)
		rawC, cErr := BuildClientJSON(TopologyConfig{ClientPassword: iPSK + ":" + pass}, cPort, "127.0.0.1", srvPort, 0, "")
		require.NoError(t, cErr)
		cBox, bErr := StartBoxWithLog(t, rawC, "", cPort)
		require.NoError(t, bErr)
		t.Cleanup(func() { _ = cBox.Close() })
		return cBox
	}

	cliAlice := startClient(alicePass)
	cliBob := startClient(bobPass)
	cliMallory := startClient(malloryPass)

	// alice TCP + UDP hit echoA / udpA regardless of requested sentinel port.
	sentinel := "127.0.0.1:1"
	mustDialSOCKS5OnAddr(t, cliAlice.ListenAddr, sentinel, DeterministicBytes(3111, 256))
	require.Equal(t, int64(1), echoA.Connections())
	require.Equal(t, int64(0), echoB.Connections())

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	ucAlice, err := DialSOCKS5UDP(ctx, cliAlice.ListenAddr)
	require.NoError(t, err)
	mustSOCKS5EchoUDP(t, ucAlice, sentinel, DeterministicBytes(3112, 180))
	_ = ucAlice.Close()
	require.Equal(t, int64(1), udpA.Packets())
	require.Equal(t, int64(0), udpB.Packets())

	// bob TCP + UDP hit echoB / udpB.
	mustDialSOCKS5OnAddr(t, cliBob.ListenAddr, sentinel, DeterministicBytes(3113, 256))
	require.Equal(t, int64(1), echoA.Connections())
	require.Equal(t, int64(1), echoB.Connections())

	ucBob, err := DialSOCKS5UDP(ctx, cliBob.ListenAddr)
	require.NoError(t, err)
	mustSOCKS5EchoUDP(t, ucBob, sentinel, DeterministicBytes(3114, 180))
	_ = ucBob.Close()
	require.Equal(t, int64(1), udpA.Packets())
	require.Equal(t, int64(1), udpB.Packets())

	// mallory TCP + Native CommandUDP are rejected by route rule.
	mConn, err := DialSOCKS5TCP(ctx, cliMallory.ListenAddr, echoA.Addr())
	if err == nil {
		_, err = mConn.Write([]byte("ping"))
		if err == nil {
			_ = mConn.SetReadDeadline(time.Now().Add(2 * time.Second))
			_, err = mConn.Read(make([]byte, 32))
		}
		_ = mConn.Close()
	}
	require.Error(t, err)
	require.Equal(t, int64(1), echoA.Connections())

	outMallory, ok := cliMallory.Box.Outbound().Outbound("aether-out")
	require.True(t, ok)
	mpConn, err := outMallory.ListenPacket(ctx, M.ParseSocksaddr(udpA.Addr()))
	if err == nil {
		_ = mpConn.SetDeadline(time.Now().Add(2 * time.Second))
		_ = mpConn.(N.PacketConn).WritePacket(buf.As([]byte("mallory-udp")), M.ParseSocksaddr(udpA.Addr()))
		rb := buf.NewPacket()
		_, rErr := mpConn.(N.PacketConn).ReadPacket(rb)
		rb.Release()
		_ = mpConn.Close()
		require.Error(t, rErr)
	}
	require.Equal(t, int64(1), udpA.Packets())
}

func testT312ClientInitialWrite128KiB(t *testing.T) {
	privKey, pubKey := GenerateAetherKeyPairCLI(t)
	psk := GenerateRandomKeyBase64(t)
	echoTarget := StartTCPEchoTarget(t)

	topo := StartTopology(t, TopologyConfig{
		ServerPassword:        psk,
		ServerPrivateKey:      privKey,
		ClientPassword:        psk,
		ClientServerPublicKey: pubKey,
	})

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	out, ok := topo.Client.Box.Outbound().Outbound("aether-out")
	require.True(t, ok)

	conn, err := out.DialContext(ctx, N.NetworkTCP, M.ParseSocksaddr(echoTarget.Addr()))
	require.NoError(t, err)
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(15 * time.Second))

	payload128K := DeterministicBytes(3121, 128*1024)
	echoStreamExact(t, conn, payload128K)

	sessions := topo.Tap.WaitForSessions(t, 1, 5*time.Second)
	require.True(t, sessions[0].WaitBytes(DirC2S, 128*1024, 5*time.Second))
	info, err := SpecInspectClientBurst(sessions[0].Bytes(DirC2S), psk, "", nil, privKey)
	require.NoError(t, err)
	require.LessOrEqual(t, int(info.FixedHeader.VarHeaderLen), SpecMaxFrameDataSize)
	require.LessOrEqual(t, len(info.VarHeader.InitialPayload), SpecMaxFrameDataSize)
	require.False(t, sessions[0].HasSegmentOfExactSize(DirC2S, 2))
	require.False(t, sessions[0].HasSegmentOfExactSize(DirS2C, 2))

	// Check exact Frame 0..5 vs Frame 6+ via SpecEchoRelayServer with 128 KiB first Write.
	mockSrv := StartSpecEchoRelayServer(t, psk, "", nil, privKey)
	mHost, mPortStr, err := net.SplitHostPort(mockSrv.Addr())
	require.NoError(t, err)
	mPort, err := strconv.Atoi(mPortStr)
	require.NoError(t, err)
	port2 := AllocFreeTCPPort(t)
	raw2, err := BuildClientJSON(TopologyConfig{
		ClientPassword:        psk,
		ClientServerPublicKey: pubKey,
	}, port2, mHost, uint16(mPort), 0, "")
	require.NoError(t, err)
	cli2, err := StartBoxWithLog(t, raw2, "", port2)
	require.NoError(t, err)
	defer func() { _ = cli2.Close() }()
	out2, ok := cli2.Box.Outbound().Outbound("aether-out")
	require.True(t, ok)
	conn2, err := out2.DialContext(ctx, N.NetworkTCP, M.ParseSocksaddr(echoTarget.Addr()))
	require.NoError(t, err)
	defer conn2.Close()
	_ = conn2.SetDeadline(time.Now().Add(15 * time.Second))
	echoStreamExact(t, conn2, payload128K)

	srvSess := mockSrv.WaitForSessions(t, 1, 5*time.Second)
	frames := srvSess[0].C2SDataFrames()
	require.GreaterOrEqual(t, len(frames), 7)
	for _, fr := range frames {
		require.LessOrEqual(t, len(fr.Data), SpecMaxFrameDataSize)
		if fr.Seq < 6 {
			require.GreaterOrEqual(t, int(fr.PadLen), 16)
		} else {
			require.Equal(t, byte(0), fr.PadLen)
		}
	}
}

func testT313ChaffPingPongDataCloseWrite(t *testing.T) {
	psk := GenerateRandomKeyBase64(t)
	hcTarget := StartTCPHalfCloseTarget(t, []byte("T3-13-TRAILER-OK"))

	srvPort := AllocFreeTCPPort(t)
	rawSrv, err := BuildServerJSON(TopologyConfig{ServerPassword: psk}, srvPort, 0, "")
	require.NoError(t, err)
	srvBox, err := StartBoxWithLog(t, rawSrv, "", srvPort)
	require.NoError(t, err)
	defer func() { _ = srvBox.Close() }()

	ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
	defer cancel()
	sc, err := DialSpecClient(ctx, srvBox.ListenAddr, SpecDialOptions{
		Password:   psk,
		TargetAddr: hcTarget.Addr(),
	})
	require.NoError(t, err)
	defer sc.Close()
	_, err = sc.ReadServerResp(5 * time.Second)
	require.NoError(t, err)

	// Send Chaff interleaved with Ping -> Pong.
	require.NoError(t, sc.SendChaff(2, 32))
	require.NoError(t, sc.SendPing(32))
	pong, err := sc.ReadUntilFrameType(SpecFramePong, 5*time.Second)
	require.NoError(t, err)
	require.Equal(t, SpecFramePong, pong.FrameType)

	// Stream 64 KiB across frames + another Chaff + CloseWrite.
	payload := DeterministicBytes(3131, 64*1024)
	for off := 0; off < len(payload); off += 12000 {
		end := off + 12000
		if end > len(payload) {
			end = len(payload)
		}
		require.NoError(t, sc.WriteFrame(SpecFrameData, 0, payload[off:end]))
		if off == 12000 {
			require.NoError(t, sc.SendChaff(1, 0))
		}
	}
	require.NoError(t, sc.SendCloseWrite())

	var trailer bytes.Buffer
	for {
		fr, rErr := sc.ReadFrame(5 * time.Second)
		if rErr != nil {
			require.ErrorIs(t, rErr, io.EOF)
			break
		}
		switch fr.FrameType {
		case SpecFramePing:
			_ = sc.SendPong(32)
		case SpecFramePong:
		case SpecFrameData:
			trailer.Write(fr.Data)
		case SpecFrameCloseWrite:
			require.Equal(t, "T3-13-TRAILER-OK", trailer.String())
			goto done
		}
	}
done:
	require.Equal(t, "T3-13-TRAILER-OK", trailer.String())
	require.Eventually(t, func() bool { return hcTarget.EOFObserved.Load() }, 3*time.Second, 20*time.Millisecond)
	require.Equal(t, sha256.Sum256(payload), hcTarget.ReceivedHash)
}

func testT314WriteBufferDeadlineWriteBroken(t *testing.T) {
	psk := GenerateRandomKeyBase64(t)
	stalled := StartStalledTCPServer(t)

	topo := StartTopology(t, TopologyConfig{
		ServerPassword: psk,
		ClientPassword: psk,
		ClientCipher:   "chacha20-poly1305",
	})

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	out, ok := topo.Client.Box.Outbound().Outbound("aether-out")
	require.True(t, ok)

	rawConn, err := out.DialContext(ctx, N.NetworkTCP, M.ParseSocksaddr(stalled.Addr()))
	require.NoError(t, err)
	defer rawConn.Close()
	extConn, ok := rawConn.(N.ExtendedConn)
	require.True(t, ok, "outbound conn must implement network.ExtendedConn")

	// Pause C2S reads on WireTapProxy to back-pressure the kernel socket buffer.
	topo.Tap.SetReadPaused(DirC2S, true)

	// Push 32 KiB WriteBuffers with a tight 5ms write deadline until timeout triggers.
	var timedOutErr error
	for i := 0; i < 512; i++ {
		_ = extConn.SetWriteDeadline(time.Now().Add(5 * time.Millisecond))
		b := buf.NewSize(32 * 1024)
		_, _ = b.Write(bytes.Repeat([]byte{byte(i)}, 32*1024))
		err = extConn.WriteBuffer(b)
		if err != nil {
			timedOutErr = err
			break
		}
	}
	require.Error(t, timedOutErr, "WriteBuffer under backpressure must hit deadline")
	require.True(t, isTimeoutError(timedOutErr), "expected timeout error, got %v", timedOutErr)

	// Release backpressure and grant a generous future deadline; writeBroken must reject subsequent WriteBuffer immediately!
	topo.Tap.SetReadPaused(DirC2S, false)
	stalled.Release()
	_ = extConn.SetWriteDeadline(time.Now().Add(3 * time.Second))
	bAfter := buf.NewSize(128)
	_, _ = bAfter.Write(bytes.Repeat([]byte("X"), 128))
	errAfter := extConn.WriteBuffer(bAfter)
	require.Error(t, errAfter, "subsequent WriteBuffer after write timeout must immediately fail due to writeBroken latch")
	require.NoError(t, extConn.Close())
}

func testT315MultiUser200ProbesUnderH2MuxLoad(t *testing.T) {
	iPSK := GenerateRandomKeyBase64(t)
	alicePass := "alice-under-bombardment"
	users := []UserSpec{
		{Name: "alice", Password: alicePass},
		{Name: "bob", Password: "bob-under-bombardment"},
	}

	echoTarget := StartTCPEchoTarget(t)
	dnsSrv := StartLoopbackDNSServer(t, map[string]string{
		"internal.corp.": "10.99.0.10",
	})

	topo := StartTopology(t, TopologyConfig{
		ServerPassword:         iPSK,
		ServerUsers:            users,
		ServerHandshakeTimeout: "500ms",
		ServerMultiplex:        &MultiplexServerSpec{Enabled: true, Padding: true},
		ClientPassword:         iPSK + ":" + alicePass,
		ClientMultiplex: &MultiplexClientSpec{
			Enabled:        true,
			Protocol:       "h2mux",
			MaxConnections: 2,
			Padding:        true,
		},
	})

	var (
		probeWG      sync.WaitGroup
		drainedCount atomic.Int32
		failedCount  atomic.Int32
	)
	probePayloads := [][]byte{
		DeterministicBytes(3151, 34),
		DeterministicBytes(3152, 96),
		DeterministicBytes(3153, 112),
		append([]byte("GET / HTTP/1.1\r\nHost: x\r\n\r\n"), DeterministicBytes(3154, 485)...),
	}

	// Launch 200 concurrent probes (bounded in 4 overlapping groups of 50 or directly all 200 on Go loopback).
	// On macOS ulimit -n=1048575, 200 concurrent probes finish within a single ~10s StealthDrain window.
	for i := 0; i < 200; i++ {
		i := i
		probeWG.Add(1)
		go func() {
			defer probeWG.Done()
			payload := probePayloads[i%len(probePayloads)]
			halfClose := len(payload) >= 96
			res, pErr := SendRawProbe(topo.ServerAddr(), payload, halfClose, 13*time.Second)
			if pErr != nil || res.ClosedByRST || len(res.BytesReceived) > 0 || !res.ClosedCleanEOF {
				failedCount.Add(1)
				return
			}
			drainedCount.Add(1)
		}()
	}

	// While probes bombard Server, alice streams 2 MiB TCP + 20 UDP DNS queries cleanly!
	var aliceWG sync.WaitGroup
	aliceWG.Add(2)
	go func() {
		defer aliceWG.Done()
		mustSOCKS5EchoTCP(t, topo, "", "", echoTarget.Addr(), DeterministicBytes(3159, 2*1024*1024))
	}()
	go func() {
		defer aliceWG.Done()
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		uc, err := topo.OpenSOCKS5UDP(ctx)
		require.NoError(t, err)
		defer uc.Close()
		for q := 0; q < 20; q++ {
			resp := mustQueryDNSOverSOCKS5UDP(t, uc, dnsSrv.UDPAddr(), "internal.corp", dns.TypeA)
			require.Equal(t, dns.RcodeSuccess, resp.Rcode)
		}
	}()
	aliceWG.Wait()
	probeWG.Wait()

	require.Zero(t, failedCount.Load(), "some probes received data, RST, or hung")
	require.Equal(t, int32(200), drainedCount.Load())
}

func testT316URLTestFailoverOnPrimaryBlackhole(t *testing.T) {
	psk := GenerateRandomKeyBase64(t)
	srvPort := AllocFreeTCPPort(t)
	rawSrv, err := BuildServerJSON(TopologyConfig{
		ServerPassword:          psk,
		ServerHeartbeatInterval: "350ms",
	}, srvPort, 0, "")
	require.NoError(t, err)
	srvBox, err := StartBoxWithLog(t, rawSrv, "", srvPort)
	require.NoError(t, err)
	defer func() { _ = srvBox.Close() }()

	tapPrimary := StartWireTapProxy(t, srvBox.ListenAddr)
	tapBackup := StartWireTapProxy(t, srvBox.ListenAddr)
	// Bias initial latency toward primary so URLTest deterministically picks primary first.
	tapBackup.SetThrottle(35*time.Millisecond, 1024)

	healthSrv := startHTTP204HealthServer(t)
	httpTarget := StartTLS13HTTPSTarget(t)

	proxyPort := AllocFreeTCPPort(t)
	rawCli := buildDualAetherURLTestClientJSON(t, dualAetherClientSpec{
		ProxyPort:         proxyPort,
		PrimaryAddr:       tapPrimary.Addr(),
		BackupAddr:        tapBackup.Addr(),
		Password:          psk,
		HeartbeatInterval: "350ms",
		HealthURL:         healthSrv.URL + "/",
		Interval:          "400ms",
		Tolerance:         5,
	})
	cliBox, err := StartBoxWithLog(t, rawCli, "", proxyPort)
	require.NoError(t, err)
	defer func() { _ = cliBox.Close() }()

	httpClient := &http.Client{
		Timeout: 4 * time.Second,
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				return DialSOCKS5TCP(ctx, cliBox.ListenAddr, addr)
			},
			TLSClientConfig:   httpTarget.ClientTLSConfig("127.0.0.1"),
			DisableKeepAlives: true,
		},
	}

	// Confirm traffic initially works over primary.
	require.Eventually(t, func() bool {
		resp, gErr := httpClient.Get("https://" + httpTarget.Addr() + "/api/v1/health")
		if gErr != nil {
			return false
		}
		_ = resp.Body.Close()
		return resp.StatusCode == http.StatusOK && tapPrimary.SessionCount() >= 1
	}, 6*time.Second, 100*time.Millisecond)

	// Remove backup throttle and blackhole primary.
	tapBackup.SetThrottle(0, 0)
	backupBytesBefore := totalTapBytes(tapBackup)
	tapPrimary.SetBlackhole(true, true)

	// Failover via DPD + urltest probe must route subsequent requests cleanly through backup.
	require.Eventually(t, func() bool {
		resp, gErr := httpClient.Get("https://" + httpTarget.Addr() + "/api/v1/health")
		if gErr != nil {
			return false
		}
		_, _ = io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		return resp.StatusCode == http.StatusOK && totalTapBytes(tapBackup) > backupBytesBefore
	}, 24*time.Second, 250*time.Millisecond)
}

func totalTapBytes(tap *WireTapProxy) int64 {
	var total int64
	for _, s := range tap.Sessions() {
		total += s.TotalBytes(DirC2S) + s.TotalBytes(DirS2C)
	}
	return total
}

func testT317RawURLEncodingKeyAndNTPSync(t *testing.T) {
	privKey, pubKey := GenerateAetherKeyPairCLI(t)
	raw32 := DeterministicBytes(3170, 32)
	rawURLKey := base64.RawURLEncoding.EncodeToString(raw32)

	// Server uses normal clock + mock NTP (-20s); Client has local +45s skew corrected by same NTP (-20s)
	// OR both Client and Server sync to the same MockNTPServer(-20s).
	ntpSrv := StartMockNTPServer(t, -20*time.Second)
	echoTarget := StartTCPEchoTarget(t)
	udpTarget := StartUDPEchoTarget(t)

	srvPort := AllocFreeTCPPort(t)
	rawSrv, err := BuildServerJSON(TopologyConfig{
		ServerKey:        rawURLKey,
		ServerPrivateKey: privKey,
		ServerTimeWindow: "30s",
	}, srvPort, ntpSrv.Port(), "")
	require.NoError(t, err)
	srvBox, err := StartBoxWithLog(t, rawSrv, "", srvPort)
	require.NoError(t, err)
	defer func() { _ = srvBox.Close() }()

	// Poll until Server NTP sync occurred, or verify both sync to ntpSrv.
	cliPort := AllocFreeTCPPort(t)
	rawCli, err := BuildClientJSON(TopologyConfig{
		ClientKey:             rawURLKey,
		ClientServerPublicKey: pubKey,
	}, cliPort, "127.0.0.1", srvPort, ntpSrv.Port(), "")
	require.NoError(t, err)
	cliBox, err := StartBoxWithLog(t, rawCli, "", cliPort)
	require.NoError(t, err)
	defer func() { _ = cliBox.Close() }()

	require.Eventually(t, func() bool { return ntpSrv.Requests() >= 2 }, 5*time.Second, 50*time.Millisecond)

	mustDialSOCKS5OnAddr(t, cliBox.ListenAddr, echoTarget.Addr(), DeterministicBytes(3171, 2048))
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	uc, err := DialSOCKS5UDP(ctx, cliBox.ListenAddr)
	require.NoError(t, err)
	defer uc.Close()
	mustSOCKS5EchoUDP(t, uc, udpTarget.Addr(), DeterministicBytes(3172, 512))
}

func testT318AsymmetricShapingUoTv1(t *testing.T) {
	psk := GenerateRandomKeyBase64(t)
	udpTarget := StartUDPEchoTarget(t)

	topo := StartTopology(t, TopologyConfig{
		ServerPassword:       psk,
		ServerDisableShaping: false,
		ClientPassword:       psk,
		ClientDisableShaping: true,
		ClientUDPOverTCP:     map[string]any{"enabled": true, "version": 1},
	})

	ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
	defer cancel()
	uc, err := topo.OpenSOCKS5UDP(ctx)
	require.NoError(t, err)
	defer uc.Close()

	for idx, sz := range []int{12, 517, 1472, 8192} {
		mustSOCKS5EchoUDP(t, uc, udpTarget.Addr(), DeterministicBytes(uint64(3180+idx), sz))
	}

	sessions := topo.Tap.WaitForSessions(t, 1, 5*time.Second)
	s2cFirst, ok := sessions[0].FirstSegment(DirS2C)
	require.True(t, ok)
	require.GreaterOrEqual(t, s2cFirst.Size, SpecServerRespPrefixSize+36+16)
}

func testT319H2MuxPoolIdleResetNetwork(t *testing.T) {
	psk := GenerateRandomKeyBase64(t)
	echoTarget := StartTCPEchoTarget(t)
	udpTarget := StartUDPEchoTarget(t)

	baselineFDs, err := CountOpenFDs()
	require.NoError(t, err)

	topo := StartTopology(t, TopologyConfig{
		ServerPassword:  psk,
		ServerMultiplex: &MultiplexServerSpec{Enabled: true, Padding: true},
		ClientPassword:  psk,
		ClientMultiplex: &MultiplexClientSpec{
			Enabled:        true,
			Protocol:       "h2mux",
			MaxConnections: 4,
			MinStreams:     1,
			MaxStreams:     2,
			Padding:        true,
		},
	})

	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		i := i
		wg.Add(1)
		go func() {
			defer wg.Done()
			mustSOCKS5EchoTCP(t, topo, "", "", echoTarget.Addr(), DeterministicBytes(uint64(3190+i), 4096))
		}()
	}
	wg.Wait()

	require.True(t, topo.CloseClientIdleConnections())
	topo.ResetClientNetwork(context.Background())

	// Subsequent requests after idle close + ResetNetwork must succeed seamlessly.
	mustSOCKS5EchoTCP(t, topo, "", "", echoTarget.Addr(), DeterministicBytes(3198, 4096))
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	uc, err := topo.OpenSOCKS5UDP(ctx)
	require.NoError(t, err)
	mustSOCKS5EchoUDP(t, uc, udpTarget.Addr(), DeterministicBytes(3199, 512))
	_ = uc.Close()

	topo.Close()
	echoTarget.Close()
	udpTarget.Close()
	leaks := WaitForNoAetherLeaks(5 * time.Second)
	require.Empty(t, leaks, "unexpected goroutine leaks: %v", leaks)

	finalFDs, err := CountOpenFDs()
	require.NoError(t, err)
	require.LessOrEqual(t, finalFDs, baselineFDs+8, "FD leak suspected: baseline=%d final=%d", baselineFDs, finalFDs)
}

func testT320ImmediateFINCoalescedCloseWrite(t *testing.T) {
	privKey, pubKey := GenerateAetherKeyPairCLI(t)
	psk := GenerateRandomKeyBase64(t)
	finTarget := StartImmediateFINServer(t)

	topo := StartTopology(t, TopologyConfig{
		ServerPassword:        psk,
		ServerPrivateKey:      privKey,
		ClientPassword:        psk,
		ClientCipher:          "chacha20-poly1305",
		ClientServerPublicKey: pubKey,
	})

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	conn, err := topo.DialSOCKS5(ctx, finTarget.Addr())
	require.NoError(t, err)
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(8 * time.Second))

	got, err := io.ReadAll(conn)
	require.NoError(t, err)
	require.Empty(t, got)
	require.NoError(t, conn.Close())

	sessions := topo.Tap.WaitForSessions(t, 1, 5*time.Second)
	require.True(t, sessions[0].WaitClosed(5*time.Second))
	s2cFirst, ok := sessions[0].FirstSegment(DirS2C)
	require.True(t, ok)
	// 84B ServerRespPrefix + coalesced shaped FrameCloseWrite (18B + >=18B + 16B = >=52B; >=136B).
	require.GreaterOrEqual(t, s2cFirst.Size, SpecServerRespPrefixSize+52)
}

func testT321TCPInjectableInboundNetPipeEIH(t *testing.T) {
	iPSK := GenerateRandomKeyBase64(t)
	alicePass := "alice-pipe-secret"
	bobPass := "bob-pipe-secret-18!"
	users := []UserSpec{
		{Name: "alice", Password: alicePass},
		{Name: "bob", Password: bobPass},
	}

	echoB := StartTCPEchoTarget(t)
	srvPort := AllocFreeTCPPort(t)
	rawSrv, err := BuildServerJSON(TopologyConfig{
		ServerPassword: iPSK,
		ServerUsers:    users,
		ServerUserRoutes: map[string]UserRouteOverride{
			"bob": {Outbound: "direct-out", OverrideAddress: "127.0.0.1", OverridePort: echoB.Port()},
		},
	}, srvPort, 0, "")
	require.NoError(t, err)
	srvBox, err := StartBoxWithLog(t, rawSrv, "", srvPort)
	require.NoError(t, err)
	defer func() { _ = srvBox.Close() }()

	ib, ok := srvBox.Box.Inbound().Get("aether-in")
	require.True(t, ok)
	inj, ok := ib.(adapter.TCPInjectableInbound)
	require.True(t, ok, "aether inbound must implement adapter.TCPInjectableInbound")

	cClient, cServer := net.Pipe()
	defer cClient.Close()

	// Override target sentinel with auth_user == "bob" rule -> echoB.
	burst, sc, err := BuildSpecClientInitialBurst(SpecDialOptions{
		Password:       iPSK,
		Key:            bobPass,
		TargetAddr:     "127.0.0.1:1",
		InitialPayload: DeterministicBytes(3211, 128),
	})
	require.NoError(t, err)
	require.GreaterOrEqual(t, len(burst), SpecClientPrefixEIHSize+48)
	sc.Conn = cClient

	var injWG sync.WaitGroup
	injWG.Add(1)
	go func() {
		defer injWG.Done()
		inj.NewConnection(context.Background(), cServer, adapter.InboundContext{
			Inbound:     "aether-in",
			InboundType: C.TypeAether,
			Network:     N.NetworkTCP,
			Source:      M.ParseSocksaddr("127.0.0.1:41234"),
		}, nil)
	}()

	writeDone := make(chan error, 1)
	go func() {
		_, wErr := cClient.Write(burst)
		writeDone <- wErr
	}()
	_, err = sc.ReadServerResp(5 * time.Second)
	require.NoError(t, err)
	require.NoError(t, <-writeDone)

	fr, err := sc.ReadNextDataFrame(5 * time.Second)
	require.NoError(t, err)
	require.Equal(t, DeterministicBytes(3211, 128), fr.Data)

	extra := DeterministicBytes(3212, 512)
	require.NoError(t, sc.WriteFrame(SpecFrameData, 16, extra))
	fr2, err := sc.ReadNextDataFrame(5 * time.Second)
	require.NoError(t, err)
	require.Equal(t, extra, fr2.Data)

	require.NoError(t, sc.SendCloseWrite())
	_ = sc.Close()
	injWG.Wait()
	require.Equal(t, int64(1), echoB.Connections())
}

func testT322NativeUDPDialContextCoalesced(t *testing.T) {
	psk := GenerateRandomKeyBase64(t)
	udpTarget := StartUDPEchoTarget(t)

	topo := StartTopology(t, TopologyConfig{
		ServerPassword: psk,
		ClientPassword: psk,
	})

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	out, ok := topo.Client.Box.Outbound().Outbound("aether-out")
	require.True(t, ok)

	conn, err := out.DialContext(ctx, N.NetworkUDP, M.ParseSocksaddr(udpTarget.Addr()))
	require.NoError(t, err)
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(8 * time.Second))

	dgram := DeterministicBytes(3221, 512)
	_, err = conn.Write(dgram)
	require.NoError(t, err)
	reply := make([]byte, 2048)
	n, err := conn.Read(reply)
	require.NoError(t, err)
	require.Equal(t, dgram, reply[:n])

	sessions := topo.Tap.WaitForSessions(t, 1, 5*time.Second)
	require.True(t, sessions[0].WaitBytes(DirC2S, int64(SpecClientPrefixNoEIHSize+48), 5*time.Second))
	info, err := SpecInspectClientBurst(sessions[0].Bytes(DirC2S), psk, "", nil, "")
	require.NoError(t, err)
	require.Equal(t, SpecCommandUDP, info.FixedHeader.Command)
}

func testT323EndToEndCLIChain(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	psk := GenerateAetherKeyCLI(t)
	privKey, pubKey := GenerateAetherKeyPairCLI(t)
	require.NotEmpty(t, psk)
	require.NotEmpty(t, privKey)
	require.NotEmpty(t, pubKey)

	schemaRes := RunCLI(t, ctx, "schema")
	require.Equal(t, 0, schemaRes.ExitCode, "sing-box schema stderr=%s", schemaRes.Stderr)
	require.True(t, json.Valid([]byte(schemaRes.Stdout)), "sing-box schema did not emit valid JSON")
	require.Contains(t, schemaRes.Stdout, `"const": "aether"`)
	require.Contains(t, schemaRes.Stdout, `"AetherUser"`)
	require.Contains(t, schemaRes.Stdout, `"disable_shaping"`)

	srvPort := AllocFreeTCPPort(t)
	rawSrv, err := BuildServerJSON(TopologyConfig{
		ServerPassword:   psk,
		ServerPrivateKey: privKey,
	}, srvPort, 0, "")
	require.NoError(t, err)

	cliPort := AllocFreeTCPPort(t)
	rawCli, err := BuildClientJSON(TopologyConfig{
		ClientPassword:        psk,
		ClientServerPublicKey: pubKey,
	}, cliPort, "127.0.0.1", srvPort, 0, "")
	require.NoError(t, err)

	checkSrv := CheckConfigCLI(t, rawSrv)
	require.Equal(t, 0, checkSrv.ExitCode, "server check stderr=%s", checkSrv.Stderr)
	checkCli := CheckConfigCLI(t, rawCli)
	require.Equal(t, 0, checkCli.ExitCode, "client check stderr=%s", checkCli.Stderr)

	srvProc := StartCLIDaemon(t, rawSrv, srvPort)
	cliProc := StartCLIDaemon(t, rawCli, cliPort)

	tcpTarget := StartTCPEchoTarget(t)
	udpTarget := StartUDPEchoTarget(t)
	mustDialSOCKS5OnAddr(t, fmt.Sprintf("127.0.0.1:%d", cliPort), tcpTarget.Addr(), DeterministicBytes(3231, 4096))

	uc, err := DialSOCKS5UDP(ctx, fmt.Sprintf("127.0.0.1:%d", cliPort))
	require.NoError(t, err)
	mustSOCKS5EchoUDP(t, uc, udpTarget.Addr(), DeterministicBytes(3232, 700))
	_ = uc.Close()

	require.NoError(t, cliProc.Signal(syscall.SIGTERM))
	cCode, err := cliProc.Wait(8 * time.Second)
	require.NoError(t, err)
	require.Equal(t, 0, cCode, "client stderr=%s", cliProc.Stderr())

	require.NoError(t, srvProc.Signal(syscall.SIGTERM))
	sCode, err := srvProc.Wait(8 * time.Second)
	require.NoError(t, err)
	require.Equal(t, 0, sCode, "server stderr=%s", srvProc.Stderr())
}

func testT324UniformStealthDrainAcross3Failures(t *testing.T) {
	users := make([]UserSpec, 5)
	for i := range users {
		users[i] = UserSpec{
			Name:     fmt.Sprintf("user-%d", i),
			Password: fmt.Sprintf("secret-%d-%s", i, GenerateRandomKeyBase64(t)),
		}
	}
	echoTarget := StartTCPEchoTarget(t)

	topo := StartTopology(t, TopologyConfig{
		ServerPassword:   "",
		ServerUsers:      users,
		ServerTimeWindow: "30s",
		ClientPassword:   users[0].Password,
	})

	// Perform 1 valid session and capture raw 96B+ burst to construct an exact replay probe.
	mustSOCKS5EchoTCP(t, topo, "", "", echoTarget.Addr(), DeterministicBytes(3241, 256))
	sessions := topo.Tap.WaitForSessions(t, 1, 5*time.Second)
	c2s := sessions[0].Bytes(DirC2S)
	info, err := SpecInspectClientBurst(c2s, "", "", users, "")
	require.NoError(t, err)
	replayBurst := append([]byte(nil), c2s[:info.TotalInitialConsumed]...)

	wrongPassBurst, _, err := BuildSpecClientInitialBurst(SpecDialOptions{
		Password:   "wrong-password-attempt",
		ForceNoEIH: true,
		TargetAddr: echoTarget.Addr(),
	})
	require.NoError(t, err)

	expiredTS := time.Now().Add(40 * time.Second).Unix()
	expiredBurst, _, err := BuildSpecClientInitialBurst(SpecDialOptions{
		Password:     users[2].Password,
		ForceNoEIH:   true,
		TimestampSec: &expiredTS,
		TargetAddr:   echoTarget.Addr(),
	})
	require.NoError(t, err)

	results := make([]ProbeResult, 3)
	errs := make([]error, 3)
	probes := [][]byte{wrongPassBurst, replayBurst, expiredBurst}
	var wg sync.WaitGroup
	for i := range probes {
		i := i
		wg.Add(1)
		go func() {
			defer wg.Done()
			results[i], errs[i] = SendRawProbe(topo.ServerAddr(), probes[i], true, 13*time.Second)
		}()
	}
	wg.Wait()

	for i := range probes {
		require.NoError(t, errs[i])
		assertExpectedStealthDrain(t, results[i])
	}
}

func testT325MixedWriteWriteBufferIOCopyCutover(t *testing.T) {
	psk := GenerateRandomKeyBase64(t)
	echoTarget := StartTCPEchoTarget(t)

	topo := StartTopology(t, TopologyConfig{
		ServerPassword: psk,
		ClientPassword: psk,
		ClientCipher:   "aes-256-gcm",
	})

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	out, ok := topo.Client.Box.Outbound().Outbound("aether-out")
	require.True(t, ok)

	rawConn, err := out.DialContext(ctx, N.NetworkTCP, M.ParseSocksaddr(echoTarget.Addr()))
	require.NoError(t, err)
	defer rawConn.Close()
	extConn, ok := rawConn.(N.ExtendedConn)
	require.True(t, ok)
	_ = extConn.SetDeadline(time.Now().Add(15 * time.Second))

	chunkA := DeterministicBytes(3251, 100)
	chunkB := DeterministicBytes(3252, 2000)
	chunkC := DeterministicBytes(3253, 128*1024)
	var expected bytes.Buffer
	expected.Write(chunkA)
	expected.Write(chunkB)
	expected.Write(chunkC)

	errCh := make(chan error, 1)
	go func() {
		if _, e := extConn.Write(chunkA); e != nil {
			errCh <- e
			return
		}
		// Buffer with explicit headroom for encryption/length encapsulation.
		b := buf.NewSize(2000 + 256)
		b.Resize(64, 0)
		_, _ = b.Write(chunkB)
		if e := extConn.WriteBuffer(b); e != nil {
			errCh <- e
			return
		}
		if _, e := io.Copy(extConn, bytes.NewReader(chunkC)); e != nil {
			errCh <- e
			return
		}
		errCh <- N.CloseWrite(extConn)
	}()

	got, err := io.ReadAll(extConn)
	require.NoError(t, err)
	require.NoError(t, <-errCh)
	require.Equal(t, sha256.Sum256(expected.Bytes()), sha256.Sum256(got))
}

func testT326RegressionR5MuxAndUoTSimultaneous(t *testing.T) {
	psk := GenerateRandomKeyBase64(t)
	tcpTarget := StartTCPEchoTarget(t)
	udpTarget := StartUDPEchoTarget(t)

	topo := StartTopology(t, TopologyConfig{
		ServerPassword:  psk,
		ServerMultiplex: &MultiplexServerSpec{Enabled: true, Padding: true},
		ClientPassword:  psk,
		ClientMultiplex: &MultiplexClientSpec{
			Enabled:  true,
			Protocol: "smux",
			Padding:  true,
		},
		ClientUDPOverTCP: map[string]any{"enabled": true, "version": 2},
	})

	ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
	defer cancel()

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		mustSOCKS5EchoTCP(t, topo, "", "", tcpTarget.Addr(), DeterministicBytes(3261, 16*1024))
	}()
	go func() {
		defer wg.Done()
		uc, err := topo.OpenSOCKS5UDP(ctx)
		require.NoError(t, err)
		defer uc.Close()
		mustSOCKS5EchoUDP(t, uc, udpTarget.Addr(), DeterministicBytes(3262, 1024))
	}()
	wg.Wait()
}

func testT327MaxNoise384UDP10PacketsCutover(t *testing.T) {
	psk := GenerateRandomKeyBase64(t)
	udpTarget := StartUDPEchoTarget(t)

	srvPort := AllocFreeTCPPort(t)
	rawSrv, err := BuildServerJSON(TopologyConfig{ServerPassword: psk}, srvPort, 0, "")
	require.NoError(t, err)
	srvBox, err := StartBoxWithLog(t, rawSrv, "", srvPort)
	require.NoError(t, err)
	defer func() { _ = srvBox.Close() }()

	tap := StartWireTapProxy(t, srvBox.ListenAddr)

	ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
	defer cancel()
	cmdUDP := SpecCommandUDP
	sc, err := DialSpecClient(ctx, tap.Addr(), SpecDialOptions{
		Password:    psk,
		Command:     &cmdUDP,
		CustomNoise: DeterministicBytes(3270, SpecNoiseMax),
		TargetAddr:  fmt.Sprintf("localhost:%d", udpTarget.Port()),
	})
	require.NoError(t, err)
	defer sc.Close()
	_, err = sc.ReadServerResp(5 * time.Second)
	require.NoError(t, err)

	targetHostPort := fmt.Sprintf("localhost:%d", udpTarget.Port())
	for seq := 0; seq < 10; seq++ {
		pkt := DeterministicBytes(uint64(3271+seq), 200+seq*16)
		require.NoError(t, sc.SendUDPDatagram(targetHostPort, pkt, nil))
		fr, fErr := sc.ReadNextDataFrame(5 * time.Second)
		require.NoError(t, fErr)
		require.Equal(t, SpecFrameData, fr.FrameType)
		if seq < 6 {
			require.GreaterOrEqual(t, int(fr.PadLen), 16)
		} else {
			require.Equal(t, byte(0), fr.PadLen)
		}
		// UDP frame holdssocksaddr + uint16 len + payload; payload is at tail.
		require.GreaterOrEqual(t, len(fr.Data), len(pkt)+2)
		require.Equal(t, pkt, fr.Data[len(fr.Data)-len(pkt):])
	}

	sessions := tap.WaitForSessions(t, 1, 5*time.Second)
	info, err := SpecInspectClientBurst(sessions[0].Bytes(DirC2S), psk, "", nil, "")
	require.NoError(t, err)
	require.Equal(t, uint16(SpecNoiseMax), info.FixedHeader.NoiseLen)
	require.Equal(t, SpecCommandUDP, info.FixedHeader.Command)
}

func testT328ReleaseEngineeringConsistency(t *testing.T) {
	root, err := RepoRoot()
	require.NoError(t, err)

	versionGoBytes, err := os.ReadFile(filepath.Join(root, "constant", "version.go"))
	require.NoError(t, err)
	verMatch := regexp.MustCompile(`var Version = "([^"]+)"`).FindSubmatch(versionGoBytes)
	require.Len(t, verMatch, 2, "constant/version.go missing var Version")
	repoVersion := string(verMatch[1])
	require.Regexp(t, `^1\.[0-9]+\.[0-9]+-Custom-Aether$`, repoVersion)

	ldflagsBytes, err := os.ReadFile(filepath.Join(root, "release", "LDFLAGS"))
	require.NoError(t, err)
	ldflagsStr := strings.TrimSpace(string(ldflagsBytes))
	require.Contains(t, ldflagsStr, "multipathtcp=0")
	require.Contains(t, ldflagsStr, "tlssha1=1")
	require.Contains(t, ldflagsStr, "-checklinkname=0")

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	verRes := RunCLI(t, ctx, "version")
	require.Equal(t, 0, verRes.ExitCode, "sing-box version stderr=%s", verRes.Stderr)
	require.Contains(t, verRes.Stdout, repoVersion)

	schemaRes := RunCLI(t, ctx, "schema")
	require.Equal(t, 0, schemaRes.ExitCode, "sing-box schema stderr=%s", schemaRes.Stderr)
	require.True(t, json.Valid([]byte(schemaRes.Stdout)), "sing-box schema did not emit valid JSON")
	require.Contains(t, schemaRes.Stdout, `"const": "aether"`)
	require.Contains(t, schemaRes.Stdout, `"AetherUser"`)
	require.Contains(t, schemaRes.Stdout, `"private_key"`)
	require.Contains(t, schemaRes.Stdout, `"public_key"`)
	require.Contains(t, schemaRes.Stdout, `"handshake_timeout"`)
	require.Contains(t, schemaRes.Stdout, `"heartbeat_interval"`)
	require.Contains(t, schemaRes.Stdout, `"disable_shaping"`)

	buildWorkflowBytes, err := os.ReadFile(filepath.Join(root, ".github", "workflows", "build-linux-amd64.yml"))
	require.NoError(t, err)
	buildWF := string(buildWorkflowBytes)
	require.Contains(t, buildWF, Default9BuildTags)
	require.Contains(t, buildWF, "CGO_ENABLED:")
	require.Contains(t, buildWF, "go test -race")
	require.Contains(t, buildWF, "release/LDFLAGS")
	require.Contains(t, buildWF, "github.com/sagernet/sing-box/constant.Version=")

	syncWorkflowBytes, err := os.ReadFile(filepath.Join(root, ".github", "workflows", "upstream-sync-release.yml"))
	require.NoError(t, err)
	syncWF := string(syncWorkflowBytes)
	require.Contains(t, syncWF, "SagerNet/sing-box")
	require.Contains(t, syncWF, Default9BuildTags)
	require.Contains(t, syncWF, "CGO_ENABLED=1 go test -race -count=1 ./cmd/sing-box/... ./option/... ./schema/... ./protocol/aether/...")
	require.Contains(t, syncWF, "git checkout HEAD -- .github/workflows/")
	require.Contains(t, syncWF, "-Custom-Aether")
	require.Contains(t, syncWF, "release/LDFLAGS")
	require.Contains(t, syncWF, "SHA256SUMS")
}

func testT329StaticKeyServerMixedCipherClients(t *testing.T) {
	privKey, pubKey := GenerateAetherKeyPairCLI(t)
	psk := GenerateRandomKeyBase64(t)
	echoTarget := StartTCPEchoTarget(t)

	srvPort := AllocFreeTCPPort(t)
	rawSrv, err := BuildServerJSON(TopologyConfig{
		ServerPassword:   psk,
		ServerPrivateKey: privKey,
	}, srvPort, 0, "")
	require.NoError(t, err)
	srvBox, err := StartBoxWithLog(t, rawSrv, "", srvPort)
	require.NoError(t, err)
	defer func() { _ = srvBox.Close() }()

	tap := StartWireTapProxy(t, srvBox.ListenAddr)
	host, portStr, err := net.SplitHostPort(tap.Addr())
	require.NoError(t, err)
	tapPort, err := strconv.Atoi(portStr)
	require.NoError(t, err)

	startCipherClient := func(cipher string) *BoxInstance {
		p := AllocFreeTCPPort(t)
		raw, rErr := BuildClientJSON(TopologyConfig{
			ClientPassword:        psk,
			ClientCipher:          cipher,
			ClientServerPublicKey: pubKey,
		}, p, host, uint16(tapPort), 0, "")
		require.NoError(t, rErr)
		cb, cErr := StartBoxWithLog(t, raw, "", p)
		require.NoError(t, cErr)
		t.Cleanup(func() { _ = cb.Close() })
		return cb
	}

	cliAES := startCipherClient("aes-256-gcm")
	cliChaCha := startCipherClient("chacha20-poly1305")

	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		i := i
		addr := cliAES.ListenAddr
		if i%2 == 1 {
			addr = cliChaCha.ListenAddr
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			mustDialSOCKS5OnAddr(t, addr, echoTarget.Addr(), DeterministicBytes(uint64(3290+i), 4096))
		}()
	}
	wg.Wait()

	sessions := tap.WaitForSessions(t, 20, 8*time.Second)
	var seenAES, seenChaCha int
	for _, s := range sessions {
		info, iErr := SpecInspectClientBurst(s.Bytes(DirC2S), psk, "", nil, privKey)
		if iErr == nil {
			switch info.FixedHeader.CipherSuite {
			case SpecCipherAES256GCM:
				seenAES++
			case SpecCipherChaCha20Poly1305:
				seenChaCha++
			}
		}
	}
	require.Equal(t, 10, seenAES)
	require.Equal(t, 10, seenChaCha)
}

func testT330HalfCloseIdleHeartbeatSurvival(t *testing.T) {
	psk := GenerateRandomKeyBase64(t)
	upPayload := DeterministicBytes(3301, 16*1024)
	downPayload := DeterministicBytes(3302, 64*1024)

	// Custom half-close server: reads until client EOF, sleeps 1.2s (> 3x 350ms heartbeats), then writes 64 KiB.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, aErr := ln.Accept()
			if aErr != nil {
				return
			}
			go func(conn net.Conn) {
				defer conn.Close()
				up, rErr := io.ReadAll(conn)
				if rErr != nil || !bytes.Equal(up, upPayload) {
					return
				}
				time.Sleep(1200 * time.Millisecond)
				_, _ = conn.Write(downPayload)
			}(c)
		}
	}()

	topo := StartTopology(t, TopologyConfig{
		ServerPassword:          psk,
		ServerHeartbeatInterval: "350ms",
		ClientPassword:          psk,
		ClientHeartbeatInterval: "350ms",
	})

	ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
	defer cancel()
	conn, err := topo.DialSOCKS5(ctx, ln.Addr().String())
	require.NoError(t, err)
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))

	gotDown := echoExtendedConnHalfClose(t, conn, upPayload)
	require.Equal(t, sha256.Sum256(downPayload), sha256.Sum256(gotDown))
}

func testT331NegativeHeartbeatDisablesPingYamux4MiB(t *testing.T) {
	iPSK := GenerateRandomKeyBase64(t)
	users := []UserSpec{
		{Name: "alice", Password: "alice-no-hb-secret"},
		{Name: "bob", Password: "bob-no-hb-secret-18!"},
	}
	echoTarget := StartTCPEchoTarget(t)

	topo := StartTopology(t, TopologyConfig{
		ServerPassword:          iPSK,
		ServerUsers:             users,
		ServerHeartbeatInterval: "-1s",
		ServerMultiplex:         &MultiplexServerSpec{Enabled: true, Padding: true},
		ClientPassword:          iPSK + ":" + users[0].Password,
		ClientHeartbeatInterval: "-1s",
		ClientMultiplex: &MultiplexClientSpec{
			Enabled:  true,
			Protocol: "yamux",
			Padding:  true,
		},
	})

	// Stream 4 MiB across 8 parallel streams (512 KiB each).
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		i := i
		wg.Add(1)
		go func() {
			defer wg.Done()
			mustSOCKS5EchoTCP(t, topo, "", "", echoTarget.Addr(), DeterministicBytes(uint64(3310+i), 512*1024))
		}()
	}
	wg.Wait()

	// Verify Server sends zero FramePing during a 1.1s idle window when heartbeat_interval == "-1s".
	// Seed InitialPayload so the 84B ServerRespPrefix coalesces with the echo instead of a 100ms 0B control frame.
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	probeMsg := []byte("hb-off-probe")
	sc, err := DialSpecClient(ctx, topo.ServerAddr(), SpecDialOptions{
		Password:       iPSK,
		Key:            users[0].Password,
		TargetAddr:     echoTarget.Addr(),
		InitialPayload: probeMsg,
	})
	require.NoError(t, err)
	defer sc.Close()
	_, err = sc.ReadServerResp(5 * time.Second)
	require.NoError(t, err)
	echoFr, err := sc.ReadNextDataFrame(5 * time.Second)
	require.NoError(t, err)
	require.Equal(t, probeMsg, echoFr.Data)

	_, rErr := sc.ReadFrame(1100 * time.Millisecond)
	require.Error(t, rErr)
	require.True(t, isTimeoutError(rErr), "server sent unexpected frame when heartbeat_interval=-1s: %v", rErr)
}

func testT332Interleaved150Valid40BadZeroLeaks(t *testing.T) {
	psk := GenerateRandomKeyBase64(t)
	tcpTarget := StartTCPEchoTarget(t)
	udpTarget := StartUDPEchoTarget(t)

	baselineFDs, err := CountOpenFDs()
	require.NoError(t, err)

	topo := StartTopology(t, TopologyConfig{
		ServerPassword:         psk,
		ServerHandshakeTimeout: "500ms",
		ClientPassword:         psk,
	})

	// Run 150 short-lived legitimate TCP/UDP transfers interleaved with 40 malformed probes.
	ctx, cancel := context.WithTimeout(context.Background(), 35*time.Second)
	defer cancel()

	var (
		wg        sync.WaitGroup
		sem       = make(chan struct{}, 25)
		validOK   atomic.Int32
		badProbeN atomic.Int32
	)

	for i := 0; i < 150; i++ {
		i := i
		wg.Add(1)
		go func() {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			if i%3 == 0 {
				uc, uErr := topo.OpenSOCKS5UDP(ctx)
				require.NoError(t, uErr)
				mustSOCKS5EchoUDP(t, uc, udpTarget.Addr(), DeterministicBytes(uint64(3320+i), 256))
				_ = uc.Close()
			} else {
				mustSOCKS5EchoTCP(t, topo, "", "", tcpTarget.Addr(), DeterministicBytes(uint64(3320+i), 1024))
			}
			validOK.Add(1)
		}()

		if i%4 == 0 && badProbeN.Add(1) <= 40 {
			idx := i
			wg.Add(1)
			go func() {
				defer wg.Done()
				// Truncated 40B burst triggers Server HandshakeTimeout(500ms); bad-tag triggers StealthDrain.
				var probePayload []byte
				if idx%8 == 0 {
					probePayload = DeterministicBytes(uint64(9000+idx), 40)
				} else {
					probePayload = DeterministicBytes(uint64(9000+idx), 100)
				}
				_, _ = SendRawProbe(topo.ServerAddr(), probePayload, idx%8 != 0, 12*time.Second)
			}()
		}
	}
	wg.Wait()
	require.Equal(t, int32(150), validOK.Load())

	topo.Close()
	tcpTarget.Close()
	udpTarget.Close()
	leaks := WaitForNoAetherLeaks(5 * time.Second)
	require.Empty(t, leaks, "leaked Aether/sing-box goroutines: %v", leaks)

	finalFDs, err := CountOpenFDs()
	require.NoError(t, err)
	require.LessOrEqual(t, finalFDs, baselineFDs+8, "open FD count leaked: baseline=%d final=%d", baselineFDs, finalFDs)
}
