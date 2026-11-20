package e2e_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
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

// TestTier4Workloads validates Tier 4 realistic workloads, soak checks,
// concurrent torture tests, DPI forensics, and weekly upstream-sync CI
// simulation (T4-01..T4-16).
func TestTier4Workloads(t *testing.T) {
	VerifyOpaqueImports(t)

	t.Run("T4-01_ConcurrentInnerHTTPSTLS13_16Clients_RandomShaping", testT401ConcurrentInnerHTTPS16Clients)
	t.Run("T4-02_HighThroughputBulk_8MiBUp_16MiBDown_Zero2BOverhead", testT402BulkTransferZero2BLowOverhead)
	t.Run("T4-03_ConvergedEnterpriseBranch_DNS_HTTPS_SSH_OverH2Mux", testT403ConvergedEnterpriseBranchH2Mux)
	t.Run("T4-04_FiberCutBlackholeDPD_ResetNetwork_Recovery", testT404FiberCutBlackholeDPDRecovery)
	t.Run("T4-05_ProvincialPortScanAndReplayBombardment_UnderLiveLoad", testT405BombardmentUnderLiveLoad)
	t.Run("T4-06_UpstreamSyncWorkflowSimulation_EndToEnd", testT406UpstreamSyncWorkflowSimulation)
	t.Run("T4-07_MultiTenantEnterpriseHub_BranchIsolationAndRevoke", testT407MultiTenantEnterpriseHubIsolation)
	t.Run("T4-08_DualLineActiveStandbyHA_URLTestSwitchover", testT408DualLineActiveStandbyHASwitchover)
	t.Run("T4-09_VoIPRTP_MultiPeerFullCone_Burst32KiB_NativeUDP", testT409VoIPRTPMultiPeerFullConeNativeUDP)
	t.Run("T4-10_DualStack_IPv4_IPv6_HostsDNS_EnterpriseTransit", testT410DualStackHostsDNSEnterpriseTransit)
	t.Run("T4-11_HTTP2BidirectionalStreamingAndTrailers_ChaChaH2Mux", testT411HTTP2BidirectionalStreamingChaChaH2Mux)
	t.Run("T4-12_LongLivedIdleHeartbeatSurvival_Across70sBloomRotation", testT412IdleHeartbeatAcross70sBloomRotation)
	t.Run("T4-13_ProductionDaemonLifecycle_StartSIGHUPCharlieSIGTERM", testT413ProductionDaemonLifecycleSIGHUPSIGTERM)
	t.Run("T4-14_FirewallDPISignatureEntropyAndLengthDistributionAudit", testT414FirewallDPIAndStatisticalAudit)
	t.Run("T4-15_CongestedCrossCarrierTorture_YamuxUoTHeartbeat", testT415CongestedCrossCarrierTorture)
	t.Run("T4-16_ZeroDowntimeKeyRotationAndCipherMigration", testT416ZeroDowntimeKeyRotationAndMigration)
}

// ---------------------------------------------------------------------------
// Tier 4 Workflow Simulation Helpers (No gopkg.in/yaml.v3 per opaque rules)
// ---------------------------------------------------------------------------

type workflowStep struct {
	Name string
	ID   string
	If   string
	Env  map[string]string
	Run  string
}

// parseWorkflowRunSteps extracts shell steps (`run: |`) from a GitHub Actions
// workflow YAML without external YAML dependencies.
func parseWorkflowRunSteps(yamlContent string) []workflowStep {
	lines := strings.Split(strings.ReplaceAll(yamlContent, "\r\n", "\n"), "\n")
	var steps []workflowStep
	inSteps := false

	for i := 0; i < len(lines); i++ {
		trimmed := strings.TrimSpace(lines[i])
		if trimmed == "steps:" {
			inSteps = true
			continue
		}
		if !inSteps {
			continue
		}
		if strings.HasPrefix(lines[i], "      - name: ") {
			st := workflowStep{
				Name: strings.TrimSpace(strings.TrimPrefix(lines[i], "      - name: ")),
				Env:  make(map[string]string),
			}
			for j := i + 1; j < len(lines); j++ {
				if strings.HasPrefix(lines[j], "      - ") || (len(lines[j]) > 0 && lines[j][0] != ' ') {
					i = j - 1
					break
				}
				lt := strings.TrimSpace(lines[j])
				switch {
				case strings.HasPrefix(lt, "id:"):
					st.ID = strings.TrimSpace(strings.TrimPrefix(lt, "id:"))
				case strings.HasPrefix(lt, "if:"):
					st.If = strings.TrimSpace(strings.TrimPrefix(lt, "if:"))
				case lt == "env:":
					for k := j + 1; k < len(lines); k++ {
						if !strings.HasPrefix(lines[k], "          ") {
							j = k - 1
							break
						}
						kv := strings.TrimSpace(lines[k])
						if idx := strings.IndexByte(kv, ':'); idx > 0 {
							key := strings.TrimSpace(kv[:idx])
							val := strings.Trim(strings.TrimSpace(kv[idx+1:]), `"'`)
							st.Env[key] = val
						}
						j = k
					}
				case lt == "run: |":
					var block []string
					for k := j + 1; k < len(lines); k++ {
						if lines[k] == "" {
							block = append(block, "")
							j = k
							continue
						}
						if !strings.HasPrefix(lines[k], "          ") {
							j = k - 1
							break
						}
						block = append(block, strings.TrimPrefix(lines[k], "          "))
						j = k
					}
					st.Run = strings.Join(block, "\n")
				}
				i = j
			}
			steps = append(steps, st)
		}
	}
	return steps
}

type workflowRunResult struct {
	Outputs    map[string]map[string]string
	Env        map[string]string
	Log        string
	Err        error
	FailedStep string
}

func runParsedWorkflow(t testing.TB, steps []workflowStep, workDir string, baseEnv []string) workflowRunResult {
	t.Helper()
	res := workflowRunResult{
		Outputs: make(map[string]map[string]string),
		Env:     make(map[string]string),
	}
	runnerTemp := t.TempDir()
	envFile := filepath.Join(runnerTemp, "github_env")
	require.NoError(t, os.WriteFile(envFile, nil, 0o600))

	var fullLog strings.Builder
	for i, st := range steps {
		if st.Run == "" {
			continue
		}
		if !evaluateWorkflowIf(st.If, res.Outputs) {
			continue
		}
		outFile := filepath.Join(runnerTemp, fmt.Sprintf("github_output_%d", i))
		require.NoError(t, os.WriteFile(outFile, nil, 0o600))

		cmd := exec.Command("bash", "-c", st.Run)
		cmd.Dir = workDir
		env := append([]string{}, baseEnv...)
		env = append(env, "GITHUB_ENV="+envFile, "GITHUB_OUTPUT="+outFile, "GITHUB_REF_NAME=main")
		for k, v := range res.Env {
			env = append(env, k+"="+v)
		}
		for k, v := range st.Env {
			val := v
			if strings.Contains(val, "secrets.") {
				val = "mock-token"
			}
			env = append(env, k+"="+val)
		}
		cmd.Env = env
		out, err := cmd.CombinedOutput()
		fullLog.WriteString("=== STEP: " + st.Name + " ===\n")
		fullLog.Write(out)
		fullLog.WriteByte('\n')

		if st.ID != "" {
			res.Outputs[st.ID] = readKVFile(t, outFile)
		}
		_ = os.Remove(outFile)
		for k, v := range readKVFile(t, envFile) {
			res.Env[k] = v
		}
		if err != nil {
			res.Err = err
			res.FailedStep = st.Name
			res.Log = fullLog.String()
			return res
		}
	}
	res.Log = fullLog.String()
	return res
}

func evaluateWorkflowIf(expr string, outputs map[string]map[string]string) bool {
	expr = strings.TrimSpace(expr)
	if expr == "" {
		return true
	}
	// Evaluate canonical workflow expressions like `steps.discover.outputs.should_sync == 'true'`
	// or conjunctions joined by `&&`.
	parts := strings.Split(expr, "&&")
	for _, p := range parts {
		eq := strings.SplitN(strings.TrimSpace(p), "==", 2)
		if len(eq) != 2 {
			continue
		}
		lhs := strings.TrimSpace(eq[0])
		rhs := strings.Trim(strings.TrimSpace(eq[1]), `"'`)
		toks := strings.Split(lhs, ".")
		if len(toks) == 4 && toks[0] == "steps" && toks[2] == "outputs" {
			got := outputs[toks[1]][toks[3]]
			if got != rhs {
				return false
			}
		}
	}
	return true
}

func readKVFile(t testing.TB, path string) map[string]string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		return map[string]string{}
	}
	m := make(map[string]string)
	for _, line := range strings.Split(strings.TrimSpace(string(b)), "\n") {
		if line == "" {
			continue
		}
		if idx := strings.IndexByte(line, '='); idx > 0 {
			m[line[:idx]] = line[idx+1:]
		}
	}
	return m
}

func runGit(t testing.TB, dir string, env []string, args ...string) string {
	t.Helper()
	cmd := exec.Command("git", append([]string{"-C", dir}, args...)...)
	if env != nil {
		cmd.Env = env
	}
	out, err := cmd.CombinedOutput()
	require.NoError(t, err, "git %v failed: %s", args, string(out))
	return strings.TrimSpace(string(out))
}

func writeExecutable(t testing.TB, path, body string) {
	t.Helper()
	require.NoError(t, os.WriteFile(path, []byte(body), 0o755))
}

// ---------------------------------------------------------------------------
// Tier 4 Case Implementations (T4-01 .. T4-16)
// ---------------------------------------------------------------------------

func testT401ConcurrentInnerHTTPS16Clients(t *testing.T) {
	iPSK := GenerateRandomKeyBase64(t)
	alicePass := "alice-https-16clients"
	users := []UserSpec{
		{Name: "alice", Password: alicePass},
		{Name: "bob", Password: "bob-https-16clients"},
	}

	httpsTarget := StartTLS13HTTPSTarget(t)
	topo := StartTopology(t, TopologyConfig{
		ServerPassword: iPSK,
		ServerUsers:    users,
		ClientPassword: iPSK + ":" + alicePass,
		ClientCipher:   "aes-256-gcm",
	})

	const clients = 16
	var wg sync.WaitGroup
	for i := 0; i < clients; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			cli := &http.Client{
				Timeout: 12 * time.Second,
				Transport: &http.Transport{
					DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
						return topo.DialSOCKS5(ctx, addr)
					},
					TLSClientConfig:   httpsTarget.ClientTLSConfig("127.0.0.1"),
					DisableKeepAlives: true,
				},
			}
			resp, err := cli.Get("https://" + httpsTarget.Addr() + "/api/v1/health")
			require.NoError(t, err)
			body, rErr := io.ReadAll(resp.Body)
			_ = resp.Body.Close()
			require.NoError(t, rErr)
			require.Equal(t, http.StatusOK, resp.StatusCode)
			require.Contains(t, string(body), `"tls":"1.3"`)
		}()
	}
	wg.Wait()

	sessions := topo.Tap.WaitForSessions(t, clients, 8*time.Second)
	require.GreaterOrEqual(t, len(sessions), clients)

	distinctC2SFirstSizes := make(map[int]struct{})
	for _, s := range sessions[:clients] {
		require.True(t, s.WaitClosed(5*time.Second))
		require.False(t, s.HasOuterTLSRecordHeader(), "outer wire leaked inner TLS ClientHello record header")
		require.False(t, s.HasSegmentOfExactSize(DirC2S, 2))
		require.False(t, s.HasSegmentOfExactSize(DirS2C, 2))

		c2sFirst, ok := s.FirstSegment(DirC2S)
		require.True(t, ok)
		distinctC2SFirstSizes[c2sFirst.Size] = struct{}{}

		info, iErr := SpecInspectClientBurst(s.Bytes(DirC2S), iPSK, "", users, "")
		require.NoError(t, iErr)
		require.True(t, info.HasEIH)
		require.Equal(t, "alice", info.UserName)

		s2cFirst, okS2C := s.FirstSegment(DirS2C)
		require.True(t, okS2C)
		require.GreaterOrEqual(t, s2cFirst.Size, SpecServerRespPrefixSize+36+16)
	}
	require.GreaterOrEqual(t, len(distinctC2SFirstSizes), 3, "random NoiseLen + PadLen should diversify initial packet lengths")
}

func testT402BulkTransferZero2BLowOverhead(t *testing.T) {
	privKey, pubKey := GenerateAetherKeyPairCLI(t)
	psk := GenerateRandomKeyBase64(t)

	const upBytes = 8 * 1024 * 1024
	const downBytes = 16 * 1024 * 1024
	upPayload := DeterministicBytes(4021, upBytes)
	downPayload := DeterministicBytes(4022, downBytes)
	hcTarget := StartTCPHalfCloseTarget(t, downPayload)

	topo := StartTopology(t, TopologyConfig{
		ServerPassword:        psk,
		ServerPrivateKey:      privKey,
		ClientPassword:        psk,
		ClientCipher:          "aes-256-gcm",
		ClientServerPublicKey: pubKey,
	})

	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	out, ok := topo.Client.Box.Outbound().Outbound("aether-out")
	require.True(t, ok)

	conn, err := out.DialContext(ctx, N.NetworkTCP, M.ParseSocksaddr(hcTarget.Addr()))
	require.NoError(t, err)
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(45 * time.Second))

	gotDown := echoExtendedConnHalfClose(t, conn, upPayload)
	require.Equal(t, len(downPayload), len(gotDown))
	require.Equal(t, sha256.Sum256(downPayload), sha256.Sum256(gotDown))
	require.Eventually(t, func() bool { return hcTarget.EOFObserved.Load() }, 5*time.Second, 20*time.Millisecond)
	require.Equal(t, sha256.Sum256(upPayload), hcTarget.ReceivedHash)
	require.NoError(t, conn.Close())

	sessions := topo.Tap.WaitForSessions(t, 1, 5*time.Second)
	require.True(t, sessions[0].WaitClosed(5*time.Second))
	require.False(t, sessions[0].HasSegmentOfExactSize(DirC2S, 2))
	require.False(t, sessions[0].HasSegmentOfExactSize(DirS2C, 2))
	require.False(t, sessions[0].HasSegmentOfExactSize(DirC2S, 18))
	require.False(t, sessions[0].HasSegmentOfExactSize(DirS2C, 18))

	wireC2S := float64(sessions[0].TotalBytes(DirC2S))
	wireS2C := float64(sessions[0].TotalBytes(DirS2C))
	// Check asymptotic framing overhead stays near 36B / 16384B = 0.002197 (< 0.003 total with shaping).
	c2sOverhead := (wireC2S - upBytes) / wireC2S
	s2cOverhead := (wireS2C - downBytes) / wireS2C
	require.Less(t, c2sOverhead, 0.0030, "C2S wire overhead unexpectedly high: %v", c2sOverhead)
	require.Less(t, s2cOverhead, 0.0028, "S2C wire overhead unexpectedly high: %v", s2cOverhead)
}

func testT403ConvergedEnterpriseBranchH2Mux(t *testing.T) {
	psk := GenerateRandomKeyBase64(t)
	dnsSrv := StartLoopbackDNSServer(t, map[string]string{
		"api.branch.internal.": "10.10.20.30",
	})
	httpsTarget := StartTLS13HTTPSTarget(t)
	sshBanner := []byte("SSH-2.0-OpenSSH_9.6p1\r\n")
	sshTarget := StartServerSpeaksFirstTarget(t, sshBanner)

	topo := StartTopology(t, TopologyConfig{
		ServerPassword:  psk,
		ServerMultiplex: &MultiplexServerSpec{Enabled: true, Padding: true},
		ClientPassword:  psk,
		ClientCipher:    "aes-256-gcm",
		ClientMultiplex: &MultiplexClientSpec{
			Enabled:        true,
			Protocol:       "h2mux",
			MaxConnections: 4,
			Padding:        true,
		},
	})

	var wg sync.WaitGroup
	// 20 concurrent DNS UDP queries via SOCKS5 UDP.
	wg.Add(1)
	go func() {
		defer wg.Done()
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		uc, err := topo.OpenSOCKS5UDP(ctx)
		require.NoError(t, err)
		defer uc.Close()
		for i := 0; i < 20; i++ {
			qtype := dns.TypeA
			if i%2 == 1 {
				qtype = dns.TypeAAAA
			}
			resp := mustQueryDNSOverSOCKS5UDP(t, uc, dnsSrv.UDPAddr(), "api.branch.internal", qtype)
			require.Equal(t, dns.RcodeSuccess, resp.Rcode)
		}
	}()

	// 10 HTTPS calls through h2mux.
	httpCli, err := topo.NewHTTPClient(httpsTarget.ClientTLSConfig("127.0.0.1"), 12*time.Second)
	require.NoError(t, err)
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			resp, gErr := httpCli.Get("https://" + httpsTarget.Addr() + "/api/v1/health")
			require.NoError(t, gErr)
			body, rErr := io.ReadAll(resp.Body)
			_ = resp.Body.Close()
			require.NoError(t, rErr)
			require.Equal(t, http.StatusOK, resp.StatusCode)
			require.Contains(t, string(body), `"status":"ok"`)
		}()
	}

	// 4 SSH banner + bidirectional CloseWrite sessions.
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			defer cancel()
			conn, dErr := topo.DialSOCKS5(ctx, sshTarget.Addr())
			require.NoError(t, dErr)
			defer conn.Close()
			_ = conn.SetDeadline(time.Now().Add(12 * time.Second))
			gotBanner := make([]byte, len(sshBanner))
			_, bErr := io.ReadFull(conn, gotBanner)
			require.NoError(t, bErr)
			require.Equal(t, sshBanner, gotBanner)
			echoStreamExact(t, conn, []byte("SSH-2.0-BranchTerminal\r\n"))
		}()
	}
	wg.Wait()
}

func testT404FiberCutBlackholeDPDRecovery(t *testing.T) {
	psk := GenerateRandomKeyBase64(t)
	tcpTarget := StartTCPEchoTarget(t)
	udpTarget := StartUDPEchoTarget(t)

	topo := StartTopology(t, TopologyConfig{
		ServerPassword:          psk,
		ServerHeartbeatInterval: "350ms",
		ServerMultiplex:         &MultiplexServerSpec{Enabled: true, Padding: true},
		ClientPassword:          psk,
		ClientHeartbeatInterval: "350ms",
		ClientMultiplex: &MultiplexClientSpec{
			Enabled:        true,
			Protocol:       "smux",
			MaxConnections: 1,
			Padding:        true,
		},
	})

	// Phase 1: Establish active smux transport session.
	mustSOCKS5EchoTCP(t, topo, "", "", tcpTarget.Addr(), DeterministicBytes(4041, 4096))
	sessions := topo.Tap.WaitForSessions(t, 1, 5*time.Second)
	activeSess := sessions[0]

	// Phase 2: Fiber cut (symmetric blackhole) -> active mux TCP session closes via DPD within < 2s.
	blackholeStart := time.Now()
	topo.Tap.SetBlackhole(true, true)
	require.True(t, activeSess.WaitClosed(2*time.Second), "DPD did not close smux session on blackhole within 2s")
	t.Logf("T4-04 DPD closure elapsed: %v", time.Since(blackholeStart))

	// Phase 3: Restore link & trigger interface/network reset; new TCP & UDP flows recover immediately.
	topo.Tap.SetBlackhole(false, false)
	if out, ok := topo.Client.Box.Outbound().Outbound("aether-out"); ok {
		if listener, ok := out.(adapter.InterfaceUpdateListener); ok {
			listener.InterfaceUpdated(context.Background())
		}
	}
	_ = topo.Client.Box.Network().UpdateInterfaces()
	topo.ResetClientNetwork(context.Background())

	mustSOCKS5EchoTCP(t, topo, "", "", tcpTarget.Addr(), DeterministicBytes(4042, 8192))
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	uc, err := topo.OpenSOCKS5UDP(ctx)
	require.NoError(t, err)
	mustSOCKS5EchoUDP(t, uc, udpTarget.Addr(), DeterministicBytes(4043, 512))
	_ = uc.Close()
}

func testT405BombardmentUnderLiveLoad(t *testing.T) {
	iPSK := GenerateRandomKeyBase64(t)
	alicePass := "alice-live-idc-scan"
	users := []UserSpec{
		{Name: "alice", Password: alicePass},
		{Name: "bob", Password: "bob-live-idc-scan"},
	}

	httpsTarget := StartTLS13HTTPSTarget(t)
	dnsSrv := StartLoopbackDNSServer(t, map[string]string{
		"edge.example.": "10.88.1.2",
	})

	topo := StartTopology(t, TopologyConfig{
		ServerPassword:         iPSK,
		ServerUsers:            users,
		ServerHandshakeTimeout: "500ms",
		ClientPassword:         iPSK + ":" + alicePass,
	})

	// First perform 1 valid request to capture a real encrypted client burst for replay testing.
	httpCli, err := topo.NewHTTPClient(httpsTarget.ClientTLSConfig("127.0.0.1"), 10*time.Second)
	require.NoError(t, err)
	resp, err := httpCli.Get("https://" + httpsTarget.Addr() + "/api/v1/health")
	require.NoError(t, err)
	_ = resp.Body.Close()

	firstSessions := topo.Tap.WaitForSessions(t, 1, 5*time.Second)
	require.True(t, firstSessions[0].WaitBytes(DirC2S, int64(SpecClientPrefixEIHSize+48), 5*time.Second))
	c2sRaw := firstSessions[0].Bytes(DirC2S)
	info, err := SpecInspectClientBurst(c2sRaw, iPSK, "", users, "")
	require.NoError(t, err)
	replayBurst := append([]byte(nil), c2sRaw[:info.TotalInitialConsumed]...)

	scannerPayloads := [][]byte{
		{}, // 0B immediate FIN
		DeterministicBytes(4051, 34),
		DeterministicBytes(4052, 95),
		DeterministicBytes(4053, 111),
		[]byte("GET / HTTP/1.1\r\nHost: scan\r\n\r\n" + strings.Repeat("Z", 482)),
		replayBurst,
	}

	var (
		scanWG       sync.WaitGroup
		scanFailures atomic.Int32
		liveWG       sync.WaitGroup
		liveErrors   atomic.Int32
	)

	// 220 concurrent active scanner & replay probes against Server.
	// Stagger initial SYN waves slightly (32 per 5ms -> 30ms total) so macOS somaxconn=128
	// does not reset SYNs in kernel before Accept(), while all 220 overlap across the 3s..10s drain window.
	for i := 0; i < 220; i++ {
		i := i
		scanWG.Add(1)
		go func() {
			defer scanWG.Done()
			if wave := i / 32; wave > 0 {
				time.Sleep(time.Duration(wave) * 5 * time.Millisecond)
			}
			payload := scannerPayloads[i%len(scannerPayloads)]
			pr, pErr := SendRawProbe(topo.ServerAddr(), payload, true, 13*time.Second)
			if pErr != nil || pr.ClosedByRST || len(pr.BytesReceived) > 0 || !pr.ClosedCleanEOF {
				scanFailures.Add(1)
			}
		}()
	}

	// 8 concurrent legitimate HTTPS + UDP DNS client workers throughout the bombardment.
	for w := 0; w < 8; w++ {
		liveWG.Add(1)
		go func() {
			defer liveWG.Done()
			ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
			defer cancel()
			uc, uErr := topo.OpenSOCKS5UDP(ctx)
			if uErr != nil {
				liveErrors.Add(1)
				return
			}
			defer uc.Close()
			for r := 0; r < 5; r++ {
				hr, hErr := httpCli.Get("https://" + httpsTarget.Addr() + "/api/v1/health")
				if hErr != nil {
					liveErrors.Add(1)
					continue
				}
				_, _ = io.ReadAll(hr.Body)
				_ = hr.Body.Close()
				if hr.StatusCode != http.StatusOK {
					liveErrors.Add(1)
				}
				dnsResp := mustQueryDNSOverSOCKS5UDP(t, uc, dnsSrv.UDPAddr(), "edge.example", dns.TypeA)
				if dnsResp.Rcode != dns.RcodeSuccess {
					liveErrors.Add(1)
				}
			}
		}()
	}

	liveWG.Wait()
	scanWG.Wait()
	require.Zero(t, liveErrors.Load(), "legitimate traffic failed during scanner bombardment")
	require.Zero(t, scanFailures.Load(), "some probes received bytes, RST, or failed clean EOF")
}

func testT406UpstreamSyncWorkflowSimulation(t *testing.T) {
	root, err := RepoRoot()
	require.NoError(t, err)
	wfBytes, err := os.ReadFile(filepath.Join(root, ".github", "workflows", "upstream-sync-release.yml"))
	require.NoError(t, err)
	steps := parseWorkflowRunSteps(string(wfBytes))
	require.GreaterOrEqual(t, len(steps), 6, "unexpected number of parsed steps in upstream-sync-release.yml")

	tmpRoot := t.TempDir()
	mockBin := filepath.Join(tmpRoot, "bin")
	require.NoError(t, os.MkdirAll(mockBin, 0o755))

	bareUpstream := filepath.Join(tmpRoot, "upstream.git")
	bareOrigin := filepath.Join(tmpRoot, "origin.git")
	seedUpstream := filepath.Join(tmpRoot, "seed-upstream")
	seedFork := filepath.Join(tmpRoot, "seed-fork")
	gitConfig := filepath.Join(tmpRoot, "gitconfig")
	mockStateDir := filepath.Join(tmpRoot, "state")
	require.NoError(t, os.MkdirAll(mockStateDir, 0o755))

	baseGitEnv := append(os.Environ(),
		"GIT_CONFIG_GLOBAL="+gitConfig,
		"GIT_AUTHOR_NAME=Test Author",
		"GIT_AUTHOR_EMAIL=test@example.com",
		"GIT_COMMITTER_NAME=Test Author",
		"GIT_COMMITTER_EMAIL=test@example.com",
	)
	runGit(t, tmpRoot, baseGitEnv, "init", "--bare", "-b", "main", bareUpstream)
	runGit(t, tmpRoot, baseGitEnv, "init", "--bare", "-b", "main", bareOrigin)
	runGit(t, tmpRoot, baseGitEnv, "clone", "file://"+bareUpstream, seedUpstream)

	// Populate base v1.14.4 upstream repo.
	require.NoError(t, os.MkdirAll(filepath.Join(seedUpstream, "constant"), 0o755))
	require.NoError(t, os.MkdirAll(filepath.Join(seedUpstream, "option"), 0o755))
	require.NoError(t, os.MkdirAll(filepath.Join(seedUpstream, "cmd", "sing-box"), 0o755))
	require.NoError(t, os.MkdirAll(filepath.Join(seedUpstream, "docs"), 0o755))
	require.NoError(t, os.MkdirAll(filepath.Join(seedUpstream, "release"), 0o755))
	require.NoError(t, os.MkdirAll(filepath.Join(seedUpstream, ".github", "workflows"), 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(seedUpstream, "constant", "version.go"), []byte("package constant\n\nvar Version = \"1.14.4\"\n"), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(seedUpstream, "option", "aether.go"), []byte("package option\n\ntype UpstreamBase struct{}\n"), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(seedUpstream, "cmd", "sing-box", "cmd_schema.go"), []byte("package main\n"), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(seedUpstream, "docs", "schema.json"), []byte("{}\n"), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(seedUpstream, "release", "DEFAULT_BUILD_TAGS_OTHERS"), []byte(DefaultOfficialPureGoBuildTags+"\n"), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(seedUpstream, ".github", "workflows", "release.yml"), []byte("name: upstream\n"), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(seedUpstream, "LICENSE"), []byte("GPLv3\n"), 0o644))
	runGit(t, seedUpstream, baseGitEnv, "add", "-A")
	runGit(t, seedUpstream, baseGitEnv, "commit", "-m", "upstream v1.14.4")
	runGit(t, seedUpstream, baseGitEnv, "tag", "v1.14.4")
	runGit(t, seedUpstream, baseGitEnv, "push", "origin", "HEAD:main", "--tags")

	// Create fork seeded from upstream v1.14.4 with custom workflows + version + option/aether.go.
	runGit(t, tmpRoot, baseGitEnv, "clone", "file://"+bareUpstream, seedFork)
	require.NoError(t, os.MkdirAll(filepath.Join(seedFork, "release"), 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(seedFork, "release", "LDFLAGS"), []byte("-X runtime.godebugDefault=multipathtcp=0,tlssha1=1 -checklinkname=0\n"), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(seedFork, "release", "DEFAULT_BUILD_TAGS_OTHERS"), []byte(DefaultOfficialPureGoBuildTags+"\n"), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(seedFork, "constant", "version.go"), []byte("package constant\n\nvar Version = \"1.14.4-Custom-Aether\"\n"), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(seedFork, "option", "aether.go"), []byte("package option\n\ntype AetherInboundOptions struct{}\n"), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(seedFork, ".github", "workflows", "upstream-sync-release.yml"), wfBytes, 0o644))
	runGit(t, seedFork, baseGitEnv, "remote", "set-url", "origin", "file://"+bareOrigin)
	runGit(t, seedFork, baseGitEnv, "add", "-A")
	runGit(t, seedFork, baseGitEnv, "commit", "-m", "fork base 1.14.4-Custom-Aether")
	runGit(t, seedFork, baseGitEnv, "tag", "-a", "v1.14.4-Custom-Aether", "-m", "release v1.14.4")
	runGit(t, seedFork, baseGitEnv, "push", "origin", "HEAD:main", "refs/tags/v1.14.4-Custom-Aether")

	// Redirect https://github.com/SagerNet/sing-box.git -> offline bareUpstream in isolated GIT_CONFIG_GLOBAL.
	require.NoError(t, os.WriteFile(gitConfig, []byte(fmt.Sprintf("[url \"file://%s\"]\n\tinsteadOf = https://github.com/SagerNet/sing-box.git\n", bareUpstream)), 0o644))

	// Create mock curl, gh, and go shims.
	writeExecutable(t, filepath.Join(mockBin, "curl"), `#!/usr/bin/env bash
set -euo pipefail
cat "${MOCK_RELEASE_JSON_FILE}"
`)
	writeExecutable(t, filepath.Join(mockBin, "gh"), `#!/usr/bin/env bash
set -euo pipefail
if [ "${1:-}" = "release" ] && [ "${2:-}" = "view" ]; then
  tag="${3:-}"
  [ -f "${MOCK_STATE_DIR}/released_${tag}" ] && exit 0 || exit 1
fi
if [ "${1:-}" = "release" ] && [ "${2:-}" = "create" ]; then
  tag="${3:-}"
  shift 3
  printf '%s %s\n' "${tag}" "$*" >> "${MOCK_STATE_DIR}/gh_releases.log"
  touch "${MOCK_STATE_DIR}/released_${tag}"
  for arg in "$@"; do
    case "${arg}" in
      dist/*.tar.gz) [ -s "${arg}" ] || { echo "missing tarball ${arg}"; exit 1; } ;;
      dist/SHA256SUMS) grep -q '\.tar\.gz' "${arg}" || { echo "invalid SHA256SUMS"; exit 1; } ;;
    esac
  done
  exit 0
fi
exit 1
`)
	writeExecutable(t, filepath.Join(mockBin, "go"), `#!/usr/bin/env bash
set -euo pipefail
printf '%s\n' "$*" >> "${MOCK_STATE_DIR}/go_invocations.log"
sub="${1:-}"
case "${sub}" in
  run)
    out=""
    prev=""
    for a in "$@"; do
      if [ "${prev}" = "-o" ]; then out="${a}"; fi
      prev="${a}"
    done
    if [ -n "${out}" ]; then
      printf '{"mock_schema":true}\n' > "${out}"
    else
      printf '{"mock_schema":true}\n'
    fi
    ;;
  test)
    if [ "${MOCK_GO_FAIL_RACE:-0}" = "1" ]; then
      echo "simulated -race failure" >&2
      exit 1
    fi
    ;;
  build)
    out=""
    prev=""
    for a in "$@"; do
      if [ "${prev}" = "-o" ]; then out="${a}"; fi
      prev="${a}"
    done
    if [ -n "${out}" ]; then
      mkdir -p "$(dirname "${out}")"
      printf '#!/bin/sh\necho mock-sing-box\n' > "${out}"
      chmod +x "${out}"
    fi
    ;;
esac
`)
	require.NoError(t, os.WriteFile(filepath.Join(mockStateDir, "released_v1.14.4-Custom-Aether"), []byte("1"), 0o644))

	newWorktree := func(name string) string {
		wd := filepath.Join(tmpRoot, name)
		runGit(t, tmpRoot, baseGitEnv, "clone", "file://"+bareOrigin, wd)
		return wd
	}
	stepEnv := func(jsonFile string, extra ...string) []string {
		e := append([]string{}, baseGitEnv...)
		e = append(e,
			"PATH="+mockBin+":"+os.Getenv("PATH"),
			"MOCK_RELEASE_JSON_FILE="+jsonFile,
			"MOCK_STATE_DIR="+mockStateDir,
		)
		return append(e, extra...)
	}

	// Scenario 1: Prerelease tag skipped cleanly.
	jsonPre := filepath.Join(tmpRoot, "rel_pre.json")
	require.NoError(t, os.WriteFile(jsonPre, []byte(`{"tag_name":"v1.15.0-alpha.1","draft":false,"prerelease":true}`), 0o644))
	wt1 := newWorktree("wt1-prerelease")
	r1 := runParsedWorkflow(t, steps, wt1, stepEnv(jsonPre))
	require.NoError(t, r1.Err, r1.Log)
	require.Equal(t, "false", r1.Outputs["discover"]["should_sync"])

	// Scenario 2: Already synced v1.14.4 skipped idempotently.
	json144 := filepath.Join(tmpRoot, "rel_144.json")
	require.NoError(t, os.WriteFile(json144, []byte(`{"tag_name":"v1.14.4","draft":false,"prerelease":false}`), 0o644))
	wt2 := newWorktree("wt2-idempotent")
	r2 := runParsedWorkflow(t, steps, wt2, stepEnv(json144))
	require.NoError(t, r2.Err, r2.Log)
	require.Equal(t, "false", r2.Outputs["idempotency"]["should_proceed"])

	// Scenario 3: New clean stable upstream v1.14.5 touching source + upstream workflow.
	require.NoError(t, os.WriteFile(filepath.Join(seedUpstream, "constant", "version.go"), []byte("package constant\n\nvar Version = \"1.14.5\"\n"), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(seedUpstream, "upstream_feature.go"), []byte("package box\n"), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(seedUpstream, ".github", "workflows", "upstream_extra.yml"), []byte("name: extra\n"), 0o644))
	runGit(t, seedUpstream, baseGitEnv, "add", "-A")
	runGit(t, seedUpstream, baseGitEnv, "commit", "-m", "upstream v1.14.5")
	runGit(t, seedUpstream, baseGitEnv, "tag", "v1.14.5")
	runGit(t, seedUpstream, baseGitEnv, "push", "origin", "HEAD:main", "--tags")

	json145 := filepath.Join(tmpRoot, "rel_145.json")
	require.NoError(t, os.WriteFile(json145, []byte(`{"tag_name":"v1.14.5","draft":false,"prerelease":false}`), 0o644))

	// Sub-check 3a: -race failure aborts BEFORE push/release!
	wt3Fail := newWorktree("wt3-racefail")
	r3Fail := runParsedWorkflow(t, steps, wt3Fail, stepEnv(json145, "MOCK_GO_FAIL_RACE=1"))
	require.Error(t, r3Fail.Err)
	require.Contains(t, r3Fail.FailedStep, "-race")
	_, statReleaseErr := os.Stat(filepath.Join(mockStateDir, "released_v1.14.5-Custom-Aether"))
	require.ErrorIs(t, statReleaseErr, os.ErrNotExist)

	// Sub-check 3b: Full v1.14.5 success: workflow dir untouched, version updated, -race passed, artifacts published!
	wt3 := newWorktree("wt3-success")
	preMergeWF := runGit(t, wt3, baseGitEnv, "ls-tree", "-r", "HEAD", ".github/workflows")
	r3 := runParsedWorkflow(t, steps, wt3, stepEnv(json145))
	require.NoError(t, r3.Err, r3.Log)
	postMergeWF := runGit(t, wt3, baseGitEnv, "ls-tree", "-r", "HEAD", ".github/workflows")
	require.Equal(t, preMergeWF, postMergeWF, "fork .github/workflows/ must match pre-merge tree identically")
	_, extraErr := os.Stat(filepath.Join(wt3, ".github", "workflows", "upstream_extra.yml"))
	require.ErrorIs(t, extraErr, os.ErrNotExist)

	verBytes, err := os.ReadFile(filepath.Join(wt3, "constant", "version.go"))
	require.NoError(t, err)
	require.Contains(t, string(verBytes), `var Version = "1.14.5-Custom-Aether"`)

	goLog, err := os.ReadFile(filepath.Join(mockStateDir, "go_invocations.log"))
	require.NoError(t, err)
	require.Contains(t, string(goLog), "test -race -count=1 ./cmd/sing-box/... ./option/... ./schema/... ./protocol/aether/...")
	require.Contains(t, string(goLog), "with_tailscale")
	require.Contains(t, string(goLog), "-o dist/sing-box-1.14.5-Custom-Aether-linux-amd64/sing-box ./cmd/sing-box")
	require.Contains(t, string(goLog), "-o dist/sing-box-1.14.5-Custom-Aether-linux-arm64/sing-box ./cmd/sing-box")

	ghLog, err := os.ReadFile(filepath.Join(mockStateDir, "gh_releases.log"))
	require.NoError(t, err)
	require.Contains(t, string(ghLog), "v1.14.5-Custom-Aether")
	require.Contains(t, string(ghLog), "dist/SHA256SUMS")

	// Scenario 4: Upstream v1.14.6 introduces unresolvable conflict in option/aether.go -> aborts cleanly.
	require.NoError(t, os.WriteFile(filepath.Join(seedUpstream, "option", "aether.go"), []byte("package option\n\ntype ConflictByUpstream struct{ X int }\n"), 0o644))
	runGit(t, seedUpstream, baseGitEnv, "add", "option/aether.go")
	runGit(t, seedUpstream, baseGitEnv, "commit", "-m", "upstream v1.14.6 conflicting option/aether.go")
	runGit(t, seedUpstream, baseGitEnv, "tag", "v1.14.6")
	runGit(t, seedUpstream, baseGitEnv, "push", "origin", "HEAD:main", "--tags")

	json146 := filepath.Join(tmpRoot, "rel_146.json")
	require.NoError(t, os.WriteFile(json146, []byte(`{"tag_name":"v1.14.6","draft":false,"prerelease":false}`), 0o644))
	wt4 := newWorktree("wt4-conflict")
	r4 := runParsedWorkflow(t, steps, wt4, stepEnv(json146))
	require.Error(t, r4.Err)
	require.Contains(t, r4.FailedStep, "Merge")
	require.Empty(t, runGit(t, wt4, baseGitEnv, "status", "--porcelain"), "conflict abort must restore clean working tree")
}

func testT407MultiTenantEnterpriseHubIsolation(t *testing.T) {
	privKey, pubKey := GenerateAetherKeyPairCLI(t)
	iPSK := GenerateRandomKeyBase64(t)
	gzPass := "gz-branch-secret-key"
	szPass := "sz-branch-secret-key"
	revokedPass := "revoked-branch-secret"
	users := []UserSpec{
		{Name: "gz-branch", Password: gzPass},
		{Name: "sz-branch", Password: szPass},
		{Name: "revoked-branch", Password: revokedPass},
	}

	gzTCP := StartTCPEchoTarget(t)
	szTCP := StartTCPEchoTarget(t)
	gzUDP := StartUDPEchoTarget(t)
	szUDP := StartUDPEchoTarget(t)

	srvPort := AllocFreeTCPPort(t)
	rawSrv, err := BuildServerJSON(TopologyConfig{
		ServerPassword:   iPSK,
		ServerUsers:      users,
		ServerPrivateKey: privKey,
		ServerExtraRouteRules: []map[string]any{
			{"auth_user": []string{"gz-branch"}, "network": "tcp", "action": C.RuleActionTypeRoute, "outbound": "direct-out", "override_address": "127.0.0.1", "override_port": gzTCP.Port()},
			{"auth_user": []string{"gz-branch"}, "network": "udp", "action": C.RuleActionTypeRoute, "outbound": "direct-out", "override_address": "127.0.0.1", "override_port": gzUDP.Port()},
			{"auth_user": []string{"sz-branch"}, "network": "tcp", "action": C.RuleActionTypeRoute, "outbound": "direct-out", "override_address": "127.0.0.1", "override_port": szTCP.Port()},
			{"auth_user": []string{"sz-branch"}, "network": "udp", "action": C.RuleActionTypeRoute, "outbound": "direct-out", "override_address": "127.0.0.1", "override_port": szUDP.Port()},
			{"auth_user": []string{"revoked-branch"}, "action": C.RuleActionTypeReject},
		},
	}, srvPort, 0, "")
	require.NoError(t, err)
	srvBox, err := StartBoxWithLog(t, rawSrv, "", srvPort)
	require.NoError(t, err)
	defer func() { _ = srvBox.Close() }()

	startTenant := func(pass string) *BoxInstance {
		p := AllocFreeTCPPort(t)
		rawC, cErr := BuildClientJSON(TopologyConfig{
			ClientPassword:        iPSK + ":" + pass,
			ClientServerPublicKey: pubKey,
		}, p, "127.0.0.1", srvPort, 0, "")
		require.NoError(t, cErr)
		cb, bErr := StartBoxWithLog(t, rawC, "", p)
		require.NoError(t, bErr)
		t.Cleanup(func() { _ = cb.Close() })
		return cb
	}
	cliGZ := startTenant(gzPass)
	cliSZ := startTenant(szPass)
	cliRevoked := startTenant(revokedPass)

	sentinel := "127.0.0.1:9"
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		mustDialSOCKS5OnAddr(t, cliGZ.ListenAddr, sentinel, DeterministicBytes(4071, 2048))
		uc, uErr := DialSOCKS5UDP(ctx, cliGZ.ListenAddr)
		require.NoError(t, uErr)
		mustSOCKS5EchoUDP(t, uc, sentinel, DeterministicBytes(4072, 300))
		_ = uc.Close()
	}()
	go func() {
		defer wg.Done()
		mustDialSOCKS5OnAddr(t, cliSZ.ListenAddr, sentinel, DeterministicBytes(4073, 2048))
		uc, uErr := DialSOCKS5UDP(ctx, cliSZ.ListenAddr)
		require.NoError(t, uErr)
		mustSOCKS5EchoUDP(t, uc, sentinel, DeterministicBytes(4074, 300))
		_ = uc.Close()
	}()
	wg.Wait()

	require.Equal(t, int64(1), gzTCP.Connections())
	require.Equal(t, int64(1), gzUDP.Packets())
	require.Equal(t, int64(1), szTCP.Connections())
	require.Equal(t, int64(1), szUDP.Packets())

	// Revoked branch fails cleanly.
	rConn, err := DialSOCKS5TCP(ctx, cliRevoked.ListenAddr, gzTCP.Addr())
	if err == nil {
		_, err = rConn.Write([]byte("revoked"))
		if err == nil {
			_ = rConn.SetReadDeadline(time.Now().Add(2 * time.Second))
			_, err = rConn.Read(make([]byte, 32))
		}
		_ = rConn.Close()
	}
	require.Error(t, err)
	require.Equal(t, int64(1), gzTCP.Connections())
}

func testT408DualLineActiveStandbyHASwitchover(t *testing.T) {
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

	tapTelecom := StartWireTapProxy(t, srvBox.ListenAddr)
	tapUnicom := StartWireTapProxy(t, srvBox.ListenAddr)
	tapUnicom.SetThrottle(35*time.Millisecond, 1024)

	healthSrv := startHTTP204HealthServer(t)
	httpTarget := StartTLS13HTTPSTarget(t)

	proxyPort := AllocFreeTCPPort(t)
	rawCli := buildDualAetherURLTestClientJSON(t, dualAetherClientSpec{
		ProxyPort:         proxyPort,
		PrimaryAddr:       tapTelecom.Addr(),
		BackupAddr:        tapUnicom.Addr(),
		Password:          psk,
		HeartbeatInterval: "350ms",
		HealthURL:         healthSrv.URL + "/",
		Interval:          "400ms",
		Tolerance:         5,
		PrimaryTag:        "line-telecom",
		BackupTag:         "line-unicom",
	})
	cliBox, err := StartBoxWithLog(t, rawCli, "", proxyPort)
	require.NoError(t, err)
	defer func() { _ = cliBox.Close() }()

	httpCli := &http.Client{
		Timeout: 3 * time.Second,
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				return DialSOCKS5TCP(ctx, cliBox.ListenAddr, addr)
			},
			TLSClientConfig:   httpTarget.ClientTLSConfig("127.0.0.1"),
			DisableKeepAlives: true,
		},
	}

	require.Eventually(t, func() bool {
		resp, gErr := httpCli.Get("https://" + httpTarget.Addr() + "/api/v1/health")
		if gErr != nil {
			return false
		}
		_ = resp.Body.Close()
		return resp.StatusCode == http.StatusOK && tapTelecom.SessionCount() >= 1
	}, 6*time.Second, 100*time.Millisecond)

	tapUnicom.SetThrottle(0, 0)
	unicomBefore := totalTapBytes(tapUnicom)
	tapTelecom.SetBlackhole(true, true)

	require.Eventually(t, func() bool {
		resp, gErr := httpCli.Get("https://" + httpTarget.Addr() + "/api/v1/health")
		if gErr != nil {
			return false
		}
		_, _ = io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		return resp.StatusCode == http.StatusOK && totalTapBytes(tapUnicom) > unicomBefore
	}, 24*time.Second, 250*time.Millisecond)
}

func testT409VoIPRTPMultiPeerFullConeNativeUDP(t *testing.T) {
	psk := GenerateRandomKeyBase64(t)
	fullCone := StartFullConeUDPTargets(t)

	topo := StartTopology(t, TopologyConfig{
		ServerPassword: psk,
		ClientPassword: psk,
	})

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	out, ok := topo.Client.Box.Outbound().Outbound("aether-out")
	require.True(t, ok)

	// Single Native CommandUDP PacketConn serving 3 peers + Full-Cone unsolicited reply + large RTCP burst.
	pc, err := out.ListenPacket(ctx, M.ParseSocksaddr(fullCone.PeerA.Addr()))
	require.NoError(t, err)
	defer pc.Close()
	_ = pc.SetDeadline(time.Now().Add(15 * time.Second))

	peers := []*UDPEchoTarget{fullCone.PeerA, fullCone.PeerB, fullCone.PeerC}
	rBuf := buf.NewSize(40960)
	defer rBuf.Release()

	// 30 rapid 160B VoIP RTP frames across peers at ~50 pps (bounded CI duration).
	for i := 0; i < 30; i++ {
		target := peers[i%len(peers)]
		frame := DeterministicBytes(uint64(4090+i), 160)
		require.NoError(t, pc.(N.PacketConn).WritePacket(buf.As(append([]byte(nil), frame...)), M.ParseSocksaddr(target.Addr())))
		rBuf.Reset()
		src, rErr := pc.(N.PacketConn).ReadPacket(rBuf)
		require.NoError(t, rErr)
		require.Equal(t, frame, rBuf.Bytes())
		require.Equal(t, target.Port(), src.Port)
		if i%5 == 0 {
			time.Sleep(15 * time.Millisecond)
		}
	}

	// Verify Full-Cone NAT unsolicited reply from PeerC to PeerA's NAT binding.
	natA := fullCone.PeerA.LastClientUDPAddr()
	require.NotNil(t, natA)
	unsol := DeterministicBytes(4098, 240)
	require.NoError(t, fullCone.PeerC.SendUnsolicitedTo(unsol, natA))
	rBuf.Reset()
	srcUnsol, err := pc.(N.PacketConn).ReadPacket(rBuf)
	require.NoError(t, err)
	require.Equal(t, unsol, rBuf.Bytes())
	require.Equal(t, fullCone.PeerC.Port(), srcUnsol.Port)

	// Large RTCP/control UDP burst (32 KiB on Linux, 8 KiB OS-safe max on macOS loopback UDP).
	rtcpSize := 32 * 1024
	if runtime.GOOS == "darwin" {
		rtcpSize = 8192
	}
	rtcp := DeterministicBytes(4099, rtcpSize)
	require.NoError(t, pc.(N.PacketConn).WritePacket(buf.As(append([]byte(nil), rtcp...)), M.ParseSocksaddr(fullCone.PeerB.Addr())))
	rBuf.Reset()
	_, err = pc.(N.PacketConn).ReadPacket(rBuf)
	require.NoError(t, err)
	require.Equal(t, sha256.Sum256(rtcp), sha256.Sum256(rBuf.Bytes()))
}

func testT410DualStackHostsDNSEnterpriseTransit(t *testing.T) {
	psk := GenerateRandomKeyBase64(t)
	v4TCP := StartTCPEchoTarget(t)
	v6TCP := StartTCPEchoTargetOn(t, "tcp6", "[::1]:0")
	dualTCP := StartTCPEchoTargetOn(t, "tcp", ":0")
	v4UDP := StartUDPEchoTarget(t)
	v6UDP := StartUDPEchoTargetOn(t, "udp6", "[::1]:0")

	topo := StartTopology(t, TopologyConfig{
		ServerPassword: psk,
		ServerPredefinedHosts: map[string]string{
			"corp.internal": "127.0.0.1",
		},
		ClientPassword: psk,
	})

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	// TCP over 127.0.0.1, [::1], localhost, and hosts-DNS corp.internal.
	mustSOCKS5EchoTCP(t, topo, "", "", v4TCP.Addr(), DeterministicBytes(4101, 2048))
	mustSOCKS5EchoTCP(t, topo, "", "", v6TCP.Addr(), DeterministicBytes(4102, 2048))
	mustSOCKS5EchoTCP(t, topo, "", "", fmt.Sprintf("localhost:%d", dualTCP.Port()), DeterministicBytes(4103, 2048))
	mustSOCKS5EchoTCP(t, topo, "", "", fmt.Sprintf("corp.internal:%d", v4TCP.Port()), DeterministicBytes(4104, 2048))

	// UDP over 127.0.0.1, hosts-DNS corp.internal, and [::1].
	// Separate SOCKS5 UDP associations per destination family/FQDN so server direct-out
	// binds udp4 vs udp6 and wraps DNS NATPacketConn cleanly.
	uc, err := topo.OpenSOCKS5UDP(ctx)
	require.NoError(t, err)
	defer uc.Close()
	mustSOCKS5EchoUDP(t, uc, v4UDP.Addr(), DeterministicBytes(4105, 512))

	ucHost, err := topo.OpenSOCKS5UDP(ctx)
	require.NoError(t, err)
	defer ucHost.Close()
	mustSOCKS5EchoUDP(t, ucHost, fmt.Sprintf("corp.internal:%d", v4UDP.Port()), DeterministicBytes(4107, 512))

	uc6, err := topo.OpenSOCKS5UDP(ctx)
	require.NoError(t, err)
	defer uc6.Close()
	mustSOCKS5EchoUDP(t, uc6, v6UDP.Addr(), DeterministicBytes(4106, 512))
}

func startHTTP2StreamingTLS13Target(t testing.TB) (string, *tls.Config) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	require.NoError(t, err)
	cert := tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
	parsedCert, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	pool := x509.NewCertPool()
	pool.AddCert(parsedCert)

	rawLn, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	srvTLS := &tls.Config{
		MinVersion:   tls.VersionTLS13,
		MaxVersion:   tls.VersionTLS13,
		Certificates: []tls.Certificate{cert},
		NextProtos:   []string{"h2"},
	}

	srv := &http.Server{
		TLSConfig: srvTLS,
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.ProtoMajor != 2 {
				http.Error(w, "expected h2", http.StatusHTTPVersionNotSupported)
				return
			}
			w.Header().Set("Trailer", "X-Stream-SHA256")
			w.Header().Set("Content-Type", "application/octet-stream")
			w.WriteHeader(http.StatusOK)

			h := sha256.New()
			flusher, hasFlush := w.(http.Flusher)
			bufChunk := make([]byte, 8192)
			for {
				n, rErr := r.Body.Read(bufChunk)
				if n > 0 {
					_, _ = h.Write(bufChunk[:n])
					_, _ = w.Write(bufChunk[:n])
					if hasFlush {
						flusher.Flush()
					}
				}
				if rErr == io.EOF {
					break
				}
				if rErr != nil {
					return
				}
			}
			w.Header().Set("X-Stream-SHA256", fmt.Sprintf("%x", h.Sum(nil)))
		}),
	}
	go func() { _ = srv.ServeTLS(rawLn, "", "") }()
	t.Cleanup(func() {
		_ = srv.Close()
		_ = rawLn.Close()
	})

	cliTLS := &tls.Config{
		MinVersion: tls.VersionTLS13,
		MaxVersion: tls.VersionTLS13,
		RootCAs:    pool,
		ServerName: "127.0.0.1",
		NextProtos: []string{"h2"},
	}
	return rawLn.Addr().String(), cliTLS
}

func testT411HTTP2BidirectionalStreamingChaChaH2Mux(t *testing.T) {
	privKey, pubKey := GenerateAetherKeyPairCLI(t)
	psk := GenerateRandomKeyBase64(t)
	h2Addr, cliTLS := startHTTP2StreamingTLS13Target(t)

	topo := StartTopology(t, TopologyConfig{
		ServerPassword:        psk,
		ServerPrivateKey:      privKey,
		ServerMultiplex:       &MultiplexServerSpec{Enabled: true, Padding: true},
		ClientPassword:        psk,
		ClientCipher:          "chacha20-poly1305",
		ClientServerPublicKey: pubKey,
		ClientMultiplex: &MultiplexClientSpec{
			Enabled:        true,
			Protocol:       "h2mux",
			MaxConnections: 2,
			Padding:        true,
		},
	})

	cli := &http.Client{
		Timeout: 15 * time.Second,
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				return topo.DialSOCKS5(ctx, addr)
			},
			TLSClientConfig:   cliTLS,
			ForceAttemptHTTP2: true,
		},
	}

	var wg sync.WaitGroup
	for i, sz := range []int{100, 1024, 16384, 65536} {
		i, sz := i, sz
		wg.Add(1)
		go func() {
			defer wg.Done()
			payload := DeterministicBytes(uint64(4110+i), sz)
			wantHex := fmt.Sprintf("%x", sha256.Sum256(payload))
			pr, pw := io.Pipe()
			go func() {
				for off := 0; off < len(payload); off += 4096 {
					end := off + 4096
					if end > len(payload) {
						end = len(payload)
					}
					_, _ = pw.Write(payload[off:end])
				}
				_ = pw.Close()
			}()
			req, rErr := http.NewRequest(http.MethodPost, "https://"+h2Addr+"/stream", pr)
			require.NoError(t, rErr)
			resp, dErr := cli.Do(req)
			require.NoError(t, dErr)
			gotBody, bErr := io.ReadAll(resp.Body)
			_ = resp.Body.Close()
			require.NoError(t, bErr)
			require.Equal(t, http.StatusOK, resp.StatusCode)
			require.Equal(t, 2, resp.ProtoMajor)
			require.Equal(t, payload, gotBody)
			require.Equal(t, wantHex, resp.Trailer.Get("X-Stream-SHA256"))
		}()
	}
	wg.Wait()
}

func testT412IdleHeartbeatAcross70sBloomRotation(t *testing.T) {
	privKey, pubKey := GenerateAetherKeyPairCLI(t)
	psk := GenerateRandomKeyBase64(t)
	srvTS := NewMockTimeService(0)
	cliTS := NewMockTimeService(0)
	echoTarget := StartTCPEchoTarget(t)

	topo := StartTopology(t, TopologyConfig{
		ServerPassword:          psk,
		ServerPrivateKey:        privKey,
		ServerHeartbeatInterval: "300ms",
		ServerTimeService:       srvTS,
		ServerMultiplex:         &MultiplexServerSpec{Enabled: true},
		ClientPassword:          psk,
		ClientServerPublicKey:   pubKey,
		ClientHeartbeatInterval: "300ms",
		ClientTimeService:       cliTS,
		ClientMultiplex: &MultiplexClientSpec{
			Enabled:        true,
			Protocol:       "h2mux",
			MaxConnections: 1,
		},
	})

	// Initial traffic warms mux session.
	mustSOCKS5EchoTCP(t, topo, "", "", echoTarget.Addr(), DeterministicBytes(4121, 8192))

	// Idle across 4+ jittered heartbeat Ping/Pong cycles (~1.4s) while advancing both MockTimeServices +70s (2 Bloom rotations).
	time.Sleep(700 * time.Millisecond)
	srvTS.Advance(35 * time.Second)
	cliTS.Advance(35 * time.Second)
	time.Sleep(750 * time.Millisecond)
	srvTS.Advance(35 * time.Second)
	cliTS.Advance(35 * time.Second)

	// Surviving connection + fresh parallel session both succeed cleanly with 0 stale-nonce failures.
	var wg sync.WaitGroup
	for i := 0; i < 2; i++ {
		i := i
		wg.Add(1)
		go func() {
			defer wg.Done()
			mustSOCKS5EchoTCP(t, topo, "", "", echoTarget.Addr(), DeterministicBytes(uint64(4122+i), 512*1024))
		}()
	}
	wg.Wait()
}

func testT413ProductionDaemonLifecycleSIGHUPSIGTERM(t *testing.T) {
	psk := GenerateAetherKeyCLI(t)
	privKey, pubKey := GenerateAetherKeyPairCLI(t)
	alicePass := "daemon-alice-pass!"
	bobPass := "daemon-bob-pass-18!"
	charliePass := "daemon-charlie-pass!"

	httpsTarget := StartTLS13HTTPSTarget(t)
	dnsSrv := StartLoopbackDNSServer(t, map[string]string{"svc.prod.internal.": "10.20.30.40"})

	srvPort := AllocFreeTCPPort(t)
	buildSrvCfg := func(users []UserSpec) []byte {
		raw, err := BuildServerJSON(TopologyConfig{
			ServerPassword:   psk,
			ServerUsers:      users,
			ServerPrivateKey: privKey,
		}, srvPort, 0, "")
		require.NoError(t, err)
		return raw
	}

	srvProc := StartCLIDaemon(t, buildSrvCfg([]UserSpec{
		{Name: "alice", Password: alicePass},
		{Name: "bob", Password: bobPass},
	}), srvPort)

	cliPort := AllocFreeTCPPort(t)
	rawCli, err := BuildClientJSON(TopologyConfig{
		ClientPassword:        psk + ":" + alicePass,
		ClientServerPublicKey: pubKey,
	}, cliPort, "127.0.0.1", srvPort, 0, "")
	require.NoError(t, err)
	cliProc := StartCLIDaemon(t, rawCli, cliPort)

	// Verify HTTPS + DNS over running daemon processes.
	cli := &http.Client{
		Timeout: 8 * time.Second,
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				return DialSOCKS5TCP(ctx, fmt.Sprintf("127.0.0.1:%d", cliPort), addr)
			},
			TLSClientConfig: httpsTarget.ClientTLSConfig("127.0.0.1"),
		},
	}
	resp, err := cli.Get("https://" + httpsTarget.Addr() + "/api/v1/health")
	require.NoError(t, err)
	_ = resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)

	ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
	defer cancel()
	uc, err := DialSOCKS5UDP(ctx, fmt.Sprintf("127.0.0.1:%d", cliPort))
	require.NoError(t, err)
	dnsResp := mustQueryDNSOverSOCKS5UDP(t, uc, dnsSrv.UDPAddr(), "svc.prod.internal", dns.TypeA)
	require.Equal(t, dns.RcodeSuccess, dnsResp.Rcode)
	_ = uc.Close()

	// Update server config on disk adding `charlie` and send SIGHUP to reload cleanly.
	updatedSrv := buildSrvCfg([]UserSpec{
		{Name: "alice", Password: alicePass},
		{Name: "bob", Password: bobPass},
		{Name: "charlie", Password: charliePass},
	})
	require.NoError(t, os.WriteFile(srvProc.ConfigPath(), updatedSrv, 0o600))
	require.NoError(t, srvProc.Signal(syscall.SIGHUP))

	charliePort := AllocFreeTCPPort(t)
	rawCharlie, err := BuildClientJSON(TopologyConfig{
		ClientPassword:        psk + ":" + charliePass,
		ClientServerPublicKey: pubKey,
	}, charliePort, "127.0.0.1", srvPort, 0, "")
	require.NoError(t, err)
	charlieProc := StartCLIDaemon(t, rawCharlie, charliePort)

	// Retry briefly until SIGHUP reload rebinds srvPort with charlie enabled.
	echoTarget := StartTCPEchoTarget(t)
	require.Eventually(t, func() bool {
		cCtx, cCancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cCancel()
		cConn, dErr := DialSOCKS5TCP(cCtx, fmt.Sprintf("127.0.0.1:%d", charliePort), echoTarget.Addr())
		if dErr != nil {
			return false
		}
		defer cConn.Close()
		_, wErr := cConn.Write([]byte("charlie-reloaded"))
		if wErr != nil {
			return false
		}
		bufGot := make([]byte, len("charlie-reloaded"))
		_ = cConn.SetReadDeadline(time.Now().Add(2 * time.Second))
		_, rErr := io.ReadFull(cConn, bufGot)
		return rErr == nil && string(bufGot) == "charlie-reloaded"
	}, 8*time.Second, 150*time.Millisecond)

	for _, proc := range []*CLIProcess{charlieProc, cliProc, srvProc} {
		require.NoError(t, proc.Signal(syscall.SIGTERM))
		code, wErr := proc.Wait(8 * time.Second)
		require.NoError(t, wErr)
		require.Equal(t, 0, code)
	}
}

func testT414FirewallDPIAndStatisticalAudit(t *testing.T) {
	privKey, pubKey := GenerateAetherKeyPairCLI(t)
	psk := GenerateRandomKeyBase64(t)
	httpsTarget := StartTLS13HTTPSTarget(t)
	dnsSrv := StartLoopbackDNSServer(t, map[string]string{"dpi.test.": "10.0.0.42"})
	sshTarget := StartServerSpeaksFirstTarget(t, []byte("SSH-2.0-Audit_1.0\r\n"))
	echoTarget := StartTCPEchoTarget(t)

	topo := StartTopology(t, TopologyConfig{
		ServerPassword:        psk,
		ServerPrivateKey:      privKey,
		ClientPassword:        psk,
		ClientServerPublicKey: pubKey,
	})

	httpsCli, err := topo.NewHTTPClient(httpsTarget.ClientTLSConfig("127.0.0.1"), 8*time.Second)
	require.NoError(t, err)
	httpTr := httpsCli.Transport.(*http.Transport)
	httpTr.DisableKeepAlives = true

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Capture 64 heterogeneous sessions (HTTPS, UDP DNS, SSH-banner, Bulk TCP).
	const totalSessions = 64
	for i := 0; i < totalSessions; i++ {
		switch i % 4 {
		case 0:
			r, gErr := httpsCli.Get("https://" + httpsTarget.Addr() + "/api/v1/health")
			require.NoError(t, gErr)
			_, _ = io.ReadAll(r.Body)
			_ = r.Body.Close()
		case 1:
			uc, uErr := topo.OpenSOCKS5UDP(ctx)
			require.NoError(t, uErr)
			_ = mustQueryDNSOverSOCKS5UDP(t, uc, dnsSrv.UDPAddr(), "dpi.test", dns.TypeA)
			_ = uc.Close()
		case 2:
			c, dErr := topo.DialSOCKS5(ctx, sshTarget.Addr())
			require.NoError(t, dErr)
			banner := make([]byte, len("SSH-2.0-Audit_1.0\r\n"))
			_, _ = io.ReadFull(c, banner)
			_ = c.Close()
		case 3:
			mustSOCKS5EchoTCP(t, topo, "", "", echoTarget.Addr(), DeterministicBytes(uint64(4140+i), 4096))
		}
	}

	sessions := topo.Tap.WaitForSessions(t, totalSessions, 10*time.Second)
	require.GreaterOrEqual(t, len(sessions), totalSessions)

	pcapPath := filepath.Join(t.TempDir(), "t414_dpi_audit.pcap")
	require.NoError(t, topo.Tap.SavePCAP(pcapPath))
	pktCount, err := ValidatePCAPFile(pcapPath)
	require.NoError(t, err)
	require.GreaterOrEqual(t, pktCount, totalSessions*2)

	forbiddenSignatures := [][]byte{
		{0x16, 0x03, 0x01},
		{0x16, 0x03, 0x03},
		[]byte("GET /"),
		[]byte("HTTP/1."),
		{0x05, 0x01, 0x00},
		{0x01, 0x00, 0x00, 0x00}, // WireGuard initiation prefix
	}

	distinctInitLens := make(map[int]struct{})
	for _, s := range sessions[:totalSessions] {
		require.False(t, s.HasOuterTLSRecordHeader())
		require.False(t, s.HasSegmentOfExactSize(DirC2S, 2))
		require.False(t, s.HasSegmentOfExactSize(DirS2C, 2))
		require.False(t, s.HasSegmentOfExactSize(DirC2S, 18))
		require.False(t, s.HasSegmentOfExactSize(DirS2C, 18))

		for _, sig := range forbiddenSignatures {
			require.False(t, s.ContainsBytes(DirC2S, sig), "C2S contained plaintext signature %x", sig)
			require.False(t, s.ContainsBytes(DirS2C, sig), "S2C contained plaintext signature %x", sig)
		}
		if seg, ok := s.FirstSegment(DirC2S); ok {
			distinctInitLens[seg.Size] = struct{}{}
		}
	}
	require.GreaterOrEqual(t, len(distinctInitLens), 8, "initial wire packet sizes must not collapse to a single fixed length")

	_, _, c2sBitRatio := topo.Tap.EPKBit255Stats(DirC2S)
	_, _, s2cBitRatio := topo.Tap.EPKBit255Stats(DirS2C)
	require.True(t, c2sBitRatio >= 0.30 && c2sBitRatio <= 0.70, "C2S MaskedEPK bit 255 ratio %v out of [0.30, 0.70]", c2sBitRatio)
	require.True(t, s2cBitRatio >= 0.30 && s2cBitRatio <= 0.70, "S2C MaskedEPK bit 255 ratio %v out of [0.30, 0.70]", s2cBitRatio)

	entC2S := topo.Tap.AggregateShannonEntropy(DirC2S)
	entS2C := topo.Tap.AggregateShannonEntropy(DirS2C)
	require.Greater(t, entC2S, 7.95, "C2S Shannon entropy %v <= 7.95", entC2S)
	require.Greater(t, entS2C, 7.95, "S2C Shannon entropy %v <= 7.95", entS2C)
}

func testT415CongestedCrossCarrierTorture(t *testing.T) {
	psk := GenerateRandomKeyBase64(t)
	tcpTarget := StartTCPEchoTarget(t)
	udpTarget := StartUDPEchoTarget(t)

	topo := StartTopology(t, TopologyConfig{
		ServerPassword:          psk,
		ServerHeartbeatInterval: "300ms",
		ServerMultiplex:         &MultiplexServerSpec{Enabled: true, Padding: true},
		ClientPassword:          psk,
		ClientHeartbeatInterval: "300ms",
		ClientMultiplex: &MultiplexClientSpec{
			Enabled:        true,
			Protocol:       "yamux",
			MaxConnections: 3,
			Padding:        true,
		},
		ClientUDPOverTCP: map[string]any{"enabled": true, "version": 2},
	})

	// Simulate congested leased line (4 KiB read cap + 1ms chunk delay + 8 KiB window).
	topo.Tap.SetTCPWindowBytes(8192)
	topo.Tap.SetThrottle(1*time.Millisecond, 4096)

	var wg sync.WaitGroup
	for w := 0; w < 12; w++ {
		w := w
		wg.Add(1)
		go func() {
			defer wg.Done()
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			for r := 0; r < 2; r++ {
				if (w+r)%2 == 0 {
					mustSOCKS5EchoTCP(t, topo, "", "", tcpTarget.Addr(), DeterministicBytes(uint64(4150+w*10+r), 16*1024))
				} else {
					uc, uErr := topo.OpenSOCKS5UDP(ctx)
					require.NoError(t, uErr)
					mustSOCKS5EchoUDP(t, uc, udpTarget.Addr(), DeterministicBytes(uint64(4155+w*10+r), 768))
					_ = uc.Close()
				}
			}
		}()
	}
	wg.Wait()
}

func testT416ZeroDowntimeKeyRotationAndMigration(t *testing.T) {
	privKey, pubKey := GenerateAetherKeyPairCLI(t)
	keyV1 := "ops-v1-" + GenerateRandomKeyBase64(t)
	keyV2 := "ops-v2-" + GenerateRandomKeyBase64(t)

	echoTarget := StartTCPEchoTarget(t)
	srvPort := AllocFreeTCPPort(t)
	cfgPath := filepath.Join(t.TempDir(), "rotate-server.json")

	writeSrv := func(users []UserSpec) []byte {
		raw, err := BuildServerJSON(TopologyConfig{
			ServerUsers:      users,
			ServerPrivateKey: privKey,
		}, srvPort, 0, "")
		require.NoError(t, err)
		return raw
	}
	rawInitial := writeSrv([]UserSpec{
		{Name: "ops-v1", Password: keyV1},
		{Name: "ops-v2", Password: keyV2},
	})
	require.NoError(t, os.WriteFile(cfgPath, rawInitial, 0o600))
	srvProc := StartCLIDaemonFromFile(t, cfgPath, srvPort)

	startFleetClient := func(pass, cipher string) *BoxInstance {
		p := AllocFreeTCPPort(t)
		rawC, cErr := BuildClientJSON(TopologyConfig{
			ClientPassword:        pass,
			ClientCipher:          cipher,
			ClientServerPublicKey: pubKey,
		}, p, "127.0.0.1", srvPort, 0, "")
		require.NoError(t, cErr)
		cb, bErr := StartBoxWithLog(t, rawC, "", p)
		require.NoError(t, bErr)
		t.Cleanup(func() { _ = cb.Close() })
		return cb
	}
	cliV1 := startFleetClient(keyV1, "chacha20-poly1305")
	cliV2 := startFleetClient(keyV2, "aes-256-gcm")

	// Phase 1: Dual-key window supports BOTH keyV1 (ChaCha20) and keyV2 (AES-256-GCM) simultaneously.
	var phase1WG sync.WaitGroup
	for i := 0; i < 6; i++ {
		i := i
		phase1WG.Add(2)
		go func() {
			defer phase1WG.Done()
			mustDialSOCKS5OnAddr(t, cliV1.ListenAddr, echoTarget.Addr(), DeterministicBytes(uint64(4161+i), 2048))
		}()
		go func() {
			defer phase1WG.Done()
			mustDialSOCKS5OnAddr(t, cliV2.ListenAddr, echoTarget.Addr(), DeterministicBytes(uint64(4171+i), 2048))
		}()
	}
	phase1WG.Wait()

	// Phase 2: Retire keyV1 cleanly via SIGHUP config reload while keyV2 fleet keeps serving.
	// Hold a live pre-SIGHUP connection via cliV1 so its teardown proves the old instance closed.
	holdCtx, holdCancel := context.WithTimeout(context.Background(), 5*time.Second)
	holdV1, err := DialSOCKS5TCP(holdCtx, cliV1.ListenAddr, echoTarget.Addr())
	holdCancel()
	require.NoError(t, err)
	defer holdV1.Close()
	_ = holdV1.SetDeadline(time.Now().Add(5 * time.Second))
	_, err = holdV1.Write([]byte("hold"))
	require.NoError(t, err)
	holdEcho := make([]byte, 4)
	_, err = io.ReadFull(holdV1, holdEcho)
	require.NoError(t, err)
	require.Equal(t, "hold", string(holdEcho))

	rawRetired := writeSrv([]UserSpec{
		{Name: "ops-v2", Password: keyV2},
	})
	require.NoError(t, os.WriteFile(cfgPath, rawRetired, 0o600))
	require.NoError(t, srvProc.Signal(syscall.SIGHUP))

	// Wait until old instance teardown closes holdV1 before probing the reloaded instance.
	_ = holdV1.SetReadDeadline(time.Now().Add(5 * time.Second))
	_, closeErr := holdV1.Read(make([]byte, 1))
	require.Error(t, closeErr, "SIGHUP reload must close pre-reload instance connections")
	_ = holdV1.Close()

	// Wait until reloaded daemon is accepting keyV2, then confirm keyV2 passes 20 consecutive calls.
	require.Eventually(t, func() bool {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		c, dErr := DialSOCKS5TCP(ctx, cliV2.ListenAddr, echoTarget.Addr())
		if dErr != nil {
			return false
		}
		defer c.Close()
		_, wErr := c.Write([]byte("v2-ok"))
		if wErr != nil {
			return false
		}
		b := make([]byte, 5)
		_ = c.SetReadDeadline(time.Now().Add(2 * time.Second))
		_, rErr := io.ReadFull(c, b)
		return rErr == nil && string(b) == "v2-ok"
	}, 8*time.Second, 150*time.Millisecond)

	for i := 0; i < 20; i++ {
		mustDialSOCKS5OnAddr(t, cliV2.ListenAddr, echoTarget.Addr(), DeterministicBytes(uint64(4180+i), 1024))
	}

	// Retired keyV1 burst must now enter StealthDrain!
	retiredBurst, _, err := BuildSpecClientInitialBurst(SpecDialOptions{
		Password:        keyV1,
		ServerPublicKey: pubKey,
		ForceNoEIH:      true,
		TargetAddr:      echoTarget.Addr(),
	})
	require.NoError(t, err)
	pr, err := SendRawProbe(fmt.Sprintf("127.0.0.1:%d", srvPort), retiredBurst, true, 13*time.Second)
	require.NoError(t, err)
	assertExpectedStealthDrain(t, pr)

	require.NoError(t, srvProc.Signal(syscall.SIGTERM))
	code, err := srvProc.Wait(8 * time.Second)
	require.NoError(t, err)
	require.Equal(t, 0, code)
}
