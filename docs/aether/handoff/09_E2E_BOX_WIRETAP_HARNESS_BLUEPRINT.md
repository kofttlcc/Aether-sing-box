# Handoff Report — Opaque-Box E2E Test Harness Architecture & Verified `harness_test.go` Blueprint (`explorer_e2e_2`)

> **Core Summary**: A 100% opaque-box `protocol/aether/e2e/harness_test.go` (`package e2e_test`) importing **only** `box`, `constant`, `include`, and `option` from `sing-box` (zero `protocol/aether` or `github.com/sagernet/sing/...` imports) has been designed and empirically verified under `go vet`, untagged `go test -race` (`2.969s`), and full 9-tag `go test -race` (`3.021s`) against M1 `HEAD` (`ea7a70b6be9f40a66188a626df5654729d1dc743`). It eliminates **both** the `include/quic_stub.go:48` global write race **and** a newly uncovered `sing/service/context.go:13-18` shared-registry mutation race across concurrent `box.New` instances via `WarmBaseRegistries()` (`sync.Once`) + `valueFreeContext` in `NewBoxContext`.

---

## Synthesis Across Peer E2E Investigations (`spec_miner_e2e_1`, `explorer_e2e_3`, `explorer_e2e_2`)

### Consensus
1. **Subpackage Placement & Cycle Freedom** (`spec_miner_e2e_1/handoff.md:25,38`, `explorer_e2e_2`): Placing the opaque-box suite in `protocol/aether/e2e` (`package e2e_test`) avoids the `protocol/aether <-> include` test import cycle while ensuring `go test -race ./protocol/aether/...` automatically executes all E2E tiers.
2. **Pre-Built CLI Binary + Fast Configurable Timers + Base64 Default Keys** (`spec_miner_e2e_1/handoff.md:41`, `explorer_e2e_3/handoff.md:3,115-118`, `explorer_e2e_2`): Building `/tmp/aether-e2e-cli-*/sing-box` once in `TestMain` (`1.59s` measured), defaulting non-KDF topologies to 32B Base64 keys (`< 1µs` vs `332.7ms` per `Argon2id` call under `-race`), and driving expiry/DPD tests via short JSON durations (`"time_window": "2s"`, `"handshake_timeout": "500ms"`, `"heartbeat_interval": "400ms"`) keeps full `-race` execution fast and deterministic on 2 vCPUs.
3. **Raw Kernel TCP Socket Requirement for `StealthDrain` `FIN` vs `RST` Verification** (`spec_miner_e2e_1/handoff.md:68`, `explorer_e2e_3/handoff.md:21-25`, `explorer_e2e_2`): `sing/common/network/handshake.go:47-51` (`N.CloseOnHandshakeFailure`) triggers `SetLinger(0)` (`TCP RST` / `syscall.ECONNRESET`) on real `*net.TCPConn` sockets. Active probe/replay/truncation helpers (`SendRawProbe`, `SendSlowlorisProbe`) must therefore dial `topo.Server.ListenAddr` directly over real loopback TCP sockets and assert `ClosedCleanEOF == true && ClosedByRST == false`.

### Resolved Conflicts
1. **Direct `protocol/aether` Import in `explorer_e2e_3` vs Mandatory Zero-Internal-Dependency Rule**:
   - *Conflict*: `explorer_e2e_3/handoff.md:89-96` proposed a custom `newBaseContext` calling `aether.RegisterInbound(inReg)` and `aether.RegisterOutbound(outReg)` directly (violating Dispatch Requirement #1: *"NEVER importing `github.com/sagernet/sing-box/protocol/aether` directly"*) out of concern that `include` would add `~15s` to `-race` runs and hit `include/quic_stub.go:48`.
   - *Evidence-Based Resolution*: Caching `include.{Inbound,Outbound,Endpoint,DNSTransport,Service,CertificateProvider}Registry()` inside `WarmBaseRegistries()` (`sync.Once`) + `NewBoxContext` (using generic `newRegistryHolder(box.Context)`) requires **zero** `protocol/aether` or `adapter` imports, registers `"local"` and `"hosts"` DNS transports automatically (`box.go:402-410`), eliminates `include/quic_stub.go:48` races completely, and compiled + ran 6 parallel full topologies + `TestMain` CLI build in **`2.969s` untagged `-race`** and **`3.021s` 9-tag `-race`**. Adopt `WarmBaseRegistries()` + `NewBoxContext`.
2. **Multi-User Routing Rule JSON Key (`"auth_user"` vs `"user"`)**:
   - *Conflict*: In `sing-box` route rules (`option/rule.go:144` vs `line 167`), `"user"` matches OS process username (`ProcessInfo`), whereas **`"auth_user"`** matches `metadata.User` populated by inbound authentication (`F10`, noted in `spec_miner_e2e_1/handoff.md:23`).
   - *Evidence-Based Resolution*: `BuildServerJSON` in the blueprint below uses `"auth_user": cfg.ServerAllowedUsers` so `F10` multi-user routing rules match `metadata.User` accurately.
3. **Indirect `go.mod` Imports (`gopkg.in/yaml.v3`, `gopacket/pcapgo`)**:
   - *Conflict*: `spec_miner_e2e_1/handoff.md:31,40` warned against importing `// indirect` modules in root `go.mod`, whereas `explorer_e2e_3/handoff.md:32,57` imported `yaml.v3` / `pcapgo`.
   - *Evidence-Based Resolution*: `WireTapProxy.SavePCAP` in `harness_test.go` writes standard `0xa1b2c3d4` (`LINKTYPE_RAW = 101`) `.pcap` files in 35 lines of pure Go stdlib (`encoding/binary`), avoiding `gopacket` completely and guaranteeing zero `go.mod` drift across all Go versions.

### Dissenting Views
- None.

### Gaps Closed by `explorer_e2e_2`
- Discovered and eliminated the **`sing/service/context.go:13-18` shared `defaultRegistry` race/overwrite bug** when multiple `box.Box` instances share a parent registry context without stripping/cloning `service.Registry`.
- Discovered that `golang.org/x/net/proxy`'s internal `socks.Conn` strips `*net.TCPConn.CloseWrite()`, and solved it with a pure-stdlib 65-line `DialSOCKS5TCP` returning `*SOCKS5StreamConn` (`*net.TCPConn`) so end-to-end TCP half-close (`FrameCloseWrite = 0x04`) works natively.
- Added an AST-based `VerifyOpaqueImports` helper enforcing the Zero-Internal-Dependency invariant across `protocol/aether/e2e/*.go` on every test run.

---

## 1. Observation

1. **`include/quic_stub.go:48` Unsynchronized Package-Global Write**:
   - `include/quic_stub.go:46-50` (`//go:build !with_quic`): `registerQUICInbounds` executes `naive.ConfigureHTTP3ListenerFunc = func(...) { return nil, C.ErrQUICNotIncluded }` on every call to `include.InboundRegistry()` (`include/registry.go:53-55`).
   - All 6 registry types (`adapter/inbound/registry.go:36-80`, `adapter/outbound/registry.go:36-80`, `adapter/endpoint/registry.go:36-80`, `dns/transport_registry.go:36-80`, `adapter/service/registry.go:36-80`, `adapter/certificate/registry.go:36-80`) protect `OptionTypes()`, `CreateOptions()`, and `Create*()` with internal `access sync.Mutex` locks and are never mutated after `include.*Registry()` returns.

2. **Shared `service.Registry` Mutation Inside `box.New` (`box.go` + `sing/service/context.go`)**:
   - `box.go:116`: `ctx = service.ContextWithDefaultRegistry(ctx)`.
   - `/home/antigravity/go/pkg/mod/github.com/sagernet/sing@v0.9.7-0.20261023115459-5dc452e537bf/service/context.go:13-18`:
     ```go
     func ContextWithDefaultRegistry(ctx context.Context) context.Context {
         if RegistryFromContext(ctx) != nil {
             return ctx
         }
         return context.WithValue(ctx, common.DefaultValue[*Registry](), NewRegistry())
     }
     ```
   - `box.go:185, 217-222, 260-263` then calls `service.MustRegister[log.Factory](ctx, ...)`, `service.MustRegister[adapter.Router](ctx, ...)`, `service.MustRegister[adapter.OutboundManager](ctx, ...)`, and `service.MustRegister[ntp.TimeService](ctx, ...)` directly on `ctx`'s `service.Registry`.
   - `box.go:80-107` (`box.Context(ctx, inReg, outReg, endReg, dnsReg, svcReg, certReg)`) creates a brand-new `service.NewRegistry()` whenever `RegistryFromContext(ctx) == nil`.

3. **Public JSON Unmarshaling, NTP, Hosts DNS & Network Reset Entrypoints**:
   - `option/options.go:39-48`: `(*option.Options).UnmarshalJSONContext(ctx, content)` decodes full JSON configs with `decoder.DisallowUnknownFields()` and `checkOptions(o)`.
   - `box.go:258-263, 447-467, 597-605` & `common/tls/time_wrapper.go:9-21`: Setting `"ntp": {"enabled": true, "server": "127.0.0.1", "server_port": port, "interval": "200ms"}` registers `tls.TimeServiceWrapper` into `ctx` before `NewInbound`/`NewOutbound` run and synchronously executes RFC 5905 SNTPv4 `s.ntpService.Start()` (`sing/common/ntp/message.go:222-317`) during `Box.Start()` before `s.inbound` starts (`box.go:609`).
   - `dns/transport/hosts/hosts.go:33-102` & `option/dns.go:179-182`: `"type": "hosts"` with `"predefined": {"echo.aether.test": "127.0.0.1"}` + `"default_domain_resolver": "hosts-dns"` resolves test FQDNs in-memory on Server `Box` with zero external DNS queries.
   - `route/network.go:455-482`: `Box.Network().ResetNetwork(ctx)` iterates all outbounds and invokes `InterfaceUpdated(ctx)`.
   - `route/route.go:110, 156-158` & `route/conn.go:298-305, 347-377`: Adding `{"action": "sniff", "timeout": "50ms"}` on Client `Box` caches the client's first payload into `bufio.NewCachedConn` so `kickWriteHandshake` deterministically passes `cachedBuffer.Bytes()` to `EarlyWriter.Write` (0-RTT coalescing), and `connectionCopy` propagates `N.WriteCloser.CloseWrite()` end-to-end.

4. **Empirical Verification Results Against M1 `HEAD` (`ea7a70b6be9f40a66188a626df5654729d1dc743`)**:
   - Tested in isolated `/tmp/explorer_e2e_2_test` (`module e2e_verify` with `replace github.com/sagernet/sing-box => .`):
     - `go vet ./...` -> exit code `0`
     - `go test -race -count=1 ./...` (untagged, `quic_stub.go` active, 6 parallel `t.Parallel()` topologies) -> `ok e2e_verify 2.969s`
     - `go test -race -count=1 -tags "with_gvisor,with_quic,with_dhcp,with_wireguard,with_utls,with_acme,with_clash_api,badlinkname,tfogo_checklinkname0" -ldflags "$(cat release/LDFLAGS)" ./...` -> `ok e2e_verify 3.021s`
     - `/tmp/explorer_e2e_2_test` removed; `git status --short --branch` -> `## dev/aether-v2` (empty diff).

---

## 2. Logic Chain

1. **Zero Internal Dependency (`Obs 2`, `Obs 3`)**: Because `(*option.Options).UnmarshalJSONContext` decodes complete `sing-box` JSON configurations into `option.Options` without requiring callers to construct `badoption.*` structs, and `newRegistryHolder(box.Context)` infers all 6 `adapter.*Registry` interface types via Go generics directly from `box.Context`, `harness_test.go` needs **only** 4 `sing-box` imports (`box`, `constant`, `include`, `option`) plus Go stdlib, `golang.org/x/net/proxy`, and `github.com/stretchr/testify/require`.
2. **Dual Race Elimination (`Obs 1`, `Obs 2`)**:
   - Calling `include.*Registry()` inside `baseRegistries.once.Do(...)` (`WarmBaseRegistries()`) guarantees `include/quic_stub.go:48`'s global write happens at most once with full happens-before synchronization before any parallel subtest runs.
   - Wrapping `parent` in `valueFreeContext{Context: parent}` (`Value(any) any { return nil }`) inside `NewBoxContext(parent)` ensures `box.Context` sees `RegistryFromContext == nil` and allocates a **fresh `service.NewRegistry()` per `box.Box` instance**, preventing Client `Box`, Server `Box`, and parallel subtests from overwriting one another's `Router`, `OutboundManager`, `LogFactory`, or `ntp.TimeService`.
3. **Opaque-Box Wire & Timing Observability (`Obs 3`)**:
   - Interposing `WireTapProxy` between Client `Box` and Server `Box` enables O(1)-memory Shannon entropy (`[256]uint64` byte histogram), `MaskedClientEPK` (`c2s[32:64]`) & `MaskedServerEPK` (`s2c[32:64]`) MSB-bias statistics, zero-`2B`-split assertions, substring/TLS-header absence checks, standard `.pcap` export, silent blackholing (`SetBlackhole` without `FIN`/`RST` for `F22` DPD), TCP window backpressure (`SetReadPaused` + `SetTCPWindowBytes` for `F20` `pongCh` saturation), and byte-exact bit-flip tampering (`InstallSingleBitFlip`).
   - `StartMockNTPServer` shifts `ntp.TimeFuncFromContext(ctx)` on either Client `Box` or Server `Box` to any `±Duration` (`±29s`, `±35s`, `+61s` Bloom generation rotation) purely through `"ntp"` JSON options.

---

## 3. Caveats

1. **Loopback TCP Segment Coalescing Under Bulk Saturation**: On Linux loopback (`MTU = 65536`, `TCP_NODELAY = true`), initial handshake bursts (`FirstSegment(DirC2S)` and `FirstSegment(DirS2C)`) and paced writes map `1 Write() == 1 TapSegment`, whereas multi-megabyte back-to-back `io.Copy` bursts can be coalesced across adjacent frames by the kernel socket buffer (`<= 65536B` per `Read`). Steady-state `Frame 6+` `< 0.22%` overhead assertions on bulk transfers should therefore check `float64(sess.TotalBytes(DirC2S)-handshakeBytes-payloadBytes)/float64(payloadBytes)` alongside `!sess.HasSegmentOfExactSize(DirC2S, 2)`.
2. **`os.Exit` in `TestMain`**: `os.Exit` skips deferred functions in the same frame; `TestMain` MUST delegate to `runTestMain(m)` (as implemented below) so `defer os.RemoveAll(cliTempDir)` always deletes `/tmp/aether-e2e-cli-*`.
3. **M1 vs M4 Protocol Shim Behavior**: Against M1 `HEAD`, legacy v1 `aether` supports TCP + `udp_over_tcp: true` (verified passing in `smoke_verify_test.go`), whereas Aether v2 wire offsets (`96B`/`112B` prefix, `84B` response, `CommandUDP = 0x02`, `FrameCloseWrite = 0x04`, `StealthDrain`) take effect once M2–M4 land.

---

## 4. Conclusion & Complete `protocol/aether/e2e/harness_test.go` Blueprint

`worker_e2e_1` can write the following compiler-and-`-race`-verified blueprint directly to `protocol/aether/e2e/harness_test.go` (extending it only with pure-stdlib/spec-derived wire helpers if needed, keeping `VerifyOpaqueImports` green):

```go
package e2e_test

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"go/parser"
	"go/token"
	"io"
	"math"
	"math/big"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	box "github.com/sagernet/sing-box"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/include"
	"github.com/sagernet/sing-box/option"

	"github.com/stretchr/testify/require"
	"golang.org/x/net/proxy"
)

// Default9BuildTags matches PROJECT.md § Interface Contracts § 1 canonical build tags.
const Default9BuildTags = "with_gvisor,with_quic,with_dhcp,with_wireguard,with_utls,with_acme,with_clash_api,badlinkname,tfogo_checklinkname0"

// ---------------------------------------------------------------------------
// 1. Thread-Safe include Registry Initialization & Per-Box Context Isolation
// ---------------------------------------------------------------------------

// valueFreeContext preserves cancellation and deadlines from Context while
// hiding parent context values so box.Context always allocates an isolated
// per-Box service.Registry (preventing concurrent box.New calls from mutating
// a shared service.defaultRegistry).
type valueFreeContext struct {
	context.Context
}

func (valueFreeContext) Value(any) any {
	return nil
}

type registryHolder[In, Out, End, DNS, Svc, Cert any] struct {
	once   sync.Once
	boxCtx func(context.Context, In, Out, End, DNS, Svc, Cert) context.Context
	in     In
	out    Out
	end    End
	dns    DNS
	svc    Svc
	cert   Cert
}

func newRegistryHolder[In, Out, End, DNS, Svc, Cert any](
	boxCtx func(context.Context, In, Out, End, DNS, Svc, Cert) context.Context,
) *registryHolder[In, Out, End, DNS, Svc, Cert] {
	return &registryHolder[In, Out, End, DNS, Svc, Cert]{boxCtx: boxCtx}
}

func (h *registryHolder[In, Out, End, DNS, Svc, Cert]) store(
	in In, out Out, end End, dns DNS, svc Svc, cert Cert,
) {
	h.in = in
	h.out = out
	h.end = end
	h.dns = dns
	h.svc = svc
	h.cert = cert
}

var baseRegistries = newRegistryHolder(box.Context)

// WarmBaseRegistries initializes all 6 protocol registries exactly once.
// Safe to call concurrently; eliminates the unsynchronized global write in
// include/quic_stub.go:48 when running `go test -race` without `with_quic`.
func WarmBaseRegistries() {
	baseRegistries.once.Do(func() {
		baseRegistries.store(
			include.InboundRegistry(),
			include.OutboundRegistry(),
			include.EndpointRegistry(),
			include.DNSTransportRegistry(),
			include.ServiceRegistry(),
			include.CertificateProviderRegistry(),
		)
	})
}

// NewBoxContext returns a fresh context carrying an isolated per-Box registry
// populated with the process-wide cached protocol registries.
func NewBoxContext(parent context.Context) context.Context {
	WarmBaseRegistries()
	if parent == nil {
		parent = context.Background()
	}
	return baseRegistries.boxCtx(
		valueFreeContext{Context: parent},
		baseRegistries.in,
		baseRegistries.out,
		baseRegistries.end,
		baseRegistries.dns,
		baseRegistries.svc,
		baseRegistries.cert,
	)
}

// UnmarshalBoxOptions parses raw sing-box JSON configuration using the exact
// production option.Options.UnmarshalJSONContext pipeline (including
// DisallowUnknownFields and checkOptions).
func UnmarshalBoxOptions(rawJSON []byte) (option.Options, error) {
	var opts option.Options
	err := opts.UnmarshalJSONContext(NewBoxContext(context.Background()), rawJSON)
	return opts, err
}

// CheckConfigInProcess validates a raw JSON configuration via UnmarshalJSONContext
// + box.New + immediate Close without binding listening sockets.
func CheckConfigInProcess(rawJSON []byte) error {
	opts, err := UnmarshalBoxOptions(rawJSON)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithCancel(NewBoxContext(context.Background()))
	defer cancel()
	instance, err := box.New(box.Options{
		Context: ctx,
		Options: opts,
	})
	if err != nil {
		return err
	}
	return instance.Close()
}

// ---------------------------------------------------------------------------
// 2. TestMain Pre-Built CLI Binary Lifecycle & Keygen Helpers
// ---------------------------------------------------------------------------

var (
	cliBuildOnce sync.Once
	cliTempDir   string
	cliBinPath   string
	cliBuildErr  error
)

func TestMain(m *testing.M) {
	os.Exit(runTestMain(m))
}

func runTestMain(m *testing.M) int {
	WarmBaseRegistries()
	ensureCLIBinaryBuilt()
	defer func() {
		if cliTempDir != "" {
			_ = os.RemoveAll(cliTempDir)
		}
	}()
	return m.Run()
}

func RepoRoot() (string, error) {
	if envRoot := os.Getenv("SING_BOX_REPO_ROOT"); envRoot != "" && isSingBoxRepoRoot(envRoot) {
		return filepath.Clean(envRoot), nil
	}
	if _, file, _, ok := runtime.Caller(0); ok {
		candidate := filepath.Clean(filepath.Join(filepath.Dir(file), "..", "..", ".."))
		if isSingBoxRepoRoot(candidate) {
			return candidate, nil
		}
	}
	dir, err := os.Getwd()
	if err != nil {
		return "", err
	}
	for {
		if isSingBoxRepoRoot(dir) {
			return dir, nil
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}
	return "", errors.New("unable to locate sing-box repository root (go.mod)")
}

func isSingBoxRepoRoot(dir string) bool {
	content, err := os.ReadFile(filepath.Join(dir, "go.mod"))
	if err != nil {
		return false
	}
	return strings.Contains(string(content), "module github.com/sagernet/sing-box")
}

func ensureCLIBinaryBuilt() {
	cliBuildOnce.Do(func() {
		root, err := RepoRoot()
		if err != nil {
			cliBuildErr = err
			return
		}
		tmpDir, err := os.MkdirTemp("", "aether-e2e-cli-*")
		if err != nil {
			cliBuildErr = err
			return
		}
		cliTempDir = tmpDir
		outBin := filepath.Join(tmpDir, "sing-box")

		ldflagsBytes, err := os.ReadFile(filepath.Join(root, "release", "LDFLAGS"))
		if err != nil {
			cliBuildErr = fmt.Errorf("read release/LDFLAGS: %w", err)
			return
		}
		ldflags := fmt.Sprintf(
			"-X 'github.com/sagernet/sing-box/constant.Version=%s' %s -s -w -buildid=",
			C.Version,
			strings.TrimSpace(string(ldflagsBytes)),
		)

		cmd := exec.Command(
			"go", "build", "-trimpath",
			"-tags", Default9BuildTags,
			"-ldflags", ldflags,
			"-o", outBin,
			"./cmd/sing-box",
		)
		cmd.Dir = root
		cmd.Env = append(os.Environ(),
			"GOPROXY=direct",
			"GOSUMDB=off",
			"CGO_ENABLED=0",
		)
		var stderr bytes.Buffer
		cmd.Stderr = &stderr
		if err := cmd.Run(); err != nil {
			cliBuildErr = fmt.Errorf("go build sing-box CLI failed: %w\n%s", err, stderr.String())
			return
		}
		cliBinPath = outBin
	})
}

// CLIBinaryPath returns the pre-built 9-tag sing-box binary path.
func CLIBinaryPath(t testing.TB) string {
	t.Helper()
	ensureCLIBinaryBuilt()
	require.NoError(t, cliBuildErr)
	require.NotEmpty(t, cliBinPath)
	return cliBinPath
}

// CLIResult captures stdout, stderr, and exit status from a sing-box CLI invocation.
type CLIResult struct {
	Stdout   string
	Stderr   string
	ExitCode int
	Err      error
}

// RunCLI executes the pre-built sing-box binary with args and returns CLIResult.
func RunCLI(t testing.TB, ctx context.Context, args ...string) CLIResult {
	t.Helper()
	bin := CLIBinaryPath(t)
	cmd := exec.CommandContext(ctx, bin, args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	exitCode := 0
	if err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			exitCode = exitErr.ExitCode()
		} else {
			exitCode = -1
		}
	}
	return CLIResult{
		Stdout:   stdout.String(),
		Stderr:   stderr.String(),
		ExitCode: exitCode,
		Err:      err,
	}
}

// CheckConfigCLI writes rawJSON to a temp file and runs `sing-box check -c <file>`.
func CheckConfigCLI(t testing.TB, rawJSON []byte) CLIResult {
	t.Helper()
	cfgPath := filepath.Join(t.TempDir(), "config.json")
	require.NoError(t, os.WriteFile(cfgPath, rawJSON, 0o600))
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	return RunCLI(t, ctx, "check", "-c", cfgPath)
}

// GenerateAetherKeyCLI generates a 44-char Base64 uPSK via `sing-box generate aether-key`.
func GenerateAetherKeyCLI(t testing.TB) string {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	res := RunCLI(t, ctx, "generate", "aether-key")
	require.Equal(t, 0, res.ExitCode, "stderr: %s", res.Stderr)
	return strings.TrimSuffix(res.Stdout, "\n")
}

// GenerateAetherKeyPairCLI generates (privateKeyB64, publicKeyB64) via `sing-box generate aether-keypair`.
func GenerateAetherKeyPairCLI(t testing.TB) (string, string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	res := RunCLI(t, ctx, "generate", "aether-keypair")
	require.Equal(t, 0, res.ExitCode, "stderr: %s", res.Stderr)
	lines := strings.Split(strings.TrimSuffix(res.Stdout, "\n"), "\n")
	require.Len(t, lines, 2)
	priv, ok1 := strings.CutPrefix(lines[0], "PrivateKey: ")
	pub, ok2 := strings.CutPrefix(lines[1], "PublicKey: ")
	require.True(t, ok1 && ok2)
	return priv, pub
}

// GenerateRandomKeyBase64 generates a non-zero 32-byte CSPRNG key encoded with base64.StdEncoding.
func GenerateRandomKeyBase64(t testing.TB) string {
	t.Helper()
	var key [32]byte
	for {
		_, err := io.ReadFull(rand.Reader, key[:])
		require.NoError(t, err)
		if key != ([32]byte{}) {
			return base64.StdEncoding.EncodeToString(key[:])
		}
	}
}

// GenerateX25519KeyPairBase64 generates an X25519 (privateKeyB64, publicKeyB64) pair using Go stdlib crypto/ecdh.
func GenerateX25519KeyPairBase64(t testing.TB) (string, string) {
	t.Helper()
	priv, err := ecdh.X25519().GenerateKey(rand.Reader)
	require.NoError(t, err)
	return base64.StdEncoding.EncodeToString(priv.Bytes()), base64.StdEncoding.EncodeToString(priv.PublicKey().Bytes())
}

type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// CLIProcess manages a live `sing-box run -c` child process.
type CLIProcess struct {
	cmd     *exec.Cmd
	stdout  *syncBuffer
	stderr  *syncBuffer
	doneCh  chan error
	stopMu  sync.Once
	exitMu  sync.Mutex
	waited  bool
	exitErr error
}

// StartCLIProcess starts `sing-box run -c` with rawJSON and waits until all waitTCPPorts accept TCP connections.
func StartCLIProcess(t testing.TB, rawJSON []byte, waitTCPPorts ...uint16) *CLIProcess {
	t.Helper()
	bin := CLIBinaryPath(t)
	cfgPath := filepath.Join(t.TempDir(), "run-config.json")
	require.NoError(t, os.WriteFile(cfgPath, rawJSON, 0o600))

	stdout := &syncBuffer{}
	stderr := &syncBuffer{}
	cmd := exec.Command(bin, "run", "-c", cfgPath)
	cmd.Stdout = stdout
	cmd.Stderr = stderr
	require.NoError(t, cmd.Start())

	proc := &CLIProcess{
		cmd:    cmd,
		stdout: stdout,
		stderr: stderr,
		doneCh: make(chan error, 1),
	}
	go func() {
		proc.doneCh <- cmd.Wait()
	}()
	t.Cleanup(func() {
		_ = proc.Stop(5 * time.Second)
	})

	deadline := time.Now().Add(8 * time.Second)
	for _, port := range waitTCPPorts {
		addr := net.JoinHostPort("127.0.0.1", strconv.Itoa(int(port)))
		for {
			select {
			case err := <-proc.doneCh:
				proc.recordExit(err)
				t.Fatalf("sing-box run exited prematurely (%v)\nstdout:\n%s\nstderr:\n%s", err, stdout.String(), stderr.String())
			default:
			}
			conn, dialErr := net.DialTimeout("tcp", addr, 100*time.Millisecond)
			if dialErr == nil {
				_ = conn.Close()
				break
			}
			if time.Now().After(deadline) {
				t.Fatalf("timed out waiting for sing-box run port %d\nstdout:\n%s\nstderr:\n%s", port, stdout.String(), stderr.String())
			}
			time.Sleep(25 * time.Millisecond)
		}
	}
	return proc
}

func (p *CLIProcess) recordExit(err error) {
	p.exitMu.Lock()
	defer p.exitMu.Unlock()
	if !p.waited {
		p.waited = true
		p.exitErr = err
	}
}

func (p *CLIProcess) Stdout() string             { return p.stdout.String() }
func (p *CLIProcess) Stderr() string             { return p.stderr.String() }
func (p *CLIProcess) Signal(sig os.Signal) error { return p.cmd.Process.Signal(sig) }

// Stop sends SIGTERM and waits up to timeout before falling back to SIGKILL.
func (p *CLIProcess) Stop(timeout time.Duration) error {
	p.stopMu.Do(func() {
		p.exitMu.Lock()
		alreadyExited := p.waited
		p.exitMu.Unlock()
		if alreadyExited {
			return
		}
		_ = p.cmd.Process.Signal(syscall.SIGTERM)
		select {
		case err := <-p.doneCh:
			p.recordExit(err)
		case <-time.After(timeout):
			_ = p.cmd.Process.Kill()
			err := <-p.doneCh
			p.recordExit(err)
		}
	})
	p.exitMu.Lock()
	defer p.exitMu.Unlock()
	return p.exitErr
}

// ---------------------------------------------------------------------------
// 3. Collision-Free Ephemeral Port Allocator & Opaque Import Verifier
// ---------------------------------------------------------------------------

var (
	portAllocMu    sync.Mutex
	allocatedPorts = make(map[uint16]struct{})
)

// AllocFreeTCPPort reserves an unused loopback TCP port not yet handed out in this test process.
func AllocFreeTCPPort(t testing.TB) uint16 {
	t.Helper()
	portAllocMu.Lock()
	defer portAllocMu.Unlock()
	for range 64 {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		require.NoError(t, err)
		port := uint16(ln.Addr().(*net.TCPAddr).Port)
		_ = ln.Close()
		if _, taken := allocatedPorts[port]; !taken {
			allocatedPorts[port] = struct{}{}
			return port
		}
	}
	t.Fatal("failed to allocate unique ephemeral TCP port")
	return 0
}

func isAddrInUseError(err error) bool {
	if err == nil {
		return false
	}
	return errors.Is(err, syscall.EADDRINUSE) || strings.Contains(err.Error(), "address already in use")
}

// VerifyOpaqueImports parses Go source files in dir and asserts zero imports of
// internal protocol/aether or internal sing-box/sing packages.
func VerifyOpaqueImports(t testing.TB, dir string) {
	t.Helper()
	entries, err := os.ReadDir(dir)
	require.NoError(t, err)

	allowedSingBox := map[string]bool{
		"github.com/sagernet/sing-box":          true,
		"github.com/sagernet/sing-box/constant": true,
		"github.com/sagernet/sing-box/include":  true,
		"github.com/sagernet/sing-box/option":   true,
		"github.com/sagernet/sing-box/schema":   true,
	}

	fset := token.NewFileSet()
	checkedFiles := 0
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".go") {
			continue
		}
		checkedFiles++
		fullPath := filepath.Join(dir, entry.Name())
		astFile, parseErr := parser.ParseFile(fset, fullPath, nil, parser.ImportsOnly)
		require.NoError(t, parseErr, "parse %s", fullPath)
		require.Equal(t, "e2e_test", astFile.Name.Name, "file %s must declare package e2e_test", entry.Name())
		for _, imp := range astFile.Imports {
			impPath, unqErr := strconv.Unquote(imp.Path.Value)
			require.NoError(t, unqErr)
			if strings.HasPrefix(impPath, "github.com/sagernet/sing-box") {
				require.True(t, allowedSingBox[impPath],
					"forbidden internal sing-box import %q in %s", impPath, entry.Name())
			}
			require.False(t, strings.HasPrefix(impPath, "github.com/sagernet/sing/"),
				"forbidden internal sing import %q in %s", impPath, entry.Name())
		}
	}
	require.Positive(t, checkedFiles, "expected at least one .go file in %s", dir)
}

// ---------------------------------------------------------------------------
// 4. Mock Loopback SNTPv4 Server (Opaque-Box Clock Skew & Rotation Control)
// ---------------------------------------------------------------------------

var ntpEpoch = time.Date(1900, 1, 1, 0, 0, 0, 0, time.UTC)

// MockNTPServer serves RFC 5905 SNTPv4 UDP responses with a dynamically adjustable clock offset.
type MockNTPServer struct {
	conn       net.PacketConn
	addr       string
	port       uint16
	offsetNano atomic.Int64
	requests   atomic.Int64
	doneCh     chan struct{}
	closeOnce  sync.Once
}

// StartMockNTPServer starts an ephemeral loopback SNTPv4 server reporting time.Now().Add(initialOffset).
func StartMockNTPServer(t testing.TB, initialOffset time.Duration) *MockNTPServer {
	t.Helper()
	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	require.NoError(t, err)
	udpAddr := conn.LocalAddr().(*net.UDPAddr)
	srv := &MockNTPServer{
		conn:   conn,
		addr:   udpAddr.String(),
		port:   uint16(udpAddr.Port),
		doneCh: make(chan struct{}),
	}
	srv.offsetNano.Store(int64(initialOffset))
	go srv.serve()
	t.Cleanup(srv.Close)
	return srv
}

func (s *MockNTPServer) Addr() string              { return s.addr }
func (s *MockNTPServer) Port() uint16              { return s.port }
func (s *MockNTPServer) Requests() int64           { return s.requests.Load() }
func (s *MockNTPServer) SetOffset(d time.Duration) { s.offsetNano.Store(int64(d)) }
func (s *MockNTPServer) Offset() time.Duration     { return time.Duration(s.offsetNano.Load()) }

func (s *MockNTPServer) Close() {
	s.closeOnce.Do(func() {
		_ = s.conn.Close()
		<-s.doneCh
	})
}

func toNTPFixed64(t time.Time) uint64 {
	d := t.Sub(ntpEpoch)
	sec := uint64(d / time.Second)
	rem := uint64(d % time.Second)
	frac := (rem << 32) / uint64(time.Second)
	return (sec << 32) | frac
}

func (s *MockNTPServer) serve() {
	defer close(s.doneCh)
	var req [64]byte
	for {
		n, peer, err := s.conn.ReadFrom(req[:])
		if err != nil {
			return
		}
		if n < 48 {
			continue
		}
		s.requests.Add(1)
		virtualNow := time.Now().Add(s.Offset())
		refTime := virtualNow.Add(-1 * time.Second)

		var resp [48]byte
		resp[0] = (0 << 6) | (4 << 3) | 4 // LI=0 (no warning), VN=4, Mode=4 (server)
		resp[1] = 1                       // Stratum 1
		resp[2] = 4                       // Poll
		resp[3] = 0xec                    // Precision = -20 (~1us)
		copy(resp[12:16], "LOCL")
		binary.BigEndian.PutUint64(resp[16:24], toNTPFixed64(refTime))
		copy(resp[24:32], req[40:48]) // OriginTime = client TransmitTime
		binary.BigEndian.PutUint64(resp[32:40], toNTPFixed64(virtualNow))
		binary.BigEndian.PutUint64(resp[40:48], toNTPFixed64(virtualNow))
		_, _ = s.conn.WriteTo(resp[:], peer)
	}
}

// ---------------------------------------------------------------------------
// 5. Loopback TCP Wire-Tap Proxy (Capture, Entropy, EPK Bias, PCAP & Faults)
// ---------------------------------------------------------------------------

type TapDirection uint8

const (
	DirC2S TapDirection = 0 // Client Outbound -> Server Inbound
	DirS2C TapDirection = 1 // Server Inbound  -> Client Outbound
)

func (d TapDirection) String() string {
	if d == DirC2S {
		return "c2s"
	}
	return "s2c"
}

// TapSegment records one TCP Read chunk observed by WireTapProxy.
type TapSegment struct {
	Direction    TapDirection
	Index        int
	StreamOffset int64
	Size         int
	Timestamp    time.Time
	Data         []byte // Populated up to MaxCaptureBytesPerDirection
}

// TapTamperFunc inspects/mutates an in-flight chunk before WireTapProxy writes it downstream.
// Returning dropConn == true immediately closes both sides of the tapped connection.
type TapTamperFunc func(sessionID int, dir TapDirection, streamOffset int64, chunk []byte) (mutated []byte, dropConn bool)

// TapSession stores wire telemetry for one proxied TCP connection.
type TapSession struct {
	ID         int
	ClientAddr string
	AcceptedAt time.Time

	mu          sync.RWMutex
	closedAt    time.Time
	segments    []TapSegment
	c2sCaptured []byte
	s2cCaptured []byte
	totalBytes  [2]int64
	byteHist    [2][256]uint64
	maxCapture  int
}

func (s *TapSession) recordChunk(dir TapDirection, raw []byte, ts time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()

	offset := s.totalBytes[dir]
	s.totalBytes[dir] += int64(len(raw))
	for _, b := range raw {
		s.byteHist[dir][b]++
	}

	dirIdx := 0
	for _, seg := range s.segments {
		if seg.Direction == dir {
			dirIdx++
		}
	}

	var capturedCopy []byte
	curBuf := &s.c2sCaptured
	if dir == DirS2C {
		curBuf = &s.s2cCaptured
	}
	if rem := s.maxCapture - len(*curBuf); rem > 0 {
		take := min(len(raw), rem)
		capturedCopy = append([]byte(nil), raw[:take]...)
		*curBuf = append(*curBuf, raw[:take]...)
	}

	s.segments = append(s.segments, TapSegment{
		Direction:    dir,
		Index:        dirIdx,
		StreamOffset: offset,
		Size:         len(raw),
		Timestamp:    ts,
		Data:         capturedCopy,
	})
}

func (s *TapSession) markClosed() {
	s.mu.Lock()
	if s.closedAt.IsZero() {
		s.closedAt = time.Now()
	}
	s.mu.Unlock()
}

func (s *TapSession) TotalBytes(dir TapDirection) int64 {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.totalBytes[dir]
}

func (s *TapSession) Bytes(dir TapDirection) []byte {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if dir == DirC2S {
		return append([]byte(nil), s.c2sCaptured...)
	}
	return append([]byte(nil), s.s2cCaptured...)
}

func (s *TapSession) Segments() []TapSegment {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]TapSegment, len(s.segments))
	copy(out, s.segments)
	return out
}

func (s *TapSession) SegmentsByDir(dir TapDirection) []TapSegment {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var out []TapSegment
	for _, seg := range s.segments {
		if seg.Direction == dir {
			out = append(out, seg)
		}
	}
	return out
}

func (s *TapSession) FirstSegment(dir TapDirection) (TapSegment, bool) {
	segs := s.SegmentsByDir(dir)
	if len(segs) == 0 {
		return TapSegment{}, false
	}
	return segs[0], true
}

func (s *TapSession) HasSegmentOfExactSize(dir TapDirection, size int) bool {
	for _, seg := range s.SegmentsByDir(dir) {
		if seg.Size == size {
			return true
		}
	}
	return false
}

// ShannonEntropy computes exact Shannon entropy (0.0..8.0 bits/byte) across ALL
// bytes observed in dir (using the O(1)-memory byte frequency histogram).
func (s *TapSession) ShannonEntropy(dir TapDirection) float64 {
	s.mu.RLock()
	total := s.totalBytes[dir]
	hist := s.byteHist[dir]
	s.mu.RUnlock()
	if total == 0 {
		return 0
	}
	invTotal := 1.0 / float64(total)
	var entropy float64
	for _, count := range hist {
		if count == 0 {
			continue
		}
		p := float64(count) * invTotal
		entropy -= p * math.Log2(p)
	}
	return entropy
}

// MaskedClientEPK extracts C2S bytes [32:64] (invariant across 96B single-user and 112B EIH prefixes).
func (s *TapSession) MaskedClientEPK() ([32]byte, bool) {
	var epk [32]byte
	c2s := s.Bytes(DirC2S)
	if len(c2s) < 64 {
		return epk, false
	}
	copy(epk[:], c2s[32:64])
	return epk, true
}

// MaskedServerEPK extracts S2C bytes [32:64] from the 84B Server Response Prefix.
func (s *TapSession) MaskedServerEPK() ([32]byte, bool) {
	var epk [32]byte
	s2c := s.Bytes(DirS2C)
	if len(s2c) < 64 {
		return epk, false
	}
	copy(epk[:], s2c[32:64])
	return epk, true
}

func (s *TapSession) ContainsBytes(dir TapDirection, needle []byte) bool {
	return bytes.Contains(s.Bytes(dir), needle)
}

func (s *TapSession) HasOuterTLSRecordHeader() bool {
	for _, dir := range []TapDirection{DirC2S, DirS2C} {
		b := s.Bytes(dir)
		if len(b) >= 3 && (b[0] == 0x16 || b[0] == 0x14 || b[0] == 0x17) && b[1] == 0x03 && b[2] <= 0x04 {
			return true
		}
	}
	return false
}

// WireTapProxy is a programmable loopback TCP MITM wire-tap and fault injector.
type WireTapProxy struct {
	ln        net.Listener
	addr      string
	port      uint16
	target    string
	maxCap    int
	closeOnce sync.Once
	wg        sync.WaitGroup

	mu            sync.Mutex
	sessions      []*TapSession
	activeConns   map[net.Conn]struct{}
	tamperFn      TapTamperFunc
	tcpBufBytes   int
	pauseCond     *sync.Cond
	readPaused    [2]bool
	blackholeDrop [2]atomic.Bool
}

// StartWireTapProxy starts a loopback TCP wire-tap forwarding to targetAddr.
func StartWireTapProxy(t testing.TB, targetAddr string) *WireTapProxy {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	tcpAddr := ln.Addr().(*net.TCPAddr)

	tap := &WireTapProxy{
		ln:          ln,
		addr:        tcpAddr.String(),
		port:        uint16(tcpAddr.Port),
		target:      targetAddr,
		maxCap:      8 << 20, // 8 MiB raw byte capture per direction per session
		activeConns: make(map[net.Conn]struct{}),
	}
	tap.pauseCond = sync.NewCond(&tap.mu)

	tap.wg.Add(1)
	go tap.acceptLoop()
	t.Cleanup(tap.Close)
	return tap
}

func (p *WireTapProxy) Addr() string { return p.addr }
func (p *WireTapProxy) Port() uint16 { return p.port }

// SetBlackhole enables/disables silent packet dropping (without TCP FIN/RST) for DPD testing.
func (p *WireTapProxy) SetBlackhole(c2sDrop, s2cDrop bool) {
	p.blackholeDrop[DirC2S].Store(c2sDrop)
	p.blackholeDrop[DirS2C].Store(s2cDrop)
}

// SetReadPaused pauses/resumes socket reads on dir to force kernel TCP send/recv window saturation (R-1).
func (p *WireTapProxy) SetReadPaused(dir TapDirection, paused bool) {
	p.mu.Lock()
	p.readPaused[dir] = paused
	p.pauseCond.Broadcast()
	p.mu.Unlock()
}

// SetTCPWindowBytes configures SO_RCVBUF / SO_SNDBUF on newly accepted/dialed tap sockets.
func (p *WireTapProxy) SetTCPWindowBytes(bytes int) {
	p.mu.Lock()
	p.tcpBufBytes = bytes
	p.mu.Unlock()
}

// SetTamperFunc installs an in-flight stream mutator/dropper.
func (p *WireTapProxy) SetTamperFunc(fn TapTamperFunc) {
	p.mu.Lock()
	p.tamperFn = fn
	p.mu.Unlock()
}

// InstallSingleBitFlip flips xorMask at exact byte targetOffset on sessionID (or -1 for any session).
func (p *WireTapProxy) InstallSingleBitFlip(sessionID int, dir TapDirection, targetOffset int64, xorMask byte) {
	var fired atomic.Bool
	p.SetTamperFunc(func(sid int, d TapDirection, offset int64, chunk []byte) ([]byte, bool) {
		if d != dir || (sessionID >= 0 && sid != sessionID) {
			return chunk, false
		}
		if targetOffset >= offset && targetOffset < offset+int64(len(chunk)) {
			if fired.CompareAndSwap(false, true) {
				cp := append([]byte(nil), chunk...)
				cp[targetOffset-offset] ^= xorMask
				return cp, false
			}
		}
		return chunk, false
	})
}

func (p *WireTapProxy) SessionCount() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return len(p.sessions)
}

func (p *WireTapProxy) Sessions() []*TapSession {
	p.mu.Lock()
	defer p.mu.Unlock()
	out := make([]*TapSession, len(p.sessions))
	copy(out, p.sessions)
	return out
}

func (p *WireTapProxy) WaitForSessions(t testing.TB, count int, timeout time.Duration) []*TapSession {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for {
		sessions := p.Sessions()
		if len(sessions) >= count {
			return sessions
		}
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %d wire-tap sessions (got %d)", count, len(sessions))
		}
		time.Sleep(15 * time.Millisecond)
	}
}

// EPKBit255Stats returns (ones, total, ratio) for bit 255 (byte[31] >> 7) of MaskedClientEPK or MaskedServerEPK
// across all recorded sessions. Unmasked X25519 keys have ratio == 0.0; ChaCha20-masked keys have ratio ~ 0.5.
func (p *WireTapProxy) EPKBit255Stats(dir TapDirection) (ones int, total int, ratio float64) {
	for _, s := range p.Sessions() {
		var (
			epk [32]byte
			ok  bool
		)
		if dir == DirC2S {
			epk, ok = s.MaskedClientEPK()
		} else {
			epk, ok = s.MaskedServerEPK()
		}
		if !ok {
			continue
		}
		total++
		if (epk[31] & 0x80) != 0 {
			ones++
		}
	}
	if total > 0 {
		ratio = float64(ones) / float64(total)
	}
	return ones, total, ratio
}

// SavePCAP writes captured segments across all sessions into a standard libpcap (DLT_RAW = 101) file.
func (p *WireTapProxy) SavePCAP(path string) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()

	var ghdr [24]byte
	binary.LittleEndian.PutUint32(ghdr[0:4], 0xa1b2c3d4)
	binary.LittleEndian.PutUint16(ghdr[4:6], 2)
	binary.LittleEndian.PutUint16(ghdr[6:8], 4)
	binary.LittleEndian.PutUint32(ghdr[16:20], 65535)
	binary.LittleEndian.PutUint32(ghdr[20:24], 101) // LINKTYPE_RAW
	if _, err := f.Write(ghdr[:]); err != nil {
		return err
	}

	for _, sess := range p.Sessions() {
		var seq [2]uint32
		for _, seg := range sess.Segments() {
			if len(seg.Data) == 0 {
				continue
			}
			pkt := buildSyntheticIPv4TCPPacket(seg.Direction, uint16(10000+(sess.ID%50000)), p.port, seq[seg.Direction], seg.Data)
			seq[seg.Direction] += uint32(len(seg.Data))

			var rhdr [16]byte
			binary.LittleEndian.PutUint32(rhdr[0:4], uint32(seg.Timestamp.Unix()))
			binary.LittleEndian.PutUint32(rhdr[4:8], uint32(seg.Timestamp.Nanosecond()/1000))
			binary.LittleEndian.PutUint32(rhdr[8:12], uint32(len(pkt)))
			binary.LittleEndian.PutUint32(rhdr[12:16], uint32(len(pkt)))
			if _, err := f.Write(rhdr[:]); err != nil {
				return err
			}
			if _, err := f.Write(pkt); err != nil {
				return err
			}
		}
	}
	return nil
}

func buildSyntheticIPv4TCPPacket(dir TapDirection, clientPort, serverPort uint16, seq uint32, payload []byte) []byte {
	totalLen := 20 + 20 + len(payload)
	pkt := make([]byte, totalLen)
	pkt[0] = 0x45
	binary.BigEndian.PutUint16(pkt[2:4], uint16(totalLen))
	pkt[8] = 64
	pkt[9] = 6 // TCP
	copy(pkt[12:16], []byte{127, 0, 0, 1})
	copy(pkt[16:20], []byte{127, 0, 0, 1})

	srcPort, dstPort := clientPort, serverPort
	if dir == DirS2C {
		srcPort, dstPort = serverPort, clientPort
	}
	binary.BigEndian.PutUint16(pkt[20:22], srcPort)
	binary.BigEndian.PutUint16(pkt[22:24], dstPort)
	binary.BigEndian.PutUint32(pkt[24:28], seq)
	pkt[32] = 5 << 4 // Data offset = 20B
	pkt[33] = 0x18   // PSH | ACK
	binary.BigEndian.PutUint16(pkt[34:36], 65535)
	copy(pkt[40:], payload)
	return pkt
}

func (p *WireTapProxy) Close() {
	p.closeOnce.Do(func() {
		_ = p.ln.Close()
		p.mu.Lock()
		p.readPaused[DirC2S] = false
		p.readPaused[DirS2C] = false
		p.pauseCond.Broadcast()
		for c := range p.activeConns {
			_ = c.Close()
		}
		p.mu.Unlock()
		p.wg.Wait()
	})
}

func (p *WireTapProxy) trackConn(c net.Conn, add bool) {
	p.mu.Lock()
	if add {
		p.activeConns[c] = struct{}{}
	} else {
		delete(p.activeConns, c)
	}
	p.mu.Unlock()
}

func (p *WireTapProxy) acceptLoop() {
	defer p.wg.Done()
	for {
		clientConn, err := p.ln.Accept()
		if err != nil {
			return
		}
		p.wg.Add(1)
		go p.handleConn(clientConn)
	}
}

func configureTapTCPConn(c net.Conn, bufBytes int) {
	if tcpConn, ok := c.(*net.TCPConn); ok {
		_ = tcpConn.SetNoDelay(true)
		if bufBytes > 0 {
			_ = tcpConn.SetReadBuffer(bufBytes)
			_ = tcpConn.SetWriteBuffer(bufBytes)
		}
	}
}

func (p *WireTapProxy) handleConn(clientConn net.Conn) {
	defer p.wg.Done()

	p.mu.Lock()
	bufBytes := p.tcpBufBytes
	sessID := len(p.sessions)
	sess := &TapSession{
		ID:         sessID,
		ClientAddr: clientConn.RemoteAddr().String(),
		AcceptedAt: time.Now(),
		maxCapture: p.maxCap,
	}
	p.sessions = append(p.sessions, sess)
	p.mu.Unlock()

	configureTapTCPConn(clientConn, bufBytes)
	serverConn, err := net.DialTimeout("tcp", p.target, 5*time.Second)
	if err != nil {
		sess.markClosed()
		_ = clientConn.Close()
		return
	}
	configureTapTCPConn(serverConn, bufBytes)

	p.trackConn(clientConn, true)
	p.trackConn(serverConn, true)
	defer func() {
		p.trackConn(clientConn, false)
		p.trackConn(serverConn, false)
		_ = clientConn.Close()
		_ = serverConn.Close()
		sess.markClosed()
	}()

	var pipeWG sync.WaitGroup
	pipeWG.Add(2)
	go func() {
		defer pipeWG.Done()
		p.pump(sess, DirC2S, clientConn, serverConn)
	}()
	go func() {
		defer pipeWG.Done()
		p.pump(sess, DirS2C, serverConn, clientConn)
	}()
	pipeWG.Wait()
}

func (p *WireTapProxy) waitIfPaused(dir TapDirection) {
	p.mu.Lock()
	for p.readPaused[dir] {
		p.pauseCond.Wait()
	}
	p.mu.Unlock()
}

func (p *WireTapProxy) pump(sess *TapSession, dir TapDirection, src, dst net.Conn) {
	buf := make([]byte, 65536)
	for {
		p.waitIfPaused(dir)
		n, rErr := src.Read(buf)
		if n > 0 {
			now := time.Now()
			streamOffset := sess.TotalBytes(dir)
			sess.recordChunk(dir, buf[:n], now)

			if !p.blackholeDrop[dir].Load() {
				outChunk := buf[:n]
				p.mu.Lock()
				tamper := p.tamperFn
				p.mu.Unlock()
				if tamper != nil {
					var drop bool
					outChunk, drop = tamper(sess.ID, dir, streamOffset, outChunk)
					if drop {
						_ = src.Close()
						_ = dst.Close()
						return
					}
				}
				if len(outChunk) > 0 {
					if _, wErr := dst.Write(outChunk); wErr != nil {
						_ = src.Close()
						_ = dst.Close()
						return
					}
				}
			}
		}
		if rErr != nil {
			if errors.Is(rErr, io.EOF) {
				if !p.blackholeDrop[dir].Load() {
					if tcpDst, ok := dst.(*net.TCPConn); ok {
						_ = tcpDst.CloseWrite()
					} else {
						_ = dst.Close()
					}
				}
			} else {
				_ = src.Close()
				_ = dst.Close()
			}
			return
		}
	}
}

// ---------------------------------------------------------------------------
// 6. Active Probe, Truncation, Slowloris & Replay Helpers
// ---------------------------------------------------------------------------

// ProbeResult captures exact timing and TCP FIN vs RST behavior of an inbound port.
type ProbeResult struct {
	BytesReceived  []byte
	Elapsed        time.Duration
	ClosedCleanEOF bool // Server closed via normal TCP FIN (io.EOF with 0 unread bytes)
	ClosedByRST    bool // Server closed via TCP RST (ECONNRESET / SetLinger(0))
	TimedOut       bool // Read timed out at maxWait before server closed
	Err            error
}

// SendRawProbe connects directly to addr, sends payload, optionally half-closes write, and waits up to maxWait for close.
func SendRawProbe(addr string, payload []byte, halfCloseWrite bool, maxWait time.Duration) (ProbeResult, error) {
	conn, err := net.DialTimeout("tcp", addr, 3*time.Second)
	if err != nil {
		return ProbeResult{}, err
	}
	defer conn.Close()
	if tcpConn, ok := conn.(*net.TCPConn); ok {
		_ = tcpConn.SetNoDelay(true)
	}

	start := time.Now()
	if len(payload) > 0 {
		_ = conn.SetWriteDeadline(time.Now().Add(3 * time.Second))
		if _, wErr := conn.Write(payload); wErr != nil {
			elapsed := time.Since(start)
			return ProbeResult{
				Elapsed:     elapsed,
				ClosedByRST: errors.Is(wErr, syscall.ECONNRESET) || errors.Is(wErr, syscall.EPIPE),
				Err:         wErr,
			}, nil
		}
		_ = conn.SetWriteDeadline(time.Time{})
	}
	if halfCloseWrite {
		if tcpConn, ok := conn.(*net.TCPConn); ok {
			_ = tcpConn.CloseWrite()
		}
	}

	_ = conn.SetReadDeadline(time.Now().Add(maxWait))
	received, rErr := io.ReadAll(conn)
	elapsed := time.Since(start)

	var netErr net.Error
	timedOut := errors.As(rErr, &netErr) && netErr.Timeout()
	isRST := errors.Is(rErr, syscall.ECONNRESET)
	cleanEOF := rErr == nil

	return ProbeResult{
		BytesReceived:  received,
		Elapsed:        elapsed,
		ClosedCleanEOF: cleanEOF,
		ClosedByRST:    isRST,
		TimedOut:       timedOut,
		Err:            rErr,
	}, nil
}

// SendSlowlorisProbe drips 1 chunk every stepDelay to test HandshakeTimeout enforcement.
func SendSlowlorisProbe(addr string, chunk []byte, stepDelay time.Duration, maxChunks int, maxWait time.Duration) (ProbeResult, error) {
	conn, err := net.DialTimeout("tcp", addr, 3*time.Second)
	if err != nil {
		return ProbeResult{}, err
	}
	defer conn.Close()
	if tcpConn, ok := conn.(*net.TCPConn); ok {
		_ = tcpConn.SetNoDelay(true)
	}

	start := time.Now()
	readDone := make(chan struct{})
	var (
		received []byte
		rErr     error
	)
	go func() {
		defer close(readDone)
		_ = conn.SetReadDeadline(start.Add(maxWait))
		received, rErr = io.ReadAll(conn)
	}()

	for i := range maxChunks {
		if i > 0 {
			select {
			case <-readDone:
			case <-time.After(stepDelay):
			}
		}
		select {
		case <-readDone:
			break
		default:
		}
		_ = conn.SetWriteDeadline(time.Now().Add(time.Second))
		if _, wErr := conn.Write(chunk); wErr != nil {
			break
		}
	}

	<-readDone
	elapsed := time.Since(start)
	var netErr net.Error
	timedOut := errors.As(rErr, &netErr) && netErr.Timeout()
	return ProbeResult{
		BytesReceived:  received,
		Elapsed:        elapsed,
		ClosedCleanEOF: rErr == nil,
		ClosedByRST:    errors.Is(rErr, syscall.ECONNRESET),
		TimedOut:       timedOut,
		Err:            rErr,
	}, nil
}

// ---------------------------------------------------------------------------
// 7. Opaque-Box Client + WireTap + Server Topology Builder
// ---------------------------------------------------------------------------

// UserSpec describes an AetherUser entry for JSON config generation.
type UserSpec struct {
	Name     string `json:"name,omitempty"`
	Password string `json:"password,omitempty"`
	Key      string `json:"key,omitempty"`
}

// MultiplexServerSpec describes InboundMultiplexOptions for JSON config generation.
type MultiplexServerSpec struct {
	Enabled bool            `json:"enabled,omitempty"`
	Padding bool            `json:"padding,omitempty"`
	Brutal  *BrutalRateSpec `json:"brutal,omitempty"`
}

// MultiplexClientSpec describes OutboundMultiplexOptions for JSON config generation.
type MultiplexClientSpec struct {
	Enabled        bool            `json:"enabled,omitempty"`
	Protocol       string          `json:"protocol,omitempty"`
	MaxConnections int             `json:"max_connections,omitempty"`
	MinStreams     int             `json:"min_streams,omitempty"`
	MaxStreams     int             `json:"max_streams,omitempty"`
	Padding        bool            `json:"padding,omitempty"`
	Brutal         *BrutalRateSpec `json:"brutal,omitempty"`
}

type BrutalRateSpec struct {
	Enabled  bool `json:"enabled,omitempty"`
	UpMbps   int  `json:"up_mbps,omitempty"`
	DownMbps int  `json:"down_mbps,omitempty"`
}

// TopologyConfig parameterizes a full Client Box <-> [WireTapProxy] <-> Server Box rig.
type TopologyConfig struct {
	// Server Aether Inbound settings
	ServerPassword          string
	ServerKey               string
	ServerUsers             []UserSpec
	ServerPrivateKey        string
	ServerTimeWindow        string // e.g. "30s", "2s"
	ServerHandshakeTimeout  string // e.g. "6s", "500ms"
	ServerHeartbeatInterval string // e.g. "30s", "300ms", "-1s"
	ServerDisableShaping    bool
	ServerMultiplex         *MultiplexServerSpec
	ServerPredefinedHosts   map[string]string // domain -> IP resolved locally via in-memory hosts DNS
	ServerAllowedUsers      []string          // if non-empty, only these auth_user (metadata.User) values route to direct
	ServerClockOffset       *time.Duration    // if non-nil, attaches MockNTPServer to Server Box
	ServerLogLevel          string            // default "info" when CaptureLogs is true

	// Client Aether Outbound + Local Proxy Inbound settings
	ClientInboundType       string // default C.TypeMixed ("mixed"), or C.TypeSOCKS ("socks")
	ClientUDPTimeout        string // default "15s"
	ClientSniffTimeout      string // e.g. "50ms" to guarantee 0-RTT InitialPayload coalescing before Dial
	ClientPassword          string
	ClientKey               string
	ClientCipher            string // "", "auto", "aes-256-gcm", "chacha20-poly1305"
	ClientNetwork           any    // nil, "tcp", "udp", or []string{"tcp", "udp"}
	ClientServerPublicKey   string
	ClientHeartbeatInterval string // e.g. "30s", "300ms", "-1s"
	ClientDisableShaping    bool
	ClientMultiplex         *MultiplexClientSpec
	ClientUDPOverTCP        any            // nil, bool, or map[string]any{"enabled": true, "version": 2}
	ClientClockOffset       *time.Duration // if non-nil, attaches MockNTPServer to Client Box
	ClientLogLevel          string

	// Harness controls
	DisableWireTap    bool // if false (default), inserts WireTapProxy between Client Box and Server Box
	CaptureLogs       bool // writes Server & Client logs to temp files accessible via ReadLogs()
	WireTapWindowSize int  // optional SO_RCVBUF/SO_SNDBUF override on WireTapProxy sockets
}

// BoxInstance wraps a running in-process *box.Box and its context/log path.
type BoxInstance struct {
	Box        *box.Box
	Cancel     context.CancelFunc
	RawJSON    []byte
	LogPath    string
	ListenPort uint16
	ListenAddr string
	closeOnce  sync.Once
}

func (b *BoxInstance) Close() error {
	var err error
	b.closeOnce.Do(func() {
		if b.Box != nil {
			err = b.Box.Close()
		}
		if b.Cancel != nil {
			b.Cancel()
		}
	})
	return err
}

func (b *BoxInstance) ReadLogs() string {
	if b.LogPath == "" {
		return ""
	}
	data, _ := os.ReadFile(b.LogPath)
	return string(data)
}

// Topology represents a live end-to-end Client Box <-> [WireTapProxy] <-> Server Box rig.
type Topology struct {
	Server    *BoxInstance
	Client    *BoxInstance
	Tap       *WireTapProxy
	ServerNTP *MockNTPServer
	ClientNTP *MockNTPServer
}

// BuildServerJSON constructs a canonical sing-box JSON config for the Server Box.
func BuildServerJSON(cfg TopologyConfig, listenPort uint16, ntpPort uint16, logPath string) ([]byte, error) {
	aetherIn := map[string]any{
		"type":        C.TypeAether,
		"tag":         "aether-in",
		"listen":      "127.0.0.1",
		"listen_port": listenPort,
		"reuse_addr":  true,
	}
	if cfg.ServerPassword != "" {
		aetherIn["password"] = cfg.ServerPassword
	}
	if cfg.ServerKey != "" {
		aetherIn["key"] = cfg.ServerKey
	}
	if len(cfg.ServerUsers) > 0 {
		aetherIn["users"] = cfg.ServerUsers
	}
	if cfg.ServerPrivateKey != "" {
		aetherIn["private_key"] = cfg.ServerPrivateKey
	}
	if cfg.ServerTimeWindow != "" {
		aetherIn["time_window"] = cfg.ServerTimeWindow
	}
	if cfg.ServerHandshakeTimeout != "" {
		aetherIn["handshake_timeout"] = cfg.ServerHandshakeTimeout
	}
	if cfg.ServerHeartbeatInterval != "" {
		aetherIn["heartbeat_interval"] = cfg.ServerHeartbeatInterval
	}
	if cfg.ServerDisableShaping {
		aetherIn["disable_shaping"] = true
	}
	if cfg.ServerMultiplex != nil {
		aetherIn["multiplex"] = cfg.ServerMultiplex
	}

	logObj := map[string]any{"disabled": true}
	if logPath != "" {
		lvl := cfg.ServerLogLevel
		if lvl == "" {
			lvl = "info"
		}
		logObj = map[string]any{
			"disabled":  false,
			"level":     lvl,
			"output":    logPath,
			"timestamp": true,
		}
	}

	root := map[string]any{
		"log":      logObj,
		"inbounds": []any{aetherIn},
		"outbounds": []any{
			map[string]any{
				"type": C.TypeDirect,
				"tag":  "direct-out",
			},
		},
	}

	routeObj := map[string]any{
		"final": "direct-out",
	}
	if len(cfg.ServerPredefinedHosts) > 0 {
		root["dns"] = map[string]any{
			"servers": []any{
				map[string]any{
					"type":       "hosts",
					"tag":        "hosts-dns",
					"predefined": cfg.ServerPredefinedHosts,
				},
			},
			"final": "hosts-dns",
		}
		routeObj["default_domain_resolver"] = "hosts-dns"
	}
	if len(cfg.ServerAllowedUsers) > 0 {
		routeObj["rules"] = []any{
			map[string]any{
				"auth_user": cfg.ServerAllowedUsers,
				"action":    C.RuleActionTypeRoute,
				"outbound":  "direct-out",
			},
			map[string]any{
				"inbound": []string{"aether-in"},
				"action":  C.RuleActionTypeReject,
			},
		}
	}
	root["route"] = routeObj

	if ntpPort > 0 {
		root["ntp"] = map[string]any{
			"enabled":     true,
			"server":      "127.0.0.1",
			"server_port": ntpPort,
			"interval":    "200ms",
		}
	}
	return json.Marshal(root)
}

// BuildClientJSON constructs a canonical sing-box JSON config for the Client Box.
func BuildClientJSON(cfg TopologyConfig, proxyPort uint16, dialHost string, dialPort uint16, ntpPort uint16, logPath string) ([]byte, error) {
	inType := cfg.ClientInboundType
	if inType == "" {
		inType = C.TypeMixed
	}
	udpTimeout := cfg.ClientUDPTimeout
	if udpTimeout == "" {
		udpTimeout = "15s"
	}
	proxyIn := map[string]any{
		"type":        inType,
		"tag":         "proxy-in",
		"listen":      "127.0.0.1",
		"listen_port": proxyPort,
		"reuse_addr":  true,
		"udp_timeout": udpTimeout,
	}

	aetherOut := map[string]any{
		"type":        C.TypeAether,
		"tag":         "aether-out",
		"server":      dialHost,
		"server_port": dialPort,
	}
	if cfg.ClientPassword != "" {
		aetherOut["password"] = cfg.ClientPassword
	}
	if cfg.ClientKey != "" {
		aetherOut["key"] = cfg.ClientKey
	}
	if cfg.ClientCipher != "" {
		aetherOut["cipher"] = cfg.ClientCipher
	}
	if cfg.ClientNetwork != nil {
		aetherOut["network"] = cfg.ClientNetwork
	}
	if cfg.ClientServerPublicKey != "" {
		aetherOut["public_key"] = cfg.ClientServerPublicKey
	}
	if cfg.ClientHeartbeatInterval != "" {
		aetherOut["heartbeat_interval"] = cfg.ClientHeartbeatInterval
	}
	if cfg.ClientDisableShaping {
		aetherOut["disable_shaping"] = true
	}
	if cfg.ClientMultiplex != nil {
		aetherOut["multiplex"] = cfg.ClientMultiplex
	}
	if cfg.ClientUDPOverTCP != nil {
		aetherOut["udp_over_tcp"] = cfg.ClientUDPOverTCP
	}

	logObj := map[string]any{"disabled": true}
	if logPath != "" {
		lvl := cfg.ClientLogLevel
		if lvl == "" {
			lvl = "info"
		}
		logObj = map[string]any{
			"disabled":  false,
			"level":     lvl,
			"output":    logPath,
			"timestamp": true,
		}
	}

	var rules []any
	if cfg.ClientSniffTimeout != "" {
		rules = append(rules, map[string]any{
			"inbound": []string{"proxy-in"},
			"action":  C.RuleActionTypeSniff,
			"timeout": cfg.ClientSniffTimeout,
		})
	}
	rules = append(rules, map[string]any{
		"inbound":  []string{"proxy-in"},
		"action":   C.RuleActionTypeRoute,
		"outbound": "aether-out",
	})

	root := map[string]any{
		"log":      logObj,
		"inbounds": []any{proxyIn},
		"outbounds": []any{
			aetherOut,
			map[string]any{
				"type": C.TypeDirect,
				"tag":  "direct-out",
			},
		},
		"route": map[string]any{
			"rules": rules,
			"final": "aether-out",
		},
	}

	if ntpPort > 0 {
		root["ntp"] = map[string]any{
			"enabled":     true,
			"server":      "127.0.0.1",
			"server_port": ntpPort,
			"interval":    "200ms",
		}
	}
	return json.Marshal(root)
}

// StartBoxFromJSONBuilder allocates a free loopback port, builds JSON via buildFn(port),
// starts an isolated *box.Box (retrying on EADDRINUSE), and registers t.Cleanup.
func StartBoxFromJSONBuilder(t testing.TB, logPath string, buildFn func(port uint16) ([]byte, error)) (*BoxInstance, error) {
	t.Helper()
	var lastErr error
	for range 6 {
		port := AllocFreeTCPPort(t)
		rawJSON, err := buildFn(port)
		if err != nil {
			return nil, err
		}
		opts, err := UnmarshalBoxOptions(rawJSON)
		if err != nil {
			return nil, err
		}
		ctx, cancel := context.WithCancel(NewBoxContext(context.Background()))
		instance, err := box.New(box.Options{
			Context: ctx,
			Options: opts,
		})
		if err != nil {
			cancel()
			return nil, err
		}
		if startErr := instance.Start(); startErr != nil {
			_ = instance.Close()
			cancel()
			lastErr = startErr
			if isAddrInUseError(startErr) {
				continue
			}
			return nil, startErr
		}
		bi := &BoxInstance{
			Box:        instance,
			Cancel:     cancel,
			RawJSON:    rawJSON,
			LogPath:    logPath,
			ListenPort: port,
			ListenAddr: net.JoinHostPort("127.0.0.1", strconv.Itoa(int(port))),
		}
		t.Cleanup(func() {
			_ = bi.Close()
		})
		return bi, nil
	}
	return nil, lastErr
}

// StartTopology spins up Server Box, optional WireTapProxy, optional MockNTPServers, and Client Box.
func StartTopology(t testing.TB, cfg TopologyConfig) *Topology {
	t.Helper()
	topo, err := TryStartTopology(t, cfg)
	require.NoError(t, err)
	return topo
}

// TryStartTopology is the error-returning variant of StartTopology (for negative startup/config tests).
func TryStartTopology(t testing.TB, cfg TopologyConfig) (*Topology, error) {
	t.Helper()
	var topo Topology

	var serverNTPPort uint16
	if cfg.ServerClockOffset != nil {
		topo.ServerNTP = StartMockNTPServer(t, *cfg.ServerClockOffset)
		serverNTPPort = topo.ServerNTP.Port()
	}
	var clientNTPPort uint16
	if cfg.ClientClockOffset != nil {
		topo.ClientNTP = StartMockNTPServer(t, *cfg.ClientClockOffset)
		clientNTPPort = topo.ClientNTP.Port()
	}

	var serverLogPath, clientLogPath string
	if cfg.CaptureLogs {
		tmp := t.TempDir()
		serverLogPath = filepath.Join(tmp, "server.log")
		clientLogPath = filepath.Join(tmp, "client.log")
	}

	srvInst, err := StartBoxFromJSONBuilder(t, serverLogPath, func(port uint16) ([]byte, error) {
		return BuildServerJSON(cfg, port, serverNTPPort, serverLogPath)
	})
	if err != nil {
		return nil, fmt.Errorf("start server box: %w", err)
	}
	topo.Server = srvInst

	dialPort := srvInst.ListenPort
	if !cfg.DisableWireTap {
		topo.Tap = StartWireTapProxy(t, srvInst.ListenAddr)
		if cfg.WireTapWindowSize > 0 {
			topo.Tap.SetTCPWindowBytes(cfg.WireTapWindowSize)
		}
		dialPort = topo.Tap.Port()
	}

	cliInst, err := StartBoxFromJSONBuilder(t, clientLogPath, func(port uint16) ([]byte, error) {
		return BuildClientJSON(cfg, port, "127.0.0.1", dialPort, clientNTPPort, clientLogPath)
	})
	if err != nil {
		_ = srvInst.Close()
		return nil, fmt.Errorf("start client box: %w", err)
	}
	topo.Client = cliInst
	return &topo, nil
}

// DialSOCKS5 dials targetHostPort through Client Box's SOCKS5 proxy, preserving TCP CloseWrite().
func (topo *Topology) DialSOCKS5(ctx context.Context, targetHostPort string) (*SOCKS5StreamConn, error) {
	return DialSOCKS5TCP(ctx, topo.Client.ListenAddr, targetHostPort)
}

// DialHTTPConnect dials targetHostPort through Client Box's HTTP CONNECT proxy (mixed inbound).
func (topo *Topology) DialHTTPConnect(ctx context.Context, targetHostPort string) (*HTTPConnectConn, error) {
	return DialHTTPConnectTCP(ctx, topo.Client.ListenAddr, targetHostPort)
}

// OpenSOCKS5UDP opens an RFC 1928 SOCKS5 UDP ASSOCIATE session on Client Box.
func (topo *Topology) OpenSOCKS5UDP(ctx context.Context) (*SOCKS5UDPConn, error) {
	return DialSOCKS5UDP(ctx, topo.Client.ListenAddr)
}

// NewHTTPClient returns an *http.Client routed through Client Box via golang.org/x/net/proxy SOCKS5.
func (topo *Topology) NewHTTPClient(tlsCfg *tls.Config, timeout time.Duration) (*http.Client, error) {
	d, err := proxy.SOCKS5("tcp", topo.Client.ListenAddr, nil, proxy.Direct)
	if err != nil {
		return nil, err
	}
	ctxDialer := d.(proxy.ContextDialer)
	if timeout <= 0 {
		timeout = 15 * time.Second
	}
	return &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			DialContext:       ctxDialer.DialContext,
			TLSClientConfig:   tlsCfg,
			ForceAttemptHTTP2: true,
		},
	}, nil
}

// ResetClientNetwork invokes public Box.Network().ResetNetwork(ctx), triggering
// InterfaceUpdated(ctx) -> multiplexDialer.Reset() on aether-out (F24 / R-6).
func (topo *Topology) ResetClientNetwork(ctx context.Context) {
	topo.Client.Box.Network().ResetNetwork(ctx)
}

// ClientMultiplexEnabled queries aether-out's MultiplexEnabled() via public OutboundManager.
func (topo *Topology) ClientMultiplexEnabled() (bool, bool) {
	out, loaded := topo.Client.Box.Outbound().Outbound("aether-out")
	if !loaded {
		return false, false
	}
	muxOut, ok := any(out).(interface{ MultiplexEnabled() bool })
	if !ok {
		return false, false
	}
	return muxOut.MultiplexEnabled(), true
}

// CloseClientIdleConnections triggers IdleConnectionKeeper.CloseIdleConnections() on aether-out.
func (topo *Topology) CloseClientIdleConnections() bool {
	out, loaded := topo.Client.Box.Outbound().Outbound("aether-out")
	if !loaded {
		return false
	}
	keeper, ok := any(out).(interface{ CloseIdleConnections() })
	if !ok {
		return false
	}
	keeper.CloseIdleConnections()
	return true
}

// ---------------------------------------------------------------------------
// 8. Pure-Stdlib SOCKS5 TCP (Half-Close Capable), HTTP CONNECT & SOCKS5 UDP
// ---------------------------------------------------------------------------

func encodeSocksAddrHostPort(hostPort string) ([]byte, error) {
	host, portStr, err := net.SplitHostPort(hostPort)
	if err != nil {
		return nil, err
	}
	portNum, err := strconv.ParseUint(portStr, 10, 16)
	if err != nil {
		return nil, err
	}
	var out []byte
	if addr, ipErr := netip.ParseAddr(host); ipErr == nil {
		if addr.Is4() {
			v4 := addr.As4()
			out = append(out, 0x01)
			out = append(out, v4[:]...)
		} else {
			v6 := addr.As16()
			out = append(out, 0x04)
			out = append(out, v6[:]...)
		}
	} else {
		if len(host) == 0 || len(host) > 255 {
			return nil, fmt.Errorf("invalid socks5 domain length: %d", len(host))
		}
		out = append(out, 0x03, byte(len(host)))
		out = append(out, host...)
	}
	var portBytes [2]byte
	binary.BigEndian.PutUint16(portBytes[:], uint16(portNum))
	out = append(out, portBytes[:]...)
	return out, nil
}

func readSocksAddr(r io.Reader) (string, error) {
	var atyp [1]byte
	if _, err := io.ReadFull(r, atyp[:]); err != nil {
		return "", err
	}
	var host string
	switch atyp[0] {
	case 0x01:
		var ip4 [4]byte
		if _, err := io.ReadFull(r, ip4[:]); err != nil {
			return "", err
		}
		host = netip.AddrFrom4(ip4).String()
	case 0x04:
		var ip6 [16]byte
		if _, err := io.ReadFull(r, ip6[:]); err != nil {
			return "", err
		}
		host = netip.AddrFrom16(ip6).String()
	case 0x03:
		var dlen [1]byte
		if _, err := io.ReadFull(r, dlen[:]); err != nil {
			return "", err
		}
		dom := make([]byte, dlen[0])
		if _, err := io.ReadFull(r, dom); err != nil {
			return "", err
		}
		host = string(dom)
	default:
		return "", fmt.Errorf("unsupported socks5 atyp: 0x%02x", atyp[0])
	}
	var portBuf [2]byte
	if _, err := io.ReadFull(r, portBuf[:]); err != nil {
		return "", err
	}
	port := binary.BigEndian.Uint16(portBuf[:])
	return net.JoinHostPort(host, strconv.Itoa(int(port))), nil
}

// SOCKS5StreamConn wraps *net.TCPConn directly so CloseWrite() propagates TCP FIN.
type SOCKS5StreamConn struct {
	*net.TCPConn
	BoundAddr string
}

// DialSOCKS5TCP performs an RFC 1928 CONNECT handshake without client-side DNS resolution.
func DialSOCKS5TCP(ctx context.Context, proxyAddr, targetHostPort string) (*SOCKS5StreamConn, error) {
	addrBytes, err := encodeSocksAddrHostPort(targetHostPort)
	if err != nil {
		return nil, err
	}
	var d net.Dialer
	rawConn, err := d.DialContext(ctx, "tcp", proxyAddr)
	if err != nil {
		return nil, err
	}
	tcpConn := rawConn.(*net.TCPConn)
	_ = tcpConn.SetNoDelay(true)

	stop := context.AfterFunc(ctx, func() { _ = tcpConn.Close() })
	defer stop()

	if _, err := tcpConn.Write([]byte{0x05, 0x01, 0x00}); err != nil {
		_ = tcpConn.Close()
		return nil, err
	}
	var authResp [2]byte
	if _, err := io.ReadFull(tcpConn, authResp[:]); err != nil {
		_ = tcpConn.Close()
		return nil, err
	}
	if authResp[0] != 0x05 || authResp[1] != 0x00 {
		_ = tcpConn.Close()
		return nil, fmt.Errorf("socks5 auth rejected: %x", authResp)
	}

	req := append([]byte{0x05, 0x01, 0x00}, addrBytes...)
	if _, err := tcpConn.Write(req); err != nil {
		_ = tcpConn.Close()
		return nil, err
	}
	var hdr [3]byte
	if _, err := io.ReadFull(tcpConn, hdr[:]); err != nil {
		_ = tcpConn.Close()
		return nil, err
	}
	if hdr[0] != 0x05 || hdr[1] != 0x00 {
		_ = tcpConn.Close()
		return nil, fmt.Errorf("socks5 connect failed with reply code 0x%02x", hdr[1])
	}
	bnd, err := readSocksAddr(tcpConn)
	if err != nil {
		_ = tcpConn.Close()
		return nil, err
	}
	return &SOCKS5StreamConn{TCPConn: tcpConn, BoundAddr: bnd}, nil
}

// HTTPConnectConn wraps an HTTP CONNECT tunnel preserving buffered bytes and TCP CloseWrite().
type HTTPConnectConn struct {
	*net.TCPConn
	br *bufio.Reader
}

func (c *HTTPConnectConn) Read(p []byte) (int, error) {
	return c.br.Read(p)
}

// DialHTTPConnectTCP establishes an HTTP CONNECT tunnel via mixed/http inbound.
func DialHTTPConnectTCP(ctx context.Context, proxyAddr, targetHostPort string) (*HTTPConnectConn, error) {
	var d net.Dialer
	rawConn, err := d.DialContext(ctx, "tcp", proxyAddr)
	if err != nil {
		return nil, err
	}
	tcpConn := rawConn.(*net.TCPConn)
	_ = tcpConn.SetNoDelay(true)

	stop := context.AfterFunc(ctx, func() { _ = tcpConn.Close() })
	defer stop()

	reqStr := fmt.Sprintf("CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", targetHostPort, targetHostPort)
	if _, err := tcpConn.Write([]byte(reqStr)); err != nil {
		_ = tcpConn.Close()
		return nil, err
	}
	br := bufio.NewReader(tcpConn)
	resp, err := http.ReadResponse(br, &http.Request{Method: http.MethodConnect, URL: &url.URL{Host: targetHostPort}})
	if err != nil {
		_ = tcpConn.Close()
		return nil, err
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		_ = tcpConn.Close()
		return nil, fmt.Errorf("HTTP CONNECT failed with status %s", resp.Status)
	}
	return &HTTPConnectConn{TCPConn: tcpConn, br: br}, nil
}

// SOCKS5UDPConn implements net.PacketConn + domain-addressed UDP over RFC 1928 UDP ASSOCIATE.
type SOCKS5UDPConn struct {
	ctrlConn  net.Conn
	udpConn   *net.UDPConn
	relayAddr *net.UDPAddr
	closeOnce sync.Once
}

var _ net.PacketConn = (*SOCKS5UDPConn)(nil)

// DialSOCKS5UDP negotiates SOCKS5 UDP ASSOCIATE on proxyAddr and opens a matching IPv4/IPv6 local UDP socket.
func DialSOCKS5UDP(ctx context.Context, proxyAddr string) (*SOCKS5UDPConn, error) {
	var d net.Dialer
	ctrlConn, err := d.DialContext(ctx, "tcp", proxyAddr)
	if err != nil {
		return nil, err
	}
	if tcpConn, ok := ctrlConn.(*net.TCPConn); ok {
		_ = tcpConn.SetNoDelay(true)
	}

	stop := context.AfterFunc(ctx, func() { _ = ctrlConn.Close() })
	defer stop()

	if _, err := ctrlConn.Write([]byte{0x05, 0x01, 0x00}); err != nil {
		_ = ctrlConn.Close()
		return nil, err
	}
	var authResp [2]byte
	if _, err := io.ReadFull(ctrlConn, authResp[:]); err != nil {
		_ = ctrlConn.Close()
		return nil, err
	}
	if authResp[0] != 0x05 || authResp[1] != 0x00 {
		_ = ctrlConn.Close()
		return nil, fmt.Errorf("socks5 udp auth failed: %x", authResp)
	}

	assocReq := []byte{0x05, 0x03, 0x00, 0x01, 0, 0, 0, 0, 0, 0}
	if _, err := ctrlConn.Write(assocReq); err != nil {
		_ = ctrlConn.Close()
		return nil, err
	}
	var hdr [3]byte
	if _, err := io.ReadFull(ctrlConn, hdr[:]); err != nil {
		_ = ctrlConn.Close()
		return nil, err
	}
	if hdr[0] != 0x05 || hdr[1] != 0x00 {
		_ = ctrlConn.Close()
		return nil, fmt.Errorf("socks5 udp associate failed: 0x%02x", hdr[1])
	}
	bndHostPort, err := readSocksAddr(ctrlConn)
	if err != nil {
		_ = ctrlConn.Close()
		return nil, err
	}
	relayUDPAddr, err := net.ResolveUDPAddr("udp", bndHostPort)
	if err != nil {
		_ = ctrlConn.Close()
		return nil, err
	}
	if relayUDPAddr.IP.IsUnspecified() {
		proxyHost, _, _ := net.SplitHostPort(proxyAddr)
		relayUDPAddr.IP = net.ParseIP(proxyHost)
	}

	udpNet := "udp4"
	localBind := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0}
	if relayUDPAddr.IP != nil && relayUDPAddr.IP.To4() == nil {
		udpNet = "udp6"
		localBind = &net.UDPAddr{IP: net.IPv6loopback, Port: 0}
	}
	udpLn, err := net.ListenUDP(udpNet, localBind)
	if err != nil {
		_ = ctrlConn.Close()
		return nil, err
	}
	_ = udpLn.SetReadBuffer(2 << 20)
	_ = udpLn.SetWriteBuffer(2 << 20)

	return &SOCKS5UDPConn{
		ctrlConn:  ctrlConn,
		udpConn:   udpLn,
		relayAddr: relayUDPAddr,
	}, nil
}

// WriteToHostPort sends a UDP datagram to an IP:port or FQDN:port (ATYP=0x03) without client DNS lookup.
func (c *SOCKS5UDPConn) WriteToHostPort(payload []byte, targetHostPort string) error {
	addrBytes, err := encodeSocksAddrHostPort(targetHostPort)
	if err != nil {
		return err
	}
	pkt := make([]byte, 0, 3+len(addrBytes)+len(payload))
	pkt = append(pkt, 0x00, 0x00, 0x00) // RSV(2B), FRAG=0(1B)
	pkt = append(pkt, addrBytes...)
	pkt = append(pkt, payload...)
	_, err = c.udpConn.WriteToUDP(pkt, c.relayAddr)
	return err
}

func (c *SOCKS5UDPConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	if err := c.WriteToHostPort(p, addr.String()); err != nil {
		return 0, err
	}
	return len(p), nil
}

// ReadFromHostPort reads a UDP datagram and returns (n, sourceHostPort, error).
func (c *SOCKS5UDPConn) ReadFromHostPort(p []byte) (int, string, error) {
	buf := make([]byte, 65536)
	n, _, err := c.udpConn.ReadFromUDP(buf)
	if err != nil {
		return 0, "", err
	}
	if n < 4 || buf[2] != 0x00 {
		return 0, "", fmt.Errorf("invalid socks5 udp header (len=%d)", n)
	}
	r := bytes.NewReader(buf[3:n])
	srcHostPort, err := readSocksAddr(r)
	if err != nil {
		return 0, "", err
	}
	payloadLen := r.Len()
	if len(p) < payloadLen {
		_, _ = r.Read(p)
		return len(p), srcHostPort, io.ErrShortBuffer
	}
	nn, _ := r.Read(p)
	return nn, srcHostPort, nil
}

func (c *SOCKS5UDPConn) ReadFrom(p []byte) (int, net.Addr, error) {
	n, srcHostPort, err := c.ReadFromHostPort(p)
	if err != nil && !errors.Is(err, io.ErrShortBuffer) {
		return 0, nil, err
	}
	udpAddr, resolveErr := net.ResolveUDPAddr("udp", srcHostPort)
	if resolveErr != nil {
		return n, dummyAddr(srcHostPort), err
	}
	return n, udpAddr, err
}

func (c *SOCKS5UDPConn) LocalAddr() net.Addr                { return c.udpConn.LocalAddr() }
func (c *SOCKS5UDPConn) SetDeadline(t time.Time) error      { return c.udpConn.SetDeadline(t) }
func (c *SOCKS5UDPConn) SetReadDeadline(t time.Time) error  { return c.udpConn.SetReadDeadline(t) }
func (c *SOCKS5UDPConn) SetWriteDeadline(t time.Time) error { return c.udpConn.SetWriteDeadline(t) }

func (c *SOCKS5UDPConn) Close() error {
	var err error
	c.closeOnce.Do(func() {
		err = errors.Join(c.udpConn.Close(), c.ctrlConn.Close())
	})
	return err
}

type dummyAddr string

func (d dummyAddr) Network() string { return "udp" }
func (d dummyAddr) String() string  { return string(d) }

// ---------------------------------------------------------------------------
// 9. Local Go Target Servers (TCP Echo, Server-First, Half-Close, HTTPS, UDP)
// ---------------------------------------------------------------------------

type TCPEchoTarget struct {
	ln          net.Listener
	addr        string
	port        uint16
	conns       atomic.Int64
	bytesEchoed atomic.Int64
	wg          sync.WaitGroup
	closeOnce   sync.Once
}

func StartTCPEchoTarget(t testing.TB) *TCPEchoTarget {
	t.Helper()
	return StartTCPEchoTargetOn(t, "tcp", "127.0.0.1:0")
}

func StartTCPEchoTargetOn(t testing.TB, network, listenAddr string) *TCPEchoTarget {
	t.Helper()
	ln, err := net.Listen(network, listenAddr)
	require.NoError(t, err)
	tcpAddr := ln.Addr().(*net.TCPAddr)
	srv := &TCPEchoTarget{
		ln:   ln,
		addr: tcpAddr.String(),
		port: uint16(tcpAddr.Port),
	}
	srv.wg.Add(1)
	go func() {
		defer srv.wg.Done()
		for {
			conn, acceptErr := ln.Accept()
			if acceptErr != nil {
				return
			}
			srv.conns.Add(1)
			srv.wg.Add(1)
			go func(c net.Conn) {
				defer srv.wg.Done()
				defer c.Close()
				if tc, ok := c.(*net.TCPConn); ok {
					_ = tc.SetNoDelay(true)
				}
				n, _ := io.Copy(c, c)
				srv.bytesEchoed.Add(n)
				if tc, ok := c.(*net.TCPConn); ok {
					_ = tc.CloseWrite()
				}
			}(conn)
		}
	}()
	t.Cleanup(srv.Close)
	return srv
}

func (s *TCPEchoTarget) Addr() string       { return s.addr }
func (s *TCPEchoTarget) Port() uint16       { return s.port }
func (s *TCPEchoTarget) Connections() int64 { return s.conns.Load() }
func (s *TCPEchoTarget) BytesEchoed() int64 { return s.bytesEchoed.Load() }
func (s *TCPEchoTarget) Close() {
	s.closeOnce.Do(func() {
		_ = s.ln.Close()
		s.wg.Wait()
	})
}

// StartServerSpeaksFirstTarget immediately writes banner upon TCP accept before reading,
// then echoes any subsequent client bytes.
func StartServerSpeaksFirstTarget(t testing.TB, banner []byte) *TCPEchoTarget {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	tcpAddr := ln.Addr().(*net.TCPAddr)
	srv := &TCPEchoTarget{
		ln:   ln,
		addr: tcpAddr.String(),
		port: uint16(tcpAddr.Port),
	}
	bannerCopy := append([]byte(nil), banner...)
	srv.wg.Add(1)
	go func() {
		defer srv.wg.Done()
		for {
			conn, acceptErr := ln.Accept()
			if acceptErr != nil {
				return
			}
			srv.conns.Add(1)
			srv.wg.Add(1)
			go func(c net.Conn) {
				defer srv.wg.Done()
				defer c.Close()
				if tc, ok := c.(*net.TCPConn); ok {
					_ = tc.SetNoDelay(true)
				}
				if _, wErr := c.Write(bannerCopy); wErr != nil {
					return
				}
				n, _ := io.Copy(c, c)
				srv.bytesEchoed.Add(n)
			}(conn)
		}
	}()
	t.Cleanup(srv.Close)
	return srv
}

// HalfCloseTarget waits until it receives io.EOF (client CloseWrite) BEFORE writing back
// [32B SHA-256 of received || 8B uint64 BE byte count || trailer], proving true TCP half-close.
type HalfCloseTarget struct {
	ln        net.Listener
	addr      string
	port      uint16
	wg        sync.WaitGroup
	closeOnce sync.Once
}

func StartTCPHalfCloseTarget(t testing.TB, trailer []byte) *HalfCloseTarget {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	tcpAddr := ln.Addr().(*net.TCPAddr)
	srv := &HalfCloseTarget{
		ln:   ln,
		addr: tcpAddr.String(),
		port: uint16(tcpAddr.Port),
	}
	trailerCopy := append([]byte(nil), trailer...)
	srv.wg.Add(1)
	go func() {
		defer srv.wg.Done()
		for {
			conn, acceptErr := ln.Accept()
			if acceptErr != nil {
				return
			}
			srv.wg.Add(1)
			go func(c net.Conn) {
				defer srv.wg.Done()
				defer c.Close()
				if tc, ok := c.(*net.TCPConn); ok {
					_ = tc.SetNoDelay(true)
				}
				h := sha256.New()
				total, rErr := io.Copy(h, c)
				if rErr != nil {
					return
				}
				var lenBuf [8]byte
				binary.BigEndian.PutUint64(lenBuf[:], uint64(total))
				resp := make([]byte, 0, 32+8+len(trailerCopy))
				resp = append(resp, h.Sum(nil)...)
				resp = append(resp, lenBuf[:]...)
				resp = append(resp, trailerCopy...)
				_, _ = c.Write(resp)
				if tc, ok := c.(*net.TCPConn); ok {
					_ = tc.CloseWrite()
				}
			}(conn)
		}
	}()
	t.Cleanup(srv.Close)
	return srv
}

func (s *HalfCloseTarget) Addr() string { return s.addr }
func (s *HalfCloseTarget) Port() uint16 { return s.port }
func (s *HalfCloseTarget) Close() {
	s.closeOnce.Do(func() {
		_ = s.ln.Close()
		s.wg.Wait()
	})
}

// TLS13HTTPSTarget serves TLS 1.3 HTTPS (HTTP/1.1 & H2) on 127.0.0.1:0 with an ephemeral ECDSA P-256 cert.
type TLS13HTTPSTarget struct {
	ln       net.Listener
	server   *http.Server
	certPool *x509.CertPool
	addr     string
	port     uint16
}

func StartTLS13HTTPSTarget(t testing.TB, extraDNSNames ...string) *TLS13HTTPSTarget {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	dnsNames := append([]string{"localhost", "tls.aether.test", "echo.aether.test"}, extraDNSNames...)
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "tls.aether.test"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IsCA:                  true,
		BasicConstraintsValid: true,
		DNSNames:              dnsNames,
		IPAddresses:           []net.IP{net.IPv4(127, 0, 0, 1), net.IPv6loopback},
	}
	derBytes, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	require.NoError(t, err)

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
	keyDER, err := x509.MarshalECPrivateKey(priv)
	require.NoError(t, err)
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})

	tlsCert, err := tls.X509KeyPair(certPEM, keyPEM)
	require.NoError(t, err)
	pool := x509.NewCertPool()
	require.True(t, pool.AppendCertsFromPEM(certPEM))

	mux := http.NewServeMux()
	mux.HandleFunc("/ping", func(w http.ResponseWriter, r *http.Request) {
		sni := ""
		if r.TLS != nil {
			sni = r.TLS.ServerName
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprintf(w, `{"ok":true,"proto":%q,"sni":%q}`, r.Proto, sni)
	})
	mux.HandleFunc("/bytes", func(w http.ResponseWriter, r *http.Request) {
		n, _ := strconv.Atoi(r.URL.Query().Get("n"))
		if n < 0 {
			n = 0
		}
		payload := DeterministicBytes(uint64(n)+0xa37e, n)
		sum := sha256.Sum256(payload)
		w.Header().Set("X-SHA256", hex.EncodeToString(sum[:]))
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(payload)
	})
	mux.HandleFunc("/echo", func(w http.ResponseWriter, r *http.Request) {
		body, readErr := io.ReadAll(r.Body)
		if readErr != nil {
			http.Error(w, readErr.Error(), http.StatusBadRequest)
			return
		}
		sum := sha256.Sum256(body)
		w.Header().Set("X-SHA256", hex.EncodeToString(sum[:]))
		w.Header().Set("X-Received-Bytes", strconv.Itoa(len(body)))
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(body)
	})

	rawLn, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	tcpAddr := rawLn.Addr().(*net.TCPAddr)

	serverTLSCfg := &tls.Config{
		Certificates: []tls.Certificate{tlsCert},
		MinVersion:   tls.VersionTLS13,
		MaxVersion:   tls.VersionTLS13,
		NextProtos:   []string{"h2", "http/1.1"},
	}
	tlsLn := tls.NewListener(rawLn, serverTLSCfg)
	srv := &http.Server{Handler: mux}
	go func() { _ = srv.Serve(tlsLn) }()

	target := &TLS13HTTPSTarget{
		ln:       rawLn,
		server:   srv,
		certPool: pool,
		addr:     tcpAddr.String(),
		port:     uint16(tcpAddr.Port),
	}
	t.Cleanup(func() {
		_ = srv.Close()
		_ = rawLn.Close()
	})
	return target
}

func (s *TLS13HTTPSTarget) Addr() string { return s.addr }
func (s *TLS13HTTPSTarget) Port() uint16 { return s.port }

func (s *TLS13HTTPSTarget) ClientTLSConfig(serverName string) *tls.Config {
	if serverName == "" {
		serverName = "tls.aether.test"
	}
	return &tls.Config{
		RootCAs:    s.certPool,
		ServerName: serverName,
		MinVersion: tls.VersionTLS13,
		MaxVersion: tls.VersionTLS13,
	}
}

// UDPEchoTarget echoes UDP datagrams and records the latest observed client NAT source address.
type UDPEchoTarget struct {
	conn       *net.UDPConn
	addr       string
	port       uint16
	packets    atomic.Int64
	lastSource atomic.Value // stores *net.UDPAddr
	doneCh     chan struct{}
	closeOnce  sync.Once
}

func StartUDPEchoTarget(t testing.TB) *UDPEchoTarget {
	t.Helper()
	return StartUDPEchoTargetOn(t, "udp", "127.0.0.1:0")
}

func StartUDPEchoTargetOn(t testing.TB, network, listenAddr string) *UDPEchoTarget {
	t.Helper()
	udpAddr, err := net.ResolveUDPAddr(network, listenAddr)
	require.NoError(t, err)
	conn, err := net.ListenUDP(network, udpAddr)
	require.NoError(t, err)
	_ = conn.SetReadBuffer(2 << 20)
	_ = conn.SetWriteBuffer(2 << 20)

	local := conn.LocalAddr().(*net.UDPAddr)
	srv := &UDPEchoTarget{
		conn:   conn,
		addr:   local.String(),
		port:   uint16(local.Port),
		doneCh: make(chan struct{}),
	}
	go func() {
		defer close(srv.doneCh)
		buf := make([]byte, 65535)
		for {
			n, peer, rErr := conn.ReadFromUDP(buf)
			if rErr != nil {
				return
			}
			srv.packets.Add(1)
			cpPeer := *peer
			srv.lastSource.Store(&cpPeer)
			_, _ = conn.WriteToUDP(buf[:n], peer)
		}
	}()
	t.Cleanup(srv.Close)
	return srv
}

func (s *UDPEchoTarget) Addr() string          { return s.addr }
func (s *UDPEchoTarget) UDPAddr() *net.UDPAddr { return s.conn.LocalAddr().(*net.UDPAddr) }
func (s *UDPEchoTarget) Port() uint16          { return s.port }
func (s *UDPEchoTarget) Packets() int64        { return s.packets.Load() }

func (s *UDPEchoTarget) LastClientUDPAddr() *net.UDPAddr {
	v := s.lastSource.Load()
	if v == nil {
		return nil
	}
	return v.(*net.UDPAddr)
}

// SendUnsolicitedTo pushes a datagram from this UDP socket directly to natAddr (for Full-Cone testing).
func (s *UDPEchoTarget) SendUnsolicitedTo(payload []byte, natAddr *net.UDPAddr) error {
	_, err := s.conn.WriteToUDP(payload, natAddr)
	return err
}

func (s *UDPEchoTarget) Close() {
	s.closeOnce.Do(func() {
		_ = s.conn.Close()
		<-s.doneCh
	})
}

// FullConeUDPHarness bundles PeerA, PeerB (echo peers), and PeerC (unsolicited sender)
// to verify Endpoint-Independent Mapping and Endpoint-Independent Filtering over a single UDP session.
type FullConeUDPHarness struct {
	PeerA *UDPEchoTarget
	PeerB *UDPEchoTarget
	PeerC *UDPEchoTarget
}

func StartFullConeUDPTargets(t testing.TB) *FullConeUDPHarness {
	t.Helper()
	return &FullConeUDPHarness{
		PeerA: StartUDPEchoTarget(t),
		PeerB: StartUDPEchoTarget(t),
		PeerC: StartUDPEchoTarget(t),
	}
}

// DeterministicBytes generates fast, reproducible high-entropy pseudo-random payload bytes (SplitMix64).
func DeterministicBytes(seed uint64, length int) []byte {
	out := make([]byte, length)
	x := seed
	i := 0
	for i+8 <= length {
		x += 0x9e3779b97f4a7c15
		z := x
		z = (z ^ (z >> 30)) * 0xbf58476d1ce4e5b9
		z = (z ^ (z >> 27)) * 0x94d049bb133111eb
		z = z ^ (z >> 31)
		binary.LittleEndian.PutUint64(out[i:i+8], z)
		i += 8
	}
	if i < length {
		x += 0x9e3779b97f4a7c15
		z := x
		z = (z ^ (z >> 30)) * 0xbf58476d1ce4e5b9
		z = (z ^ (z >> 27)) * 0x94d049bb133111eb
		z = z ^ (z >> 31)
		var tail [8]byte
		binary.BigEndian.PutUint64(tail[:], z)
		copy(out[i:], tail[:length-i])
	}
	return out
}
```

---

## 5. Verification Method

Once `worker_e2e_1` writes `protocol/aether/e2e/harness_test.go` (and test files):

1. **AST Opaque-Box Import Gate**:
   - Call `VerifyOpaqueImports(t, ".")` in a top-level test in `protocol/aether/e2e/` to fail immediately if any file imports `protocol/aether` or `github.com/sagernet/sing/...`.
2. **Untagged `-race` Verification (`quic_stub.go:48` Race Regression Gate)**:
   ```bash
   GOPROXY=direct GOSUMDB=off CGO_ENABLED=1 go test -v -race -count=1 ./protocol/aether/e2e/...
   ```
3. **Full 9-Tag `-race` Verification**:
   ```bash
   GOPROXY=direct GOSUMDB=off CGO_ENABLED=1 go test -v -race -count=1 \
     -tags "with_gvisor,with_quic,with_dhcp,with_wireguard,with_utls,with_acme,with_clash_api,badlinkname,tfogo_checklinkname0" \
     -ldflags "$(cat release/LDFLAGS)" \
     ./protocol/aether/e2e/...
   ```
4. **Invalidation Conditions**:
   - Invalidated if `sing-box` changes `box.Context`'s 6-registry parameter arity (`box.go:71-79`), `(*option.Options).UnmarshalJSONContext` (`option/options.go:39`), or RFC 5905 validation rules in `sing/common/ntp/message.go:222-261`.
