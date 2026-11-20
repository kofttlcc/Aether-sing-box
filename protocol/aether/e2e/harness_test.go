package e2e_test

import (
	"bufio"
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
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

	"github.com/miekg/dns"
	box "github.com/sagernet/sing-box"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/include"
	"github.com/sagernet/sing-box/option"
	M "github.com/sagernet/sing/common/metadata"
	"github.com/sagernet/sing/common/ntp"
	"github.com/sagernet/sing/service"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/chacha20"
	"golang.org/x/crypto/chacha20poly1305"
)

// Default9BuildTags matches the legacy 9-tag subset previously used in CI workflows.
const Default9BuildTags = "with_gvisor,with_quic,with_dhcp,with_wireguard,with_utls,with_acme,with_clash_api,badlinkname,tfogo_checklinkname0"

// DefaultOfficialPureGoBuildTags matches upstream's official pure-Go release build tags in release/DEFAULT_BUILD_TAGS_OTHERS.
const DefaultOfficialPureGoBuildTags = "with_gvisor,with_quic,with_dhcp,with_wireguard,with_utls,with_acme,with_clash_api,with_tailscale,with_ccm,with_ocm,with_cloudflared,with_usbip,with_openvpn,with_openconnect,badlinkname,tfogo_checklinkname0"

// FallbackMacGoPath is the darwin/arm64 fallback binary location when `go` is absent from PATH.
const FallbackMacGoPath = "/Users/mac/.local/go/bin/go"

// ---------------------------------------------------------------------------
// 0. Platform Helpers (macOS & Linux), Time Injection & Opaque AST Guard
// ---------------------------------------------------------------------------

// FindGoBinary resolves the `go` compiler path, preferring PATH and falling back
// to /Users/mac/.local/go/bin/go on macOS sandboxes.
func FindGoBinary() (string, error) {
	if p, err := exec.LookPath("go"); err == nil && p != "" {
		return p, nil
	}
	info, err := os.Stat(FallbackMacGoPath)
	if err == nil && !info.IsDir() {
		return FallbackMacGoPath, nil
	}
	return "", fmt.Errorf("go binary not found in PATH or %s", FallbackMacGoPath)
}

// GoCommandEnv returns an environment slice derived from os.Environ() ensuring
// the directory of the resolved Go binary and /Users/mac/.local/go/bin appear
// at the front of PATH, plus any KEY=VALUE overrides.
func GoCommandEnv(overrides ...string) []string {
	var extraDirs []string
	if goBin, err := FindGoBinary(); err == nil {
		extraDirs = append(extraDirs, filepath.Dir(goBin))
	}
	fallbackDir := filepath.Dir(FallbackMacGoPath)
	if len(extraDirs) == 0 || extraDirs[0] != fallbackDir {
		if info, err := os.Stat(fallbackDir); err == nil && info.IsDir() {
			extraDirs = append(extraDirs, fallbackDir)
		}
	}

	env := os.Environ()
	merged := make(map[string]string, len(env)+len(overrides)+1)
	order := make([]string, 0, len(env)+len(overrides)+1)
	setKV := func(k, v string) {
		if _, exists := merged[k]; !exists {
			order = append(order, k)
		}
		merged[k] = v
	}
	for _, entry := range env {
		k, v, ok := strings.Cut(entry, "=")
		if !ok {
			continue
		}
		setKV(k, v)
	}
	if len(extraDirs) > 0 {
		curPath := merged["PATH"]
		prefix := strings.Join(extraDirs, string(os.PathListSeparator))
		if curPath == "" {
			setKV("PATH", prefix)
		} else {
			setKV("PATH", prefix+string(os.PathListSeparator)+curPath)
		}
	}
	for _, entry := range overrides {
		k, v, ok := strings.Cut(entry, "=")
		if !ok {
			continue
		}
		setKV(k, v)
	}
	out := make([]string, 0, len(order))
	for _, k := range order {
		out = append(out, k+"="+merged[k])
	}
	return out
}

// CountOpenFDs counts currently open file descriptors in the current process,
// trying Linux /proc/self/fd first and falling back to macOS /dev/fd.
func CountOpenFDs() (int, error) {
	if entries, err := os.ReadDir("/proc/self/fd"); err == nil {
		return len(entries), nil
	}
	// On macOS fdescfs (/dev/fd), ReadDir invokes fstatat and can fail with EBADF on
	// non-vnode descriptors; Readdirnames uses getdirentries without per-entry stat.
	f, err := os.Open("/dev/fd")
	if err != nil {
		return 0, fmt.Errorf("count open fds failed (/proc/self/fd and open /dev/fd): %w", err)
	}
	dirFDStr := strconv.Itoa(int(f.Fd()))
	names, readErr := f.Readdirnames(-1)
	_ = f.Close()
	if readErr != nil {
		return 0, fmt.Errorf("count open fds failed (readdirnames /dev/fd): %w", readErr)
	}
	count := 0
	for _, name := range names {
		if name == "." || name == ".." || name == dirFDStr {
			continue
		}
		count++
	}
	return count, nil
}

// WaitForOpenFDsAtMost polls CountOpenFDs with GC until open FDs <= maxFDs or timeout expires.
func WaitForOpenFDsAtMost(maxFDs int, timeout time.Duration) (int, error) {
	deadline := time.Now().Add(timeout)
	var last int
	for {
		runtime.GC()
		n, err := CountOpenFDs()
		if err != nil {
			return 0, err
		}
		last = n
		if n <= maxFDs || !time.Now().Before(deadline) {
			return last, nil
		}
		time.Sleep(50 * time.Millisecond)
	}
}

// IsConnReset reports whether err represents a TCP RST ("connection reset by peer")
// on both macOS and Linux.
func IsConnReset(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, syscall.ECONNRESET) {
		return true
	}
	return strings.Contains(strings.ToLower(err.Error()), "connection reset by peer")
}

// IsBrokenPipe reports whether err represents a broken pipe (EPIPE) on write.
func IsBrokenPipe(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, syscall.EPIPE) {
		return true
	}
	return strings.Contains(strings.ToLower(err.Error()), "broken pipe")
}

// IsCleanEOF reports whether err is a clean EOF (TCP FIN) and not a TCP RST.
func IsCleanEOF(err error) bool {
	return errors.Is(err, io.EOF) && !IsConnReset(err)
}

// RepoRoot walks up from os.Getwd() (and runtime.Caller fallback) until go.mod
// declaring module github.com/sagernet/sing-box is found.
func RepoRoot() (string, error) {
	if envRoot := os.Getenv("SING_BOX_REPO_ROOT"); envRoot != "" && isSingBoxRepoRoot(envRoot) {
		return filepath.Clean(envRoot), nil
	}
	dir, err := os.Getwd()
	if err == nil {
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
	}
	if _, file, _, ok := runtime.Caller(0); ok {
		candidate := filepath.Clean(filepath.Join(filepath.Dir(file), "..", "..", ".."))
		if isSingBoxRepoRoot(candidate) {
			return candidate, nil
		}
	}
	return "", errors.New("unable to locate sing-box repository root (go.mod)")
}

func isSingBoxRepoRoot(dir string) bool {
	content, err := os.ReadFile(filepath.Join(dir, "go.mod"))
	if err != nil {
		return false
	}
	return strings.Contains(string(content), "github.com/sagernet/sing-box")
}

// VerifyOpaqueImports AST-scans harness_test.go and tier1..tier4 Go files in
// protocol/aether/e2e (excluding tier5_adversarial_test.go) to enforce strict
// zero dependency on internal protocol/aether and absent/indirect packages.
func VerifyOpaqueImports(t testing.TB) {
	t.Helper()
	root, err := RepoRoot()
	require.NoError(t, err)
	VerifyOpaqueImportsInDir(t, filepath.Join(root, "protocol", "aether", "e2e"))
}

// VerifyOpaqueImportsInDir runs the opaque-box AST import check on the given directory.
func VerifyOpaqueImportsInDir(t testing.TB, dir string) {
	t.Helper()
	entries, err := os.ReadDir(dir)
	require.NoError(t, err)

	forbiddenExact := map[string]bool{
		"go.uber.org/goleak":         true,
		"gopkg.in/yaml.v3":           true,
		"github.com/google/gopacket": true,
	}

	fset := token.NewFileSet()
	checkedFiles := 0
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || !strings.HasSuffix(name, ".go") {
			continue
		}
		if name == "tier5_adversarial_test.go" {
			continue
		}
		checkedFiles++
		fullPath := filepath.Join(dir, name)
		astFile, parseErr := parser.ParseFile(fset, fullPath, nil, parser.ImportsOnly)
		require.NoError(t, parseErr, "parse %s", fullPath)
		require.Equal(t, "e2e_test", astFile.Name.Name, "file %s must declare package e2e_test", name)
		for _, imp := range astFile.Imports {
			impPath, unqErr := strconv.Unquote(imp.Path.Value)
			require.NoError(t, unqErr)
			require.False(t,
				impPath == "github.com/sagernet/sing-box/protocol/aether" ||
					strings.HasPrefix(impPath, "github.com/sagernet/sing-box/protocol/aether/"),
				"forbidden internal protocol/aether import %q in %s", impPath, name,
			)
			require.False(t,
				strings.HasPrefix(impPath, "github.com/sagernet/sing-box/protocol/"),
				"forbidden internal protocol import %q in %s", impPath, name,
			)
			require.False(t,
				forbiddenExact[impPath] || strings.HasPrefix(impPath, "github.com/google/gopacket/"),
				"forbidden external/indirect import %q in %s", impPath, name,
			)
		}
	}
	require.Positive(t, checkedFiles, "expected at least one .go file in %s", dir)
}

// ---------------------------------------------------------------------------
// 1. Box Context Isolation, MockTimeService & Safe Registry Initialization
// ---------------------------------------------------------------------------

type valueFreeContext struct {
	context.Context
}

func (valueFreeContext) Value(any) any { return nil }

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
	fn func(context.Context, In, Out, End, DNS, Svc, Cert) context.Context,
) *registryHolder[In, Out, End, DNS, Svc, Cert] {
	return &registryHolder[In, Out, End, DNS, Svc, Cert]{boxCtx: fn}
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

// WarmBaseRegistries initializes all 6 sing-box protocol registries once.
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

// MockTimeService implements sing's ntp.TimeService interface for deterministic
// E2E clock skew, sliding Bloom rotation, and replay boundary testing.
type MockTimeService struct {
	offsetNano atomic.Int64
	frozen     atomic.Bool
	frozenNano atomic.Int64
	upstream   netip.AddrPort
}

// NewMockTimeService creates a MockTimeService returning time.Now().Add(initialOffset).
func NewMockTimeService(initialOffset time.Duration) *MockTimeService {
	ts := &MockTimeService{}
	ts.offsetNano.Store(int64(initialOffset))
	return ts
}

// NewFrozenMockTimeService creates a MockTimeService frozen at the given instant.
func NewFrozenMockTimeService(fixed time.Time) *MockTimeService {
	ts := &MockTimeService{}
	ts.Freeze(fixed)
	return ts
}

// SetOffset sets a dynamic relative offset applied on top of wall-clock or frozen base time.
func (m *MockTimeService) SetOffset(d time.Duration) {
	m.offsetNano.Store(int64(d))
}

// Advance adds delta to the current offset.
func (m *MockTimeService) Advance(delta time.Duration) {
	m.offsetNano.Add(int64(delta))
}

// Offset returns the current configured offset.
func (m *MockTimeService) Offset() time.Duration {
	return time.Duration(m.offsetNano.Load())
}

// Freeze locks the base clock to fixed (offset still adds on top of fixed).
func (m *MockTimeService) Freeze(fixed time.Time) {
	m.frozenNano.Store(fixed.UnixNano())
	m.frozen.Store(true)
}

// Unfreeze resumes tracking wall-clock time.Now() + offset.
func (m *MockTimeService) Unfreeze() {
	m.frozen.Store(false)
}

// Now returns the simulated current time.
func (m *MockTimeService) Now() time.Time {
	off := time.Duration(m.offsetNano.Load())
	if m.frozen.Load() {
		return time.Unix(0, m.frozenNano.Load()).Add(off)
	}
	return time.Now().Add(off)
}

// TimeFunc satisfies ntp.TimeService.
func (m *MockTimeService) TimeFunc() func() time.Time {
	return m.Now
}

// Upstream satisfies ntp.TimeService.
func (m *MockTimeService) Upstream() netip.AddrPort {
	return m.upstream
}

var _ ntp.TimeService = (*MockTimeService)(nil)

// NewBoxContext returns a fresh context carrying an isolated per-Box registry
// chain and optional MockTimeService implementing ntp.TimeService.
func NewBoxContext(parent context.Context, mockTS ...*MockTimeService) context.Context {
	WarmBaseRegistries()
	if parent == nil {
		parent = context.Background()
	}
	ctx := baseRegistries.boxCtx(
		valueFreeContext{Context: parent},
		baseRegistries.in,
		baseRegistries.out,
		baseRegistries.end,
		baseRegistries.dns,
		baseRegistries.svc,
		baseRegistries.cert,
	)
	if len(mockTS) > 0 && mockTS[0] != nil {
		ctx = service.ContextWith[ntp.TimeService](ctx, mockTS[0])
	}
	return ctx
}

// UnmarshalBoxOptions parses raw sing-box JSON configuration via production
// option.Options.UnmarshalJSONContext.
func UnmarshalBoxOptions(rawJSON []byte, mockTS ...*MockTimeService) (option.Options, error) {
	var opts option.Options
	err := opts.UnmarshalJSONContext(NewBoxContext(context.Background(), mockTS...), rawJSON)
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
// 2. TestMain Singleton 9-Tag CLI Builder, CLI Wrappers & Leak Checking
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

	baselineFDs, fdErr := CountOpenFDs()
	exitCode := m.Run()
	if exitCode != 0 {
		return exitCode
	}

	if leaked := WaitForNoAetherLeaks(3 * time.Second); len(leaked) > 0 {
		fmt.Fprintf(os.Stderr, "e2e TestMain: leaked goroutines after suite:\n%s\n", strings.Join(leaked, "\n---\n"))
		return 1
	}

	if fdErr == nil {
		deadline := time.Now().Add(2 * time.Second)
		for {
			curFDs, err := CountOpenFDs()
			if err == nil && curFDs <= baselineFDs+8 {
				break
			}
			if time.Now().After(deadline) {
				if err == nil {
					fmt.Fprintf(os.Stderr, "e2e TestMain: open FD count grew from baseline=%d to %d\n", baselineFDs, curFDs)
					return 1
				}
				break
			}
			time.Sleep(50 * time.Millisecond)
		}
	}
	return 0
}

// ActiveAetherAndBoxGoroutines returns stack traces of any running goroutines
// rooted in protocol/aether, sing-box Box/route/listener/mux/uot, or WireTapProxy.
func ActiveAetherAndBoxGoroutines() []string {
	buf := make([]byte, 1<<20)
	for {
		n := runtime.Stack(buf, true)
		if n < len(buf) {
			buf = buf[:n]
			break
		}
		buf = make([]byte, len(buf)*2)
	}
	blocks := strings.Split(string(buf), "\n\n")
	var leaked []string
	for _, blk := range blocks {
		if strings.Contains(blk, "ActiveAetherAndBoxGoroutines") || strings.Contains(blk, "WaitForNoAetherLeaks") {
			continue
		}
		if strings.Contains(blk, "protocol/aether.") {
			leaked = append(leaked, blk)
			continue
		}
		if strings.Contains(blk, "sing-box/common/listener") ||
			strings.Contains(blk, "sing-box/route.") ||
			strings.Contains(blk, "sing-box/experimental/") ||
			strings.Contains(blk, "(*WireTapProxy).") ||
			strings.Contains(blk, "(*SpecMockServer).") {
			leaked = append(leaked, blk)
		}
	}
	return leaked
}

// WaitForNoAetherLeaks polls up to timeout for Aether/Box/WireTap goroutines to terminate.
func WaitForNoAetherLeaks(timeout time.Duration) []string {
	deadline := time.Now().Add(timeout)
	for {
		leaked := ActiveAetherAndBoxGoroutines()
		if len(leaked) == 0 || time.Now().After(deadline) {
			return leaked
		}
		time.Sleep(50 * time.Millisecond)
	}
}

func ensureCLIBinaryBuilt() {
	cliBuildOnce.Do(func() {
		goBin, err := FindGoBinary()
		if err != nil {
			cliBuildErr = err
			return
		}
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
		tagsBytes, err := os.ReadFile(filepath.Join(root, "release", "DEFAULT_BUILD_TAGS_OTHERS"))
		if err != nil {
			cliBuildErr = fmt.Errorf("read release/DEFAULT_BUILD_TAGS_OTHERS: %w", err)
			return
		}
		buildTags := strings.TrimSpace(string(tagsBytes))
		if buildTags == "" {
			cliBuildErr = fmt.Errorf("release/DEFAULT_BUILD_TAGS_OTHERS is empty")
			return
		}
		ldflags := fmt.Sprintf(
			"-X 'github.com/sagernet/sing-box/constant.Version=%s' %s -s -w -buildid=",
			C.Version,
			strings.TrimSpace(string(ldflagsBytes)),
		)

		cmd := exec.Command(
			goBin, "build", "-trimpath",
			"-tags", buildTags,
			"-ldflags", ldflags,
			"-o", outBin,
			"./cmd/sing-box",
		)
		cmd.Dir = root
		cmd.Env = GoCommandEnv(
			"CGO_ENABLED=0",
			"GOTOOLCHAIN=local",
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

// CLIBinaryPath returns the singleton pre-built official pure-Go tag sing-box binary path.
func CLIBinaryPath(t testing.TB) string {
	t.Helper()
	ensureCLIBinaryBuilt()
	require.NoError(t, cliBuildErr)
	require.NotEmpty(t, cliBinPath)
	return cliBinPath
}

// SingBoxBinary aliases CLIBinaryPath.
func SingBoxBinary(t testing.TB) string {
	t.Helper()
	return CLIBinaryPath(t)
}

// CLIResult captures stdout, stderr, and exit status from a sing-box CLI invocation.
type CLIResult struct {
	Stdout   string
	Stderr   string
	ExitCode int
	Err      error
}

// RunCLI executes the pre-built official pure-Go tag sing-box CLI binary with args.
func RunCLI(t testing.TB, ctx context.Context, args ...string) CLIResult {
	t.Helper()
	if ctx == nil {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
	}
	bin := CLIBinaryPath(t)
	cmd := exec.CommandContext(ctx, bin, args...)
	cmd.Env = GoCommandEnv()
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

// RunCLITimeout runs the CLI binary bounded by timeout.
func RunCLITimeout(t testing.TB, timeout time.Duration, args ...string) CLIResult {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	return RunCLI(t, ctx, args...)
}

// CheckConfigCLI writes rawJSON to a temp file and validates it via `sing-box check -c <path>`.
func CheckConfigCLI(t testing.TB, rawJSON []byte) CLIResult {
	t.Helper()
	cfgPath := filepath.Join(t.TempDir(), "check.json")
	require.NoError(t, os.WriteFile(cfgPath, rawJSON, 0o600))
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	return RunCLI(t, ctx, "check", "-c", cfgPath)
}

// GenerateAetherKeyCLI runs `sing-box generate aether-key` and validates output.
func GenerateAetherKeyCLI(t testing.TB) string {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	res := RunCLI(t, ctx, "generate", "aether-key")
	require.Equal(t, 0, res.ExitCode, "generate aether-key failed: stderr=%s", res.Stderr)
	return strings.TrimSpace(res.Stdout)
}

// GenerateAetherKeyPairCLI runs `sing-box generate aether-keypair` and parses PrivateKey + PublicKey.
func GenerateAetherKeyPairCLI(t testing.TB) (privKey, pubKey string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	res := RunCLI(t, ctx, "generate", "aether-keypair")
	require.Equal(t, 0, res.ExitCode, "generate aether-keypair failed: stderr=%s", res.Stderr)
	for _, line := range strings.Split(res.Stdout, "\n") {
		line = strings.TrimSpace(line)
		if val, ok := strings.CutPrefix(line, "PrivateKey:"); ok {
			privKey = strings.TrimSpace(val)
		} else if val, ok := strings.CutPrefix(line, "PublicKey:"); ok {
			pubKey = strings.TrimSpace(val)
		}
	}
	require.NotEmpty(t, privKey, "missing PrivateKey in output: %s", res.Stdout)
	require.NotEmpty(t, pubKey, "missing PublicKey in output: %s", res.Stdout)
	return privKey, pubKey
}

// GenerateRandomKeyBase64 generates a non-zero 32-byte standard Base64 key via stdlib CSPRNG.
func GenerateRandomKeyBase64(t testing.TB) string {
	t.Helper()
	var b [32]byte
	for {
		_, err := io.ReadFull(rand.Reader, b[:])
		require.NoError(t, err)
		if !bytes.Equal(b[:], make([]byte, 32)) {
			break
		}
	}
	return base64.StdEncoding.EncodeToString(b[:])
}

// GenerateX25519KeyPairBase64 generates an X25519 keypair encoded with standard Base64,
// matching `sing-box generate aether-keypair`.
func GenerateX25519KeyPairBase64(t testing.TB) (privB64, pubB64 string) {
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

// CLIProcess represents a running `sing-box run` child process with captured stdio.
type CLIProcess struct {
	cmd      *exec.Cmd
	cfgPath  string
	stdout   syncBuffer
	stderr   syncBuffer
	waitOnce sync.Once
	waitCh   chan error
	exitErr  error
	stopped  atomic.Bool
}

// StartCLIDaemon aliases StartCLIProcess for convenience.
func StartCLIDaemon(t testing.TB, rawJSON []byte, waitTCPPorts ...uint16) *CLIProcess {
	t.Helper()
	return StartCLIProcess(t, rawJSON, waitTCPPorts...)
}

// StartCLIDaemonFromFile launches `sing-box run -c cfgPath` with an existing config file.
func StartCLIDaemonFromFile(t testing.TB, cfgPath string, waitTCPPorts ...uint16) *CLIProcess {
	t.Helper()
	bin := CLIBinaryPath(t)
	cmd := exec.Command(bin, "run", "-c", cfgPath)
	cmd.Env = GoCommandEnv()
	proc := &CLIProcess{
		cmd:     cmd,
		cfgPath: cfgPath,
		waitCh:  make(chan error, 1),
	}
	cmd.Stdout = &proc.stdout
	cmd.Stderr = &proc.stderr
	require.NoError(t, cmd.Start())

	go func() {
		err := cmd.Wait()
		proc.recordExit(err)
	}()

	t.Cleanup(func() {
		_ = proc.Stop(5 * time.Second)
	})

	for _, port := range waitTCPPorts {
		addr := net.JoinHostPort("127.0.0.1", strconv.Itoa(int(port)))
		deadline := time.Now().Add(10 * time.Second)
		for {
			select {
			case err := <-proc.waitCh:
				t.Fatalf("sing-box CLI exited prematurely while waiting for %s: %v\nstdout:\n%s\nstderr:\n%s",
					addr, err, proc.Stdout(), proc.Stderr())
			default:
			}
			conn, err := net.DialTimeout("tcp", addr, 150*time.Millisecond)
			if err == nil {
				_ = conn.Close()
				break
			}
			if time.Now().After(deadline) {
				t.Fatalf("timed out waiting for CLI port %s\nstdout:\n%s\nstderr:\n%s",
					addr, proc.Stdout(), proc.Stderr())
			}
			time.Sleep(25 * time.Millisecond)
		}
	}
	return proc
}

// StartCLIProcess writes rawJSON to a temp file and launches `sing-box run -c <path>`,
// optionally polling until all waitTCPPorts accept TCP connections.
func StartCLIProcess(t testing.TB, rawJSON []byte, waitTCPPorts ...uint16) *CLIProcess {
	t.Helper()
	cfgPath := filepath.Join(t.TempDir(), "run.json")
	require.NoError(t, os.WriteFile(cfgPath, rawJSON, 0o600))
	return StartCLIDaemonFromFile(t, cfgPath, waitTCPPorts...)
}

func (p *CLIProcess) recordExit(err error) {
	p.waitOnce.Do(func() {
		p.exitErr = err
		p.stopped.Store(true)
		p.waitCh <- err
		close(p.waitCh)
	})
}

func (p *CLIProcess) PID() int           { return p.cmd.Process.Pid }
func (p *CLIProcess) ConfigPath() string { return p.cfgPath }
func (p *CLIProcess) Stdout() string     { return p.stdout.String() }
func (p *CLIProcess) Stderr() string     { return p.stderr.String() }
func (p *CLIProcess) Signal(sig os.Signal) error {
	if p.cmd.Process == nil {
		return errors.New("process not started")
	}
	return p.cmd.Process.Signal(sig)
}

// Wait waits up to timeout for the CLI process to exit naturally.
func (p *CLIProcess) Wait(timeout time.Duration) (int, error) {
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	select {
	case err, ok := <-p.waitCh:
		if !ok {
			err = p.exitErr
		}
		if err == nil {
			return 0, nil
		}
		var ee *exec.ExitError
		if errors.As(err, &ee) {
			return ee.ExitCode(), err
		}
		return -1, err
	case <-timer.C:
		return -1, context.DeadlineExceeded
	}
}

// Stop sends SIGTERM (or kills after timeout) and waits for full process exit.
func (p *CLIProcess) Stop(timeout time.Duration) error {
	if p.stopped.Load() || p.cmd.Process == nil {
		return p.exitErr
	}
	_ = p.cmd.Process.Signal(syscall.SIGTERM)
	if timeout <= 0 {
		timeout = 3 * time.Second
	}
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	select {
	case err, ok := <-p.waitCh:
		if !ok {
			return p.exitErr
		}
		return err
	case <-timer.C:
		_ = p.cmd.Process.Kill()
		err, ok := <-p.waitCh
		if !ok {
			return p.exitErr
		}
		return err
	}
}

// ---------------------------------------------------------------------------
// 3. Port Allocation & Import Guard
// ---------------------------------------------------------------------------

// AllocFreeTCPPort probes an unused ephemeral loopback TCP port via net.Listen.
func AllocFreeTCPPort(t testing.TB) uint16 {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	port := uint16(ln.Addr().(*net.TCPAddr).Port)
	_ = ln.Close()
	return port
}

// AllocFreeUDPPort probes an unused ephemeral loopback UDP port via net.ListenPacket.
func AllocFreeUDPPort(t testing.TB) uint16 {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	require.NoError(t, err)
	port := uint16(pc.LocalAddr().(*net.UDPAddr).Port)
	_ = pc.Close()
	return port
}

func isAddrInUseError(err error) bool {
	if err == nil {
		return false
	}
	msg := strings.ToLower(err.Error())
	return errors.Is(err, syscall.EADDRINUSE) || strings.Contains(msg, "address already in use")
}

// ---------------------------------------------------------------------------
// 4. Mock Loopback SNTPv4 Server (RFC 5905)
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
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	require.NoError(t, err)
	uaddr := pc.LocalAddr().(*net.UDPAddr)
	srv := &MockNTPServer{
		conn:   pc,
		addr:   uaddr.String(),
		port:   uint16(uaddr.Port),
		doneCh: make(chan struct{}),
	}
	srv.offsetNano.Store(int64(initialOffset))
	go srv.serve()
	t.Cleanup(srv.Close)
	return srv
}

// StartMockSNTPServer aliases StartMockNTPServer.
func StartMockSNTPServer(t testing.TB, initialOffset time.Duration) *MockNTPServer {
	t.Helper()
	return StartMockNTPServer(t, initialOffset)
}

func (s *MockNTPServer) Addr() string              { return s.addr }
func (s *MockNTPServer) Port() uint16              { return s.port }
func (s *MockNTPServer) Requests() int64           { return s.requests.Load() }
func (s *MockNTPServer) SetOffset(d time.Duration) { s.offsetNano.Store(int64(d)) }
func (s *MockNTPServer) Advance(d time.Duration)   { s.offsetNano.Add(int64(d)) }
func (s *MockNTPServer) Offset() time.Duration     { return time.Duration(s.offsetNano.Load()) }

func (s *MockNTPServer) Close() {
	s.closeOnce.Do(func() {
		close(s.doneCh)
		_ = s.conn.Close()
	})
}

func toNTPFixed64(t time.Time) uint64 {
	d := t.UTC().Sub(ntpEpoch)
	secs := uint64(d / time.Second)
	rem := d % time.Second
	frac := (uint64(rem) << 32) / uint64(time.Second)
	return (secs << 32) | frac
}

func (s *MockNTPServer) serve() {
	buf := make([]byte, 512)
	for {
		n, peer, err := s.conn.ReadFrom(buf)
		if err != nil {
			select {
			case <-s.doneCh:
				return
			default:
				if ne, ok := err.(net.Error); ok && ne.Timeout() {
					continue
				}
				return
			}
		}
		if n < 48 {
			continue
		}
		s.requests.Add(1)
		now := time.Now().Add(time.Duration(s.offsetNano.Load()))
		var resp [48]byte
		vn := (buf[0] >> 3) & 0x07
		if vn == 0 {
			vn = 4
		}
		resp[0] = (vn << 3) | 4 // LI=0, VN=vn, Mode=4 (Server)
		resp[1] = 1             // Stratum 1
		resp[2] = buf[2]
		resp[3] = 0xec // Precision (-20)
		copy(resp[12:16], []byte("LOCL"))
		copy(resp[24:32], buf[40:48]) // Originate = client Transmit
		rxNTP := toNTPFixed64(now)
		txNTP := toNTPFixed64(now)
		binary.BigEndian.PutUint64(resp[16:24], txNTP)
		binary.BigEndian.PutUint64(resp[32:40], rxNTP)
		binary.BigEndian.PutUint64(resp[40:48], txNTP)
		_, _ = s.conn.WriteTo(resp[:], peer)
	}
}

// ---------------------------------------------------------------------------
// 5. WireTapProxy, Shannon Entropy, Chi-Square Uniformity & Libpcap Writer
// ---------------------------------------------------------------------------

// TapDirection identifies stream flow relative to Client -> Server.
type TapDirection uint8

const (
	DirC2S TapDirection = 0
	DirS2C TapDirection = 1
)

func (d TapDirection) String() string {
	if d == DirC2S {
		return "C2S"
	}
	return "S2C"
}

const MaxCaptureBytesPerDirection = 8 * 1024 * 1024

// TapSegment records one raw TCP read chunk observed across the proxy.
type TapSegment struct {
	Direction    TapDirection
	Index        int
	StreamOffset int64
	Size         int
	Timestamp    time.Time
	Data         []byte
}

// TapTamperFunc mutates or drops forwarded wire bytes in real time.
type TapTamperFunc func(sessionID int, dir TapDirection, streamOffset int64, chunk []byte) (mutated []byte, dropConn bool)

// TapSession captures full metadata and byte streams for one proxied TCP connection.
type TapSession struct {
	ID         int
	ClientAddr string
	AcceptedAt time.Time

	mu        sync.RWMutex
	segments  []TapSegment
	buf       [2]bytes.Buffer
	total     [2]int64
	closed    bool
	closedCh  chan struct{}
	closeOnce sync.Once
}

func newTapSession(id int, clientAddr string) *TapSession {
	return &TapSession{
		ID:         id,
		ClientAddr: clientAddr,
		AcceptedAt: time.Now(),
		closedCh:   make(chan struct{}),
	}
}

func (s *TapSession) recordChunk(dir TapDirection, raw []byte, ts time.Time) int64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	offset := s.total[dir]
	s.total[dir] += int64(len(raw))
	var copied []byte
	if s.buf[dir].Len() < MaxCaptureBytesPerDirection {
		remain := MaxCaptureBytesPerDirection - s.buf[dir].Len()
		keep := raw
		if len(keep) > remain {
			keep = raw[:remain]
		}
		_, _ = s.buf[dir].Write(keep)
		copied = make([]byte, len(keep))
		copy(copied, keep)
	}
	s.segments = append(s.segments, TapSegment{
		Direction:    dir,
		Index:        len(s.segments),
		StreamOffset: offset,
		Size:         len(raw),
		Timestamp:    ts,
		Data:         copied,
	})
	return offset
}

func (s *TapSession) markClosed() {
	s.mu.Lock()
	s.closed = true
	s.mu.Unlock()
	s.closeOnce.Do(func() { close(s.closedCh) })
}

func (s *TapSession) IsClosed() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.closed
}

// WaitClosed blocks until the tapped TCP session completes teardown or timeout expires.
func (s *TapSession) WaitClosed(timeout time.Duration) bool {
	select {
	case <-s.closedCh:
		return true
	case <-time.After(timeout):
		return false
	}
}

func (s *TapSession) TotalBytes(dir TapDirection) int64 {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.total[dir]
}

// WaitBytes polls until at least minBytes have been captured in dir.
func (s *TapSession) WaitBytes(dir TapDirection, minBytes int64, timeout time.Duration) bool {
	deadline := time.Now().Add(timeout)
	for {
		if s.TotalBytes(dir) >= minBytes {
			return true
		}
		if s.IsClosed() || time.Now().After(deadline) {
			return s.TotalBytes(dir) >= minBytes
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func (s *TapSession) Bytes(dir TapDirection) []byte {
	s.mu.RLock()
	defer s.mu.RUnlock()
	b := s.buf[dir].Bytes()
	out := make([]byte, len(b))
	copy(out, b)
	return out
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
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, seg := range s.segments {
		if seg.Direction == dir {
			return seg, true
		}
	}
	return TapSegment{}, false
}

func (s *TapSession) HasSegmentOfExactSize(dir TapDirection, size int) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, seg := range s.segments {
		if seg.Direction == dir && seg.Size == size {
			return true
		}
	}
	return false
}

// ComputeShannonEntropy calculates Shannon entropy in bits/byte over data (max 8.0).
func ComputeShannonEntropy(data []byte) float64 {
	if len(data) == 0 {
		return 0
	}
	var counts [256]int
	for _, b := range data {
		counts[b]++
	}
	n := float64(len(data))
	entropy := 0.0
	for _, c := range counts {
		if c == 0 {
			continue
		}
		p := float64(c) / n
		entropy -= p * math.Log2(p)
	}
	return entropy
}

// ComputeByteChiSquare returns the 256-bin byte frequency chi-square statistic
// against a uniform distribution (255 degrees of freedom).
func ComputeByteChiSquare(data []byte) float64 {
	if len(data) == 0 {
		return 0
	}
	var counts [256]int
	for _, b := range data {
		counts[b]++
	}
	expected := float64(len(data)) / 256.0
	chi2 := 0.0
	for _, c := range counts {
		diff := float64(c) - expected
		chi2 += (diff * diff) / expected
	}
	return chi2
}

// ComputeASCIIPrintableRatio reports the fraction of ASCII printable characters [0x20..0x7e].
func ComputeASCIIPrintableRatio(data []byte) float64 {
	if len(data) == 0 {
		return 0
	}
	printable := 0
	for _, b := range data {
		if b >= 0x20 && b <= 0x7e {
			printable++
		}
	}
	return float64(printable) / float64(len(data))
}

func (s *TapSession) ShannonEntropy(dir TapDirection) float64 {
	return ComputeShannonEntropy(s.Bytes(dir))
}

func (s *TapSession) ByteChiSquare(dir TapDirection) (chi2 float64, dof int, n int) {
	data := s.Bytes(dir)
	return ComputeByteChiSquare(data), 255, len(data)
}

// MaskedClientEPK returns bytes [32:64] of the C2S handshake prefix.
func (s *TapSession) MaskedClientEPK() ([32]byte, bool) {
	var epk [32]byte
	data := s.Bytes(DirC2S)
	if len(data) < 64 {
		return epk, false
	}
	copy(epk[:], data[32:64])
	return epk, true
}

// MaskedServerEPK returns bytes [32:64] of the S2C ServerResponsePrefix.
func (s *TapSession) MaskedServerEPK() ([32]byte, bool) {
	var epk [32]byte
	data := s.Bytes(DirS2C)
	if len(data) < 64 {
		return epk, false
	}
	copy(epk[:], data[32:64])
	return epk, true
}

func (s *TapSession) ContainsBytes(dir TapDirection, needle []byte) bool {
	return bytes.Contains(s.Bytes(dir), needle)
}

func (s *TapSession) HasOuterTLSRecordHeader() bool {
	c2s := s.Bytes(DirC2S)
	if len(c2s) >= 3 && c2s[0] == 0x16 && c2s[1] == 0x03 && (c2s[2] <= 0x04) {
		return true
	}
	s2c := s.Bytes(DirS2C)
	return len(s2c) >= 3 && s2c[0] == 0x16 && s2c[1] == 0x03 && (s2c[2] <= 0x04)
}

// WireTapProxy intercepts TCP traffic between client outbound and server inbound,
// providing segment timing/bytes capture, pcap export, backpressure, throttling,
// silent blackhole, byte bit-flip tampering, mid-stream abort, and burst hold/replay.
type WireTapProxy struct {
	ln         net.Listener
	addr       string
	port       uint16
	targetAddr string

	nextID atomic.Int64
	mu     sync.RWMutex
	sess   []*TapSession

	c2sDrop atomic.Bool
	s2cDrop atomic.Bool

	pauseMu   sync.Mutex
	c2sPaused atomic.Bool
	s2cPaused atomic.Bool

	throttleDelay atomic.Int64 // time.Duration nanoseconds per chunk
	maxReadChunk  atomic.Int64 // <=0 means default 32768

	tcpWindowBytes atomic.Int64

	abortLimitBytes [2]atomic.Int64 // >0 means abort after N bytes transferred in dir
	abortSendRST    [2]atomic.Bool

	holdFirstBurst atomic.Bool
	firstBurstOnce sync.Once
	firstBurstCh   chan []byte
	releaseBurstCh chan struct{}
	releaseOnce    sync.Once

	tamperMu sync.RWMutex
	tamperFn TapTamperFunc

	connMu   sync.Mutex
	conns    map[net.Conn]struct{}
	closedCh chan struct{}
	wg       sync.WaitGroup

	closeOnce sync.Once
}

// StartWireTapProxy starts a loopback TCP wiretap forwarding to targetAddr.
func StartWireTapProxy(t testing.TB, targetAddr string) *WireTapProxy {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	taddr := ln.Addr().(*net.TCPAddr)
	p := &WireTapProxy{
		ln:             ln,
		addr:           taddr.String(),
		port:           uint16(taddr.Port),
		targetAddr:     targetAddr,
		conns:          make(map[net.Conn]struct{}),
		closedCh:       make(chan struct{}),
		firstBurstCh:   make(chan []byte, 1),
		releaseBurstCh: make(chan struct{}),
	}
	p.wg.Add(1)
	go p.acceptLoop()
	t.Cleanup(p.Close)
	return p
}

func (p *WireTapProxy) Addr() string { return p.addr }
func (p *WireTapProxy) Port() uint16 { return p.port }

// SetBlackhole enables/disables silent packet dropping after handshake or anytime.
func (p *WireTapProxy) SetBlackhole(c2sDrop, s2cDrop bool) {
	p.c2sDrop.Store(c2sDrop)
	p.s2cDrop.Store(s2cDrop)
}

// SetReadPaused pauses reads from the given direction to exercise TCP backpressure.
func (p *WireTapProxy) SetReadPaused(dir TapDirection, paused bool) {
	if dir == DirC2S {
		p.c2sPaused.Store(paused)
	} else {
		p.s2cPaused.Store(paused)
	}
}

// SetThrottle adds per-chunk delay and/or caps read chunk sizes (useful to saturate TCP windows cleanly).
func (p *WireTapProxy) SetThrottle(delayPerChunk time.Duration, maxReadChunk int) {
	p.throttleDelay.Store(int64(delayPerChunk))
	p.maxReadChunk.Store(int64(maxReadChunk))
}

// SetTCPWindowBytes configures SO_RCVBUF / SO_SNDBUF on newly accepted/dialed sockets.
func (p *WireTapProxy) SetTCPWindowBytes(n int) {
	p.tcpWindowBytes.Store(int64(n))
}

// SetAbortAfterBytes drops the connection in dir once limit bytes have been forwarded.
func (p *WireTapProxy) SetAbortAfterBytes(dir TapDirection, limit int64, sendRST bool) {
	p.abortLimitBytes[dir].Store(limit)
	p.abortSendRST[dir].Store(sendRST)
}

// SetHoldInitialBurst pauses forwarding the first C2S read chunk until ReleaseInitialBurst is called.
func (p *WireTapProxy) SetHoldInitialBurst(hold bool) {
	p.holdFirstBurst.Store(hold)
}

// WaitFirstBurst waits for the captured first C2S chunk (e.g., for clock-skew replay tests).
func (p *WireTapProxy) WaitFirstBurst(timeout time.Duration) ([]byte, bool) {
	select {
	case b := <-p.firstBurstCh:
		return b, true
	case <-time.After(timeout):
		return nil, false
	}
}

// ReleaseInitialBurst unblocks forwarding when SetHoldInitialBurst(true) was set.
func (p *WireTapProxy) ReleaseInitialBurst() {
	p.releaseOnce.Do(func() { close(p.releaseBurstCh) })
}

// SetTamperFunc installs a real-time byte mutator / connection dropper.
func (p *WireTapProxy) SetTamperFunc(fn TapTamperFunc) {
	p.tamperMu.Lock()
	p.tamperFn = fn
	p.tamperMu.Unlock()
}

// InstallSingleBitFlip installs a one-shot XOR bit-flip at targetOffset in dir.
func (p *WireTapProxy) InstallSingleBitFlip(sessionID int, dir TapDirection, targetOffset int64, xorMask byte) {
	var fired atomic.Bool
	p.SetTamperFunc(func(sid int, d TapDirection, off int64, chunk []byte) ([]byte, bool) {
		if d != dir || (sessionID > 0 && sid != sessionID) || fired.Load() {
			return chunk, false
		}
		if off <= targetOffset && targetOffset < off+int64(len(chunk)) {
			if fired.CompareAndSwap(false, true) {
				out := make([]byte, len(chunk))
				copy(out, chunk)
				out[targetOffset-off] ^= xorMask
				return out, false
			}
		}
		return chunk, false
	})
}

func (p *WireTapProxy) SessionCount() int {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return len(p.sess)
}

func (p *WireTapProxy) Sessions() []*TapSession {
	p.mu.RLock()
	defer p.mu.RUnlock()
	out := make([]*TapSession, len(p.sess))
	copy(out, p.sess)
	return out
}

// WaitForSessions polls until at least count sessions have been accepted.
func (p *WireTapProxy) WaitForSessions(t testing.TB, count int, timeout time.Duration) []*TapSession {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for {
		ss := p.Sessions()
		if len(ss) >= count {
			return ss
		}
		require.False(t, time.Now().After(deadline),
			"timed out waiting for %d wiretap sessions (got %d)", count, len(ss))
		time.Sleep(10 * time.Millisecond)
	}
}

// AggregateShannonEntropy concatenates all captured bytes in dir across sessions and returns Shannon entropy.
func (p *WireTapProxy) AggregateShannonEntropy(dir TapDirection) float64 {
	var buf bytes.Buffer
	for _, s := range p.Sessions() {
		buf.Write(s.Bytes(dir))
	}
	return ComputeShannonEntropy(buf.Bytes())
}

// EPKBit255Stats measures bit 255 (byte[31] & 0x80) distribution across all captured EPKs in dir.
func (p *WireTapProxy) EPKBit255Stats(dir TapDirection) (ones int, total int, ratio float64) {
	return p.EPKBitDistribution(dir, 255)
}

// EPKBitDistribution measures bit distribution at bitIndex (0..255) across captured EPKs in dir.
func (p *WireTapProxy) EPKBitDistribution(dir TapDirection, bitIndex int) (ones int, total int, ratio float64) {
	if bitIndex < 0 || bitIndex >= 256 {
		return 0, 0, 0
	}
	byteIdx := bitIndex / 8
	bitMask := byte(1 << (bitIndex % 8))
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
		if (epk[byteIdx] & bitMask) != 0 {
			ones++
		}
	}
	if total > 0 {
		ratio = float64(ones) / float64(total)
	}
	return ones, total, ratio
}

// EPKChiSquareUniformity runs a 256-bin byte frequency chi-square test across all masked EPKs in dir.
func (p *WireTapProxy) EPKChiSquareUniformity(dir TapDirection) (chi2 float64, totalBytes int) {
	var all []byte
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
		if ok {
			all = append(all, epk[:]...)
		}
	}
	return ComputeByteChiSquare(all), len(all)
}

// SavePCAP writes captured segments across all sessions into a pure-stdlib
// standard libpcap (DLT_RAW = 101, IPv4+TCP synthetic frames) file, chunking
// payloads > 65495 bytes so IPv4 16-bit TotalLength never overflows.
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

	const maxIPv4TCPPayload = 65535 - 40
	for _, sess := range p.Sessions() {
		var seq [2]uint32
		clientPort := uint16(10000 + (sess.ID % 50000))
		for _, seg := range sess.Segments() {
			data := seg.Data
			if len(data) == 0 {
				continue
			}
			for len(data) > 0 {
				part := data
				if len(part) > maxIPv4TCPPayload {
					part = data[:maxIPv4TCPPayload]
				}
				pkt := buildSyntheticIPv4TCPPacket(seg.Direction, clientPort, p.port, seq[seg.Direction], part)
				seq[seg.Direction] += uint32(len(part))
				data = data[len(part):]

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
	}
	return nil
}

// ValidatePCAPFile parses a pure-stdlib libpcap file and verifies header + packet bounds.
func ValidatePCAPFile(path string) (int, error) {
	f, err := os.Open(path)
	if err != nil {
		return 0, err
	}
	defer f.Close()

	var ghdr [24]byte
	if _, err := io.ReadFull(f, ghdr[:]); err != nil {
		return 0, err
	}
	magic := binary.LittleEndian.Uint32(ghdr[0:4])
	if magic != 0xa1b2c3d4 {
		return 0, fmt.Errorf("unexpected pcap magic 0x%08x", magic)
	}
	if linkType := binary.LittleEndian.Uint32(ghdr[20:24]); linkType != 101 {
		return 0, fmt.Errorf("unexpected pcap link type %d", linkType)
	}

	count := 0
	var rhdr [16]byte
	for {
		_, err := io.ReadFull(f, rhdr[:])
		if errors.Is(err, io.EOF) {
			return count, nil
		}
		if err != nil {
			return count, err
		}
		inclLen := binary.LittleEndian.Uint32(rhdr[8:12])
		if inclLen == 0 || inclLen > 65535 {
			return count, fmt.Errorf("invalid pcap record len %d", inclLen)
		}
		payload := make([]byte, inclLen)
		if _, err := io.ReadFull(f, payload); err != nil {
			return count, err
		}
		if len(payload) < 40 || (payload[0]>>4) != 4 || payload[9] != 6 {
			return count, fmt.Errorf("packet %d is not synthetic IPv4+TCP", count)
		}
		count++
	}
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
	pkt[32] = 5 << 4
	pkt[33] = 0x18 // PSH | ACK
	binary.BigEndian.PutUint16(pkt[34:36], 65535)
	copy(pkt[40:], payload)
	return pkt
}

func (p *WireTapProxy) Close() {
	p.closeOnce.Do(func() {
		p.ReleaseInitialBurst()
		close(p.closedCh)
		_ = p.ln.Close()
		p.connMu.Lock()
		for c := range p.conns {
			_ = c.Close()
		}
		p.connMu.Unlock()
		p.wg.Wait()
	})
}

func (p *WireTapProxy) trackConn(c net.Conn, add bool) {
	p.connMu.Lock()
	if add {
		p.conns[c] = struct{}{}
	} else {
		delete(p.conns, c)
	}
	p.connMu.Unlock()
}

func (p *WireTapProxy) acceptLoop() {
	defer p.wg.Done()
	for {
		c, err := p.ln.Accept()
		if err != nil {
			select {
			case <-p.closedCh:
				return
			default:
				return
			}
		}
		p.wg.Add(1)
		go func(conn net.Conn) {
			defer p.wg.Done()
			p.handleConn(conn)
		}(c)
	}
}

func configureTapTCPConn(c net.Conn, bufBytes int) {
	if bufBytes <= 0 {
		return
	}
	if tc, ok := c.(*net.TCPConn); ok {
		_ = tc.SetReadBuffer(bufBytes)
		_ = tc.SetWriteBuffer(bufBytes)
	}
}

func closeWithRST(c net.Conn) {
	if tc, ok := c.(*net.TCPConn); ok {
		_ = tc.SetLinger(0)
	}
	_ = c.Close()
}

func (p *WireTapProxy) handleConn(clientConn net.Conn) {
	p.trackConn(clientConn, true)
	defer func() {
		p.trackConn(clientConn, false)
		_ = clientConn.Close()
	}()

	winBytes := int(p.tcpWindowBytes.Load())
	configureTapTCPConn(clientConn, winBytes)

	serverConn, err := net.DialTimeout("tcp", p.targetAddr, 5*time.Second)
	if err != nil {
		return
	}
	p.trackConn(serverConn, true)
	defer func() {
		p.trackConn(serverConn, false)
		_ = serverConn.Close()
	}()
	configureTapTCPConn(serverConn, winBytes)

	sid := int(p.nextID.Add(1))
	sess := newTapSession(sid, clientConn.RemoteAddr().String())
	p.mu.Lock()
	p.sess = append(p.sess, sess)
	p.mu.Unlock()
	defer sess.markClosed()

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		p.pump(sess, DirC2S, clientConn, serverConn)
		if tc, ok := serverConn.(*net.TCPConn); ok && !p.c2sDrop.Load() {
			_ = tc.CloseWrite()
		}
	}()
	go func() {
		defer wg.Done()
		p.pump(sess, DirS2C, serverConn, clientConn)
		if tc, ok := clientConn.(*net.TCPConn); ok && !p.s2cDrop.Load() {
			_ = tc.CloseWrite()
		}
	}()
	wg.Wait()
}

func (p *WireTapProxy) waitIfPaused(dir TapDirection) bool {
	for {
		select {
		case <-p.closedCh:
			return false
		default:
		}
		paused := (dir == DirC2S && p.c2sPaused.Load()) || (dir == DirS2C && p.s2cPaused.Load())
		if !paused {
			return true
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func (p *WireTapProxy) pump(sess *TapSession, dir TapDirection, src, dst net.Conn) {
	buf := make([]byte, 32*1024)
	var forwarded int64
	isFirstC2S := dir == DirC2S
	for {
		if !p.waitIfPaused(dir) {
			return
		}
		readBuf := buf
		if maxChunk := int(p.maxReadChunk.Load()); maxChunk > 0 && maxChunk < len(buf) {
			readBuf = buf[:maxChunk]
		}
		n, err := src.Read(readBuf)
		if n > 0 {
			chunk := readBuf[:n]
			ts := time.Now()
			offset := sess.recordChunk(dir, chunk, ts)

			if isFirstC2S {
				isFirstC2S = false
				p.firstBurstOnce.Do(func() {
					cp := make([]byte, len(chunk))
					copy(cp, chunk)
					select {
					case p.firstBurstCh <- cp:
					default:
					}
				})
				if p.holdFirstBurst.Load() {
					select {
					case <-p.releaseBurstCh:
					case <-p.closedCh:
						return
					}
				}
			}

			if (dir == DirC2S && p.c2sDrop.Load()) || (dir == DirS2C && p.s2cDrop.Load()) {
				// Silent blackhole: consume bytes from sender without writing to peer or closing socket.
				if err != nil {
					return
				}
				continue
			}

			out := chunk
			drop := false
			p.tamperMu.RLock()
			fn := p.tamperFn
			p.tamperMu.RUnlock()
			if fn != nil {
				out, drop = fn(sess.ID, dir, offset, chunk)
			}

			limit := p.abortLimitBytes[dir].Load()
			if limit > 0 && forwarded+int64(len(out)) >= limit {
				remain := limit - forwarded
				if remain > 0 && int(remain) <= len(out) {
					_, _ = writeAll(dst, out[:remain])
				}
				if p.abortSendRST[dir].Load() {
					closeWithRST(src)
					closeWithRST(dst)
				} else {
					_ = src.Close()
					_ = dst.Close()
				}
				return
			}

			if len(out) > 0 {
				if _, werr := writeAll(dst, out); werr != nil {
					return
				}
				forwarded += int64(len(out))
			}
			if drop {
				_ = src.Close()
				_ = dst.Close()
				return
			}
			if d := time.Duration(p.throttleDelay.Load()); d > 0 {
				select {
				case <-time.After(d):
				case <-p.closedCh:
					return
				}
			}
		}
		if err != nil {
			return
		}
	}
}

func writeAll(w io.Writer, b []byte) (int, error) {
	written := 0
	for written < len(b) {
		n, err := w.Write(b[written:])
		written += n
		if err != nil {
			return written, err
		}
		if n == 0 {
			return written, io.ErrShortWrite
		}
	}
	return written, nil
}

// ---------------------------------------------------------------------------
// 6. Active Probe Helpers (StealthDrain FIN vs RST & Slowloris Exhaustion)
// ---------------------------------------------------------------------------

// ProbeResult captures exact server termination behavior on unauthenticated probes.
type ProbeResult struct {
	BytesReceived  []byte
	Elapsed        time.Duration
	ClosedCleanEOF bool
	ClosedByRST    bool
	TimedOut       bool
	Err            error
}

// SendRawProbe dials addr, sends payload (optionally calling CloseWrite()),
// and measures server bytes + FIN vs RST close within maxWait.
func SendRawProbe(addr string, payload []byte, halfCloseWrite bool, maxWait time.Duration) (ProbeResult, error) {
	var conn net.Conn
	var err error
	for attempt := 0; attempt < 8; attempt++ {
		conn, err = net.DialTimeout("tcp", addr, 3*time.Second)
		if err == nil || !IsConnReset(err) {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if err != nil {
		return ProbeResult{Err: err}, err
	}
	defer conn.Close()

	start := time.Now()
	if len(payload) > 0 {
		_ = conn.SetWriteDeadline(time.Now().Add(3 * time.Second))
		if _, werr := writeAll(conn, payload); werr != nil && !IsBrokenPipe(werr) && !IsConnReset(werr) {
			return ProbeResult{Elapsed: time.Since(start), Err: werr}, werr
		}
		_ = conn.SetWriteDeadline(time.Time{})
	}
	if halfCloseWrite {
		if tc, ok := conn.(*net.TCPConn); ok {
			_ = tc.CloseWrite()
		}
	}

	_ = conn.SetReadDeadline(time.Now().Add(maxWait))
	var recv bytes.Buffer
	tmp := make([]byte, 4096)
	for {
		n, rerr := conn.Read(tmp)
		if n > 0 {
			recv.Write(tmp[:n])
		}
		if rerr != nil {
			res := ProbeResult{
				BytesReceived: recv.Bytes(),
				Elapsed:       time.Since(start),
				Err:           rerr,
			}
			if errors.Is(rerr, io.EOF) {
				res.ClosedCleanEOF = true
			} else if IsConnReset(rerr) {
				res.ClosedByRST = true
			} else if ne, ok := rerr.(net.Error); ok && ne.Timeout() {
				res.TimedOut = true
			}
			return res, nil
		}
	}
}

// SendSlowlorisProbe sends small chunks spaced by stepDelay without closing write
// to exercise HandshakeTimeout + StealthDrain bounds.
func SendSlowlorisProbe(addr string, chunk []byte, stepDelay time.Duration, maxChunks int, maxWait time.Duration) (ProbeResult, error) {
	conn, err := net.DialTimeout("tcp", addr, 3*time.Second)
	if err != nil {
		return ProbeResult{Err: err}, err
	}
	defer conn.Close()

	start := time.Now()
	stopSend := make(chan struct{})
	defer close(stopSend)
	go func() {
		for i := 0; i < maxChunks; i++ {
			if _, werr := writeAll(conn, chunk); werr != nil {
				return
			}
			select {
			case <-time.After(stepDelay):
			case <-stopSend:
				return
			}
		}
	}()

	_ = conn.SetReadDeadline(time.Now().Add(maxWait))
	var recv bytes.Buffer
	tmp := make([]byte, 4096)
	for {
		n, rerr := conn.Read(tmp)
		if n > 0 {
			recv.Write(tmp[:n])
		}
		if rerr != nil {
			res := ProbeResult{
				BytesReceived: recv.Bytes(),
				Elapsed:       time.Since(start),
				Err:           rerr,
			}
			if errors.Is(rerr, io.EOF) {
				res.ClosedCleanEOF = true
			} else if IsConnReset(rerr) {
				res.ClosedByRST = true
			} else if ne, ok := rerr.(net.Error); ok && ne.Timeout() {
				res.TimedOut = true
			}
			return res, nil
		}
	}
}

// ---------------------------------------------------------------------------
// 7. In-Process Topology Config, BoxInstance & NewBoxPair / StartTopology
// ---------------------------------------------------------------------------

// UserSpec describes an Aether or SOCKS user entry for JSON generation.
type UserSpec struct {
	Name     string `json:"name,omitempty"`
	Password string `json:"password,omitempty"`
	Key      string `json:"key,omitempty"`
}

// UserRouteOverride configures per-user destination override routing rules on Server Box.
type UserRouteOverride struct {
	Outbound        string
	OverrideAddress string
	OverridePort    uint16
}

// BrutalRateSpec describes multiplex.brutal settings.
type BrutalRateSpec struct {
	Enabled  bool `json:"enabled,omitempty"`
	UpMbps   int  `json:"up_mbps,omitempty"`
	DownMbps int  `json:"down_mbps,omitempty"`
}

// MultiplexServerSpec describes server inbound multiplex settings.
type MultiplexServerSpec struct {
	Enabled bool            `json:"enabled,omitempty"`
	Padding bool            `json:"padding,omitempty"`
	Brutal  *BrutalRateSpec `json:"brutal,omitempty"`
}

// MultiplexClientSpec describes client outbound multiplex settings.
type MultiplexClientSpec struct {
	Enabled        bool            `json:"enabled,omitempty"`
	Protocol       string          `json:"protocol,omitempty"`
	MaxConnections int             `json:"max_connections,omitempty"`
	MinStreams     int             `json:"min_streams,omitempty"`
	MaxStreams     int             `json:"max_streams,omitempty"`
	Padding        bool            `json:"padding,omitempty"`
	Brutal         *BrutalRateSpec `json:"brutal,omitempty"`
}

// TopologyConfig parametrizes a Client Box -> [WireTapProxy] -> Server Box E2E pair.
type TopologyConfig struct {
	// Server inbound options
	ServerPassword          string
	ServerKey               string
	ServerUsers             []UserSpec
	ServerPrivateKey        string
	ServerTimeWindow        string
	ServerHandshakeTimeout  string
	ServerHeartbeatInterval string
	ServerDisableShaping    bool
	ServerMultiplex         *MultiplexServerSpec
	ServerPredefinedHosts   map[string]string
	ServerDNSAddr           string // optional "127.0.0.1:port" external loopback DNS transport
	ServerAllowedUsers      []string
	ServerUserRoutes        map[string]UserRouteOverride
	ServerExtraRouteRules   []map[string]any
	ServerClockOffset       *time.Duration
	ServerTimeService       *MockTimeService
	ServerLogLevel          string
	ServerLogPath           string

	// Client inbound & outbound options
	ClientInboundType       string // default C.TypeMixed ("mixed"), or C.TypeSOCKS ("socks")
	ClientInboundUsers      []UserSpec
	ClientUDPTimeout        string // default "15s"
	ClientSniffTimeout      string // e.g. "50ms" to force InitialPayload coalescing before Dial
	ClientPassword          string
	ClientKey               string
	ClientCipher            string
	ClientNetwork           any // nil, "tcp", "udp", or []string{"tcp", "udp"}
	ClientServerPublicKey   string
	ClientHeartbeatInterval string
	ClientDisableShaping    bool
	ClientMultiplex         *MultiplexClientSpec
	ClientUDPOverTCP        any // nil, bool, or map[string]any{"enabled": true, "version": 2}
	ClientClockOffset       *time.Duration
	ClientTimeService       *MockTimeService
	ClientLogLevel          string
	ClientLogPath           string

	// Harness options
	DisableWireTap    bool
	CaptureLogs       bool
	WireTapWindowSize int
}

// BoxInstance wraps a started in-process sing-box *box.Box and cleanup lifecycle.
type BoxInstance struct {
	Box         *box.Box
	Cancel      context.CancelFunc
	RawJSON     []byte
	LogPath     string
	ListenPort  uint16
	ListenAddr  string
	TimeService *MockTimeService
}

func (b *BoxInstance) Close() error {
	if b == nil {
		return nil
	}
	var err error
	if b.Box != nil {
		err = b.Box.Close()
	}
	if b.Cancel != nil {
		b.Cancel()
	}
	return err
}

func (b *BoxInstance) ReadLogs() string {
	if b == nil || b.LogPath == "" {
		return ""
	}
	data, err := os.ReadFile(b.LogPath)
	if err != nil {
		return ""
	}
	return string(data)
}

// Topology links the running Server Box, optional WireTapProxy, optional MockNTPServers, and Client Box.
type Topology struct {
	Config    TopologyConfig
	Server    *BoxInstance
	Client    *BoxInstance
	Tap       *WireTapProxy
	ServerNTP *MockNTPServer
	ClientNTP *MockNTPServer
}

func (topo *Topology) ClientProxyAddr() string {
	if topo.Client == nil {
		return ""
	}
	return topo.Client.ListenAddr
}

func (topo *Topology) ServerAddr() string {
	if topo.Server == nil {
		return ""
	}
	return topo.Server.ListenAddr
}

func (topo *Topology) TapOrServerAddr() string {
	if topo.Tap != nil {
		return topo.Tap.Addr()
	}
	return topo.ServerAddr()
}

func (topo *Topology) Close() {
	if topo == nil {
		return
	}
	if topo.Client != nil {
		_ = topo.Client.Close()
	}
	if topo.Tap != nil {
		topo.Tap.Close()
	}
	if topo.Server != nil {
		_ = topo.Server.Close()
	}
	if topo.ClientNTP != nil {
		topo.ClientNTP.Close()
	}
	if topo.ServerNTP != nil {
		topo.ServerNTP.Close()
	}
}

// BuildServerJSON constructs a canonical sing-box JSON config for Server Box.
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

	var dnsServers []any
	dnsFinal := ""
	if len(cfg.ServerPredefinedHosts) > 0 {
		dnsServers = append(dnsServers, map[string]any{
			"type":       "hosts",
			"tag":        "hosts-dns",
			"predefined": cfg.ServerPredefinedHosts,
		})
		dnsFinal = "hosts-dns"
	}
	if cfg.ServerDNSAddr != "" {
		h, pStr, err := net.SplitHostPort(cfg.ServerDNSAddr)
		if err != nil {
			return nil, fmt.Errorf("invalid ServerDNSAddr %q: %w", cfg.ServerDNSAddr, err)
		}
		pNum, err := strconv.ParseUint(pStr, 10, 16)
		if err != nil {
			return nil, fmt.Errorf("invalid ServerDNSAddr port %q: %w", pStr, err)
		}
		dnsServers = append(dnsServers, map[string]any{
			"type":        "udp",
			"tag":         "loopback-dns",
			"server":      h,
			"server_port": uint16(pNum),
		})
		if dnsFinal == "" {
			dnsFinal = "loopback-dns"
		}
	}
	if len(dnsServers) > 0 {
		root["dns"] = map[string]any{
			"servers": dnsServers,
			"final":   dnsFinal,
		}
		routeObj["default_domain_resolver"] = dnsFinal
	}

	var rules []any
	for _, r := range cfg.ServerExtraRouteRules {
		rules = append(rules, r)
	}
	for user, ov := range cfg.ServerUserRoutes {
		outTag := ov.Outbound
		if outTag == "" {
			outTag = "direct-out"
		}
		rule := map[string]any{
			"auth_user": []string{user},
			"action":    C.RuleActionTypeRoute,
			"outbound":  outTag,
		}
		if ov.OverrideAddress != "" {
			rule["override_address"] = ov.OverrideAddress
		}
		if ov.OverridePort > 0 {
			rule["override_port"] = ov.OverridePort
		}
		rules = append(rules, rule)
	}
	if len(cfg.ServerAllowedUsers) > 0 {
		rules = append(rules,
			map[string]any{
				"auth_user": cfg.ServerAllowedUsers,
				"action":    C.RuleActionTypeRoute,
				"outbound":  "direct-out",
			},
			map[string]any{
				"inbound": []string{"aether-in"},
				"action":  C.RuleActionTypeReject,
			},
		)
	}
	if len(rules) > 0 {
		routeObj["rules"] = rules
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

// BuildClientJSON constructs a canonical sing-box JSON config for Client Box.
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
	if len(cfg.ClientInboundUsers) > 0 {
		proxyIn["users"] = cfg.ClientInboundUsers
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

// StartBox starts an isolated in-process *BoxInstance from rawJSON with optional MockTimeService.
func StartBox(t testing.TB, rawJSON []byte, mockTS ...*MockTimeService) (*BoxInstance, error) {
	t.Helper()
	return StartBoxWithLog(t, rawJSON, "", 0, mockTS...)
}

// StartBoxWithLog starts a *BoxInstance from rawJSON recording metadata.
func StartBoxWithLog(t testing.TB, rawJSON []byte, logPath string, listenPort uint16, mockTS ...*MockTimeService) (*BoxInstance, error) {
	t.Helper()
	var ts *MockTimeService
	if len(mockTS) > 0 {
		ts = mockTS[0]
	}
	ctx, cancel := context.WithCancel(NewBoxContext(context.Background(), ts))
	var opts option.Options
	if err := opts.UnmarshalJSONContext(ctx, rawJSON); err != nil {
		cancel()
		return nil, fmt.Errorf("unmarshal options: %w", err)
	}
	instance, err := box.New(box.Options{
		Context: ctx,
		Options: opts,
	})
	if err != nil {
		cancel()
		return nil, fmt.Errorf("box.New: %w", err)
	}
	if err := instance.Start(); err != nil {
		_ = instance.Close()
		cancel()
		return nil, fmt.Errorf("box.Start: %w", err)
	}
	listenAddr := ""
	if listenPort > 0 {
		listenAddr = net.JoinHostPort("127.0.0.1", strconv.Itoa(int(listenPort)))
	}
	bi := &BoxInstance{
		Box:         instance,
		Cancel:      cancel,
		RawJSON:     rawJSON,
		LogPath:     logPath,
		ListenPort:  listenPort,
		ListenAddr:  listenAddr,
		TimeService: ts,
	}
	t.Cleanup(func() { _ = bi.Close() })
	return bi, nil
}

// StartBoxFromJSONBuilder creates, starts, and registers cleanup for an isolated BoxInstance,
// retrying ephemeral port races cleanly up to 5 times.
func StartBoxFromJSONBuilder(t testing.TB, logPath string, buildFn func(port uint16) ([]byte, error), mockTS ...*MockTimeService) (*BoxInstance, error) {
	t.Helper()
	var ts *MockTimeService
	if len(mockTS) > 0 {
		ts = mockTS[0]
	}
	var lastErr error
	for attempt := 0; attempt < 5; attempt++ {
		port := AllocFreeTCPPort(t)
		rawJSON, err := buildFn(port)
		if err != nil {
			return nil, err
		}
		bi, err := StartBoxWithLog(t, rawJSON, logPath, port, ts)
		if err != nil {
			lastErr = err
			if isAddrInUseError(err) {
				continue
			}
			return nil, err
		}
		return bi, nil
	}
	return nil, lastErr
}

// StartTopology builds and starts the standard Client -> [WireTapProxy] -> Server pair
// and registers cleanup on t. It fails immediately on configuration/startup error.
func StartTopology(t testing.TB, cfg TopologyConfig) *Topology {
	t.Helper()
	topo, err := TryStartTopology(t, cfg)
	require.NoError(t, err)
	return topo
}

// NewBoxPair aliases StartTopology.
func NewBoxPair(t testing.TB, cfg TopologyConfig) *Topology {
	t.Helper()
	return StartTopology(t, cfg)
}

// TryNewBoxPair aliases TryStartTopology.
func TryNewBoxPair(t testing.TB, cfg TopologyConfig) (*Topology, error) {
	t.Helper()
	return TryStartTopology(t, cfg)
}

// TryStartTopology builds and starts Server, optional WireTapProxy, optional MockNTPServers, and Client.
func TryStartTopology(t testing.TB, cfg TopologyConfig) (*Topology, error) {
	t.Helper()
	topo := &Topology{Config: cfg}
	logDir := ""
	if cfg.CaptureLogs || cfg.ServerLogPath != "" || cfg.ClientLogPath != "" {
		logDir = t.TempDir()
	}

	var serverNTPPort, clientNTPPort uint16
	if cfg.ServerClockOffset != nil && cfg.ServerTimeService == nil {
		topo.ServerNTP = StartMockNTPServer(t, *cfg.ServerClockOffset)
		serverNTPPort = topo.ServerNTP.Port()
	}
	if cfg.ClientClockOffset != nil && cfg.ClientTimeService == nil {
		topo.ClientNTP = StartMockNTPServer(t, *cfg.ClientClockOffset)
		clientNTPPort = topo.ClientNTP.Port()
	}

	serverLogPath := cfg.ServerLogPath
	if serverLogPath == "" && logDir != "" {
		serverLogPath = filepath.Join(logDir, "server.log")
	}
	srv, err := StartBoxFromJSONBuilder(t, serverLogPath, func(port uint16) ([]byte, error) {
		return BuildServerJSON(cfg, port, serverNTPPort, serverLogPath)
	}, cfg.ServerTimeService)
	if err != nil {
		topo.Close()
		return nil, fmt.Errorf("start server box: %w", err)
	}
	topo.Server = srv

	dialHost := "127.0.0.1"
	dialPort := srv.ListenPort
	if !cfg.DisableWireTap {
		tap := StartWireTapProxy(t, srv.ListenAddr)
		if cfg.WireTapWindowSize > 0 {
			tap.SetTCPWindowBytes(cfg.WireTapWindowSize)
		}
		topo.Tap = tap
		dialPort = tap.Port()
	}

	clientLogPath := cfg.ClientLogPath
	if clientLogPath == "" && logDir != "" {
		clientLogPath = filepath.Join(logDir, "client.log")
	}
	cli, err := StartBoxFromJSONBuilder(t, clientLogPath, func(port uint16) ([]byte, error) {
		return BuildClientJSON(cfg, port, dialHost, dialPort, clientNTPPort, clientLogPath)
	}, cfg.ClientTimeService)
	if err != nil {
		topo.Close()
		return nil, fmt.Errorf("start client box: %w", err)
	}
	topo.Client = cli

	// Wait briefly for NTP calibration if MockNTPServers are active.
	if topo.ServerNTP != nil || topo.ClientNTP != nil {
		deadline := time.Now().Add(2 * time.Second)
		for time.Now().Before(deadline) {
			srvOK := topo.ServerNTP == nil || topo.ServerNTP.Requests() > 0
			cliOK := topo.ClientNTP == nil || topo.ClientNTP.Requests() > 0
			if srvOK && cliOK {
				break
			}
			time.Sleep(15 * time.Millisecond)
		}
	}
	return topo, nil
}

func (topo *Topology) DialSOCKS5(ctx context.Context, targetHostPort string) (*SOCKS5StreamConn, error) {
	return DialSOCKS5TCP(ctx, topo.Client.ListenAddr, targetHostPort)
}

func (topo *Topology) DialSOCKS5Auth(ctx context.Context, username, password, targetHostPort string) (*SOCKS5StreamConn, error) {
	return DialSOCKS5TCPAuth(ctx, topo.Client.ListenAddr, username, password, targetHostPort)
}

func (topo *Topology) DialHTTPConnect(ctx context.Context, targetHostPort string) (*HTTPConnectConn, error) {
	return DialHTTPConnectTCP(ctx, topo.Client.ListenAddr, targetHostPort)
}

func (topo *Topology) OpenSOCKS5UDP(ctx context.Context) (*SOCKS5UDPConn, error) {
	return DialSOCKS5UDP(ctx, topo.Client.ListenAddr)
}

func (topo *Topology) NewHTTPClient(tlsCfg *tls.Config, timeout time.Duration) (*http.Client, error) {
	proxyURL, err := url.Parse("http://" + topo.Client.ListenAddr)
	if err != nil {
		return nil, err
	}
	tr := &http.Transport{
		Proxy:             http.ProxyURL(proxyURL),
		TLSClientConfig:   tlsCfg,
		ForceAttemptHTTP2: false,
	}
	return &http.Client{
		Transport: tr,
		Timeout:   timeout,
	}, nil
}

func (topo *Topology) ResetClientNetwork(ctx context.Context) {
	topo.Client.Box.Network().ResetNetwork(ctx)
}

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
// 8. Pure-Stdlib SOCKS5 TCP (CloseWrite), HTTP CONNECT & SOCKS5 UDP Clients
// ---------------------------------------------------------------------------

func encodeSocksAddrHostPort(hostPort string) ([]byte, error) {
	host, portStr, err := net.SplitHostPort(hostPort)
	if err != nil {
		return nil, err
	}
	portU64, err := strconv.ParseUint(portStr, 10, 16)
	if err != nil {
		return nil, err
	}
	var out bytes.Buffer
	if ip := net.ParseIP(host); ip != nil {
		if ip4 := ip.To4(); ip4 != nil {
			out.WriteByte(0x01)
			out.Write(ip4)
		} else {
			out.WriteByte(0x04)
			out.Write(ip.To16())
		}
	} else {
		if len(host) == 0 || len(host) > 255 {
			return nil, fmt.Errorf("invalid domain length %d", len(host))
		}
		out.WriteByte(0x03)
		out.WriteByte(byte(len(host)))
		out.WriteString(host)
	}
	var portBuf [2]byte
	binary.BigEndian.PutUint16(portBuf[:], uint16(portU64))
	out.Write(portBuf[:])
	return out.Bytes(), nil
}

func readSocksAddr(r io.Reader) (string, error) {
	var head [1]byte
	if _, err := io.ReadFull(r, head[:]); err != nil {
		return "", err
	}
	var host string
	switch head[0] {
	case 0x01:
		var ip [4]byte
		if _, err := io.ReadFull(r, ip[:]); err != nil {
			return "", err
		}
		host = net.IP(ip[:]).String()
	case 0x04:
		var ip [16]byte
		if _, err := io.ReadFull(r, ip[:]); err != nil {
			return "", err
		}
		host = net.IP(ip[:]).String()
	case 0x03:
		var l [1]byte
		if _, err := io.ReadFull(r, l[:]); err != nil {
			return "", err
		}
		dom := make([]byte, int(l[0]))
		if _, err := io.ReadFull(r, dom); err != nil {
			return "", err
		}
		host = string(dom)
	default:
		return "", fmt.Errorf("unsupported SOCKS ATYP 0x%02x", head[0])
	}
	var portBuf [2]byte
	if _, err := io.ReadFull(r, portBuf[:]); err != nil {
		return "", err
	}
	port := binary.BigEndian.Uint16(portBuf[:])
	return net.JoinHostPort(host, strconv.Itoa(int(port))), nil
}

// SOCKS5StreamConn wraps a SOCKS5 CONNECT TCP stream exposing net.TCPConn.CloseWrite().
type SOCKS5StreamConn struct {
	*net.TCPConn
	BoundAddr string
}

// DialSOCKS5TCP opens a SOCKS5 CONNECT stream through proxyAddr using no-auth.
func DialSOCKS5TCP(ctx context.Context, proxyAddr, targetHostPort string) (*SOCKS5StreamConn, error) {
	return DialSOCKS5TCPAuth(ctx, proxyAddr, "", "", targetHostPort)
}

// DialSOCKS5TCPAuth opens a SOCKS5 CONNECT stream with optional RFC 1929 username/password.
func DialSOCKS5TCPAuth(ctx context.Context, proxyAddr, username, password, targetHostPort string) (*SOCKS5StreamConn, error) {
	var d net.Dialer
	raw, err := d.DialContext(ctx, "tcp", proxyAddr)
	if err != nil {
		return nil, err
	}
	tcpConn, ok := raw.(*net.TCPConn)
	if !ok {
		_ = raw.Close()
		return nil, errors.New("expected *net.TCPConn")
	}
	if dl, hasDL := ctx.Deadline(); hasDL {
		_ = tcpConn.SetDeadline(dl)
		defer func() { _ = tcpConn.SetDeadline(time.Time{}) }()
	}

	var greet []byte
	if username != "" || password != "" {
		greet = []byte{0x05, 0x02, 0x00, 0x02}
	} else {
		greet = []byte{0x05, 0x01, 0x00}
	}
	if _, err := writeAll(tcpConn, greet); err != nil {
		_ = tcpConn.Close()
		return nil, err
	}
	var methodResp [2]byte
	if _, err := io.ReadFull(tcpConn, methodResp[:]); err != nil {
		_ = tcpConn.Close()
		return nil, err
	}
	if methodResp[0] != 0x05 {
		_ = tcpConn.Close()
		return nil, fmt.Errorf("SOCKS5 greeting invalid version 0x%02x", methodResp[0])
	}
	switch methodResp[1] {
	case 0x00:
	case 0x02:
		if len(username) > 255 || len(password) > 255 {
			_ = tcpConn.Close()
			return nil, errors.New("SOCKS5 username/password too long")
		}
		var authReq bytes.Buffer
		authReq.WriteByte(0x01)
		authReq.WriteByte(byte(len(username)))
		authReq.WriteString(username)
		authReq.WriteByte(byte(len(password)))
		authReq.WriteString(password)
		if _, err := writeAll(tcpConn, authReq.Bytes()); err != nil {
			_ = tcpConn.Close()
			return nil, err
		}
		var authResp [2]byte
		if _, err := io.ReadFull(tcpConn, authResp[:]); err != nil {
			_ = tcpConn.Close()
			return nil, err
		}
		if authResp[1] != 0x00 {
			_ = tcpConn.Close()
			return nil, fmt.Errorf("SOCKS5 username/password rejected status=%d", authResp[1])
		}
	default:
		_ = tcpConn.Close()
		return nil, fmt.Errorf("SOCKS5 unsupported auth method 0x%02x", methodResp[1])
	}

	addrBytes, err := encodeSocksAddrHostPort(targetHostPort)
	if err != nil {
		_ = tcpConn.Close()
		return nil, err
	}
	req := make([]byte, 3+len(addrBytes))
	req[0], req[1], req[2] = 0x05, 0x01, 0x00
	copy(req[3:], addrBytes)
	if _, err := writeAll(tcpConn, req); err != nil {
		_ = tcpConn.Close()
		return nil, err
	}
	var repHdr [3]byte
	if _, err := io.ReadFull(tcpConn, repHdr[:]); err != nil {
		_ = tcpConn.Close()
		return nil, err
	}
	if repHdr[0] != 0x05 || repHdr[1] != 0x00 {
		_ = tcpConn.Close()
		return nil, fmt.Errorf("SOCKS5 CONNECT failed VER=0x%02x REP=0x%02x", repHdr[0], repHdr[1])
	}
	bound, err := readSocksAddr(tcpConn)
	if err != nil {
		_ = tcpConn.Close()
		return nil, err
	}
	return &SOCKS5StreamConn{TCPConn: tcpConn, BoundAddr: bound}, nil
}

// HTTPConnectConn wraps an HTTP CONNECT tunnel stream (accounting for buffered bytes after 200 OK).
type HTTPConnectConn struct {
	*net.TCPConn
	r io.Reader
}

func (c *HTTPConnectConn) Read(p []byte) (int, error) {
	return c.r.Read(p)
}

// DialHTTPConnectTCP establishes a plain HTTP CONNECT tunnel through mixed inbound.
func DialHTTPConnectTCP(ctx context.Context, proxyAddr, targetHostPort string) (*HTTPConnectConn, error) {
	var d net.Dialer
	raw, err := d.DialContext(ctx, "tcp", proxyAddr)
	if err != nil {
		return nil, err
	}
	tcpConn, ok := raw.(*net.TCPConn)
	if !ok {
		_ = raw.Close()
		return nil, errors.New("expected *net.TCPConn")
	}
	if dl, hasDL := ctx.Deadline(); hasDL {
		_ = tcpConn.SetDeadline(dl)
		defer func() { _ = tcpConn.SetDeadline(time.Time{}) }()
	}

	req := fmt.Sprintf("CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", targetHostPort, targetHostPort)
	if _, err := writeAll(tcpConn, []byte(req)); err != nil {
		_ = tcpConn.Close()
		return nil, err
	}
	br := bufio.NewReader(tcpConn)
	resp, err := http.ReadResponse(br, &http.Request{Method: http.MethodConnect})
	if err != nil {
		_ = tcpConn.Close()
		return nil, err
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		_ = tcpConn.Close()
		return nil, fmt.Errorf("HTTP CONNECT failed status=%s", resp.Status)
	}
	var reader io.Reader = tcpConn
	if br.Buffered() > 0 {
		bufBytes := make([]byte, br.Buffered())
		_, _ = io.ReadFull(br, bufBytes)
		reader = io.MultiReader(bytes.NewReader(bufBytes), tcpConn)
	}
	return &HTTPConnectConn{TCPConn: tcpConn, r: reader}, nil
}

// SOCKS5UDPConn wraps a SOCKS5 UDP ASSOCIATE control TCP conn + local UDP socket.
type SOCKS5UDPConn struct {
	ctrlConn   *net.TCPConn
	udpConn    *net.UDPConn
	relayAddr  *net.UDPAddr
	relayLabel string
}

// DialSOCKS5UDP performs SOCKS5 UDP ASSOCIATE against proxyAddr and binds a loopback UDP socket.
func DialSOCKS5UDP(ctx context.Context, proxyAddr string) (*SOCKS5UDPConn, error) {
	var d net.Dialer
	raw, err := d.DialContext(ctx, "tcp", proxyAddr)
	if err != nil {
		return nil, err
	}
	ctrlConn, ok := raw.(*net.TCPConn)
	if !ok {
		_ = raw.Close()
		return nil, errors.New("expected *net.TCPConn")
	}
	if dl, hasDL := ctx.Deadline(); hasDL {
		_ = ctrlConn.SetDeadline(dl)
		defer func() { _ = ctrlConn.SetDeadline(time.Time{}) }()
	}

	if _, err := writeAll(ctrlConn, []byte{0x05, 0x01, 0x00}); err != nil {
		_ = ctrlConn.Close()
		return nil, err
	}
	var methodResp [2]byte
	if _, err := io.ReadFull(ctrlConn, methodResp[:]); err != nil {
		_ = ctrlConn.Close()
		return nil, err
	}
	if methodResp != [2]byte{0x05, 0x00} {
		_ = ctrlConn.Close()
		return nil, fmt.Errorf("SOCKS5 auth failed: %v", methodResp)
	}

	req := []byte{0x05, 0x03, 0x00, 0x01, 0, 0, 0, 0, 0, 0}
	if _, err := writeAll(ctrlConn, req); err != nil {
		_ = ctrlConn.Close()
		return nil, err
	}
	var repHdr [3]byte
	if _, err := io.ReadFull(ctrlConn, repHdr[:]); err != nil {
		_ = ctrlConn.Close()
		return nil, err
	}
	if repHdr[0] != 0x05 || repHdr[1] != 0x00 {
		_ = ctrlConn.Close()
		return nil, fmt.Errorf("SOCKS5 UDP ASSOCIATE failed VER=0x%02x REP=0x%02x", repHdr[0], repHdr[1])
	}
	relayHostPort, err := readSocksAddr(ctrlConn)
	if err != nil {
		_ = ctrlConn.Close()
		return nil, err
	}
	rHost, rPort, err := net.SplitHostPort(relayHostPort)
	if err != nil {
		_ = ctrlConn.Close()
		return nil, err
	}
	if ip := net.ParseIP(rHost); ip != nil && ip.IsUnspecified() {
		pHost, _, _ := net.SplitHostPort(proxyAddr)
		relayHostPort = net.JoinHostPort(pHost, rPort)
	}
	relayAddr, err := net.ResolveUDPAddr("udp", relayHostPort)
	if err != nil {
		_ = ctrlConn.Close()
		return nil, err
	}
	udpConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		_ = ctrlConn.Close()
		return nil, err
	}
	return &SOCKS5UDPConn{
		ctrlConn:   ctrlConn,
		udpConn:    udpConn,
		relayAddr:  relayAddr,
		relayLabel: relayHostPort,
	}, nil
}

func (c *SOCKS5UDPConn) WriteToHostPort(payload []byte, targetHostPort string) error {
	addrBytes, err := encodeSocksAddrHostPort(targetHostPort)
	if err != nil {
		return err
	}
	pkt := make([]byte, 3+len(addrBytes)+len(payload))
	pkt[0], pkt[1], pkt[2] = 0x00, 0x00, 0x00 // RSV=0, FRAG=0
	copy(pkt[3:], addrBytes)
	copy(pkt[3+len(addrBytes):], payload)
	_, err = c.udpConn.WriteToUDP(pkt, c.relayAddr)
	return err
}

func (c *SOCKS5UDPConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	if err := c.WriteToHostPort(p, addr.String()); err != nil {
		return 0, err
	}
	return len(p), nil
}

func (c *SOCKS5UDPConn) ReadFromHostPort(p []byte) (int, string, error) {
	buf := make([]byte, len(p)+512)
	n, _, err := c.udpConn.ReadFromUDP(buf)
	if err != nil {
		return 0, "", err
	}
	if n < 4 {
		return 0, "", io.ErrUnexpectedEOF
	}
	r := bytes.NewReader(buf[3:n])
	srcAddr, err := readSocksAddr(r)
	if err != nil {
		return 0, "", err
	}
	payloadOff := 3 + (n - 3 - r.Len())
	copied := copy(p, buf[payloadOff:n])
	return copied, srcAddr, nil
}

func (c *SOCKS5UDPConn) ReadFrom(p []byte) (int, net.Addr, error) {
	n, src, err := c.ReadFromHostPort(p)
	if err != nil {
		return 0, nil, err
	}
	if uaddr, resolveErr := net.ResolveUDPAddr("udp", src); resolveErr == nil {
		return n, uaddr, nil
	}
	return n, dummyAddr(src), nil
}

func (c *SOCKS5UDPConn) LocalAddr() net.Addr                { return c.udpConn.LocalAddr() }
func (c *SOCKS5UDPConn) SetDeadline(t time.Time) error      { return c.udpConn.SetDeadline(t) }
func (c *SOCKS5UDPConn) SetReadDeadline(t time.Time) error  { return c.udpConn.SetReadDeadline(t) }
func (c *SOCKS5UDPConn) SetWriteDeadline(t time.Time) error { return c.udpConn.SetWriteDeadline(t) }

func (c *SOCKS5UDPConn) Close() error {
	var e1, e2 error
	if c.udpConn != nil {
		e1 = c.udpConn.Close()
	}
	if c.ctrlConn != nil {
		e2 = c.ctrlConn.Close()
	}
	return errors.Join(e1, e2)
}

type dummyAddr string

func (d dummyAddr) Network() string { return "udp" }
func (d dummyAddr) String() string  { return string(d) }

// ---------------------------------------------------------------------------
// 9. White-Room SpecRefCodec (Zero Imports of protocol/aether)
// ---------------------------------------------------------------------------

const (
	SpecProtocolVersion uint8 = 0x02

	SpecCommandTCP uint8 = 0x01
	SpecCommandUDP uint8 = 0x02
	SpecCommandMux uint8 = 0x03
	SpecCommandUoT uint8 = 0x04

	SpecCipherAES256GCM        uint8 = 0x01
	SpecCipherChaCha20Poly1305 uint8 = 0x02

	SpecFrameData       byte = 0x01
	SpecFramePing       byte = 0x02
	SpecFramePong       byte = 0x03
	SpecFrameCloseWrite byte = 0x04

	SpecPSKSize               = 32
	SpecHandshakeSaltSize     = 32
	SpecEPKSize               = 32
	SpecEIHSize               = 16
	SpecUserIDSize            = 16
	SpecAEADNonceSize         = 12
	SpecAEADTagSize           = 16
	SpecFixedHeaderPlainSize  = 16
	SpecEncryptedFixedHdrSize = 32
	SpecClientPrefixNoEIHSize = 96
	SpecClientPrefixEIHSize   = 112
	SpecRespHeaderPlainSize   = 4
	SpecServerRespPrefixSize  = 84
	SpecLengthHeaderPlainSize = 2
	SpecEncryptedLengthSize   = 18
	SpecMinFramePlainSize     = 2
	SpecMaxFrameDataSize      = 16384
	SpecMaxFramePadSize       = 255
	SpecMaxFramePlainSize     = 16641
	SpecNoiseMin              = 32
	SpecNoiseMax              = 384

	specArgon2Time    uint32 = 3
	specArgon2MemKiB  uint32 = 64 * 1024
	specArgon2Threads uint8  = 4
)

var (
	specStrictStdBase64    = base64.StdEncoding.Strict()
	specStrictRawStdBase64 = base64.RawStdEncoding.Strict()
	specStrictURLBase64    = base64.URLEncoding.Strict()
	specStrictRawURLBase64 = base64.RawURLEncoding.Strict()
)

func specIsAllZero32(b [32]byte) bool {
	var acc byte
	for _, x := range b {
		acc |= x
	}
	return acc == 0
}

func specDecodeBase64Key32(s string) ([32]byte, bool) {
	var out [32]byte
	if strings.ContainsAny(s, "\r\n") {
		return out, false
	}
	switch len(s) {
	case 43:
		for _, enc := range []*base64.Encoding{specStrictRawStdBase64, specStrictRawURLBase64} {
			dec, err := enc.DecodeString(s)
			if err == nil && len(dec) == 32 {
				copy(out[:], dec)
				return out, true
			}
		}
	case 44:
		if s[43] != '=' || s[42] == '=' {
			return out, false
		}
		for _, enc := range []*base64.Encoding{specStrictStdBase64, specStrictURLBase64} {
			dec, err := enc.DecodeString(s)
			if err == nil && len(dec) == 32 {
				copy(out[:], dec)
				return out, true
			}
		}
	}
	return out, false
}

// SpecDerivePSK implements Aether v2 PSK derivation identically to PROJECT_CONTRACTS.
func SpecDerivePSK(secret string) ([32]byte, error) {
	var out [32]byte
	if secret == "" {
		return out, errors.New("spec: empty secret")
	}
	if key, ok := specDecodeBase64Key32(secret); ok {
		if specIsAllZero32(key) {
			return out, errors.New("spec: all-zero key rejected")
		}
		return key, nil
	}
	if len(secret) < 16 {
		return out, errors.New("spec: weak passphrase (<16 chars and not valid 32B Base64)")
	}
	derived := argon2.IDKey([]byte(secret), []byte("AetherFlow-v2-KDF"), specArgon2Time, specArgon2MemKiB, specArgon2Threads, 32)
	copy(out[:], derived)
	return out, nil
}

// SpecCredentials represents parsed client/outbound credentials (single-key or password:key EIH).
type SpecCredentials struct {
	HasServerPSK bool
	IPSK         [32]byte
	UPSK         [32]byte
	UserID       [16]byte
}

// SpecParseCredentials parses password/key or dual "iSecret:uSecret" credentials.
func SpecParseCredentials(password, key string) (SpecCredentials, error) {
	if password != "" && key != "" {
		iPSK, err := SpecDerivePSK(password)
		if err != nil {
			return SpecCredentials{}, err
		}
		uPSK, err := SpecDerivePSK(key)
		if err != nil {
			return SpecCredentials{}, err
		}
		return SpecCredentials{
			HasServerPSK: true,
			IPSK:         iPSK,
			UPSK:         uPSK,
			UserID:       SpecDeriveUserID(uPSK),
		}, nil
	}
	secret := password
	if secret == "" {
		secret = key
	}
	if secret == "" {
		return SpecCredentials{}, errors.New("spec: empty outbound credentials")
	}
	if left, right, hasColon := strings.Cut(secret, ":"); hasColon {
		leftKey, okL := specDecodeBase64Key32(left)
		rightKey, okR := specDecodeBase64Key32(right)
		if okL && okR {
			if specIsAllZero32(leftKey) || specIsAllZero32(rightKey) {
				return SpecCredentials{}, errors.New("spec: all-zero dual key rejected")
			}
			return SpecCredentials{
				HasServerPSK: true,
				IPSK:         leftKey,
				UPSK:         rightKey,
				UserID:       SpecDeriveUserID(rightKey),
			}, nil
		}
		if len(secret) >= 16 {
			uPSK, err := SpecDerivePSK(secret)
			if err != nil {
				return SpecCredentials{}, err
			}
			return SpecCredentials{UPSK: uPSK, UserID: SpecDeriveUserID(uPSK)}, nil
		}
		return SpecCredentials{}, errors.New("spec: invalid colon credential")
	}
	uPSK, err := SpecDerivePSK(secret)
	if err != nil {
		return SpecCredentials{}, err
	}
	return SpecCredentials{UPSK: uPSK, UserID: SpecDeriveUserID(uPSK)}, nil
}

// SpecDeriveUserID returns SHA-256("AetherFlow-v2-UID" || uPSK[:])[0:16].
func SpecDeriveUserID(uPSK [32]byte) [16]byte {
	var in [17 + 32]byte
	copy(in[:17], "AetherFlow-v2-UID")
	copy(in[17:], uPSK[:])
	sum := sha256.Sum256(in[:])
	var uid [16]byte
	copy(uid[:], sum[:16])
	return uid
}

// SpecMaskEIH masks userID with HKDF-SHA256(iPSK, clientSalt, "AetherFlow-v2-EIH", 16).
func SpecMaskEIH(iPSK, clientSalt [32]byte, userID [16]byte) [16]byte {
	mask, err := hkdf.Key(sha256.New, iPSK[:], clientSalt[:], "AetherFlow-v2-EIH", 16)
	if err != nil {
		panic(err)
	}
	var out [16]byte
	for i := 0; i < 16; i++ {
		out[i] = userID[i] ^ mask[i]
	}
	return out
}

// SpecUnmaskEIH unmasks a 16B EIH back into 16B userID.
func SpecUnmaskEIH(iPSK, clientSalt [32]byte, eih [16]byte) [16]byte {
	return SpecMaskEIH(iPSK, clientSalt, eih)
}

// SpecMaskEPK XOR-masks raw X25519 public key using ChaCha20 derived from HKDF(uPSK, salt, "AetherFlow-v2-EPK-Mask", 44).
func SpecMaskEPK(uPSK, salt, rawEPK [32]byte) [32]byte {
	km, err := hkdf.Key(sha256.New, uPSK[:], salt[:], "AetherFlow-v2-EPK-Mask", 44)
	if err != nil {
		panic(err)
	}
	stream, err := chacha20.NewUnauthenticatedCipher(km[0:32], km[32:44])
	if err != nil {
		panic(err)
	}
	var out [32]byte
	stream.XORKeyStream(out[:], rawEPK[:])
	return out
}

// SpecUnmaskEPK unmasks a 32-byte ChaCha20-masked X25519 key.
func SpecUnmaskEPK(uPSK, salt, maskedEPK [32]byte) (*ecdh.PublicKey, error) {
	raw := SpecMaskEPK(uPSK, salt, maskedEPK)
	if specIsAllZero32(raw) {
		return nil, errors.New("spec: all-zero raw EPK")
	}
	return ecdh.X25519().NewPublicKey(raw[:])
}

// SpecParseX25519PrivateKey decodes a base64 X25519 private key.
func SpecParseX25519PrivateKey(s string) (*ecdh.PrivateKey, error) {
	key, ok := specDecodeBase64Key32(s)
	if !ok {
		return nil, errors.New("spec: invalid base64 X25519 private key")
	}
	return ecdh.X25519().NewPrivateKey(key[:])
}

// SpecParseX25519PublicKey decodes a base64 X25519 public key.
func SpecParseX25519PublicKey(s string) (*ecdh.PublicKey, error) {
	key, ok := specDecodeBase64Key32(s)
	if !ok {
		return nil, errors.New("spec: invalid base64 X25519 public key")
	}
	return ecdh.X25519().NewPublicKey(key[:])
}

// SpecEncodeNonce returns [0,0,0,0 || uint64_BE(seq)].
func SpecEncodeNonce(seq uint64) [12]byte {
	var n [12]byte
	binary.BigEndian.PutUint64(n[4:12], seq)
	return n
}

// SpecDeriveClientInitAEAD derives initAEAD for FixedHeader (nonce 0) and VarHeader (nonce 1).
func SpecDeriveClientInitAEAD(uPSK, clientSalt [32]byte, staticSS []byte) (cipher.AEAD, error) {
	ikm := make([]byte, 0, 64)
	ikm = append(ikm, uPSK[:]...)
	if len(staticSS) > 0 {
		ikm = append(ikm, staticSS...)
	}
	k, err := hkdf.Key(sha256.New, ikm, clientSalt[:], "AetherFlow-v2-Client-Init", 32)
	if err != nil {
		return nil, err
	}
	return chacha20poly1305.New(k)
}

// SpecSessionKeys holds all 5 HKDF-Expand-derived session keys.
type SpecSessionKeys struct {
	MasterSecret  [32]byte
	RespKey       [32]byte
	C2SHeaderKey  [32]byte
	C2SPayloadKey [32]byte
	S2CHeaderKey  [32]byte
	S2CPayloadKey [32]byte
}

func specExpand32(prk []byte, info string) [32]byte {
	outSlice, err := hkdf.Expand(sha256.New, prk, info, 32)
	if err != nil {
		panic(err)
	}
	var out [32]byte
	copy(out[:], outSlice)
	return out
}

// SpecDeriveSessionKeys performs dual-salt Extract + 5-subkey Expand identically to U-6.
func SpecDeriveSessionKeys(uPSK, clientSalt, serverSalt, ssEph [32]byte, staticSS []byte) (SpecSessionKeys, error) {
	ikm := make([]byte, 0, 96)
	ikm = append(ikm, uPSK[:]...)
	ikm = append(ikm, ssEph[:]...)
	if len(staticSS) > 0 {
		ikm = append(ikm, staticSS...)
	}
	var dualSalt [64]byte
	copy(dualSalt[0:32], clientSalt[:])
	copy(dualSalt[32:64], serverSalt[:])
	msSlice, err := hkdf.Key(sha256.New, ikm, dualSalt[:], "AetherFlow-v2-Session", 32)
	if err != nil {
		return SpecSessionKeys{}, err
	}
	var keys SpecSessionKeys
	copy(keys.MasterSecret[:], msSlice)
	keys.RespKey = specExpand32(msSlice, "AetherFlow-v2-Resp")
	keys.C2SHeaderKey = specExpand32(msSlice, "AetherFlow-v2-C2S-Header")
	keys.C2SPayloadKey = specExpand32(msSlice, "AetherFlow-v2-C2S-Payload")
	keys.S2CHeaderKey = specExpand32(msSlice, "AetherFlow-v2-S2C-Header")
	keys.S2CPayloadKey = specExpand32(msSlice, "AetherFlow-v2-S2C-Payload")
	return keys, nil
}

// SpecNewDataAEAD constructs AES-256-GCM or ChaCha20-Poly1305 AEAD for suite 0x01/0x02.
func SpecNewDataAEAD(suite uint8, key [32]byte) (cipher.AEAD, error) {
	switch suite {
	case SpecCipherAES256GCM:
		blk, err := aes.NewCipher(key[:])
		if err != nil {
			return nil, err
		}
		return cipher.NewGCM(blk)
	case SpecCipherChaCha20Poly1305:
		return chacha20poly1305.New(key[:])
	default:
		return nil, fmt.Errorf("spec: unsupported cipher suite 0x%02x", suite)
	}
}

// SpecFixedHeader is the decoded 16-byte FixedHeader plaintext.
type SpecFixedHeader struct {
	Version      uint8
	Command      uint8
	CipherSuite  uint8
	Reserved     uint8
	TimestampSec int64
	NoiseLen     uint16
	VarHeaderLen uint16
	Raw          [16]byte
}

func SpecEncodeFixedHeader(h SpecFixedHeader) [16]byte {
	var raw [16]byte
	raw[0] = h.Version
	raw[1] = h.Command
	raw[2] = h.CipherSuite
	raw[3] = h.Reserved
	binary.BigEndian.PutUint64(raw[4:12], uint64(h.TimestampSec))
	binary.BigEndian.PutUint16(raw[12:14], h.NoiseLen)
	binary.BigEndian.PutUint16(raw[14:16], h.VarHeaderLen)
	return raw
}

func SpecDecodeFixedHeader(raw [16]byte) SpecFixedHeader {
	return SpecFixedHeader{
		Version:      raw[0],
		Command:      raw[1],
		CipherSuite:  raw[2],
		Reserved:     raw[3],
		TimestampSec: int64(binary.BigEndian.Uint64(raw[4:12])),
		NoiseLen:     binary.BigEndian.Uint16(raw[12:14]),
		VarHeaderLen: binary.BigEndian.Uint16(raw[14:16]),
		Raw:          raw,
	}
}

// SpecVarHeader is the decoded VarHeader payload.
type SpecVarHeader struct {
	Noise          []byte
	Target         M.Socksaddr
	TargetAddr     string
	InitialPayload []byte
}

// SpecEncodeSocksaddr encodes targetHostPort using sing's SocksaddrSerializer wire format.
func SpecEncodeSocksaddr(targetHostPort string) ([]byte, error) {
	addr := M.ParseSocksaddr(targetHostPort)
	if !addr.IsValid() {
		return nil, fmt.Errorf("spec: invalid target address %q", targetHostPort)
	}
	var buf bytes.Buffer
	if err := M.SocksaddrSerializer.WriteAddrPort(&buf, addr); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// SpecDecodeVarHeader parses [NoiseLen bytes] + SocksaddrSerializer + InitialPayload.
func SpecDecodeVarHeader(plain []byte, noiseLen int) (SpecVarHeader, error) {
	if noiseLen < 0 || noiseLen > len(plain) {
		return SpecVarHeader{}, fmt.Errorf("spec: invalid noiseLen %d > varLen %d", noiseLen, len(plain))
	}
	noise := make([]byte, noiseLen)
	copy(noise, plain[:noiseLen])
	r := bytes.NewReader(plain[noiseLen:])
	target, err := M.SocksaddrSerializer.ReadAddrPort(r)
	if err != nil {
		return SpecVarHeader{}, fmt.Errorf("spec: read var socksaddr: %w", err)
	}
	initLen := r.Len()
	initData := make([]byte, initLen)
	if initLen > 0 {
		_, _ = io.ReadFull(r, initData)
	}
	return SpecVarHeader{
		Noise:          noise,
		Target:         target,
		TargetAddr:     target.String(),
		InitialPayload: initData,
	}, nil
}

// SpecDecodedFrame represents one authenticated wire frame on C2S or S2C.
type SpecDecodedFrame struct {
	Direction     TapDirection
	Seq           uint64
	PlainFrameLen uint16
	FrameType     byte
	PadLen        byte
	Padding       []byte
	Data          []byte
}

type specUserEntry struct {
	Name   string
	UPSK   [32]byte
	UserID [16]byte
}

func specBuildInboundAuth(password, key string, users []UserSpec) (hasEIH bool, iPSK [32]byte, singleUPSK [32]byte, hasSingle bool, table []specUserEntry, err error) {
	hasEIHMode := len(users) > 0 && (password != "" || key != "")
	hasUsersOnly := len(users) > 0 && password == "" && key == ""
	if hasEIHMode {
		sec := password
		if sec == "" {
			sec = key
		}
		iPSK, err = SpecDerivePSK(sec)
		if err != nil {
			return
		}
		hasEIH = true
		for _, u := range users {
			s := u.Password
			if s == "" {
				s = u.Key
			}
			var uPSK [32]byte
			uPSK, err = SpecDerivePSK(s)
			if err != nil {
				return
			}
			table = append(table, specUserEntry{
				Name:   u.Name,
				UPSK:   uPSK,
				UserID: SpecDeriveUserID(uPSK),
			})
		}
		return
	}
	if hasUsersOnly {
		for _, u := range users {
			s := u.Password
			if s == "" {
				s = u.Key
			}
			var uPSK [32]byte
			uPSK, err = SpecDerivePSK(s)
			if err != nil {
				return
			}
			table = append(table, specUserEntry{
				Name:   u.Name,
				UPSK:   uPSK,
				UserID: SpecDeriveUserID(uPSK),
			})
		}
		return
	}
	sec := password
	if sec == "" {
		sec = key
	}
	singleUPSK, err = SpecDerivePSK(sec)
	if err != nil {
		return
	}
	hasSingle = true
	return
}

// SpecClientInitInspection holds decrypted client initial burst fields.
type SpecClientInitInspection struct {
	ClientSalt           [32]byte
	MaskedClientEPK      [32]byte
	UnmaskedClientEPK    [32]byte
	HasEIH               bool
	EIH                  [16]byte
	UserID               [16]byte
	UserName             string
	MatchedUPSK          [32]byte
	StaticSharedSecret   []byte
	InitAEAD             cipher.AEAD
	FixedHeader          SpecFixedHeader
	VarHeader            SpecVarHeader
	TotalInitialConsumed int
	TrailingStreamBytes  []byte
}

// SpecInspectClientBurst decrypts a raw captured C2S client initial burst using server credentials.
func SpecInspectClientBurst(raw []byte, password, key string, users []UserSpec, serverStaticPrivB64 string) (*SpecClientInitInspection, error) {
	hasEIH, iPSK, singleUPSK, hasSingle, table, err := specBuildInboundAuth(password, key, users)
	if err != nil {
		return nil, err
	}
	var staticPriv *ecdh.PrivateKey
	if serverStaticPrivB64 != "" {
		staticPriv, err = SpecParseX25519PrivateKey(serverStaticPrivB64)
		if err != nil {
			return nil, err
		}
	}

	prefixLen := SpecClientPrefixNoEIHSize
	aadLen := 64
	if hasEIH {
		prefixLen = SpecClientPrefixEIHSize
		aadLen = 80
	}
	if len(raw) < prefixLen {
		return nil, fmt.Errorf("spec: client burst too short: got %d need >= %d", len(raw), prefixLen)
	}

	var clientSalt, maskedEPK [32]byte
	copy(clientSalt[:], raw[0:32])
	copy(maskedEPK[:], raw[32:64])
	aad := raw[:aadLen]
	encFixed := raw[aadLen:prefixLen]

	nonce0 := SpecEncodeNonce(0)
	nonce1 := SpecEncodeNonce(1)

	tryCandidate := func(uPSK [32]byte, name string, uid [16]byte) (*SpecClientInitInspection, bool) {
		pub, epkErr := SpecUnmaskEPK(uPSK, clientSalt, maskedEPK)
		if epkErr != nil {
			return nil, false
		}
		var staticSS []byte
		if staticPriv != nil {
			ss, ecdhErr := staticPriv.ECDH(pub)
			if ecdhErr != nil || len(ss) != 32 {
				return nil, false
			}
			var arr [32]byte
			copy(arr[:], ss)
			if specIsAllZero32(arr) {
				return nil, false
			}
			staticSS = ss
		}
		initAEAD, aeadErr := SpecDeriveClientInitAEAD(uPSK, clientSalt, staticSS)
		if aeadErr != nil {
			return nil, false
		}
		fixedPlain, openErr := initAEAD.Open(nil, nonce0[:], encFixed, aad)
		if openErr != nil || len(fixedPlain) != SpecFixedHeaderPlainSize {
			return nil, false
		}
		var fixedArr [16]byte
		copy(fixedArr[:], fixedPlain)
		fh := SpecDecodeFixedHeader(fixedArr)
		varEncStart := prefixLen
		varEncEnd := prefixLen + int(fh.VarHeaderLen) + SpecAEADTagSize
		if len(raw) < varEncEnd {
			return nil, false
		}
		varPlain, varErr := initAEAD.Open(nil, nonce1[:], raw[varEncStart:varEncEnd], fixedPlain)
		if varErr != nil {
			return nil, false
		}
		vh, vhErr := SpecDecodeVarHeader(varPlain, int(fh.NoiseLen))
		if vhErr != nil {
			return nil, false
		}
		res := &SpecClientInitInspection{
			ClientSalt:           clientSalt,
			MaskedClientEPK:      maskedEPK,
			HasEIH:               hasEIH,
			UserID:               uid,
			UserName:             name,
			MatchedUPSK:          uPSK,
			StaticSharedSecret:   staticSS,
			InitAEAD:             initAEAD,
			FixedHeader:          fh,
			VarHeader:            vh,
			TotalInitialConsumed: varEncEnd,
			TrailingStreamBytes:  raw[varEncEnd:],
		}
		copy(res.UnmaskedClientEPK[:], pub.Bytes())
		if hasEIH {
			copy(res.EIH[:], raw[64:80])
		}
		return res, true
	}

	if hasEIH {
		var eih [16]byte
		copy(eih[:], raw[64:80])
		uid := SpecUnmaskEIH(iPSK, clientSalt, eih)
		for _, u := range table {
			if subtle.ConstantTimeCompare(u.UserID[:], uid[:]) == 1 {
				if res, ok := tryCandidate(u.UPSK, u.Name, u.UserID); ok {
					return res, nil
				}
			}
		}
		return nil, errors.New("spec: EIH user lookup / AEAD verification failed")
	}
	if hasSingle {
		if res, ok := tryCandidate(singleUPSK, "", SpecDeriveUserID(singleUPSK)); ok {
			return res, nil
		}
		return nil, errors.New("spec: single-PSK prefix AEAD verification failed")
	}
	for _, u := range table {
		if res, ok := tryCandidate(u.UPSK, u.Name, u.UserID); ok {
			return res, nil
		}
	}
	return nil, errors.New("spec: users-only prefix AEAD verification failed")
}

// SpecDecryptWithPSKOnly attempts prefix decryption treating passwordOrKey as a single PSK
// (no EIH). Used to assert an attacker with only iPSK or only uPSK cannot decrypt an EIH burst.
func SpecDecryptWithPSKOnly(raw []byte, passwordOrKey string) (*SpecClientInitInspection, error) {
	if res, err := SpecInspectClientBurst(raw, passwordOrKey, "", nil, ""); err == nil {
		return res, nil
	}
	// Also attempt parsing as 112-byte EIH frame with the single key directly as uPSK.
	if len(raw) >= SpecClientPrefixEIHSize {
		uPSK, err := SpecDerivePSK(passwordOrKey)
		if err != nil {
			return nil, err
		}
		var salt, epk [32]byte
		copy(salt[:], raw[0:32])
		copy(epk[:], raw[32:64])
		initAEAD, err := SpecDeriveClientInitAEAD(uPSK, salt, nil)
		if err != nil {
			return nil, err
		}
		n0 := SpecEncodeNonce(0)
		plain, err := initAEAD.Open(nil, n0[:], raw[80:112], raw[0:80])
		if err == nil && len(plain) == 16 {
			var arr [16]byte
			copy(arr[:], plain)
			return &SpecClientInitInspection{FixedHeader: SpecDecodeFixedHeader(arr)}, nil
		}
	}
	return nil, errors.New("spec: single-PSK failed to decrypt")
}

// specDirectionalCipher wraps per-direction header + payload AEADs + monotonic seq counter.
type specDirectionalCipher struct {
	suite       uint8
	headerAEAD  cipher.AEAD
	payloadAEAD cipher.AEAD
	seq         uint64
}

func newSpecDirectionalCipher(suite uint8, hdrKey, payKey [32]byte) (*specDirectionalCipher, error) {
	h, err := SpecNewDataAEAD(suite, hdrKey)
	if err != nil {
		return nil, err
	}
	p, err := SpecNewDataAEAD(suite, payKey)
	if err != nil {
		return nil, err
	}
	return &specDirectionalCipher{suite: suite, headerAEAD: h, payloadAEAD: p}, nil
}

func (dc *specDirectionalCipher) SealFrameRaw(frameType byte, padLen byte, data []byte) (wire []byte, seqUsed uint64, err error) {
	return dc.SealFrameCustom(uint16(2+int(padLen)+len(data)), frameType, padLen, data)
}

// SealFrameCustom seals a frame where plainLenOverride allows crafting invalid boundary headers.
func (dc *specDirectionalCipher) SealFrameCustom(plainLen uint16, frameType byte, padLen byte, data []byte) (wire []byte, seqUsed uint64, err error) {
	seqUsed = dc.seq
	dc.seq++
	nonce := SpecEncodeNonce(seqUsed)
	var lenPlain [2]byte
	binary.BigEndian.PutUint16(lenPlain[:], plainLen)
	bodyPlain := make([]byte, 2+int(padLen)+len(data))
	bodyPlain[0] = frameType
	bodyPlain[1] = padLen
	if padLen > 0 {
		_, _ = io.ReadFull(rand.Reader, bodyPlain[2:2+int(padLen)])
	}
	copy(bodyPlain[2+int(padLen):], data)

	wire = make([]byte, 0, SpecEncryptedLengthSize+len(bodyPlain)+SpecAEADTagSize)
	wire = dc.headerAEAD.Seal(wire, nonce[:], lenPlain[:], nil)
	wire = dc.payloadAEAD.Seal(wire, nonce[:], bodyPlain, nil)
	return wire, seqUsed, nil
}

// SealRawBodyFrame seals an exact header plainLen alongside an exact bodyPlain byte slice.
func (dc *specDirectionalCipher) SealRawBodyFrame(plainLen uint16, bodyPlain []byte) (wire []byte, seqUsed uint64, err error) {
	seqUsed = dc.seq
	dc.seq++
	nonce := SpecEncodeNonce(seqUsed)
	var lenPlain [2]byte
	binary.BigEndian.PutUint16(lenPlain[:], plainLen)
	wire = make([]byte, 0, SpecEncryptedLengthSize+len(bodyPlain)+SpecAEADTagSize)
	wire = dc.headerAEAD.Seal(wire, nonce[:], lenPlain[:], nil)
	wire = dc.payloadAEAD.Seal(wire, nonce[:], bodyPlain, nil)
	return wire, seqUsed, nil
}

func (dc *specDirectionalCipher) ReadAndOpenFrame(r io.Reader, dir TapDirection) (SpecDecodedFrame, error) {
	var encLen [SpecEncryptedLengthSize]byte
	if _, err := io.ReadFull(r, encLen[:]); err != nil {
		return SpecDecodedFrame{}, err
	}
	seq := dc.seq
	dc.seq++
	nonce := SpecEncodeNonce(seq)
	lenPlain, err := dc.headerAEAD.Open(nil, nonce[:], encLen[:], nil)
	if err != nil || len(lenPlain) != 2 {
		return SpecDecodedFrame{}, fmt.Errorf("spec: open length header seq=%d: %w", seq, err)
	}
	plainLen := binary.BigEndian.Uint16(lenPlain)
	if plainLen < SpecMinFramePlainSize || plainLen > SpecMaxFramePlainSize {
		return SpecDecodedFrame{}, fmt.Errorf("spec: invalid plainFrameLen=%d at seq=%d", plainLen, seq)
	}
	encBody := make([]byte, int(plainLen)+SpecAEADTagSize)
	if _, err := io.ReadFull(r, encBody); err != nil {
		return SpecDecodedFrame{}, err
	}
	bodyPlain, err := dc.payloadAEAD.Open(nil, nonce[:], encBody, nil)
	if err != nil {
		return SpecDecodedFrame{}, fmt.Errorf("spec: open body seq=%d: %w", seq, err)
	}
	if len(bodyPlain) < 2 {
		return SpecDecodedFrame{}, fmt.Errorf("spec: body too short len=%d", len(bodyPlain))
	}
	ft := bodyPlain[0]
	padLen := bodyPlain[1]
	if 2+int(padLen) > len(bodyPlain) {
		return SpecDecodedFrame{}, fmt.Errorf("spec: padLen=%d exceeds bodyLen=%d", padLen, len(bodyPlain))
	}
	padding := make([]byte, int(padLen))
	copy(padding, bodyPlain[2:2+int(padLen)])
	data := make([]byte, len(bodyPlain)-2-int(padLen))
	copy(data, bodyPlain[2+int(padLen):])
	return SpecDecodedFrame{
		Direction:     dir,
		Seq:           seq,
		PlainFrameLen: plainLen,
		FrameType:     ft,
		PadLen:        padLen,
		Padding:       padding,
		Data:          data,
	}, nil
}

// SpecDialOptions configures an independent white-room raw client handshake.
type SpecDialOptions struct {
	Password         string
	Key              string
	ServerPublicKey  string
	Version          *uint8
	Command          *uint8
	CipherSuite      *uint8
	Reserved         *uint8
	TimestampSec     *int64
	CustomNoise      []byte // if nil, generates 64 random bytes; if non-nil, uses verbatim (even invalid lengths!)
	NoiseLenOverride *uint16
	VarLenOverride   *uint16
	TargetAddr       string
	RawTargetBytes   []byte // if non-nil, overrides Socksaddr serialization (e.g., invalid ATYP!)
	InitialPayload   []byte
	CustomClientSalt *[32]byte
	ForceNoEIH       bool
	TruncateBurstTo  int // if >0, writes only the first N bytes of initial burst
}

// SpecClientConn is an active white-room Aether v2 client speaking to a live Box inbound.
type SpecClientConn struct {
	Conn        net.Conn
	ClientSalt  [32]byte
	InitialWire []byte
	Fixed       SpecFixedHeader

	uPSK     [32]byte
	ekC      *ecdh.PrivateKey
	staticSS []byte
	initAEAD cipher.AEAD
	suite    uint8
	c2s      *specDirectionalCipher
	s2c      *specDirectionalCipher

	mu     sync.Mutex
	frames []SpecDecodedFrame
}

// BuildSpecClientInitialBurst constructs an exact Aether v2 0-RTT initial burst
// (prefix + EncryptedVarHeader) using white-room crypto without dialing yet.
func BuildSpecClientInitialBurst(opts SpecDialOptions) (burst []byte, state *SpecClientConn, err error) {
	creds, err := SpecParseCredentials(opts.Password, opts.Key)
	if err != nil {
		return nil, nil, err
	}
	var salt [32]byte
	if opts.CustomClientSalt != nil {
		salt = *opts.CustomClientSalt
	} else {
		_, err = io.ReadFull(rand.Reader, salt[:])
		if err != nil {
			return nil, nil, err
		}
	}
	ekC, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	var rawEPK [32]byte
	copy(rawEPK[:], ekC.PublicKey().Bytes())
	maskedEPK := SpecMaskEPK(creds.UPSK, salt, rawEPK)

	var staticSS []byte
	if opts.ServerPublicKey != "" {
		srvPub, err := SpecParseX25519PublicKey(opts.ServerPublicKey)
		if err != nil {
			return nil, nil, err
		}
		staticSS, err = ekC.ECDH(srvPub)
		if err != nil {
			return nil, nil, err
		}
	}
	initAEAD, err := SpecDeriveClientInitAEAD(creds.UPSK, salt, staticSS)
	if err != nil {
		return nil, nil, err
	}

	noise := opts.CustomNoise
	if noise == nil {
		noise = make([]byte, 64)
		_, _ = io.ReadFull(rand.Reader, noise)
	}
	var addrBytes []byte
	if opts.RawTargetBytes != nil {
		addrBytes = opts.RawTargetBytes
	} else {
		target := opts.TargetAddr
		if target == "" {
			target = "127.0.0.1:80"
		}
		addrBytes, err = SpecEncodeSocksaddr(target)
		if err != nil {
			return nil, nil, err
		}
	}
	varPlain := make([]byte, 0, len(noise)+len(addrBytes)+len(opts.InitialPayload))
	varPlain = append(varPlain, noise...)
	varPlain = append(varPlain, addrBytes...)
	varPlain = append(varPlain, opts.InitialPayload...)

	ver := SpecProtocolVersion
	if opts.Version != nil {
		ver = *opts.Version
	}
	cmd := SpecCommandTCP
	if opts.Command != nil {
		cmd = *opts.Command
	}
	suite := SpecCipherChaCha20Poly1305
	if opts.CipherSuite != nil {
		suite = *opts.CipherSuite
	}
	rsv := uint8(0x00)
	if opts.Reserved != nil {
		rsv = *opts.Reserved
	}
	ts := time.Now().Unix()
	if opts.TimestampSec != nil {
		ts = *opts.TimestampSec
	}
	nLen := uint16(len(noise))
	if opts.NoiseLenOverride != nil {
		nLen = *opts.NoiseLenOverride
	}
	vLen := uint16(len(varPlain))
	if opts.VarLenOverride != nil {
		vLen = *opts.VarLenOverride
	}

	fh := SpecFixedHeader{
		Version:      ver,
		Command:      cmd,
		CipherSuite:  suite,
		Reserved:     rsv,
		TimestampSec: ts,
		NoiseLen:     nLen,
		VarHeaderLen: vLen,
	}
	fhRaw := SpecEncodeFixedHeader(fh)
	fh.Raw = fhRaw

	var prefix []byte
	n0 := SpecEncodeNonce(0)
	if creds.HasServerPSK && !opts.ForceNoEIH {
		eih := SpecMaskEIH(creds.IPSK, salt, creds.UserID)
		prefix = make([]byte, SpecClientPrefixEIHSize)
		copy(prefix[0:32], salt[:])
		copy(prefix[32:64], maskedEPK[:])
		copy(prefix[64:80], eih[:])
		initAEAD.Seal(prefix[80:80], n0[:], fhRaw[:], prefix[0:80])
	} else {
		prefix = make([]byte, SpecClientPrefixNoEIHSize)
		copy(prefix[0:32], salt[:])
		copy(prefix[32:64], maskedEPK[:])
		initAEAD.Seal(prefix[64:64], n0[:], fhRaw[:], prefix[0:64])
	}

	n1 := SpecEncodeNonce(1)
	encVar := initAEAD.Seal(nil, n1[:], varPlain, fhRaw[:])
	burst = append(prefix, encVar...)
	sc := &SpecClientConn{
		ClientSalt:  salt,
		InitialWire: burst,
		Fixed:       fh,
		uPSK:        creds.UPSK,
		ekC:         ekC,
		staticSS:    staticSS,
		initAEAD:    initAEAD,
		suite:       suite,
	}
	return burst, sc, nil
}

// DialSpecClient connects to serverAddr and transmits the coalesced 0-RTT initial burst.
func DialSpecClient(ctx context.Context, serverAddr string, opts SpecDialOptions) (*SpecClientConn, error) {
	burst, sc, err := BuildSpecClientInitialBurst(opts)
	if err != nil {
		return nil, err
	}
	var d net.Dialer
	conn, err := d.DialContext(ctx, "tcp", serverAddr)
	if err != nil {
		return nil, err
	}
	sc.Conn = conn
	toSend := burst
	if opts.TruncateBurstTo > 0 && opts.TruncateBurstTo < len(toSend) {
		toSend = toSend[:opts.TruncateBurstTo]
	}
	if len(toSend) > 0 {
		if _, err := writeAll(conn, toSend); err != nil {
			_ = conn.Close()
			return nil, err
		}
	}
	return sc, nil
}

// ReadServerResp reads and verifies the 84-byte ServerRespPrefix and initializes
// bidirectional C2S / S2C directional AEAD ciphers.
func (sc *SpecClientConn) ReadServerResp(timeout time.Duration) ([4]byte, error) {
	var respPlain [4]byte
	if timeout > 0 {
		_ = sc.Conn.SetReadDeadline(time.Now().Add(timeout))
		defer func() { _ = sc.Conn.SetReadDeadline(time.Time{}) }()
	}
	var buf [SpecServerRespPrefixSize]byte
	if _, err := io.ReadFull(sc.Conn, buf[:]); err != nil {
		return respPlain, err
	}
	var serverSalt, maskedSrvEPK [32]byte
	copy(serverSalt[:], buf[0:32])
	copy(maskedSrvEPK[:], buf[32:64])
	srvPub, err := SpecUnmaskEPK(sc.uPSK, serverSalt, maskedSrvEPK)
	if err != nil {
		return respPlain, err
	}
	ssEphBytes, err := sc.ekC.ECDH(srvPub)
	if err != nil {
		return respPlain, err
	}
	var ssEph [32]byte
	copy(ssEph[:], ssEphBytes)
	keys, err := SpecDeriveSessionKeys(sc.uPSK, sc.ClientSalt, serverSalt, ssEph, sc.staticSS)
	if err != nil {
		return respPlain, err
	}
	respAEAD, err := chacha20poly1305.New(keys.RespKey[:])
	if err != nil {
		return respPlain, err
	}
	var aad96 [96]byte
	copy(aad96[0:32], sc.ClientSalt[:])
	copy(aad96[32:64], serverSalt[:])
	copy(aad96[64:96], maskedSrvEPK[:])
	n0 := SpecEncodeNonce(0)
	plain, err := respAEAD.Open(nil, n0[:], buf[64:84], aad96[:])
	if err != nil || len(plain) != 4 {
		return respPlain, fmt.Errorf("spec: verify ServerRespPrefix failed: %w", err)
	}
	copy(respPlain[:], plain)
	if respPlain[0] != SpecProtocolVersion || respPlain[1] != 0x00 || respPlain[2] != sc.suite || respPlain[3] != 0x00 {
		return respPlain, fmt.Errorf("spec: invalid RespHeader %x", respPlain)
	}
	sc.c2s, err = newSpecDirectionalCipher(sc.suite, keys.C2SHeaderKey, keys.C2SPayloadKey)
	if err != nil {
		return respPlain, err
	}
	sc.s2c, err = newSpecDirectionalCipher(sc.suite, keys.S2CHeaderKey, keys.S2CPayloadKey)
	if err != nil {
		return respPlain, err
	}
	return respPlain, nil
}

func (sc *SpecClientConn) WriteFrame(frameType byte, padLen byte, data []byte) error {
	wire, _, err := sc.c2s.SealFrameRaw(frameType, padLen, data)
	if err != nil {
		return err
	}
	_, err = writeAll(sc.Conn, wire)
	return err
}

// WriteCustomFrame writes a frame with arbitrary plainLen/padLen/frameType to test boundary validation.
func (sc *SpecClientConn) WriteCustomFrame(plainLen uint16, frameType byte, padLen byte, data []byte) error {
	wire, _, err := sc.c2s.SealFrameCustom(plainLen, frameType, padLen, data)
	if err != nil {
		return err
	}
	_, err = writeAll(sc.Conn, wire)
	return err
}

// WriteRawBodyFrame seals and transmits a frame with exact plainLen and exact raw bodyPlain bytes.
func (sc *SpecClientConn) WriteRawBodyFrame(plainLen uint16, bodyPlain []byte) error {
	wire, _, err := sc.c2s.SealRawBodyFrame(plainLen, bodyPlain)
	if err != nil {
		return err
	}
	_, err = writeAll(sc.Conn, wire)
	return err
}

func (sc *SpecClientConn) SendChaff(count int, padLen byte) error {
	for i := 0; i < count; i++ {
		if err := sc.WriteFrame(SpecFrameData, padLen, nil); err != nil {
			return err
		}
	}
	return nil
}

func (sc *SpecClientConn) SendPing(padLen byte) error {
	return sc.WriteFrame(SpecFramePing, padLen, nil)
}

func (sc *SpecClientConn) SendPong(padLen byte) error {
	return sc.WriteFrame(SpecFramePong, padLen, nil)
}

func (sc *SpecClientConn) SendCloseWrite() error {
	return sc.WriteFrame(SpecFrameCloseWrite, 0, nil)
}

// SendUDPDatagram writes one CommandUDP stream-framed datagram: [Socksaddr][uint16 BE len][payload].
func (sc *SpecClientConn) SendUDPDatagram(targetHostPort string, payload []byte, lengthOverride *uint16) error {
	addrBytes, err := SpecEncodeSocksaddr(targetHostPort)
	if err != nil {
		return err
	}
	pktLen := uint16(len(payload))
	if lengthOverride != nil {
		pktLen = *lengthOverride
	}
	var hdr [2]byte
	binary.BigEndian.PutUint16(hdr[:], pktLen)
	msg := make([]byte, 0, len(addrBytes)+2+len(payload))
	msg = append(msg, addrBytes...)
	msg = append(msg, hdr[:]...)
	msg = append(msg, payload...)
	for len(msg) > 0 {
		chunk := msg
		if len(chunk) > SpecMaxFrameDataSize {
			chunk = msg[:SpecMaxFrameDataSize]
		}
		if err := sc.WriteFrame(SpecFrameData, 0, chunk); err != nil {
			return err
		}
		msg = msg[len(chunk):]
	}
	return nil
}

func (sc *SpecClientConn) ReadFrame(timeout time.Duration) (SpecDecodedFrame, error) {
	if timeout > 0 {
		_ = sc.Conn.SetReadDeadline(time.Now().Add(timeout))
		defer func() { _ = sc.Conn.SetReadDeadline(time.Time{}) }()
	}
	fr, err := sc.s2c.ReadAndOpenFrame(sc.Conn, DirS2C)
	if err != nil {
		return SpecDecodedFrame{}, err
	}
	sc.mu.Lock()
	sc.frames = append(sc.frames, fr)
	sc.mu.Unlock()
	return fr, nil
}

// ReadNextDataFrame reads frames until timeout, skipping unsolicited keepalive frames
// (FramePing, FramePong, and 0-byte FrameData), returning the first non-empty FrameData
// or FrameCloseWrite frame.
func (sc *SpecClientConn) ReadNextDataFrame(timeout time.Duration) (SpecDecodedFrame, error) {
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	deadline := time.Now().Add(timeout)
	for {
		rem := time.Until(deadline)
		if rem <= 0 {
			return SpecDecodedFrame{}, fmt.Errorf("spec: timed out waiting for data frame: %w", os.ErrDeadlineExceeded)
		}
		fr, err := sc.ReadFrame(rem)
		if err != nil {
			return SpecDecodedFrame{}, err
		}
		if fr.FrameType == SpecFramePing || fr.FrameType == SpecFramePong {
			continue
		}
		if fr.FrameType == SpecFrameData && len(fr.Data) == 0 {
			continue
		}
		return fr, nil
	}
}

// ReadUntilFrameType reads frames until a frame with the given frameType arrives or timeout expires.
func (sc *SpecClientConn) ReadUntilFrameType(frameType byte, timeout time.Duration) (SpecDecodedFrame, error) {
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	deadline := time.Now().Add(timeout)
	for {
		rem := time.Until(deadline)
		if rem <= 0 {
			return SpecDecodedFrame{}, fmt.Errorf("spec: timed out waiting for frameType=0x%02x: %w", frameType, os.ErrDeadlineExceeded)
		}
		fr, err := sc.ReadFrame(rem)
		if err != nil {
			return SpecDecodedFrame{}, err
		}
		if fr.FrameType == frameType {
			return fr, nil
		}
	}
}

// ExpectPeerClose drains any server-initiated keepalive frames (FramePing, FramePong,
// or 0-byte FrameData flush) until the peer closes the connection within timeout.
// It returns nil on peer close, or an error if non-empty data/EOF-frame arrives or timeout expires.
func (sc *SpecClientConn) ExpectPeerClose(timeout time.Duration) error {
	if timeout <= 0 {
		timeout = 2 * time.Second
	}
	deadline := time.Now().Add(timeout)
	for {
		rem := time.Until(deadline)
		if rem <= 0 {
			return fmt.Errorf("spec: timed out waiting for peer close: %w", os.ErrDeadlineExceeded)
		}
		fr, err := sc.ReadFrame(rem)
		if err != nil {
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				return fmt.Errorf("spec: timed out waiting for peer close: %w", err)
			}
			if errors.Is(err, os.ErrDeadlineExceeded) {
				return fmt.Errorf("spec: timed out waiting for peer close: %w", err)
			}
			return nil
		}
		if fr.FrameType == SpecFramePing || fr.FrameType == SpecFramePong {
			continue
		}
		if fr.FrameType == SpecFrameData && len(fr.Data) == 0 {
			continue
		}
		return fmt.Errorf("spec: expected peer close, got frameType=0x%02x len=%d", fr.FrameType, len(fr.Data))
	}
}

func (sc *SpecClientConn) CloseWrite() error {
	if tc, ok := sc.Conn.(*net.TCPConn); ok {
		return tc.CloseWrite()
	}
	return nil
}

func (sc *SpecClientConn) Close() error {
	if sc.Conn != nil {
		return sc.Conn.Close()
	}
	return nil
}

// SpecServerSession represents one incoming client connection to SpecMockServer.
type SpecServerSession struct {
	ID          int
	Conn        net.Conn
	ClientSalt  [32]byte
	MaskedEPK   [32]byte
	HasEIH      bool
	EIH         [16]byte
	UserID      [16]byte
	UserName    string
	FixedHeader SpecFixedHeader
	VarHeader   SpecVarHeader

	c2s     *specDirectionalCipher
	s2c     *specDirectionalCipher
	writeMu sync.Mutex
	mu      sync.RWMutex
	frames  []SpecDecodedFrame
	err     error
	doneCh  chan struct{}
}

func (s *SpecServerSession) addFrame(f SpecDecodedFrame) {
	s.mu.Lock()
	s.frames = append(s.frames, f)
	s.mu.Unlock()
}

func (s *SpecServerSession) DecodedFrames() []SpecDecodedFrame {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]SpecDecodedFrame, len(s.frames))
	copy(out, s.frames)
	return out
}

func (s *SpecServerSession) C2SDataFrames() []SpecDecodedFrame {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var out []SpecDecodedFrame
	for _, f := range s.frames {
		if f.Direction == DirC2S && f.FrameType == SpecFrameData {
			out = append(out, f)
		}
	}
	return out
}

func (s *SpecServerSession) ReadC2SFrame(timeout time.Duration) (SpecDecodedFrame, error) {
	if timeout > 0 {
		_ = s.Conn.SetReadDeadline(time.Now().Add(timeout))
		defer func() { _ = s.Conn.SetReadDeadline(time.Time{}) }()
	}
	f, err := s.c2s.ReadAndOpenFrame(s.Conn, DirC2S)
	if err != nil {
		return SpecDecodedFrame{}, err
	}
	s.addFrame(f)
	return f, nil
}

func (s *SpecServerSession) WriteS2CFrame(frameType byte, padLen byte, data []byte) error {
	return s.WriteS2CCustomFrame(uint16(2+int(padLen)+len(data)), frameType, padLen, data)
}

func (s *SpecServerSession) WriteS2CCustomFrame(plainLen uint16, frameType byte, padLen byte, data []byte) error {
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	wire, seq, err := s.s2c.SealFrameCustom(plainLen, frameType, padLen, data)
	if err != nil {
		return err
	}
	s.addFrame(SpecDecodedFrame{
		Direction:     DirS2C,
		Seq:           seq,
		PlainFrameLen: plainLen,
		FrameType:     frameType,
		PadLen:        padLen,
		Data:          append([]byte(nil), data...),
	})
	_, err = writeAll(s.Conn, wire)
	return err
}

// WriteS2CRawBodyFrame seals and sends an S2C frame with exact plainLen and raw bodyPlain bytes.
func (s *SpecServerSession) WriteS2CRawBodyFrame(plainLen uint16, bodyPlain []byte) error {
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	wire, _, err := s.s2c.SealRawBodyFrame(plainLen, bodyPlain)
	if err != nil {
		return err
	}
	_, err = writeAll(s.Conn, wire)
	return err
}

func (s *SpecServerSession) Error() error {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.err
}

// SpecServerOptions configures an independent white-room Aether v2 mock server
// that a real sing-box `aether-out` outbound can dial cleanly.
type SpecServerOptions struct {
	Password         string
	Key              string
	Users            []UserSpec
	ServerPrivateKey string
	TimeWindow       time.Duration

	// RespOverride customizes the 4-byte RespHeader plaintext [Ver, Status, Suite, Reserved].
	RespOverride *[4]byte
	// SendTrailingRespBytes appends trailing garbage immediately after 84B ServerRespPrefix.
	SendTrailingRespBytes []byte
	// TruncateRespPrefixBytes cuts the 84B ServerRespPrefix short (e.g. 50 bytes) and closes.
	TruncateRespPrefixBytes int
	// SendLowOrderServerEPK forces a low-order 32-byte masked server EPK (all-zero raw EPK).
	SendLowOrderServerEPK bool
	// RelayTCPTarget forwards CommandTCP streams to this address (if empty and OnSession nil, echoes back).
	RelayTCPTarget string
	// RelayUDPTarget forwards CommandUDP datagrams to this address (if empty, echoes back).
	RelayUDPTarget string
	// OnSession gives test cases complete imperative control over S2C injection & reading.
	OnSession func(sess *SpecServerSession)
}

// SpecMockServer listens on loopback and performs independent white-room Aether v2 server handshakes.
type SpecMockServer struct {
	ln       net.Listener
	addr     string
	port     uint16
	opts     SpecServerOptions
	closedCh chan struct{}
	once     sync.Once
	wg       sync.WaitGroup

	connMu   sync.Mutex
	conns    map[net.Conn]struct{}
	mu       sync.RWMutex
	sessions []*SpecServerSession
	nextID   atomic.Int64
}

// StartSpecMockServer launches a SpecMockServer listening on 127.0.0.1:0.
func StartSpecMockServer(t testing.TB, opts SpecServerOptions) *SpecMockServer {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	taddr := ln.Addr().(*net.TCPAddr)
	srv := &SpecMockServer{
		ln:       ln,
		addr:     taddr.String(),
		port:     uint16(taddr.Port),
		opts:     opts,
		closedCh: make(chan struct{}),
		conns:    make(map[net.Conn]struct{}),
	}
	srv.wg.Add(1)
	go srv.acceptLoop()
	t.Cleanup(srv.Close)
	return srv
}

// StartSpecEchoRelayServer starts a SpecMockServer configured as a framing-recording relay/echo server.
func StartSpecEchoRelayServer(t testing.TB, password, key string, users []UserSpec, serverPrivB64 string) *SpecMockServer {
	t.Helper()
	return StartSpecMockServer(t, SpecServerOptions{
		Password:         password,
		Key:              key,
		Users:            users,
		ServerPrivateKey: serverPrivB64,
	})
}

func (m *SpecMockServer) Addr() string { return m.addr }
func (m *SpecMockServer) Port() uint16 { return m.port }

func (m *SpecMockServer) Sessions() []*SpecServerSession {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]*SpecServerSession, len(m.sessions))
	copy(out, m.sessions)
	return out
}

func (m *SpecMockServer) WaitForSessions(t testing.TB, count int, timeout time.Duration) []*SpecServerSession {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for {
		ss := m.Sessions()
		if len(ss) >= count {
			return ss
		}
		require.False(t, time.Now().After(deadline), "timed out waiting for %d SpecMockServer sessions", count)
		time.Sleep(10 * time.Millisecond)
	}
}

func (m *SpecMockServer) Close() {
	m.once.Do(func() {
		close(m.closedCh)
		_ = m.ln.Close()
		m.connMu.Lock()
		for c := range m.conns {
			_ = c.Close()
		}
		m.connMu.Unlock()
		m.wg.Wait()
	})
}

func (m *SpecMockServer) acceptLoop() {
	defer m.wg.Done()
	for {
		conn, err := m.ln.Accept()
		if err != nil {
			select {
			case <-m.closedCh:
				return
			default:
				return
			}
		}
		m.wg.Add(1)
		go func(c net.Conn) {
			defer m.wg.Done()
			m.handleConn(c)
		}(conn)
	}
}

func (m *SpecMockServer) handleConn(conn net.Conn) {
	m.connMu.Lock()
	select {
	case <-m.closedCh:
		m.connMu.Unlock()
		_ = conn.Close()
		return
	default:
	}
	if m.conns == nil {
		m.conns = make(map[net.Conn]struct{})
	}
	m.conns[conn] = struct{}{}
	m.connMu.Unlock()
	defer func() {
		m.connMu.Lock()
		delete(m.conns, conn)
		m.connMu.Unlock()
		_ = conn.Close()
	}()
	_ = conn.SetReadDeadline(time.Now().Add(10 * time.Second))

	hasEIH, _, _, _, _, err := specBuildInboundAuth(m.opts.Password, m.opts.Key, m.opts.Users)
	if err != nil {
		return
	}
	prefixLen := SpecClientPrefixNoEIHSize
	if hasEIH {
		prefixLen = SpecClientPrefixEIHSize
	}
	prefix := make([]byte, prefixLen)
	if _, err := io.ReadFull(conn, prefix); err != nil {
		return
	}

	// Read minimum header length first? Fixed header must decrypt before reading VarHeaderLen.
	// Inspect client prefix first:
	rawPrefixOnly := prefix
	insp, err := m.inspectPrefixOnly(rawPrefixOnly)
	if err != nil {
		return
	}
	encVar := make([]byte, int(insp.FixedHeader.VarHeaderLen)+SpecAEADTagSize)
	if _, err := io.ReadFull(conn, encVar); err != nil {
		return
	}
	_ = conn.SetReadDeadline(time.Time{})

	fullBurst := append(prefix, encVar...)
	fullInsp, err := SpecInspectClientBurst(fullBurst, m.opts.Password, m.opts.Key, m.opts.Users, m.opts.ServerPrivateKey)
	if err != nil {
		return
	}
	if m.opts.TimeWindow > 0 {
		diff := time.Since(time.Unix(fullInsp.FixedHeader.TimestampSec, 0))
		if diff < 0 {
			diff = -diff
		}
		if diff > m.opts.TimeWindow {
			return
		}
	}

	var serverSalt [32]byte
	_, _ = io.ReadFull(rand.Reader, serverSalt[:])
	ekS, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return
	}
	var rawSrvEPK [32]byte
	if !m.opts.SendLowOrderServerEPK {
		copy(rawSrvEPK[:], ekS.PublicKey().Bytes())
	}
	maskedSrvEPK := SpecMaskEPK(fullInsp.MatchedUPSK, serverSalt, rawSrvEPK)

	cliPub, err := ecdh.X25519().NewPublicKey(fullInsp.UnmaskedClientEPK[:])
	if err != nil {
		return
	}
	ssEphBytes, err := ekS.ECDH(cliPub)
	if err != nil {
		return
	}
	var ssEph [32]byte
	copy(ssEph[:], ssEphBytes)
	keys, err := SpecDeriveSessionKeys(fullInsp.MatchedUPSK, fullInsp.ClientSalt, serverSalt, ssEph, fullInsp.StaticSharedSecret)
	if err != nil {
		return
	}
	respAEAD, err := chacha20poly1305.New(keys.RespKey[:])
	if err != nil {
		return
	}
	respPlain := [4]byte{SpecProtocolVersion, 0x00, fullInsp.FixedHeader.CipherSuite, 0x00}
	if m.opts.RespOverride != nil {
		respPlain = *m.opts.RespOverride
	}
	var aad96 [96]byte
	copy(aad96[0:32], fullInsp.ClientSalt[:])
	copy(aad96[32:64], serverSalt[:])
	copy(aad96[64:96], maskedSrvEPK[:])
	n0 := SpecEncodeNonce(0)

	respPrefix := make([]byte, SpecServerRespPrefixSize)
	copy(respPrefix[0:32], serverSalt[:])
	copy(respPrefix[32:64], maskedSrvEPK[:])
	respAEAD.Seal(respPrefix[64:64], n0[:], respPlain[:], aad96[:])

	if m.opts.TruncateRespPrefixBytes > 0 && m.opts.TruncateRespPrefixBytes < len(respPrefix) {
		_, _ = writeAll(conn, respPrefix[:m.opts.TruncateRespPrefixBytes])
		return
	}
	if _, err := writeAll(conn, respPrefix); err != nil {
		return
	}
	if len(m.opts.SendTrailingRespBytes) > 0 {
		_, _ = writeAll(conn, m.opts.SendTrailingRespBytes)
	}

	suite := fullInsp.FixedHeader.CipherSuite
	c2s, err := newSpecDirectionalCipher(suite, keys.C2SHeaderKey, keys.C2SPayloadKey)
	if err != nil {
		return
	}
	s2c, err := newSpecDirectionalCipher(suite, keys.S2CHeaderKey, keys.S2CPayloadKey)
	if err != nil {
		return
	}

	sess := &SpecServerSession{
		ID:          int(m.nextID.Add(1)),
		Conn:        conn,
		ClientSalt:  fullInsp.ClientSalt,
		MaskedEPK:   fullInsp.MaskedClientEPK,
		HasEIH:      fullInsp.HasEIH,
		EIH:         fullInsp.EIH,
		UserID:      fullInsp.UserID,
		UserName:    fullInsp.UserName,
		FixedHeader: fullInsp.FixedHeader,
		VarHeader:   fullInsp.VarHeader,
		c2s:         c2s,
		s2c:         s2c,
		doneCh:      make(chan struct{}),
	}
	defer close(sess.doneCh)

	m.mu.Lock()
	m.sessions = append(m.sessions, sess)
	m.mu.Unlock()

	if m.opts.OnSession != nil {
		m.opts.OnSession(sess)
		return
	}
	m.defaultRelayOrEcho(sess)
}

func (m *SpecMockServer) inspectPrefixOnly(prefix []byte) (*SpecClientInitInspection, error) {
	hasEIH, iPSK, singleUPSK, hasSingle, table, err := specBuildInboundAuth(m.opts.Password, m.opts.Key, m.opts.Users)
	if err != nil {
		return nil, err
	}
	var staticPriv *ecdh.PrivateKey
	if m.opts.ServerPrivateKey != "" {
		staticPriv, err = SpecParseX25519PrivateKey(m.opts.ServerPrivateKey)
		if err != nil {
			return nil, err
		}
	}
	var salt, maskedEPK [32]byte
	copy(salt[:], prefix[0:32])
	copy(maskedEPK[:], prefix[32:64])
	aadLen := 64
	if hasEIH {
		aadLen = 80
	}
	n0 := SpecEncodeNonce(0)
	tryKey := func(uPSK [32]byte) (*SpecClientInitInspection, bool) {
		pub, err := SpecUnmaskEPK(uPSK, salt, maskedEPK)
		if err != nil {
			return nil, false
		}
		var staticSS []byte
		if staticPriv != nil {
			staticSS, err = staticPriv.ECDH(pub)
			if err != nil {
				return nil, false
			}
		}
		aead, err := SpecDeriveClientInitAEAD(uPSK, salt, staticSS)
		if err != nil {
			return nil, false
		}
		plain, err := aead.Open(nil, n0[:], prefix[aadLen:], prefix[:aadLen])
		if err != nil || len(plain) != 16 {
			return nil, false
		}
		var arr [16]byte
		copy(arr[:], plain)
		return &SpecClientInitInspection{FixedHeader: SpecDecodeFixedHeader(arr)}, true
	}
	if hasEIH {
		var eih [16]byte
		copy(eih[:], prefix[64:80])
		uid := SpecUnmaskEIH(iPSK, salt, eih)
		for _, u := range table {
			if subtle.ConstantTimeCompare(u.UserID[:], uid[:]) == 1 {
				if res, ok := tryKey(u.UPSK); ok {
					return res, nil
				}
			}
		}
		return nil, errors.New("spec mock: auth failed")
	}
	if hasSingle {
		if res, ok := tryKey(singleUPSK); ok {
			return res, nil
		}
		return nil, errors.New("spec mock: auth failed")
	}
	for _, u := range table {
		if res, ok := tryKey(u.UPSK); ok {
			return res, nil
		}
	}
	return nil, errors.New("spec mock: auth failed")
}

func (m *SpecMockServer) defaultRelayOrEcho(sess *SpecServerSession) {
	if sess.FixedHeader.Command == SpecCommandUDP {
		m.defaultUDPRelayOrEcho(sess)
		return
	}
	if len(sess.VarHeader.InitialPayload) > 0 && m.opts.RelayTCPTarget == "" {
		_ = sess.WriteS2CFrame(SpecFrameData, 0, sess.VarHeader.InitialPayload)
	}
	if m.opts.RelayTCPTarget != "" {
		targetConn, err := net.DialTimeout("tcp", m.opts.RelayTCPTarget, 5*time.Second)
		if err != nil {
			return
		}
		defer targetConn.Close()
		if len(sess.VarHeader.InitialPayload) > 0 {
			if _, err := writeAll(targetConn, sess.VarHeader.InitialPayload); err != nil {
				return
			}
		}
		var wg sync.WaitGroup
		wg.Add(2)
		go func() {
			defer wg.Done()
			buf := make([]byte, SpecMaxFrameDataSize)
			for {
				n, rerr := targetConn.Read(buf)
				if n > 0 {
					if werr := sess.WriteS2CFrame(SpecFrameData, 0, buf[:n]); werr != nil {
						return
					}
				}
				if rerr != nil {
					_ = sess.WriteS2CFrame(SpecFrameCloseWrite, 0, nil)
					return
				}
			}
		}()
		go func() {
			defer wg.Done()
			for {
				f, rerr := sess.ReadC2SFrame(0)
				if rerr != nil {
					_ = targetConn.Close()
					return
				}
				switch f.FrameType {
				case SpecFrameData:
					if len(f.Data) > 0 {
						if _, werr := writeAll(targetConn, f.Data); werr != nil {
							return
						}
					}
				case SpecFramePing:
					_ = sess.WriteS2CFrame(SpecFramePong, 32, nil)
				case SpecFramePong:
				case SpecFrameCloseWrite:
					if tc, ok := targetConn.(*net.TCPConn); ok {
						_ = tc.CloseWrite()
					}
					return
				default:
					_ = targetConn.Close()
					return
				}
			}
		}()
		wg.Wait()
		return
	}

	// Self-contained echo mode: echoes every C2S FrameData back as S2C FrameData.
	for {
		f, err := sess.ReadC2SFrame(0)
		if err != nil {
			return
		}
		switch f.FrameType {
		case SpecFrameData:
			if len(f.Data) > 0 {
				if werr := sess.WriteS2CFrame(SpecFrameData, 0, f.Data); werr != nil {
					return
				}
			}
		case SpecFramePing:
			_ = sess.WriteS2CFrame(SpecFramePong, 32, nil)
		case SpecFramePong:
		case SpecFrameCloseWrite:
			_ = sess.WriteS2CFrame(SpecFrameCloseWrite, 0, nil)
			return
		default:
			return
		}
	}
}

func (m *SpecMockServer) defaultUDPRelayOrEcho(sess *SpecServerSession) {
	var (
		udpSock   *net.UDPConn
		relayAddr *net.UDPAddr
		udpWg     sync.WaitGroup
	)
	sendS2CDatagram := func(srcAddr M.Socksaddr, payload []byte) error {
		var out bytes.Buffer
		_ = M.SocksaddrSerializer.WriteAddrPort(&out, srcAddr)
		var lenBuf [2]byte
		binary.BigEndian.PutUint16(lenBuf[:], uint16(len(payload)))
		out.Write(lenBuf[:])
		out.Write(payload)
		rawMsg := out.Bytes()
		for len(rawMsg) > 0 {
			chunk := rawMsg
			if len(chunk) > SpecMaxFrameDataSize {
				chunk = rawMsg[:SpecMaxFrameDataSize]
			}
			if werr := sess.WriteS2CFrame(SpecFrameData, 0, chunk); werr != nil {
				return werr
			}
			rawMsg = rawMsg[len(chunk):]
		}
		return nil
	}

	if m.opts.RelayUDPTarget != "" {
		raddr, err := net.ResolveUDPAddr("udp", m.opts.RelayUDPTarget)
		if err != nil {
			return
		}
		sock, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
		if err != nil {
			return
		}
		udpSock = sock
		relayAddr = raddr
		defer func() {
			_ = udpSock.Close()
			udpWg.Wait()
		}()
		udpWg.Add(1)
		go func() {
			defer udpWg.Done()
			buf := make([]byte, 65536)
			for {
				n, peer, rerr := udpSock.ReadFromUDP(buf)
				if rerr != nil {
					return
				}
				if werr := sendS2CDatagram(M.SocksaddrFromNet(peer), buf[:n]); werr != nil {
					return
				}
			}
		}()
	}

	var stream bytes.Buffer
	if len(sess.VarHeader.InitialPayload) > 0 {
		stream.Write(sess.VarHeader.InitialPayload)
	}
	processDatagrams := func() error {
		for stream.Len() > 0 {
			snap := stream.Bytes()
			r := bytes.NewReader(snap)
			dstAddr, err := M.SocksaddrSerializer.ReadAddrPort(r)
			if err != nil {
				if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
					return nil
				}
				return err
			}
			var lenBuf [2]byte
			if _, err := io.ReadFull(r, lenBuf[:]); err != nil {
				return nil
			}
			dLen := int(binary.BigEndian.Uint16(lenBuf[:]))
			if r.Len() < dLen {
				return nil
			}
			payload := make([]byte, dLen)
			_, _ = io.ReadFull(r, payload)
			consumed := len(snap) - r.Len()
			if udpSock != nil {
				target := relayAddr
				if dstAddr.IsIP() && dstAddr.Port > 0 {
					target = dstAddr.UDPAddr()
				}
				if _, werr := udpSock.WriteToUDP(payload, target); werr != nil {
					return werr
				}
			} else {
				if werr := sendS2CDatagram(dstAddr, payload); werr != nil {
					return werr
				}
			}
			rest := append([]byte(nil), snap[consumed:]...)
			stream.Reset()
			stream.Write(rest)
		}
		return nil
	}

	if err := processDatagrams(); err != nil {
		return
	}
	for {
		f, err := sess.ReadC2SFrame(0)
		if err != nil {
			return
		}
		switch f.FrameType {
		case SpecFrameData:
			if len(f.Data) > 0 {
				stream.Write(f.Data)
				if perr := processDatagrams(); perr != nil {
					return
				}
			}
		case SpecFramePing:
			_ = sess.WriteS2CFrame(SpecFramePong, 32, nil)
		case SpecFramePong:
		case SpecFrameCloseWrite:
			_ = sess.WriteS2CFrame(SpecFrameCloseWrite, 0, nil)
			return
		default:
			return
		}
	}
}

// ---------------------------------------------------------------------------
// 10. Loopback Targets (TCP Echo/Banner/HalfClose/FIN/RST/Stalled, TLS 1.3, UDP, DNS)
// ---------------------------------------------------------------------------

// connTracker records active accepted connections so target.Close() unblocks io.Copy
// even when t.Cleanup closes the server before upstream client/Box sockets close.
type connTracker struct {
	mu     sync.Mutex
	closed bool
	conns  map[net.Conn]struct{}
}

func (ct *connTracker) add(c net.Conn) {
	ct.mu.Lock()
	if ct.closed {
		ct.mu.Unlock()
		_ = c.Close()
		return
	}
	if ct.conns == nil {
		ct.conns = make(map[net.Conn]struct{})
	}
	ct.conns[c] = struct{}{}
	ct.mu.Unlock()
}

func (ct *connTracker) remove(c net.Conn) {
	ct.mu.Lock()
	delete(ct.conns, c)
	ct.mu.Unlock()
}

func (ct *connTracker) closeAll() {
	ct.mu.Lock()
	ct.closed = true
	for c := range ct.conns {
		_ = c.Close()
	}
	ct.mu.Unlock()
}

// TCPEchoTarget is a local TCP echo / banner server tracking connection & byte counts.
type TCPEchoTarget struct {
	ln          net.Listener
	addr        string
	port        uint16
	conns       atomic.Int64
	bytesEchoed atomic.Int64
	active      connTracker
	doneCh      chan struct{}
	once        sync.Once
	wg          sync.WaitGroup
}

func StartTCPEchoTarget(t testing.TB) *TCPEchoTarget {
	t.Helper()
	return StartTCPEchoTargetOn(t, "tcp", "127.0.0.1:0")
}

// StartTCPEchoServer aliases StartTCPEchoTarget.
func StartTCPEchoServer(t testing.TB) *TCPEchoTarget {
	t.Helper()
	return StartTCPEchoTarget(t)
}

func StartTCPEchoTargetOn(t testing.TB, network, listenAddr string) *TCPEchoTarget {
	t.Helper()
	ln, err := net.Listen(network, listenAddr)
	require.NoError(t, err)
	taddr := ln.Addr().(*net.TCPAddr)
	srv := &TCPEchoTarget{
		ln:     ln,
		addr:   taddr.String(),
		port:   uint16(taddr.Port),
		doneCh: make(chan struct{}),
	}
	srv.wg.Add(1)
	go func() {
		defer srv.wg.Done()
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			srv.conns.Add(1)
			srv.active.add(c)
			srv.wg.Add(1)
			go func(conn net.Conn) {
				defer srv.wg.Done()
				defer func() {
					srv.active.remove(conn)
					_ = conn.Close()
				}()
				n, _ := io.Copy(conn, conn)
				srv.bytesEchoed.Add(n)
			}(c)
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
	s.once.Do(func() {
		close(s.doneCh)
		_ = s.ln.Close()
		s.active.closeAll()
		s.wg.Wait()
	})
}

// StartServerSpeaksFirstTarget accepts TCP connections and immediately pushes banner before reading.
func StartServerSpeaksFirstTarget(t testing.TB, banner []byte) *TCPEchoTarget {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	taddr := ln.Addr().(*net.TCPAddr)
	srv := &TCPEchoTarget{
		ln:     ln,
		addr:   taddr.String(),
		port:   uint16(taddr.Port),
		doneCh: make(chan struct{}),
	}
	srv.wg.Add(1)
	go func() {
		defer srv.wg.Done()
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			srv.conns.Add(1)
			srv.active.add(c)
			srv.wg.Add(1)
			go func(conn net.Conn) {
				defer srv.wg.Done()
				defer func() {
					srv.active.remove(conn)
					_ = conn.Close()
				}()
				if len(banner) > 0 {
					_, _ = writeAll(conn, banner)
				}
				n, _ := io.Copy(conn, conn)
				srv.bytesEchoed.Add(n)
			}(c)
		}
	}()
	t.Cleanup(srv.Close)
	return srv
}

// StartTCPBannerServer aliases StartServerSpeaksFirstTarget.
func StartTCPBannerServer(t testing.TB, banner []byte) *TCPEchoTarget {
	t.Helper()
	return StartServerSpeaksFirstTarget(t, banner)
}

// HalfCloseTarget verifies bidirectional TCP half-close propagation: reads until io.EOF,
// then writes trailer back and closes cleanly.
type HalfCloseTarget struct {
	ln           net.Listener
	addr         string
	port         uint16
	ReceivedHash [32]byte
	ReceivedLen  atomic.Int64
	EOFObserved  atomic.Bool
	active       connTracker
	doneCh       chan struct{}
	once         sync.Once
	wg           sync.WaitGroup
}

func StartTCPHalfCloseTarget(t testing.TB, trailer []byte) *HalfCloseTarget {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	taddr := ln.Addr().(*net.TCPAddr)
	srv := &HalfCloseTarget{
		ln:     ln,
		addr:   taddr.String(),
		port:   uint16(taddr.Port),
		doneCh: make(chan struct{}),
	}
	srv.wg.Add(1)
	go func() {
		defer srv.wg.Done()
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			srv.active.add(c)
			srv.wg.Add(1)
			go func(conn net.Conn) {
				defer srv.wg.Done()
				defer func() {
					srv.active.remove(conn)
					_ = conn.Close()
				}()
				h := sha256.New()
				n, readErr := io.Copy(h, conn)
				srv.ReceivedLen.Store(n)
				copy(srv.ReceivedHash[:], h.Sum(nil))
				if readErr == nil {
					srv.EOFObserved.Store(true)
					_, _ = writeAll(conn, trailer)
				}
				if tc, ok := conn.(*net.TCPConn); ok {
					_ = tc.CloseWrite()
				}
			}(c)
		}
	}()
	t.Cleanup(srv.Close)
	return srv
}

// StartTCPHalfCloseServer aliases StartTCPHalfCloseTarget.
func StartTCPHalfCloseServer(t testing.TB, trailer []byte) *HalfCloseTarget {
	t.Helper()
	return StartTCPHalfCloseTarget(t, trailer)
}

func (s *HalfCloseTarget) Addr() string { return s.addr }
func (s *HalfCloseTarget) Port() uint16 { return s.port }
func (s *HalfCloseTarget) Close() {
	s.once.Do(func() {
		close(s.doneCh)
		_ = s.ln.Close()
		s.active.closeAll()
		s.wg.Wait()
	})
}

// ImmediateFINTarget immediately closes accepted TCP connections with a clean FIN.
type ImmediateFINTarget struct {
	ln    net.Listener
	addr  string
	port  uint16
	conns atomic.Int64
	once  sync.Once
	wg    sync.WaitGroup
}

// StartImmediateFINServer accepts TCP connections and immediately closes them cleanly.
func StartImmediateFINServer(t testing.TB) *ImmediateFINTarget {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	taddr := ln.Addr().(*net.TCPAddr)
	srv := &ImmediateFINTarget{ln: ln, addr: taddr.String(), port: uint16(taddr.Port)}
	srv.wg.Add(1)
	go func() {
		defer srv.wg.Done()
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			srv.conns.Add(1)
			_ = c.Close()
		}
	}()
	t.Cleanup(srv.Close)
	return srv
}

func (s *ImmediateFINTarget) Addr() string       { return s.addr }
func (s *ImmediateFINTarget) Port() uint16       { return s.port }
func (s *ImmediateFINTarget) Connections() int64 { return s.conns.Load() }
func (s *ImmediateFINTarget) Close() {
	s.once.Do(func() {
		_ = s.ln.Close()
		s.wg.Wait()
	})
}

// TCPResetTarget immediately closes accepted connections with SO_LINGER(0) -> RST.
type TCPResetTarget struct {
	ln    net.Listener
	addr  string
	port  uint16
	conns atomic.Int64
	once  sync.Once
	wg    sync.WaitGroup
}

// StartTCPResetServer accepts TCP connections and sends immediate TCP RST.
func StartTCPResetServer(t testing.TB) *TCPResetTarget {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	taddr := ln.Addr().(*net.TCPAddr)
	srv := &TCPResetTarget{ln: ln, addr: taddr.String(), port: uint16(taddr.Port)}
	srv.wg.Add(1)
	go func() {
		defer srv.wg.Done()
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			srv.conns.Add(1)
			closeWithRST(c)
		}
	}()
	t.Cleanup(srv.Close)
	return srv
}

func (s *TCPResetTarget) Addr() string       { return s.addr }
func (s *TCPResetTarget) Port() uint16       { return s.port }
func (s *TCPResetTarget) Connections() int64 { return s.conns.Load() }
func (s *TCPResetTarget) Close() {
	s.once.Do(func() {
		_ = s.ln.Close()
		s.wg.Wait()
	})
}

// StalledTCPTarget accepts TCP connections with minimal RCVBUF and never reads until Release().
type StalledTCPTarget struct {
	ln        net.Listener
	addr      string
	port      uint16
	releaseCh chan struct{}
	relOnce   sync.Once
	once      sync.Once
	wg        sync.WaitGroup
	mu        sync.Mutex
	conns     []net.Conn
}

// StartStalledTCPServer accepts connections and stalls reading to trigger send-window backpressure.
func StartStalledTCPServer(t testing.TB) *StalledTCPTarget {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	taddr := ln.Addr().(*net.TCPAddr)
	srv := &StalledTCPTarget{
		ln:        ln,
		addr:      taddr.String(),
		port:      uint16(taddr.Port),
		releaseCh: make(chan struct{}),
	}
	srv.wg.Add(1)
	go func() {
		defer srv.wg.Done()
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			if tc, ok := c.(*net.TCPConn); ok {
				_ = tc.SetReadBuffer(4096)
			}
			srv.mu.Lock()
			srv.conns = append(srv.conns, c)
			srv.mu.Unlock()
		}
	}()
	t.Cleanup(srv.Close)
	return srv
}

func (s *StalledTCPTarget) Addr() string { return s.addr }
func (s *StalledTCPTarget) Port() uint16 { return s.port }
func (s *StalledTCPTarget) Release() {
	s.relOnce.Do(func() { close(s.releaseCh) })
	s.mu.Lock()
	for _, c := range s.conns {
		_ = c.Close()
	}
	s.conns = nil
	s.mu.Unlock()
}
func (s *StalledTCPTarget) Close() {
	s.once.Do(func() {
		_ = s.ln.Close()
		s.Release()
		s.wg.Wait()
	})
}

// TLS13HTTPSTarget serves an isolated TLS 1.3-only HTTPS service with an ~3KB
// certificate chain (mimicking real-world ServerHello+Certificate size).
type TLS13HTTPSTarget struct {
	ln       net.Listener
	server   *http.Server
	addr     string
	port     uint16
	rootPool *x509.CertPool
	once     sync.Once
}

func StartTLS13HTTPSTarget(t testing.TB, extraDNSNames ...string) *TLS13HTTPSTarget {
	t.Helper()

	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	caTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "aether-e2e-root-ca"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	require.NoError(t, err)
	caCert, err := x509.ParseCertificate(caDER)
	require.NoError(t, err)

	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	dnsNames := []string{"localhost", "aether-e2e.internal", "api.aether.internal"}
	dnsNames = append(dnsNames, extraDNSNames...)
	// Add deterministic SAN padding entries so the full TLS 1.3 cert chain exceeds ~3KB on wire.
	for i := 0; i < 64; i++ {
		dnsNames = append(dnsNames, fmt.Sprintf("san-pad-%03d.edge.aether-e2e.internal", i))
	}
	leafTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "aether-e2e.internal"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")},
		DNSNames:     dnsNames,
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTmpl, caCert, &leafKey.PublicKey, caKey)
	require.NoError(t, err)

	pool := x509.NewCertPool()
	pool.AddCert(caCert)

	tlsCert := tls.Certificate{
		Certificate: [][]byte{leafDER, caDER},
		PrivateKey:  leafKey,
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, "aether-e2e-https-ok")
	})
	mux.HandleFunc("/api/v1/health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"status":"ok","tls":"1.3"}`)
	})
	mux.HandleFunc("/ping", func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "pong")
	})
	mux.HandleFunc("/bytes", func(w http.ResponseWriter, r *http.Request) {
		n, _ := strconv.Atoi(r.URL.Query().Get("n"))
		if n <= 0 || n > 16*1024*1024 {
			n = 4096
		}
		_, _ = w.Write(DeterministicBytes(0x71513, n))
	})
	mux.HandleFunc("/echo", func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(w, r.Body)
	})

	rawLn, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	taddr := rawLn.Addr().(*net.TCPAddr)
	tlsLn := tls.NewListener(rawLn, &tls.Config{
		MinVersion:   tls.VersionTLS13,
		MaxVersion:   tls.VersionTLS13,
		Certificates: []tls.Certificate{tlsCert},
	})
	srv := &http.Server{Handler: mux}
	go func() { _ = srv.Serve(tlsLn) }()

	target := &TLS13HTTPSTarget{
		ln:       tlsLn,
		server:   srv,
		addr:     taddr.String(),
		port:     uint16(taddr.Port),
		rootPool: pool,
	}
	t.Cleanup(target.Close)
	return target
}

// StartTLS13HTTPSServer aliases StartTLS13HTTPSTarget.
func StartTLS13HTTPSServer(t testing.TB, extraDNSNames ...string) *TLS13HTTPSTarget {
	t.Helper()
	return StartTLS13HTTPSTarget(t, extraDNSNames...)
}

func (s *TLS13HTTPSTarget) Addr() string { return s.addr }
func (s *TLS13HTTPSTarget) Port() uint16 { return s.port }
func (s *TLS13HTTPSTarget) ClientTLSConfig(serverName string) *tls.Config {
	return &tls.Config{
		MinVersion: tls.VersionTLS13,
		MaxVersion: tls.VersionTLS13,
		RootCAs:    s.rootPool,
		ServerName: serverName,
	}
}
func (s *TLS13HTTPSTarget) Close() {
	s.once.Do(func() {
		_ = s.server.Close()
		_ = s.ln.Close()
	})
}

// UDPEchoTarget serves a local UDP echo socket and exposes peer NAT addr tracking.
type UDPEchoTarget struct {
	conn     *net.UDPConn
	addr     string
	port     uint16
	packets  atomic.Int64
	mu       sync.Mutex
	lastPeer *net.UDPAddr
	doneCh   chan struct{}
	once     sync.Once
	wg       sync.WaitGroup
}

func StartUDPEchoTarget(t testing.TB) *UDPEchoTarget {
	t.Helper()
	return StartUDPEchoTargetOn(t, "udp", "127.0.0.1:0")
}

// StartUDPEchoServer aliases StartUDPEchoTarget.
func StartUDPEchoServer(t testing.TB) *UDPEchoTarget {
	t.Helper()
	return StartUDPEchoTarget(t)
}

func StartUDPEchoTargetOn(t testing.TB, network, listenAddr string) *UDPEchoTarget {
	t.Helper()
	uaddr, err := net.ResolveUDPAddr(network, listenAddr)
	require.NoError(t, err)
	conn, err := net.ListenUDP(network, uaddr)
	require.NoError(t, err)
	laddr := conn.LocalAddr().(*net.UDPAddr)
	srv := &UDPEchoTarget{
		conn:   conn,
		addr:   laddr.String(),
		port:   uint16(laddr.Port),
		doneCh: make(chan struct{}),
	}
	srv.wg.Add(1)
	go func() {
		defer srv.wg.Done()
		buf := make([]byte, 65536)
		for {
			n, peer, err := conn.ReadFromUDP(buf)
			if err != nil {
				return
			}
			srv.packets.Add(1)
			srv.mu.Lock()
			srv.lastPeer = peer
			srv.mu.Unlock()
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
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.lastPeer == nil {
		return nil
	}
	cp := *s.lastPeer
	return &cp
}

func (s *UDPEchoTarget) SendUnsolicitedTo(payload []byte, natAddr *net.UDPAddr) error {
	_, err := s.conn.WriteToUDP(payload, natAddr)
	return err
}

func (s *UDPEchoTarget) Close() {
	s.once.Do(func() {
		close(s.doneCh)
		_ = s.conn.Close()
		s.wg.Wait()
	})
}

// FullConeUDPHarness bundles 3 distinct loopback UDP echo peers to validate NAT cone mapping.
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

// LoopbackDNSServer runs a real miekg/dns loopback UDP & TCP DNS server for E2E DNS/split-DNS tests.
type LoopbackDNSServer struct {
	udpServer *dns.Server
	tcpServer *dns.Server
	udpAddr   string
	tcpAddr   string
	port      uint16
	queries   atomic.Int64
	once      sync.Once
}

// StartLoopbackDNSServer launches a loopback DNS server serving static A/AAAA records
// or invoking customHandler. Attempts to bind UDP and TCP on the same ephemeral port.
func StartLoopbackDNSServer(t testing.TB, aRecords map[string]string, customHandler ...dns.HandlerFunc) *LoopbackDNSServer {
	t.Helper()

	mux := dns.NewServeMux()
	mux.HandleFunc(".", func(w dns.ResponseWriter, r *dns.Msg) {
		if len(customHandler) > 0 && customHandler[0] != nil {
			customHandler[0](w, r)
			return
		}
		resp := new(dns.Msg)
		resp.SetReply(r)
		resp.Authoritative = true
		nameExists := false
		for _, q := range r.Question {
			name := strings.ToLower(q.Name)
			recVal, ok := aRecords[name]
			if !ok {
				recVal, ok = aRecords[strings.TrimSuffix(name, ".")]
			}
			if !ok {
				continue
			}
			nameExists = true
			ip := net.ParseIP(recVal)
			if ip == nil {
				continue
			}
			if q.Qtype == dns.TypeA && ip.To4() != nil {
				resp.Answer = append(resp.Answer, &dns.A{
					Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
					A:   ip.To4(),
				})
			} else if q.Qtype == dns.TypeAAAA && ip.To4() == nil && ip.To16() != nil {
				resp.Answer = append(resp.Answer, &dns.AAAA{
					Hdr:  dns.RR_Header{Name: q.Name, Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: 60},
					AAAA: ip.To16(),
				})
			}
		}
		if len(resp.Answer) == 0 && len(r.Question) > 0 && !nameExists {
			resp.Rcode = dns.RcodeNameError
		}
		_ = w.WriteMsg(resp)
	})

	var (
		pc   net.PacketConn
		ln   net.Listener
		port uint16
	)
	for attempt := 0; attempt < 8; attempt++ {
		var err error
		pc, err = net.ListenPacket("udp", "127.0.0.1:0")
		if err != nil {
			continue
		}
		p := uint16(pc.LocalAddr().(*net.UDPAddr).Port)
		ln, err = net.Listen("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(int(p))))
		if err == nil {
			port = p
			break
		}
		_ = pc.Close()
	}
	require.NotNil(t, pc)
	require.NotNil(t, ln)

	srv := &LoopbackDNSServer{
		udpAddr: pc.LocalAddr().String(),
		tcpAddr: ln.Addr().String(),
		port:    port,
	}
	wrapped := dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
		srv.queries.Add(1)
		mux.ServeDNS(w, r)
	})

	udpStarted := make(chan struct{})
	tcpStarted := make(chan struct{})
	srv.udpServer = &dns.Server{
		PacketConn:        pc,
		Handler:           wrapped,
		NotifyStartedFunc: func() { close(udpStarted) },
	}
	srv.tcpServer = &dns.Server{
		Listener:          ln,
		Handler:           wrapped,
		NotifyStartedFunc: func() { close(tcpStarted) },
	}
	go func() { _ = srv.udpServer.ActivateAndServe() }()
	go func() { _ = srv.tcpServer.ActivateAndServe() }()
	<-udpStarted
	<-tcpStarted

	t.Cleanup(srv.Close)
	return srv
}

func (s *LoopbackDNSServer) Addr() string    { return s.udpAddr }
func (s *LoopbackDNSServer) UDPAddr() string { return s.udpAddr }
func (s *LoopbackDNSServer) TCPAddr() string { return s.tcpAddr }
func (s *LoopbackDNSServer) Port() uint16    { return s.port }
func (s *LoopbackDNSServer) Queries() int64  { return s.queries.Load() }

func (s *LoopbackDNSServer) Close() {
	s.once.Do(func() {
		if s.udpServer != nil {
			_ = s.udpServer.Shutdown()
		}
		if s.tcpServer != nil {
			_ = s.tcpServer.Shutdown()
		}
	})
}

// DeterministicBytes produces reproducible high-entropy pseudo-random bytes for SHA-256 integrity checks.
func DeterministicBytes(seed uint64, length int) []byte {
	out := make([]byte, length)
	x := seed ^ 0x9e3779b97f4a7c15
	for i := 0; i+8 <= length; i += 8 {
		x ^= x << 13
		x ^= x >> 7
		x ^= x << 17
		binary.LittleEndian.PutUint64(out[i:i+8], x)
	}
	rem := length % 8
	if rem > 0 {
		x ^= x << 13
		x ^= x >> 7
		x ^= x << 17
		var tail [8]byte
		binary.LittleEndian.PutUint64(tail[:], x)
		copy(out[length-rem:], tail[:rem])
	}
	return out
}
