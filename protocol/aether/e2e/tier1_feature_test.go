package e2e_test

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	box "github.com/sagernet/sing-box"
	"github.com/sagernet/sing-box/adapter"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing/common/buf"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/cpu"
)

func TestTier1OpaqueIsolation(t *testing.T) {
	VerifyOpaqueImports(t)
}

func TestTier1Features(t *testing.T) {
	VerifyOpaqueImports(t)

	runTier1F01(t)
	runTier1F02(t)
	runTier1F03(t)
	runTier1F04(t)
	runTier1F05(t)
	runTier1F06(t)
	runTier1F07(t)
	runTier1F08(t)
	runTier1F09(t)
	runTier1F10(t)
	runTier1F11(t)
	runTier1F12(t)
	runTier1F13(t)
	runTier1F14(t)
	runTier1F15(t)
	runTier1F16(t)
	runTier1F17(t)
	runTier1F18(t)
	runTier1F19(t)
	runTier1F20(t)
	runTier1F21(t)
	runTier1F22(t)
	runTier1F23(t)
	runTier1F24(t)
	runTier1F25(t)
	runTier1F26(t)
	runTier1F27(t)
}

const t1DefaultBoundedWorkers = 8

func t1HasHardwareAES() bool {
	return (cpu.X86.HasAES && cpu.X86.HasPCLMULQDQ) ||
		(cpu.ARM64.HasAES && cpu.ARM64.HasPMULL)
}

func t1ExpectedAutoCipherSuite() uint8 {
	if t1HasHardwareAES() {
		return SpecCipherAES256GCM
	}
	return SpecCipherChaCha20Poly1305
}

func t1StartTopology(t testing.TB, cfg TopologyConfig) *Topology {
	t.Helper()
	topo := StartTopology(t, cfg)
	t.Cleanup(topo.Close)
	return topo
}

func t1DialAndEchoConn(t testing.TB, conn net.Conn, payload []byte) {
	t.Helper()
	require.NoError(t, conn.SetDeadline(time.Now().Add(10*time.Second)))
	defer func() { _ = conn.SetDeadline(time.Time{}) }()
	_, err := conn.Write(payload)
	require.NoError(t, err)
	got := make([]byte, len(payload))
	_, err = io.ReadFull(conn, got)
	require.NoError(t, err)
	require.Equal(t, payload, got)
}

func t1TCPEcho(t testing.TB, topo *Topology, targetAddr string, payload []byte) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
	defer cancel()
	conn, err := topo.DialSOCKS5(ctx, targetAddr)
	require.NoError(t, err)
	defer func() { _ = conn.Close() }()
	t1DialAndEchoConn(t, conn, payload)
}

func t1TCPEchoAuth(t testing.TB, topo *Topology, user, pass, targetAddr string, payload []byte) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
	defer cancel()
	conn, err := topo.DialSOCKS5Auth(ctx, user, pass, targetAddr)
	require.NoError(t, err)
	defer func() { _ = conn.Close() }()
	t1DialAndEchoConn(t, conn, payload)
}

func t1UDPEcho(t testing.TB, topo *Topology, targetAddr string, payload []byte) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
	defer cancel()
	uconn, err := topo.OpenSOCKS5UDP(ctx)
	require.NoError(t, err)
	defer func() { _ = uconn.Close() }()
	require.NoError(t, uconn.SetDeadline(time.Now().Add(8*time.Second)))
	require.NoError(t, uconn.WriteToHostPort(payload, targetAddr))
	bufRead := make([]byte, max(len(payload)+512, 4096))
	n, _, err := uconn.ReadFromHostPort(bufRead)
	require.NoError(t, err)
	require.Equal(t, payload, bufRead[:n])
}

func t1WaitNTPSynced(t testing.TB, topo *Topology, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		srvOK := topo.ServerNTP == nil || topo.ServerNTP.Requests() > 0
		cliOK := topo.ClientNTP == nil || topo.ClientNTP.Requests() > 0
		if srvOK && cliOK {
			// Allow a brief tick for NTP service callbacks to record offset.
			time.Sleep(150 * time.Millisecond)
			return
		}
		time.Sleep(30 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for mock NTP sync (server=%v client=%v)",
		topo.ServerNTP != nil && topo.ServerNTP.Requests() > 0,
		topo.ClientNTP != nil && topo.ClientNTP.Requests() > 0)
}

func t1ReadRepoFile(t testing.TB, relPath string) string {
	t.Helper()
	root, err := RepoRoot()
	require.NoError(t, err)
	data, err := os.ReadFile(filepath.Join(root, relPath))
	require.NoError(t, err, "read %s", relPath)
	return string(data)
}

func t1RunGit(t testing.TB, dir string, args ...string) (string, string, error) {
	t.Helper()
	cmd := exec.Command("git", args...)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), "GIT_TERMINAL_PROMPT=0", "GIT_CONFIG_NOSYSTEM=1")
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	return stdout.String(), stderr.String(), err
}

type t1WorkflowStep struct {
	Name string
	ID   string
	If   string
	Uses string
	Env  map[string]string
	With map[string]string
	Run  string
}

// t1ExtractWorkflowSteps parses GitHub Actions step blocks from YAML without external yaml packages.
func t1ExtractWorkflowSteps(t testing.TB, rawYAML string) []t1WorkflowStep {
	t.Helper()
	lines := strings.Split(strings.ReplaceAll(rawYAML, "\r\n", "\n"), "\n")
	var steps []t1WorkflowStep
	inSteps := false
	stepsIndent := -1

	parseKV := func(s string) (string, string, bool) {
		idx := strings.IndexByte(s, ':')
		if idx <= 0 {
			return "", "", false
		}
		k := strings.TrimSpace(s[:idx])
		v := strings.TrimSpace(s[idx+1:])
		v = strings.Trim(v, `"'`)
		return k, v, true
	}

	i := 0
	for i < len(lines) {
		line := lines[i]
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			i++
			continue
		}
		indent := len(line) - len(strings.TrimLeft(line, " "))
		if !inSteps {
			if trimmed == "steps:" {
				inSteps = true
				stepsIndent = indent
			}
			i++
			continue
		}
		if indent <= stepsIndent && !strings.HasPrefix(trimmed, "- ") {
			inSteps = false
			i++
			continue
		}
		if strings.HasPrefix(trimmed, "- ") && indent <= stepsIndent+2 {
			step := t1WorkflowStep{
				Env:  make(map[string]string),
				With: make(map[string]string),
			}
			stepIndent := indent
			rest := strings.TrimSpace(strings.TrimPrefix(trimmed, "- "))
			if k, v, ok := parseKV(rest); ok {
				switch k {
				case "name":
					step.Name = v
				case "id":
					step.ID = v
				case "uses":
					step.Uses = v
				case "if":
					step.If = v
				case "run":
					if v != "|" && v != "|-" && v != ">" {
						step.Run = v
					}
				}
			}
			i++
			var mapTarget string
			mapIndent := -1
			for i < len(lines) {
				sub := lines[i]
				subTrim := strings.TrimSpace(sub)
				if subTrim == "" || strings.HasPrefix(subTrim, "#") {
					i++
					continue
				}
				subIndent := len(sub) - len(strings.TrimLeft(sub, " "))
				if subIndent <= stepIndent || (subIndent <= stepsIndent+2 && strings.HasPrefix(subTrim, "- ")) {
					break
				}
				if mapTarget != "" && subIndent <= mapIndent {
					mapTarget = ""
				}
				if strings.HasPrefix(subTrim, "run:") {
					val := strings.TrimSpace(strings.TrimPrefix(subTrim, "run:"))
					if val == "|" || val == "|-" || val == ">" {
						i++
						var block []string
						baseIndent := -1
						for i < len(lines) {
							bl := lines[i]
							if strings.TrimSpace(bl) == "" {
								block = append(block, "")
								i++
								continue
							}
							bIndent := len(bl) - len(strings.TrimLeft(bl, " "))
							if baseIndent < 0 {
								if bIndent <= subIndent {
									break
								}
								baseIndent = bIndent
							} else if bIndent < baseIndent {
								break
							}
							if len(bl) >= baseIndent {
								block = append(block, bl[baseIndent:])
							} else {
								block = append(block, "")
							}
							i++
						}
						step.Run = strings.Join(block, "\n")
						continue
					}
					step.Run = strings.Trim(val, `"'`)
					i++
					continue
				}
				if mapTarget != "" {
					if k, v, ok := parseKV(subTrim); ok {
						if mapTarget == "env" {
							step.Env[k] = v
						} else if mapTarget == "with" {
							step.With[k] = v
						}
					}
					i++
					continue
				}
				if subTrim == "env:" {
					mapTarget = "env"
					mapIndent = subIndent
					i++
					continue
				}
				if subTrim == "with:" {
					mapTarget = "with"
					mapIndent = subIndent
					i++
					continue
				}
				if k, v, ok := parseKV(subTrim); ok {
					switch k {
					case "name":
						step.Name = v
					case "id":
						step.ID = v
					case "if":
						step.If = v
					case "uses":
						step.Uses = v
					}
				}
				i++
			}
			steps = append(steps, step)
			continue
		}
		i++
	}
	return steps
}

func t1BashSyntaxCheck(t testing.TB, label, script string) {
	t.Helper()
	cmd := exec.Command("bash", "-n")
	cmd.Stdin = strings.NewReader(script)
	out, err := cmd.CombinedOutput()
	require.NoError(t, err, "bash -n failed for %s:\n%s\noutput:\n%s", label, script, string(out))
}

func t1ExtractOnSection(yamlText string) string {
	lines := strings.Split(strings.ReplaceAll(yamlText, "\r\n", "\n"), "\n")
	var out []string
	inOn := false
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if !inOn {
			if strings.HasPrefix(line, "on:") || trimmed == "on:" {
				inOn = true
				out = append(out, line)
			}
			continue
		}
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			out = append(out, line)
			continue
		}
		if !strings.HasPrefix(line, " ") && !strings.HasPrefix(line, "\t") {
			break
		}
		out = append(out, line)
	}
	return strings.Join(out, "\n")
}

// =============================================================================
// F1: Build & Branch Integration (T1-F01-01 .. T1-F01-05)
// =============================================================================

func runTier1F01(t *testing.T) {
	t.Run("T1-F01-01", func(t *testing.T) {
		res := RunCLITimeout(t, 20*time.Second, "version", "-n")
		require.NoError(t, res.Err, "stderr=%s", res.Stderr)
		require.Equal(t, 0, res.ExitCode)
		require.Regexp(t, `^[0-9]+\.[0-9]+\.[0-9]+-Custom-Aether$`, C.Version)
		require.Equal(t, C.Version+"\n", res.Stdout)
		require.Empty(t, res.Stderr)
	})

	t.Run("T1-F01-02", func(t *testing.T) {
		res := RunCLITimeout(t, 20*time.Second, "version")
		require.NoError(t, res.Err, "stderr=%s", res.Stderr)
		require.Equal(t, 0, res.ExitCode)
		require.Contains(t, res.Stdout, "sing-box version "+C.Version)
		officialTags := strings.TrimSpace(t1ReadRepoFile(t, "release/DEFAULT_BUILD_TAGS_OTHERS"))
		require.NotEmpty(t, officialTags)
		for _, tag := range strings.Split(officialTags, ",") {
			require.Contains(t, res.Stdout, tag)
		}
		require.Contains(t, res.Stdout, "with_tailscale")
		require.Contains(t, res.Stdout, "CGO: disabled")

		ldflags := strings.TrimSpace(t1ReadRepoFile(t, "release/LDFLAGS"))
		require.Contains(t, ldflags, "multipathtcp=0")
		require.Contains(t, ldflags, "-checklinkname=0")
	})

	t.Run("T1-F01-03", func(t *testing.T) {
		root, err := RepoRoot()
		require.NoError(t, err)
		if _, statErr := os.Stat(filepath.Join(root, ".agents")); statErr == nil {
			exclude := t1ReadRepoFile(t, ".git/info/exclude")
			require.Contains(t, exclude, ".agents/")
		}
		lsOut, errOut, err := t1RunGit(t, root, "ls-files", ".agents")
		require.NoError(t, err, errOut)
		require.Empty(t, strings.TrimSpace(lsOut))
		out, errOut, err := t1RunGit(t, root, "status", "--porcelain", ".agents")
		require.NoError(t, err, errOut)
		require.Empty(t, strings.TrimSpace(out))
	})

	t.Run("T1-F01-04", func(t *testing.T) {
		root, err := RepoRoot()
		require.NoError(t, err)
		headSHA, errOut, err := t1RunGit(t, root, "rev-parse", "--verify", "HEAD")
		require.NoError(t, err, errOut)
		require.Regexp(t, `^[0-9a-f]{40}$`, strings.TrimSpace(headSHA))

		branch, errOut, err := t1RunGit(t, root, "rev-parse", "--abbrev-ref", "HEAD")
		require.NoError(t, err, errOut)
		branchName := strings.TrimSpace(branch)
		if branchName != "HEAD" {
			require.True(t, branchName == "main" || strings.HasPrefix(branchName, "dev/"), "unexpected branch %q", branchName)
		}

		if _, _, refErr := t1RunGit(t, root, "show-ref", "--verify", "--quiet", "refs/heads/main"); refErr == nil {
			_, errOut, err = t1RunGit(t, root, "merge-base", "--is-ancestor", "refs/heads/main", "HEAD")
			require.NoError(t, err, "refs/heads/main must be ancestor of HEAD: %s", errOut)
		}

		const v1BaselineCommit = "fdaa4c455761bd6ca9d336d6dd09acb3639b34f1"
		if _, _, catErr := t1RunGit(t, root, "cat-file", "-e", v1BaselineCommit+"^{commit}"); catErr == nil {
			_, errOut, err = t1RunGit(t, root, "merge-base", "--is-ancestor", v1BaselineCommit, "HEAD")
			require.NoError(t, err, "%s must be ancestor of HEAD: %s", v1BaselineCommit, errOut)
		}

		require.Equal(t, "aether", C.TypeAether)
	})

	t.Run("T1-F01-05", func(t *testing.T) {
		require.Equal(t, []adapter.StartStage{
			adapter.StartStateInitialize,
			adapter.StartStateStart,
			adapter.StartStatePostStart,
			adapter.StartStateStarted,
		}, adapter.ListStartStages)

		echo := StartTCPEchoServer(t)

		key := GenerateRandomKeyBase64(t)
		srvPort := AllocFreeTCPPort(t)
		cfg := TopologyConfig{ServerKey: key, ClientKey: key, DisableWireTap: true}
		srvJSON, err := BuildServerJSON(cfg, srvPort, 0, "")
		require.NoError(t, err)

		ctx := NewBoxContext(context.Background())
		srvOpts, err := UnmarshalBoxOptions(srvJSON)
		require.NoError(t, err)
		srvBox, err := box.New(box.Options{Context: ctx, Options: srvOpts})
		require.NoError(t, err)
		require.NoError(t, srvBox.Start())
		var srvCloseOnce sync.Once
		t.Cleanup(func() { srvCloseOnce.Do(func() { _ = srvBox.Close() }) })

		cliPort := AllocFreeTCPPort(t)
		cliJSON, err := BuildClientJSON(cfg, cliPort, "127.0.0.1", srvPort, 0, "")
		require.NoError(t, err)
		cliOpts, err := UnmarshalBoxOptions(cliJSON)
		require.NoError(t, err)
		cliBox, err := box.New(box.Options{Context: NewBoxContext(context.Background()), Options: cliOpts})
		require.NoError(t, err)
		require.NoError(t, cliBox.Start())
		var cliCloseOnce sync.Once
		t.Cleanup(func() { cliCloseOnce.Do(func() { _ = cliBox.Close() }) })

		dialCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		conn, err := DialSOCKS5TCP(dialCtx, fmt.Sprintf("127.0.0.1:%d", cliPort), echo.Addr())
		require.NoError(t, err)
		t1DialAndEchoConn(t, conn, DeterministicBytes(105, 512))
		_ = conn.Close()

		var cliCloseErr, srvCloseErr error
		cliCloseOnce.Do(func() { cliCloseErr = cliBox.Close() })
		require.NoError(t, cliCloseErr)
		srvCloseOnce.Do(func() { srvCloseErr = srvBox.Close() })
		require.NoError(t, srvCloseErr)
	})
}

// =============================================================================
// F2: CI Workflows (T1-F02-01 .. T1-F02-05)
// =============================================================================

func runTier1F02(t *testing.T) {
	checkNoActiveReleaseTrigger := func(t *testing.T, relPath string) {
		t.Helper()
		raw := t1ReadRepoFile(t, relPath)
		onSec := t1ExtractOnSection(raw)
		require.NotEmpty(t, onSec, "missing on: section in %s", relPath)
		hasDispatch := false
		for _, line := range strings.Split(onSec, "\n") {
			trimmed := strings.TrimSpace(line)
			if trimmed == "" || strings.HasPrefix(trimmed, "#") {
				continue
			}
			require.False(t, strings.HasPrefix(trimmed, "release:"), "active release trigger found in %s: %s", relPath, line)
			if strings.HasPrefix(trimmed, "workflow_dispatch:") {
				hasDispatch = true
			}
		}
		require.True(t, hasDispatch, "workflow_dispatch must be active in %s", relPath)
	}

	t.Run("T1-F02-01", func(t *testing.T) {
		checkNoActiveReleaseTrigger(t, ".github/workflows/docker.yml")
	})

	t.Run("T1-F02-02", func(t *testing.T) {
		checkNoActiveReleaseTrigger(t, ".github/workflows/linux.yml")
	})

	t.Run("T1-F02-03", func(t *testing.T) {
		raw := t1ReadRepoFile(t, ".github/workflows/build-linux-amd64.yml")
		steps := t1ExtractWorkflowSteps(t, raw)
		require.NotEmpty(t, steps)

		foundSetupGo := false
		foundRace := false
		runChecked := 0
		for _, st := range steps {
			if strings.HasPrefix(st.Uses, "actions/setup-go@") {
				foundSetupGo = true
				require.Equal(t, "go.mod", st.With["go-version-file"])
			}
			if st.Run != "" {
				t1BashSyntaxCheck(t, "build-linux-amd64.yml/"+st.Name, st.Run)
				runChecked++
				if strings.Contains(st.Run, "go test -race") {
					foundRace = true
					require.Equal(t, "1", st.Env["CGO_ENABLED"])
					require.Contains(t, st.Run, "./cmd/sing-box/...")
					require.Contains(t, st.Run, "./protocol/aether/...")
				}
			}
		}
		require.True(t, foundSetupGo, "setup-go step missing")
		require.True(t, foundRace, "go test -race gate missing")
		require.GreaterOrEqual(t, runChecked, 3)
	})

	t.Run("T1-F02-04", func(t *testing.T) {
		raw := t1ReadRepoFile(t, ".github/workflows/build-linux-amd64.yml")
		steps := t1ExtractWorkflowSteps(t, raw)
		foundBuild := false
		for _, st := range steps {
			if strings.Contains(st.Run, "go build") {
				foundBuild = true
				require.Contains(t, st.Run, "release/DEFAULT_BUILD_TAGS_OTHERS")
				for _, tag := range strings.Split(DefaultOfficialPureGoBuildTags, ",") {
					require.Contains(t, st.Run, tag)
				}
				require.Contains(t, st.Run, "$(cat release/LDFLAGS)")
				require.Contains(t, st.Run, `-X 'github.com/sagernet/sing-box/constant.Version=${VERSION}'`)
			}
		}
		require.True(t, foundBuild, "go build step missing in build-linux-amd64.yml")
	})

	t.Run("T1-F02-05", func(t *testing.T) {
		raw := t1ReadRepoFile(t, ".github/workflows/build-linux-amd64.yml")
		steps := t1ExtractWorkflowSteps(t, raw)
		var resolveRun string
		for _, st := range steps {
			if st.Name == "Resolve Version" {
				resolveRun = st.Run
				break
			}
		}
		require.NotEmpty(t, resolveRun, "Resolve Version step missing")

		workDir := t.TempDir()
		require.NoError(t, os.MkdirAll(filepath.Join(workDir, "constant"), 0o755))
		versionGo := t1ReadRepoFile(t, "constant/version.go")
		require.NoError(t, os.WriteFile(filepath.Join(workDir, "constant/version.go"), []byte(versionGo), 0o644))

		envFile := filepath.Join(workDir, "github.env")
		require.NoError(t, os.WriteFile(envFile, nil, 0o600))
		cmd := exec.Command("bash", "-c", resolveRun)
		cmd.Dir = workDir
		cmd.Env = append(os.Environ(),
			"GITHUB_REF=refs/heads/dev/aether-v2",
			"GITHUB_REF_NAME=dev/aether-v2",
			"GITHUB_ENV="+envFile,
		)
		out, err := cmd.CombinedOutput()
		require.NoError(t, err, "Resolve Version failed: %s", string(out))
		envData, err := os.ReadFile(envFile)
		require.NoError(t, err)
		require.Regexp(t, `^[0-9]+\.[0-9]+\.[0-9]+-Custom-Aether$`, C.Version)
		require.Contains(t, string(envData), "VERSION="+C.Version+"\n")
	})
}

// =============================================================================
// F3: CLI aether-key Generation (T1-F03-01 .. T1-F03-05)
// =============================================================================

func runTier1F03(t *testing.T) {
	reKey := regexp.MustCompile(`^[A-Za-z0-9+/]{43}=\n$`)

	t.Run("T1-F03-01", func(t *testing.T) {
		res := RunCLITimeout(t, 15*time.Second, "generate", "aether-key")
		require.NoError(t, res.Err, "stderr=%s", res.Stderr)
		require.Equal(t, 0, res.ExitCode)
		require.Empty(t, res.Stderr)
		require.Len(t, res.Stdout, 45)
		require.Regexp(t, reKey, res.Stdout)
	})

	t.Run("T1-F03-02", func(t *testing.T) {
		keyStr := GenerateAetherKeyCLI(t)
		raw, err := base64.StdEncoding.DecodeString(keyStr)
		require.NoError(t, err)
		require.Len(t, raw, 32)
		require.NotEqual(t, make([]byte, 32), raw)
	})

	t.Run("T1-F03-03", func(t *testing.T) {
		const total = 50
		keys := make([]string, total)
		errs := make([]error, total)
		sem := make(chan struct{}, t1DefaultBoundedWorkers)
		var wg sync.WaitGroup
		for i := 0; i < total; i++ {
			wg.Add(1)
			go func(idx int) {
				defer wg.Done()
				sem <- struct{}{}
				defer func() { <-sem }()
				res := RunCLITimeout(t, 15*time.Second, "generate", "aether-key")
				if res.Err != nil || res.ExitCode != 0 {
					errs[idx] = fmt.Errorf("exit=%d err=%v stderr=%s", res.ExitCode, res.Err, res.Stderr)
					return
				}
				keys[idx] = strings.TrimSpace(res.Stdout)
			}(i)
		}
		wg.Wait()

		seen := make(map[string]struct{}, total)
		var allBytes []byte
		for i := 0; i < total; i++ {
			require.NoError(t, errs[i])
			raw, err := base64.StdEncoding.DecodeString(keys[i])
			require.NoError(t, err)
			require.Len(t, raw, 32)
			seen[keys[i]] = struct{}{}
			allBytes = append(allBytes, raw...)
		}
		require.Len(t, seen, total)
		require.Greater(t, ComputeShannonEntropy(allBytes), 7.7)
	})

	t.Run("T1-F03-04", func(t *testing.T) {
		key := GenerateAetherKeyCLI(t)
		cfg := TopologyConfig{ServerKey: key, ClientKey: key}
		srvJSON, err := BuildServerJSON(cfg, AllocFreeTCPPort(t), 0, "")
		require.NoError(t, err)
		cliJSON, err := BuildClientJSON(cfg, AllocFreeTCPPort(t), "127.0.0.1", 443, 0, "")
		require.NoError(t, err)

		for _, raw := range [][]byte{srvJSON, cliJSON} {
			res := CheckConfigCLI(t, raw)
			require.NoError(t, res.Err, "stderr=%s", res.Stderr)
			require.Equal(t, 0, res.ExitCode)
			require.Empty(t, res.Stderr)
		}
	})

	t.Run("T1-F03-05", func(t *testing.T) {
		key := GenerateAetherKeyCLI(t)
		echo := StartTCPEchoServer(t)
		topo := t1StartTopology(t, TopologyConfig{
			ServerKey: key,
			ClientKey: key,
		})
		t1TCPEcho(t, topo, echo.Addr(), DeterministicBytes(305, 4096))
	})
}

// =============================================================================
// F4: CLI aether-keypair Generation (T1-F04-01 .. T1-F04-05)
// =============================================================================

func runTier1F04(t *testing.T) {
	rePair := regexp.MustCompile(`^PrivateKey: [A-Za-z0-9+/]{43}=\nPublicKey: [A-Za-z0-9+/]{43}=\n$`)

	t.Run("T1-F04-01", func(t *testing.T) {
		res := RunCLITimeout(t, 15*time.Second, "generate", "aether-keypair")
		require.NoError(t, res.Err, "stderr=%s", res.Stderr)
		require.Equal(t, 0, res.ExitCode)
		require.Regexp(t, rePair, res.Stdout)
	})

	t.Run("T1-F04-02", func(t *testing.T) {
		privStr, pubStr := GenerateAetherKeyPairCLI(t)
		priv, err := base64.StdEncoding.DecodeString(privStr)
		require.NoError(t, err)
		pub, err := base64.StdEncoding.DecodeString(pubStr)
		require.NoError(t, err)
		require.Len(t, priv, 32)
		require.Len(t, pub, 32)
	})

	t.Run("T1-F04-03", func(t *testing.T) {
		privStr, pubStr := GenerateAetherKeyPairCLI(t)
		privKey, err := SpecParseX25519PrivateKey(privStr)
		require.NoError(t, err)
		pubBytes, err := base64.StdEncoding.DecodeString(pubStr)
		require.NoError(t, err)
		require.Equal(t, pubBytes, privKey.PublicKey().Bytes())
	})

	t.Run("T1-F04-04", func(t *testing.T) {
		const total = 30
		privSet := make(map[string]struct{}, total)
		pubSet := make(map[string]struct{}, total)
		ephem, err := ecdh.X25519().GenerateKey(rand.Reader)
		require.NoError(t, err)

		for i := 0; i < total; i++ {
			privStr, pubStr := GenerateAetherKeyPairCLI(t)
			privSet[privStr] = struct{}{}
			pubSet[pubStr] = struct{}{}
			privKey, err := SpecParseX25519PrivateKey(privStr)
			require.NoError(t, err)
			pubKey, err := SpecParseX25519PublicKey(pubStr)
			require.NoError(t, err)

			ss1, err := privKey.ECDH(ephem.PublicKey())
			require.NoError(t, err)
			ss2, err := ephem.ECDH(pubKey)
			require.NoError(t, err)
			require.Equal(t, ss1, ss2)
		}
		require.Len(t, privSet, total)
		require.Len(t, pubSet, total)
	})

	t.Run("T1-F04-05", func(t *testing.T) {
		key := GenerateAetherKeyCLI(t)
		privStr, pubStr := GenerateAetherKeyPairCLI(t)
		cfg := TopologyConfig{
			ServerKey:             key,
			ServerPrivateKey:      privStr,
			ClientKey:             key,
			ClientServerPublicKey: pubStr,
		}
		srvJSON, err := BuildServerJSON(cfg, AllocFreeTCPPort(t), 0, "")
		require.NoError(t, err)
		cliJSON, err := BuildClientJSON(cfg, AllocFreeTCPPort(t), "127.0.0.1", 443, 0, "")
		require.NoError(t, err)
		require.Equal(t, 0, CheckConfigCLI(t, srvJSON).ExitCode)
		require.Equal(t, 0, CheckConfigCLI(t, cliJSON).ExitCode)

		tcpEcho := StartTCPEchoServer(t)
		udpEcho := StartUDPEchoServer(t)
		topo := t1StartTopology(t, cfg)
		t1TCPEcho(t, topo, tcpEcho.Addr(), DeterministicBytes(4051, 2048))
		t1UDPEcho(t, topo, udpEcho.Addr(), DeterministicBytes(4052, 512))
	})
}

// =============================================================================
// F5: PSK Derivation & Credential Modes (T1-F05-01 .. T1-F05-05)
// =============================================================================

func runTier1F05(t *testing.T) {
	t.Run("T1-F05-01", func(t *testing.T) {
		raw32 := DeterministicBytes(501, 32)
		keyStd := base64.StdEncoding.EncodeToString(raw32)
		derived, err := SpecDerivePSK(keyStd)
		require.NoError(t, err)
		require.Equal(t, raw32, derived[:])

		srvPort := AllocFreeTCPPort(t)
		srvJSON, err := BuildServerJSON(TopologyConfig{ServerPassword: keyStd}, srvPort, 0, "")
		require.NoError(t, err)
		echo := StartTCPEchoServer(t)
		t0 := time.Now()
		srvOpts, err := UnmarshalBoxOptions(srvJSON)
		require.NoError(t, err)
		srvBox, err := box.New(box.Options{Context: NewBoxContext(context.Background()), Options: srvOpts})
		require.NoError(t, err)
		require.NoError(t, srvBox.Start())
		t.Cleanup(func() { _ = srvBox.Close() })
		elapsed := time.Since(t0)
		// Base64 32B key skips Argon2id cleanly without 300ms+ KDF pause.
		require.Less(t, elapsed, 200*time.Millisecond)

		topo := t1StartTopology(t, TopologyConfig{
			ServerPassword: keyStd,
			ClientPassword: keyStd,
		})
		t1TCPEcho(t, topo, echo.Addr(), DeterministicBytes(5012, 1024))
	})

	t.Run("T1-F05-02", func(t *testing.T) {
		raw32 := DeterministicBytes(502, 32)
		srvKey := base64.StdEncoding.EncodeToString(raw32)
		cliKey := base64.RawURLEncoding.EncodeToString(raw32)
		d1, err := SpecDerivePSK(srvKey)
		require.NoError(t, err)
		d2, err := SpecDerivePSK(cliKey)
		require.NoError(t, err)
		require.Equal(t, d1, d2)

		tcpEcho := StartTCPEchoServer(t)
		udpEcho := StartUDPEchoServer(t)
		topo := t1StartTopology(t, TopologyConfig{
			ServerKey: srvKey,
			ClientKey: cliKey,
		})
		t1TCPEcho(t, topo, tcpEcho.Addr(), DeterministicBytes(5021, 1500))
		t1UDPEcho(t, topo, udpEcho.Addr(), DeterministicBytes(5022, 600))
	})

	t.Run("T1-F05-03", func(t *testing.T) {
		raw32 := DeterministicBytes(503, 32)
		srvKey := base64.RawStdEncoding.EncodeToString(raw32)
		cliKey := base64.URLEncoding.EncodeToString(raw32)
		echo := StartTCPEchoServer(t)
		topo := t1StartTopology(t, TopologyConfig{
			ServerKey: srvKey,
			ClientKey: cliKey,
		})
		t1TCPEcho(t, topo, echo.Addr(), DeterministicBytes(5031, 1024))
	})

	t.Run("T1-F05-04", func(t *testing.T) {
		const pass16 = "AetherV2Pass16Ch"
		require.Len(t, pass16, 16)
		expectedPSK, err := SpecDerivePSK(pass16)
		require.NoError(t, err)
		require.NotEqual(t, [32]byte{}, expectedPSK)

		echo := StartTCPEchoServer(t)
		topo := t1StartTopology(t, TopologyConfig{
			ServerPassword: pass16,
			ClientPassword: pass16,
		})
		t1TCPEcho(t, topo, echo.Addr(), DeterministicBytes(5041, 1024))

		sc, err := DialSpecClient(context.Background(), topo.ServerAddr(), SpecDialOptions{
			Password:       pass16,
			TargetAddr:     echo.Addr(),
			InitialPayload: []byte("spec-argon2id-kat"),
		})
		require.NoError(t, err)
		defer func() { _ = sc.Close() }()
		_, err = sc.ReadServerResp(5 * time.Second)
		require.NoError(t, err)
		fr, err := sc.ReadFrame(5 * time.Second)
		require.NoError(t, err)
		require.Equal(t, []byte("spec-argon2id-kat"), fr.Data)
	})

	t.Run("T1-F05-05", func(t *testing.T) {
		const unicodePass = "專線安全口令-AetherFlow-2026!"
		echo := StartTCPEchoServer(t)
		topo := t1StartTopology(t, TopologyConfig{
			ServerPassword: unicodePass,
			ClientKey:      unicodePass,
		})
		t1TCPEcho(t, topo, echo.Addr(), DeterministicBytes(5051, 1024))
	})
}

// =============================================================================
// F6: Masked Ephemeral Public Key Encryption (T1-F06-01 .. T1-F06-05)
// =============================================================================

func runTier1F06(t *testing.T) {
	key := GenerateRandomKeyBase64(t)
	uPSK, err := SpecDerivePSK(key)
	require.NoError(t, err)

	t.Run("T1-F06-01", func(t *testing.T) {
		echo := StartTCPEchoServer(t)
		topo := t1StartTopology(t, TopologyConfig{ServerKey: key, ClientKey: key})
		t1TCPEcho(t, topo, echo.Addr(), []byte("epk-client-check"))

		sessions := topo.Tap.WaitForSessions(t, 1, 5*time.Second)
		sess := sessions[0]
		require.True(t, sess.WaitBytes(DirC2S, SpecClientPrefixNoEIHSize, 3*time.Second))
		c2s := sess.Bytes(DirC2S)
		var clientSalt, maskedEPK [32]byte
		copy(clientSalt[:], c2s[0:32])
		copy(maskedEPK[:], c2s[32:64])

		epkPub, err := SpecUnmaskEPK(uPSK, clientSalt, maskedEPK)
		require.NoError(t, err)
		rawPub := epkPub.Bytes()
		require.Len(t, rawPub, 32)
		require.Equal(t, byte(0), rawPub[31]&0x80)
	})

	t.Run("T1-F06-02", func(t *testing.T) {
		echo := StartTCPEchoServer(t)
		topo := t1StartTopology(t, TopologyConfig{ServerKey: key, ClientKey: key})
		t1TCPEcho(t, topo, echo.Addr(), []byte("epk-server-check"))

		sessions := topo.Tap.WaitForSessions(t, 1, 5*time.Second)
		sess := sessions[0]
		require.True(t, sess.WaitBytes(DirS2C, SpecServerRespPrefixSize, 3*time.Second))
		s2c := sess.Bytes(DirS2C)
		var srvSalt, maskedSrvEPK [32]byte
		copy(srvSalt[:], s2c[0:32])
		copy(maskedSrvEPK[:], s2c[32:64])

		srvPub, err := SpecUnmaskEPK(uPSK, srvSalt, maskedSrvEPK)
		require.NoError(t, err)
		rawPub := srvPub.Bytes()
		require.Len(t, rawPub, 32)
		require.Equal(t, byte(0), rawPub[31]&0x80)
	})

	t.Run("T1-F06-03", func(t *testing.T) {
		const n = 32
		echo := StartTCPEchoServer(t)
		topo := t1StartTopology(t, TopologyConfig{ServerKey: key, ClientKey: key})
		for i := 0; i < n; i++ {
			t1TCPEcho(t, topo, echo.Addr(), []byte{byte(i), 'f', 'r', 'e', 's', 'h'})
		}
		sessions := topo.Tap.WaitForSessions(t, n, 10*time.Second)

		cSalts := make(map[[32]byte]struct{}, n)
		sSalts := make(map[[32]byte]struct{}, n)
		cEPKs := make(map[string]struct{}, n)
		sEPKs := make(map[string]struct{}, n)
		for _, sess := range sessions {
			require.True(t, sess.WaitBytes(DirC2S, SpecClientPrefixNoEIHSize, 3*time.Second))
			require.True(t, sess.WaitBytes(DirS2C, SpecServerRespPrefixSize, 3*time.Second))
			c2s := sess.Bytes(DirC2S)
			s2c := sess.Bytes(DirS2C)

			var cs, cepk, ss, sepk [32]byte
			copy(cs[:], c2s[0:32])
			copy(cepk[:], c2s[32:64])
			copy(ss[:], s2c[0:32])
			copy(sepk[:], s2c[32:64])
			cPub, err := SpecUnmaskEPK(uPSK, cs, cepk)
			require.NoError(t, err)
			sPub, err := SpecUnmaskEPK(uPSK, ss, sepk)
			require.NoError(t, err)

			cSalts[cs] = struct{}{}
			sSalts[ss] = struct{}{}
			cEPKs[string(cPub.Bytes())] = struct{}{}
			sEPKs[string(sPub.Bytes())] = struct{}{}
		}
		require.Len(t, cSalts, n)
		require.Len(t, sSalts, n)
		require.Len(t, cEPKs, n)
		require.Len(t, sEPKs, n)
	})

	t.Run("T1-F06-04", func(t *testing.T) {
		const n = 256
		echo := StartTCPEchoServer(t)
		topo := t1StartTopology(t, TopologyConfig{
			ServerKey:               key,
			ClientKey:               key,
			ServerHeartbeatInterval: "-1s", ClientHeartbeatInterval: "-1s",
		})

		jobs := make(chan int, n)
		for i := 0; i < n; i++ {
			jobs <- i
		}
		close(jobs)

		var errMu sync.Mutex
		var firstErr error
		var wg sync.WaitGroup
		for w := 0; w < t1DefaultBoundedWorkers; w++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for i := range jobs {
					ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
					conn, err := topo.DialSOCKS5(ctx, echo.Addr())
					cancel()
					if err != nil {
						errMu.Lock()
						if firstErr == nil {
							firstErr = err
						}
						errMu.Unlock()
						return
					}
					msg := fmt.Sprintf("epk-uniform-%03d", i)
					_ = conn.SetDeadline(time.Now().Add(8 * time.Second))
					_, werr := conn.Write([]byte(msg))
					got := make([]byte, len(msg))
					_, rerr := io.ReadFull(conn, got)
					_ = conn.Close()
					if werr != nil || rerr != nil || string(got) != msg {
						errMu.Lock()
						if firstErr == nil {
							firstErr = fmt.Errorf("iter=%d werr=%v rerr=%v", i, werr, rerr)
						}
						errMu.Unlock()
						return
					}
				}
			}()
		}
		wg.Wait()
		require.NoError(t, firstErr)

		sessions := topo.Tap.WaitForSessions(t, n, 10*time.Second)
		for _, sess := range sessions {
			require.True(t, sess.WaitBytes(DirC2S, 64, 3*time.Second))
			require.True(t, sess.WaitBytes(DirS2C, 64, 3*time.Second))
		}
		cOnes, cTotal, _ := topo.Tap.EPKBit255Stats(DirC2S)
		sOnes, sTotal, _ := topo.Tap.EPKBit255Stats(DirS2C)
		require.Equal(t, n, cTotal)
		require.Equal(t, n, sTotal)
		require.GreaterOrEqual(t, cOnes, 96)
		require.LessOrEqual(t, cOnes, 160)
		require.GreaterOrEqual(t, sOnes, 96)
		require.LessOrEqual(t, sOnes, 160)
	})

	t.Run("T1-F06-05", func(t *testing.T) {
		echo := StartTCPEchoServer(t)
		topo := t1StartTopology(t, TopologyConfig{ServerKey: key, ClientKey: key})

		payload := DeterministicBytes(605, 512)
		sc, err := DialSpecClient(context.Background(), topo.ServerAddr(), SpecDialOptions{
			Key:            key,
			TargetAddr:     echo.Addr(),
			InitialPayload: payload,
		})
		require.NoError(t, err)
		defer func() { _ = sc.Close() }()
		_, err = sc.ReadServerResp(5 * time.Second)
		require.NoError(t, err)
		fr, err := sc.ReadFrame(5 * time.Second)
		require.NoError(t, err)
		require.Equal(t, payload, fr.Data)
		require.NoError(t, sc.CloseWrite())
		for {
			fr, err := sc.ReadFrame(5 * time.Second)
			if err != nil {
				require.ErrorIs(t, err, io.EOF)
				break
			}
			require.True(t, fr.FrameType == SpecFrameCloseWrite || fr.FrameType == SpecFramePing,
				"unexpected post-CloseWrite frame type %d", fr.FrameType)
		}
	})
}

// =============================================================================
// F7: Optional Server Static Public Key 0-RTT PFS (T1-F07-01 .. T1-F07-05)
// =============================================================================

func runTier1F07(t *testing.T) {
	key := GenerateRandomKeyBase64(t)
	privStr, pubStr := GenerateX25519KeyPairBase64(t)

	t.Run("T1-F07-01", func(t *testing.T) {
		echo := StartTCPEchoServer(t)
		topo := t1StartTopology(t, TopologyConfig{
			ServerKey:             key,
			ServerPrivateKey:      privStr,
			ClientKey:             key,
			ClientServerPublicKey: pubStr,
		})
		t1TCPEcho(t, topo, echo.Addr(), DeterministicBytes(701, 2048))
	})

	t.Run("T1-F07-02", func(t *testing.T) {
		echo := StartTCPEchoServer(t)
		topo := t1StartTopology(t, TopologyConfig{
			ServerKey:             key,
			ServerPrivateKey:      privStr,
			ClientKey:             key,
			ClientServerPublicKey: pubStr,
		})
		t1TCPEcho(t, topo, echo.Addr(), []byte("pfs-init-check"))

		sess := topo.Tap.WaitForSessions(t, 1, 5*time.Second)[0]
		require.True(t, sess.WaitBytes(DirC2S, SpecClientPrefixNoEIHSize, 3*time.Second))
		rawC2S := sess.Bytes(DirC2S)

		_, err := SpecDecryptWithPSKOnly(rawC2S, key)
		require.Error(t, err, "uPSK alone must NOT decrypt 0-RTT PFS FixedHeader")

		inspected, err := SpecInspectClientBurst(rawC2S, "", key, nil, privStr)
		require.NoError(t, err)
		require.Equal(t, uint8(SpecProtocolVersion), inspected.FixedHeader.Version)
		require.Len(t, inspected.StaticSharedSecret, 32)
	})

	t.Run("T1-F07-03", func(t *testing.T) {
		echo := StartTCPEchoServer(t)
		topo := t1StartTopology(t, TopologyConfig{
			ServerKey:        key,
			ServerPrivateKey: privStr,
			ClientKey:        key,
			DisableWireTap:   true,
		})

		sc, err := DialSpecClient(context.Background(), topo.ServerAddr(), SpecDialOptions{
			Key:             key,
			ServerPublicKey: pubStr,
			TargetAddr:      echo.Addr(),
			InitialPayload:  []byte("pfs-session-ratchet"),
		})
		require.NoError(t, err)
		defer func() { _ = sc.Close() }()
		resp, err := sc.ReadServerResp(5 * time.Second)
		require.NoError(t, err)
		require.Equal(t, byte(SpecProtocolVersion), resp[0])
		require.Equal(t, byte(0x00), resp[1])
		fr, err := sc.ReadFrame(5 * time.Second)
		require.NoError(t, err)
		require.Equal(t, []byte("pfs-session-ratchet"), fr.Data)
	})

	t.Run("T1-F07-04", func(t *testing.T) {
		udpEcho := StartUDPEchoServer(t)
		nativeTopo := t1StartTopology(t, TopologyConfig{
			ServerKey:             key,
			ServerPrivateKey:      privStr,
			ClientKey:             key,
			ClientServerPublicKey: pubStr,
		})
		t1UDPEcho(t, nativeTopo, udpEcho.Addr(), DeterministicBytes(7041, 900))
		nativeSess := nativeTopo.Tap.WaitForSessions(t, 1, 5*time.Second)[0]
		insp, err := SpecInspectClientBurst(nativeSess.Bytes(DirC2S), "", key, nil, privStr)
		require.NoError(t, err)
		require.Equal(t, SpecCommandUDP, insp.FixedHeader.Command)

		uotTopo := t1StartTopology(t, TopologyConfig{
			ServerKey:             key,
			ServerPrivateKey:      privStr,
			ClientKey:             key,
			ClientServerPublicKey: pubStr,
			ClientUDPOverTCP:      map[string]any{"enabled": true, "version": 2},
		})
		t1UDPEcho(t, uotTopo, udpEcho.Addr(), DeterministicBytes(7042, 900))
	})

	t.Run("T1-F07-05", func(t *testing.T) {
		echoAlice := StartTCPEchoServer(t)
		echoBob := StartTCPEchoServer(t)
		iPSK := GenerateRandomKeyBase64(t)
		uAlice := GenerateRandomKeyBase64(t)
		uBob := GenerateRandomKeyBase64(t)

		topoAlice := t1StartTopology(t, TopologyConfig{
			ServerPassword:   iPSK,
			ServerPrivateKey: privStr,
			ServerUsers: []UserSpec{
				{Name: "alice", Password: uAlice},
				{Name: "bob", Password: uBob},
			},
			ServerUserRoutes: map[string]UserRouteOverride{
				"alice": {Outbound: "direct-out", OverrideAddress: "127.0.0.1", OverridePort: echoAlice.Port()},
				"bob":   {Outbound: "direct-out", OverrideAddress: "127.0.0.1", OverridePort: echoBob.Port()},
			},
			ClientPassword:        iPSK + ":" + uAlice,
			ClientServerPublicKey: pubStr,
		})
		t1TCPEcho(t, topoAlice, echoBob.Addr(), []byte("pfs-eih-alice"))
		require.Greater(t, echoAlice.Connections(), int64(0))
		require.Equal(t, int64(0), echoBob.Connections())

		sess := topoAlice.Tap.WaitForSessions(t, 1, 5*time.Second)[0]
		insp, err := SpecInspectClientBurst(sess.Bytes(DirC2S), iPSK, "", []UserSpec{
			{Name: "alice", Password: uAlice},
			{Name: "bob", Password: uBob},
		}, privStr)
		require.NoError(t, err)
		require.True(t, insp.HasEIH)
		require.Equal(t, "alice", insp.UserName)
	})
}

// =============================================================================
// F8: Dual-Salt HKDF Key Schedule & Session Ratchet (T1-F08-01 .. T1-F08-05)
// =============================================================================

func runTier1F08(t *testing.T) {
	key := GenerateRandomKeyBase64(t)

	t.Run("T1-F08-01", func(t *testing.T) {
		echo := StartTCPEchoServer(t)
		topo := t1StartTopology(t, TopologyConfig{ServerKey: key, ClientKey: key, DisableWireTap: true})
		sc, err := DialSpecClient(context.Background(), topo.ServerAddr(), SpecDialOptions{
			Key:            key,
			TargetAddr:     echo.Addr(),
			InitialPayload: []byte("dual-salt-hkdf"),
		})
		require.NoError(t, err)
		defer func() { _ = sc.Close() }()
		_, err = sc.ReadServerResp(5 * time.Second)
		require.NoError(t, err)
		fr, err := sc.ReadFrame(5 * time.Second)
		require.NoError(t, err)
		require.Equal(t, []byte("dual-salt-hkdf"), fr.Data)
	})

	t.Run("T1-F08-02", func(t *testing.T) {
		uPSK, err := SpecDerivePSK(key)
		require.NoError(t, err)
		cSalt := [32]byte{1}
		sSalt := [32]byte{2}
		ssEph := [32]byte{3}
		copy(cSalt[:], DeterministicBytes(8021, 32))
		copy(sSalt[:], DeterministicBytes(8022, 32))
		copy(ssEph[:], DeterministicBytes(8023, 32))

		keys, err := SpecDeriveSessionKeys(uPSK, cSalt, sSalt, ssEph, nil)
		require.NoError(t, err)
		subkeys := [][32]byte{
			keys.MasterSecret,
			keys.RespKey,
			keys.C2SHeaderKey,
			keys.C2SPayloadKey,
			keys.S2CHeaderKey,
			keys.S2CPayloadKey,
		}
		unique := make(map[[32]byte]struct{}, len(subkeys))
		for _, k := range subkeys {
			require.NotEqual(t, [32]byte{}, k)
			unique[k] = struct{}{}
		}
		require.Len(t, unique, len(subkeys))

		// Verify live C2S vs S2C cross-key isolation: wrong direction key fails decryption.
		c2sHdr, err := SpecNewDataAEAD(SpecCipherChaCha20Poly1305, keys.C2SHeaderKey)
		require.NoError(t, err)
		s2cHdr, err := SpecNewDataAEAD(SpecCipherChaCha20Poly1305, keys.S2CHeaderKey)
		require.NoError(t, err)
		c2sPay, err := SpecNewDataAEAD(SpecCipherChaCha20Poly1305, keys.C2SPayloadKey)
		require.NoError(t, err)
		n0 := SpecEncodeNonce(0)
		ct := c2sHdr.Seal(nil, n0[:], []byte{0, 10}, nil)
		_, err = s2cHdr.Open(nil, n0[:], ct, nil)
		require.Error(t, err)
		_, err = c2sPay.Open(nil, n0[:], ct, nil)
		require.Error(t, err)
	})

	t.Run("T1-F08-03", func(t *testing.T) {
		const count = 64
		echo := StartTCPEchoServer(t)
		topo := t1StartTopology(t, TopologyConfig{ServerKey: key, ClientKey: key, ServerHeartbeatInterval: "-1s", ClientHeartbeatInterval: "-1s"})
		for i := 0; i < count; i++ {
			t1TCPEcho(t, topo, echo.Addr(), []byte{byte(i), 's', 'a', 'l', 't'})
		}
		sessions := topo.Tap.WaitForSessions(t, count, 10*time.Second)
		srvSalts := make(map[[32]byte]struct{}, count)
		var cat []byte
		for _, sess := range sessions {
			require.True(t, sess.WaitBytes(DirS2C, SpecServerRespPrefixSize, 3*time.Second))
			var ss [32]byte
			copy(ss[:], sess.Bytes(DirS2C)[0:32])
			srvSalts[ss] = struct{}{}
			cat = append(cat, ss[:]...)
		}
		require.Len(t, srvSalts, count)
		require.Greater(t, ComputeShannonEntropy(cat), 7.8)
	})

	t.Run("T1-F08-04", func(t *testing.T) {
		mockSrv := StartSpecMockServer(t, SpecServerOptions{
			Key: key,
			OnSession: func(sess *SpecServerSession) {
				for i := 0; i < 10; i++ {
					if _, err := sess.ReadC2SFrame(5 * time.Second); err != nil {
						return
					}
				}
				for i := 0; i < 3; i++ {
					if err := sess.WriteS2CFrame(SpecFrameData, 0, []byte(fmt.Sprintf("srv-%d", i))); err != nil {
						return
					}
				}
			},
		})
		sc, err := DialSpecClient(context.Background(), mockSrv.Addr(), SpecDialOptions{
			Key:        key,
			TargetAddr: "127.0.0.1:80",
		})
		require.NoError(t, err)
		defer func() { _ = sc.Close() }()
		_, err = sc.ReadServerResp(5 * time.Second)
		require.NoError(t, err)

		for i := 0; i < 10; i++ {
			require.NoError(t, sc.WriteFrame(SpecFrameData, 0, []byte(fmt.Sprintf("cli-%d", i))))
		}
		for i := 0; i < 3; i++ {
			fr, err := sc.ReadFrame(5 * time.Second)
			require.NoError(t, err)
			require.Equal(t, uint64(i), fr.Seq)
			require.Equal(t, []byte(fmt.Sprintf("srv-%d", i)), fr.Data)
		}
		sess := mockSrv.WaitForSessions(t, 1, 5*time.Second)[0]
		frames := sess.C2SDataFrames()
		require.Len(t, frames, 10)
		for i, f := range frames {
			require.Equal(t, uint64(i), f.Seq)
		}
	})

	t.Run("T1-F08-05", func(t *testing.T) {
		const size = 4 * 1024 * 1024
		echo := StartTCPEchoServer(t)
		topo := t1StartTopology(t, TopologyConfig{ServerKey: key, ClientKey: key, DisableWireTap: true})

		payload := DeterministicBytes(805, size)
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		conn, err := topo.DialSOCKS5(ctx, echo.Addr())
		require.NoError(t, err)
		defer func() { _ = conn.Close() }()

		errCh := make(chan error, 1)
		go func() {
			_, werr := conn.Write(payload)
			if werr == nil {
				_ = conn.CloseWrite()
			}
			errCh <- werr
		}()
		got, err := io.ReadAll(conn)
		require.NoError(t, err)
		require.NoError(t, <-errCh)
		require.Equal(t, sha256.Sum256(payload), sha256.Sum256(got))
	})
}

// =============================================================================
// F9: Cipher Suite Selection (T1-F09-01 .. T1-F09-05)
// =============================================================================

func runTier1F09(t *testing.T) {
	key := GenerateRandomKeyBase64(t)

	assertWireSuite := func(t *testing.T, cipherOpt string, expectSuite uint8) {
		t.Helper()
		echo := StartTCPEchoServer(t)
		topo := t1StartTopology(t, TopologyConfig{
			ServerKey:    key,
			ClientKey:    key,
			ClientCipher: cipherOpt,
		})
		t1TCPEcho(t, topo, echo.Addr(), DeterministicBytes(900, 1024))

		sess := topo.Tap.WaitForSessions(t, 1, 5*time.Second)[0]
		insp, err := SpecInspectClientBurst(sess.Bytes(DirC2S), "", key, nil, "")
		require.NoError(t, err)
		require.Equal(t, expectSuite, insp.FixedHeader.CipherSuite)
	}

	t.Run("T1-F09-01", func(t *testing.T) {
		assertWireSuite(t, "aes-256-gcm", SpecCipherAES256GCM)
	})

	t.Run("T1-F09-02", func(t *testing.T) {
		assertWireSuite(t, "chacha20-poly1305", SpecCipherChaCha20Poly1305)
	})

	t.Run("T1-F09-03", func(t *testing.T) {
		assertWireSuite(t, "auto", t1ExpectedAutoCipherSuite())
	})

	t.Run("T1-F09-04", func(t *testing.T) {
		assertWireSuite(t, "", t1ExpectedAutoCipherSuite())
	})

	t.Run("T1-F09-05", func(t *testing.T) {
		srvPort := AllocFreeTCPPort(t)
		srvJSON, err := BuildServerJSON(TopologyConfig{ServerKey: key}, srvPort, 0, "")
		require.NoError(t, err)
		echo := StartTCPEchoServer(t)
		srvBox, err := StartBox(t, srvJSON)
		require.NoError(t, err)
		t.Cleanup(func() { _ = srvBox.Close() })

		buildClient := func(cipher string) uint16 {
			p := AllocFreeTCPPort(t)
			raw, err := BuildClientJSON(TopologyConfig{
				ClientKey:    key,
				ClientCipher: cipher,
			}, p, "127.0.0.1", srvPort, 0, "")
			require.NoError(t, err)
			b, err := StartBox(t, raw)
			require.NoError(t, err)
			t.Cleanup(func() { _ = b.Close() })
			return p
		}

		pAES := buildClient("aes-256-gcm")
		pChaCha := buildClient("chacha20-poly1305")

		var wg sync.WaitGroup
		errCh := make(chan error, 8)
		for i := 0; i < 8; i++ {
			port := pAES
			if i%2 == 1 {
				port = pChaCha
			}
			wg.Add(1)
			go func(idx int, proxyPort uint16) {
				defer wg.Done()
				ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
				defer cancel()
				c, err := DialSOCKS5TCP(ctx, fmt.Sprintf("127.0.0.1:%d", proxyPort), echo.Addr())
				if err != nil {
					errCh <- err
					return
				}
				defer func() { _ = c.Close() }()
				payload := DeterministicBytes(uint64(950+idx), 8192)
				if _, err := c.Write(payload); err != nil {
					errCh <- err
					return
				}
				got := make([]byte, len(payload))
				if _, err := io.ReadFull(c, got); err != nil {
					errCh <- err
					return
				}
				if !bytes.Equal(payload, got) {
					errCh <- errors.New("mismatch in mixed cipher stream")
				}
			}(i, port)
		}
		wg.Wait()
		close(errCh)
		for err := range errCh {
			require.NoError(t, err)
		}
	})
}

// =============================================================================
// F10: Multi-User Authentication (EIH 112B & Users-Only 96B)
// =============================================================================

func runTier1F10(t *testing.T) {
	key := GenerateRandomKeyBase64(t)
	iPSK := GenerateRandomKeyBase64(t)
	uAlice := GenerateRandomKeyBase64(t)
	uBob := GenerateRandomKeyBase64(t)
	uCharlie := GenerateRandomKeyBase64(t)
	users := []UserSpec{
		{Name: "alice", Password: uAlice},
		{Name: "bob", Password: uBob},
		{Name: "charlie", Password: uCharlie},
	}

	t.Run("T1-F10-01", func(t *testing.T) {
		echo := StartTCPEchoServer(t)
		topo := t1StartTopology(t, TopologyConfig{ServerKey: key, ClientKey: key})
		t1TCPEcho(t, topo, echo.Addr(), []byte("single-user-96b"))

		sess := topo.Tap.WaitForSessions(t, 1, 5*time.Second)[0]
		insp, err := SpecInspectClientBurst(sess.Bytes(DirC2S), "", key, nil, "")
		require.NoError(t, err)
		require.False(t, insp.HasEIH)
		expectedHeaderAndVar := SpecClientPrefixNoEIHSize + int(insp.FixedHeader.VarHeaderLen) + 16
		require.Equal(t, expectedHeaderAndVar, insp.TotalInitialConsumed)
	})

	t.Run("T1-F10-02", func(t *testing.T) {
		echo := StartTCPEchoServer(t)
		topo := t1StartTopology(t, TopologyConfig{
			ServerPassword: iPSK,
			ServerUsers:    users,
			ClientPassword: iPSK + ":" + uBob,
		})
		t1TCPEcho(t, topo, echo.Addr(), []byte("eih-112b-bob"))

		sess := topo.Tap.WaitForSessions(t, 1, 5*time.Second)[0]
		c2s := sess.Bytes(DirC2S)
		insp, err := SpecInspectClientBurst(c2s, iPSK, "", users, "")
		require.NoError(t, err)
		require.True(t, insp.HasEIH)
		require.Equal(t, "bob", insp.UserName)
		expectedLen := SpecClientPrefixEIHSize + int(insp.FixedHeader.VarHeaderLen) + 16
		require.Equal(t, expectedLen, insp.TotalInitialConsumed)

		derivedIPS, err := SpecDerivePSK(iPSK)
		require.NoError(t, err)
		derivedBob, err := SpecDerivePSK(uBob)
		require.NoError(t, err)
		expectedEIH := SpecMaskEIH(derivedIPS, insp.ClientSalt, SpecDeriveUserID(derivedBob))
		require.Equal(t, expectedEIH[:], c2s[64:80])
	})

	t.Run("T1-F10-03", func(t *testing.T) {
		srvPort := AllocFreeTCPPort(t)
		srvJSON, err := BuildServerJSON(TopologyConfig{
			ServerUsers: users,
		}, srvPort, 0, "")
		require.NoError(t, err)
		echo := StartTCPEchoServer(t)
		srvBox, err := StartBox(t, srvJSON)
		require.NoError(t, err)
		t.Cleanup(func() { _ = srvBox.Close() })

		startUserClient := func(secret string) uint16 {
			p := AllocFreeTCPPort(t)
			cliJSON, err := BuildClientJSON(TopologyConfig{ClientKey: secret}, p, "127.0.0.1", srvPort, 0, "")
			require.NoError(t, err)
			cb, err := StartBox(t, cliJSON)
			require.NoError(t, err)
			t.Cleanup(func() { _ = cb.Close() })
			return p
		}
		pAlice := startUserClient(uAlice)
		pBob := startUserClient(uBob)

		var wg sync.WaitGroup
		errs := make(chan error, 4)
		for idx, port := range []uint16{pAlice, pBob, pAlice, pBob} {
			wg.Add(1)
			go func(i int, p uint16) {
				defer wg.Done()
				ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
				defer cancel()
				c, err := DialSOCKS5TCP(ctx, fmt.Sprintf("127.0.0.1:%d", p), echo.Addr())
				if err != nil {
					errs <- err
					return
				}
				defer func() { _ = c.Close() }()
				msg := []byte(fmt.Sprintf("users-only-%d", i))
				if _, err := c.Write(msg); err != nil {
					errs <- err
					return
				}
				got := make([]byte, len(msg))
				if _, err := io.ReadFull(c, got); err != nil || !bytes.Equal(msg, got) {
					errs <- fmt.Errorf("read err=%v match=%v", err, bytes.Equal(msg, got))
				}
			}(idx, port)
		}
		wg.Wait()
		close(errs)
		for err := range errs {
			require.NoError(t, err)
		}

		// Confirm via SpecClientConn against users-only server (ForceNoEIH -> 96B prefix).
		sc, err := DialSpecClient(context.Background(), fmt.Sprintf("127.0.0.1:%d", srvPort), SpecDialOptions{
			Key:            uAlice,
			ForceNoEIH:     true,
			TargetAddr:     echo.Addr(),
			InitialPayload: []byte("users-only-spec-96b"),
		})
		require.NoError(t, err)
		defer func() { _ = sc.Close() }()
		_, err = sc.ReadServerResp(5 * time.Second)
		require.NoError(t, err)
		fr, err := sc.ReadFrame(5 * time.Second)
		require.NoError(t, err)
		require.Equal(t, []byte("users-only-spec-96b"), fr.Data)
		insp, err := SpecInspectClientBurst(sc.InitialWire, "", "", users, "")
		require.NoError(t, err)
		require.False(t, insp.HasEIH)
		require.Equal(t, "alice", insp.UserName)
	})

	t.Run("T1-F10-04", func(t *testing.T) {
		bannerA := StartTCPBannerServer(t, []byte("echo-from-A\n"))
		bannerB := StartTCPBannerServer(t, []byte("echo-from-B\n"))
		srvPort := AllocFreeTCPPort(t)
		srvJSON, err := BuildServerJSON(TopologyConfig{
			ServerPassword: iPSK,
			ServerUsers:    users[:2],
			ServerUserRoutes: map[string]UserRouteOverride{
				"alice": {Outbound: "direct-out", OverrideAddress: "127.0.0.1", OverridePort: bannerA.Port()},
				"bob":   {Outbound: "direct-out", OverrideAddress: "127.0.0.1", OverridePort: bannerB.Port()},
			},
		}, srvPort, 0, "")
		require.NoError(t, err)
		srvBox, err := StartBox(t, srvJSON)
		require.NoError(t, err)
		t.Cleanup(func() { _ = srvBox.Close() })

		dialUserBanner := func(secret string) string {
			cliPort := AllocFreeTCPPort(t)
			cliJSON, err := BuildClientJSON(TopologyConfig{
				ClientPassword: iPSK + ":" + secret,
			}, cliPort, "127.0.0.1", srvPort, 0, "")
			require.NoError(t, err)
			cb, err := StartBox(t, cliJSON)
			require.NoError(t, err)
			t.Cleanup(func() { _ = cb.Close() })

			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			// Target bannerA's port; server user route overrides Bob -> bannerB.
			c, err := DialSOCKS5TCP(ctx, fmt.Sprintf("127.0.0.1:%d", cliPort), bannerA.Addr())
			require.NoError(t, err)
			defer func() { _ = c.Close() }()
			_, err = c.Write([]byte("ping"))
			require.NoError(t, err)
			bufRead := make([]byte, 32)
			_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
			n, err := io.ReadAtLeast(c, bufRead, len("echo-from-X\n"))
			require.NoError(t, err)
			return string(bufRead[:n])
		}

		require.Contains(t, dialUserBanner(uAlice), "echo-from-A")
		require.Contains(t, dialUserBanner(uBob), "echo-from-B")
	})

	t.Run("T1-F10-05", func(t *testing.T) {
		tcpA := StartTCPBannerServer(t, []byte("mux-A\n"))
		tcpB := StartTCPBannerServer(t, []byte("mux-B\n"))
		udpA := StartUDPEchoServer(t)
		udpB := StartUDPEchoServer(t)

		srvPort := AllocFreeTCPPort(t)
		srvJSON, err := BuildServerJSON(TopologyConfig{
			ServerPassword:  iPSK,
			ServerUsers:     users[:2],
			ServerMultiplex: &MultiplexServerSpec{Enabled: true},
			ServerUserRoutes: map[string]UserRouteOverride{
				"alice": {Outbound: "direct-out", OverrideAddress: "127.0.0.1", OverridePort: tcpA.Port()},
				"bob":   {Outbound: "direct-out", OverrideAddress: "127.0.0.1", OverridePort: tcpB.Port()},
			},
		}, srvPort, 0, "")
		require.NoError(t, err)
		srvBox, err := StartBox(t, srvJSON)
		require.NoError(t, err)
		t.Cleanup(func() { _ = srvBox.Close() })

		// Verify h2mux TCP per-user routing.
		pBob := AllocFreeTCPPort(t)
		cliBobJSON, err := BuildClientJSON(TopologyConfig{
			ClientPassword:  iPSK + ":" + uBob,
			ClientMultiplex: &MultiplexClientSpec{Enabled: true, Protocol: "h2mux", MaxConnections: 2},
		}, pBob, "127.0.0.1", srvPort, 0, "")
		require.NoError(t, err)
		cliBob, err := StartBox(t, cliBobJSON)
		require.NoError(t, err)
		t.Cleanup(func() { _ = cliBob.Close() })

		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		c, err := DialSOCKS5TCP(ctx, fmt.Sprintf("127.0.0.1:%d", pBob), tcpA.Addr())
		require.NoError(t, err)
		defer func() { _ = c.Close() }()
		_, err = c.Write([]byte("x"))
		require.NoError(t, err)
		banner := make([]byte, 6)
		_, err = io.ReadFull(c, banner)
		require.NoError(t, err)
		require.Equal(t, "mux-B\n", string(banner))

		// Verify Native CommandUDP per-user auth_user routing on another server.
		udpSrvPort := AllocFreeTCPPort(t)
		udpSrvJSON, err := BuildServerJSON(TopologyConfig{
			ServerPassword: iPSK,
			ServerUsers:    users[:2],
			ServerUserRoutes: map[string]UserRouteOverride{
				"alice": {Outbound: "direct-out", OverrideAddress: "127.0.0.1", OverridePort: udpA.Port()},
				"bob":   {Outbound: "direct-out", OverrideAddress: "127.0.0.1", OverridePort: udpB.Port()},
			},
		}, udpSrvPort, 0, "")
		require.NoError(t, err)
		udpSrvBox, err := StartBox(t, udpSrvJSON)
		require.NoError(t, err)
		t.Cleanup(func() { _ = udpSrvBox.Close() })

		pBobUDP := AllocFreeTCPPort(t)
		cliBobUDPJSON, err := BuildClientJSON(TopologyConfig{
			ClientPassword: iPSK + ":" + uBob,
		}, pBobUDP, "127.0.0.1", udpSrvPort, 0, "")
		require.NoError(t, err)
		cliBobUDP, err := StartBox(t, cliBobUDPJSON)
		require.NoError(t, err)
		t.Cleanup(func() { _ = cliBobUDP.Close() })

		uconn, err := DialSOCKS5UDP(ctx, fmt.Sprintf("127.0.0.1:%d", pBobUDP))
		require.NoError(t, err)
		defer func() { _ = uconn.Close() }()
		require.NoError(t, uconn.WriteToHostPort([]byte("who-am-i"), udpA.Addr()))
		rb := make([]byte, 256)
		n, _, err := uconn.ReadFromHostPort(rb)
		require.NoError(t, err)
		require.Equal(t, []byte("who-am-i"), rb[:n])
		require.Greater(t, udpB.Packets(), int64(0))
		require.Equal(t, int64(0), udpA.Packets())
	})
}

// =============================================================================
// F11: Wire Layout & FixedHeader Commands / NoiseLen
// =============================================================================

func runTier1F11(t *testing.T) {
	key := GenerateRandomKeyBase64(t)

	inspectCmd := func(t *testing.T, cfg TopologyConfig, fn func(topo *Topology)) SpecFixedHeader {
		t.Helper()
		topo := t1StartTopology(t, cfg)
		fn(topo)
		sess := topo.Tap.WaitForSessions(t, 1, 5*time.Second)[0]
		require.True(t, sess.WaitBytes(DirC2S, SpecClientPrefixNoEIHSize, 3*time.Second))
		insp, err := SpecInspectClientBurst(sess.Bytes(DirC2S), "", key, nil, "")
		require.NoError(t, err)
		return insp.FixedHeader
	}

	t.Run("T1-F11-01", func(t *testing.T) {
		echo := StartTCPEchoServer(t)
		now := time.Now().Unix()
		fh := inspectCmd(t, TopologyConfig{ServerKey: key, ClientKey: key}, func(topo *Topology) {
			t1TCPEcho(t, topo, echo.Addr(), []byte("cmd-tcp"))
		})
		require.Equal(t, SpecProtocolVersion, fh.Version)
		require.Equal(t, SpecCommandTCP, fh.Command)
		require.Equal(t, uint8(0), fh.Reserved)
		require.GreaterOrEqual(t, int(fh.NoiseLen), SpecNoiseMin)
		require.LessOrEqual(t, int(fh.NoiseLen), SpecNoiseMax)
		require.LessOrEqual(t, absInt64(fh.TimestampSec-now), int64(5))
	})

	t.Run("T1-F11-02", func(t *testing.T) {
		udpEcho := StartUDPEchoServer(t)
		fh := inspectCmd(t, TopologyConfig{ServerKey: key, ClientKey: key}, func(topo *Topology) {
			t1UDPEcho(t, topo, udpEcho.Addr(), []byte("cmd-udp"))
		})
		require.Equal(t, SpecCommandUDP, fh.Command)
	})

	t.Run("T1-F11-03", func(t *testing.T) {
		echo := StartTCPEchoServer(t)
		fh := inspectCmd(t, TopologyConfig{
			ServerKey:       key,
			ClientKey:       key,
			ServerMultiplex: &MultiplexServerSpec{Enabled: true},
			ClientMultiplex: &MultiplexClientSpec{Enabled: true, Protocol: "h2mux", MaxConnections: 1},
		}, func(topo *Topology) {
			t1TCPEcho(t, topo, echo.Addr(), []byte("cmd-mux"))
		})
		require.Equal(t, SpecCommandMux, fh.Command)
	})

	t.Run("T1-F11-04", func(t *testing.T) {
		udpEcho := StartUDPEchoServer(t)
		fh := inspectCmd(t, TopologyConfig{
			ServerKey:        key,
			ClientKey:        key,
			ClientUDPOverTCP: map[string]any{"enabled": true, "version": 2},
		}, func(topo *Topology) {
			t1UDPEcho(t, topo, udpEcho.Addr(), []byte("cmd-uot"))
		})
		require.Equal(t, SpecCommandUoT, fh.Command)
	})

	t.Run("T1-F11-05", func(t *testing.T) {
		const n = 32
		echo := StartTCPEchoServer(t)
		topo := t1StartTopology(t, TopologyConfig{ServerKey: key, ClientKey: key, ServerHeartbeatInterval: "-1s", ClientHeartbeatInterval: "-1s"})
		for i := 0; i < n; i++ {
			t1TCPEcho(t, topo, echo.Addr(), []byte{byte(i), 'n', 'o', 'i', 's', 'e'})
		}
		sessions := topo.Tap.WaitForSessions(t, n, 10*time.Second)
		distinct := make(map[uint16]struct{}, n)
		for _, sess := range sessions {
			require.True(t, sess.WaitBytes(DirC2S, SpecClientPrefixNoEIHSize, 3*time.Second))
			insp, err := SpecInspectClientBurst(sess.Bytes(DirC2S), "", key, nil, "")
			require.NoError(t, err)
			require.GreaterOrEqual(t, int(insp.FixedHeader.NoiseLen), SpecNoiseMin)
			require.LessOrEqual(t, int(insp.FixedHeader.NoiseLen), SpecNoiseMax)
			require.Len(t, insp.VarHeader.Noise, int(insp.FixedHeader.NoiseLen))
			distinct[insp.FixedHeader.NoiseLen] = struct{}{}
		}
		require.GreaterOrEqual(t, len(distinct), 6)
	})
}

func absInt64(v int64) int64 {
	if v < 0 {
		return -v
	}
	return v
}

// =============================================================================
// F12: 0-RTT Coalesced Client Initial Burst & VarHeader
// =============================================================================

func runTier1F12(t *testing.T) {
	key := GenerateRandomKeyBase64(t)

	t.Run("T1-F12-01", func(t *testing.T) {
		echo := StartTCPEchoServer(t)
		topo := t1StartTopology(t, TopologyConfig{
			ServerKey:            key,
			ClientKey:            key,
			ServerDisableShaping: true, ClientDisableShaping: true,
			ServerHeartbeatInterval: "-1s", ClientHeartbeatInterval: "-1s",
		})
		out, ok := topo.Client.Box.Outbound().Outbound("aether-out")
		require.True(t, ok)

		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		dst := M.ParseSocksaddr(echo.Addr())
		conn, err := out.DialContext(ctx, N.NetworkTCP, dst)
		require.NoError(t, err)
		defer func() { _ = conn.Close() }()

		// Before Write: lazy 0-RTT EarlyConn must not send a bare handshake burst yet.
		time.Sleep(30 * time.Millisecond)
		for _, s := range topo.Tap.Sessions() {
			require.Empty(t, s.SegmentsByDir(DirC2S))
			require.Empty(t, s.Bytes(DirC2S))
		}

		req := DeterministicBytes(1201, 512)
		_, err = conn.Write(req)
		require.NoError(t, err)
		got := make([]byte, len(req))
		_, err = io.ReadFull(conn, got)
		require.NoError(t, err)
		require.Equal(t, req, got)

		sess := topo.Tap.WaitForSessions(t, 1, 5*time.Second)[0]
		insp, err := SpecInspectClientBurst(sess.Bytes(DirC2S), "", key, nil, "")
		require.NoError(t, err)
		require.Equal(t, req, insp.VarHeader.InitialPayload)
		seg0, ok := sess.FirstSegment(DirC2S)
		require.True(t, ok)
		require.Equal(t, insp.TotalInitialConsumed, seg0.Size)
	})

	t.Run("T1-F12-02", func(t *testing.T) {
		echo6 := StartTCPEchoTargetOn(t, "tcp6", "[::1]:0")
		topo := t1StartTopology(t, TopologyConfig{
			ServerKey:          key,
			ClientKey:          key,
			ClientSniffTimeout: "50ms",
		})
		payload := DeterministicBytes(1202, 512)
		t1TCPEcho(t, topo, echo6.Addr(), payload)

		sess := topo.Tap.WaitForSessions(t, 1, 5*time.Second)[0]
		insp, err := SpecInspectClientBurst(sess.Bytes(DirC2S), "", key, nil, "")
		require.NoError(t, err)
		require.True(t, insp.VarHeader.Target.Addr.Is6())
		require.Equal(t, echo6.Port(), insp.VarHeader.Target.Port)
	})

	t.Run("T1-F12-03", func(t *testing.T) {
		echo := StartTCPEchoServer(t)
		topo := t1StartTopology(t, TopologyConfig{ServerKey: key, ClientKey: key})
		targetFQDN := fmt.Sprintf("localhost:%d", echo.Port())
		t1TCPEcho(t, topo, targetFQDN, DeterministicBytes(1203, 512))

		sess := topo.Tap.WaitForSessions(t, 1, 5*time.Second)[0]
		insp, err := SpecInspectClientBurst(sess.Bytes(DirC2S), "", key, nil, "")
		require.NoError(t, err)
		require.Equal(t, "localhost", insp.VarHeader.Target.Fqdn)
		require.Equal(t, echo.Port(), insp.VarHeader.Target.Port)
	})

	t.Run("T1-F12-04", func(t *testing.T) {
		const banner = "220-ESMTP-READY\r\n"
		srv := StartTCPBannerServer(t, []byte(banner))
		topo := t1StartTopology(t, TopologyConfig{ServerKey: key, ClientKey: key})

		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		conn, err := topo.DialSOCKS5(ctx, srv.Addr())
		require.NoError(t, err)
		defer func() { _ = conn.Close() }()

		// Read BEFORE sending any application data (server-speaks-first protocol).
		require.NoError(t, conn.SetDeadline(time.Now().Add(8*time.Second)))
		gotBanner := make([]byte, len(banner))
		_, err = io.ReadFull(conn, gotBanner)
		require.NoError(t, err)
		require.Equal(t, banner, string(gotBanner))

		sess := topo.Tap.WaitForSessions(t, 1, 5*time.Second)[0]
		insp, err := SpecInspectClientBurst(sess.Bytes(DirC2S), "", key, nil, "")
		require.NoError(t, err)
		require.Empty(t, insp.VarHeader.InitialPayload)
		require.GreaterOrEqual(t, int(insp.FixedHeader.NoiseLen), SpecNoiseMin)

		// Verify follow-up bidirectional echo succeeds on same connection.
		reply := []byte("EHLO aether.test\r\n")
		_, err = conn.Write(reply)
		require.NoError(t, err)
		gotReply := make([]byte, len(reply))
		_, err = io.ReadFull(conn, gotReply)
		require.NoError(t, err)
		require.Equal(t, reply, gotReply)
	})

	t.Run("T1-F12-05", func(t *testing.T) {
		echo := StartTCPEchoServer(t)
		topo := t1StartTopology(t, TopologyConfig{ServerKey: key, ClientKey: key})
		t1TCPEcho(t, topo, echo.Addr(), []byte("varheader-aad-binding"))

		sess := topo.Tap.WaitForSessions(t, 1, 5*time.Second)[0]
		c2s := sess.Bytes(DirC2S)
		insp, err := SpecInspectClientBurst(c2s, "", key, nil, "")
		require.NoError(t, err)

		// Corrupt 1 bit in FixedHeader plaintext AAD: InitAEAD must reject EncryptedVarHeader.
		badAAD := insp.FixedHeader.Raw
		badAAD[3] ^= 0x01
		n1 := SpecEncodeNonce(1)
		encVarStart := SpecClientPrefixNoEIHSize
		encVarEnd := encVarStart + int(insp.FixedHeader.VarHeaderLen) + 16
		_, err = insp.InitAEAD.Open(nil, n1[:], c2s[encVarStart:encVarEnd], badAAD[:])
		require.Error(t, err)
	})
}

// =============================================================================
// F13: Coalesced 84B Server Response Prefix
// =============================================================================

func runTier1F13(t *testing.T) {
	key := GenerateRandomKeyBase64(t)

	t.Run("T1-F13-01", func(t *testing.T) {
		echo := StartTCPEchoServer(t)
		topo := t1StartTopology(t, TopologyConfig{
			ServerKey:               key,
			ClientKey:               key,
			ClientCipher:            "chacha20-poly1305",
			ServerHeartbeatInterval: "-1s", ClientHeartbeatInterval: "-1s",
		})
		req := DeterministicBytes(1301, 256)
		t1TCPEcho(t, topo, echo.Addr(), req)

		sess := topo.Tap.WaitForSessions(t, 1, 5*time.Second)[0]
		require.True(t, sess.WaitBytes(DirS2C, int64(SpecServerRespPrefixSize+SpecEncryptedLengthSize+2+len(req)+16), 5*time.Second))
		seg0, ok := sess.FirstSegment(DirS2C)
		require.True(t, ok)
		require.False(t, sess.HasSegmentOfExactSize(DirS2C, SpecServerRespPrefixSize))
		require.GreaterOrEqual(t, seg0.Size, SpecServerRespPrefixSize+SpecEncryptedLengthSize+2+len(req)+16)
	})

	t.Run("T1-F13-02", func(t *testing.T) {
		echo := StartTCPEchoServer(t)
		topo := t1StartTopology(t, TopologyConfig{ServerKey: key, ClientKey: key, DisableWireTap: true})
		for _, suite := range []uint8{SpecCipherAES256GCM, SpecCipherChaCha20Poly1305} {
			s := suite
			sc, err := DialSpecClient(context.Background(), topo.ServerAddr(), SpecDialOptions{
				Key:         key,
				CipherSuite: &s,
				TargetAddr:  echo.Addr(),
			})
			require.NoError(t, err)
			resp, err := sc.ReadServerResp(5 * time.Second)
			require.NoError(t, err)
			require.Equal(t, [4]byte{SpecProtocolVersion, 0x00, s, 0x00}, resp)
			_ = sc.Close()
		}
	})

	t.Run("T1-F13-03", func(t *testing.T) {
		finSrv := StartImmediateFINServer(t)
		topo := t1StartTopology(t, TopologyConfig{
			ServerKey:               key,
			ClientKey:               key,
			ServerHeartbeatInterval: "-1s", ClientHeartbeatInterval: "-1s",
		})
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		conn, err := topo.DialSOCKS5(ctx, finSrv.Addr())
		require.NoError(t, err)
		defer func() { _ = conn.Close() }()
		require.NoError(t, conn.SetReadDeadline(time.Now().Add(5*time.Second)))
		var b [64]byte
		n, err := conn.Read(b[:])
		require.Equal(t, 0, n)
		require.ErrorIs(t, err, io.EOF)

		sess := topo.Tap.WaitForSessions(t, 1, 5*time.Second)[0]
		require.True(t, sess.WaitBytes(DirS2C, SpecServerRespPrefixSize+SpecEncryptedLengthSize+2+16, 3*time.Second))
		require.False(t, sess.HasSegmentOfExactSize(DirS2C, SpecServerRespPrefixSize))
	})

	t.Run("T1-F13-04", func(t *testing.T) {
		stalled := StartStalledTCPServer(t)
		defer stalled.Release()
		topo := t1StartTopology(t, TopologyConfig{
			ServerKey:               key,
			ClientKey:               key,
			ServerHeartbeatInterval: "250ms", ClientHeartbeatInterval: "250ms",
		})
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		conn, err := topo.DialSOCKS5(ctx, stalled.Addr())
		require.NoError(t, err)
		defer func() { _ = conn.Close() }()
		_, err = conn.Write([]byte("hold-for-heartbeat"))
		require.NoError(t, err)

		sess := topo.Tap.WaitForSessions(t, 1, 5*time.Second)[0]
		// Coalesced 84B ServerRespPrefix + first FramePing (>= 32B pad) >= 152B.
		require.True(t, sess.WaitBytes(DirS2C, SpecServerRespPrefixSize+SpecEncryptedLengthSize+2+32+16, 5*time.Second))
		seg0, ok := sess.FirstSegment(DirS2C)
		require.True(t, ok)
		require.False(t, sess.HasSegmentOfExactSize(DirS2C, SpecServerRespPrefixSize))
		require.GreaterOrEqual(t, seg0.Size, SpecServerRespPrefixSize+SpecEncryptedLengthSize+2+32+16)
	})

	t.Run("T1-F13-05", func(t *testing.T) {
		udpEcho := StartUDPEchoServer(t)
		udpTopo := t1StartTopology(t, TopologyConfig{ServerKey: key, ClientKey: key, ServerHeartbeatInterval: "-1s", ClientHeartbeatInterval: "-1s"})
		t1UDPEcho(t, udpTopo, udpEcho.Addr(), []byte("udp-resp-coalesce"))
		udpSess := udpTopo.Tap.WaitForSessions(t, 1, 5*time.Second)[0]
		segUDP, ok := udpSess.FirstSegment(DirS2C)
		require.True(t, ok)
		require.False(t, udpSess.HasSegmentOfExactSize(DirS2C, SpecServerRespPrefixSize))
		require.GreaterOrEqual(t, segUDP.Size, SpecServerRespPrefixSize+36)

		tcpEcho := StartTCPEchoServer(t)
		muxTopo := t1StartTopology(t, TopologyConfig{
			ServerKey:               key,
			ClientKey:               key,
			ServerHeartbeatInterval: "-1s", ClientHeartbeatInterval: "-1s",
			ServerMultiplex: &MultiplexServerSpec{Enabled: true},
			ClientMultiplex: &MultiplexClientSpec{Enabled: true, Protocol: "smux", MaxConnections: 1},
		})
		t1TCPEcho(t, muxTopo, tcpEcho.Addr(), []byte("mux-resp-coalesce"))
		muxSess := muxTopo.Tap.WaitForSessions(t, 1, 5*time.Second)[0]
		segMux, ok := muxSess.FirstSegment(DirS2C)
		require.True(t, ok)
		require.False(t, muxSess.HasSegmentOfExactSize(DirS2C, SpecServerRespPrefixSize))
		require.GreaterOrEqual(t, segMux.Size, SpecServerRespPrefixSize+36)
	})
}

// =============================================================================
// F14: Two-Block Encrypted Frame Wire & Zero 2B Split
// =============================================================================

func runTier1F14(t *testing.T) {
	key := GenerateRandomKeyBase64(t)

	t.Run("T1-F14-01", func(t *testing.T) {
		echo := StartTCPEchoServer(t)
		topo := t1StartTopology(t, TopologyConfig{ServerKey: key, ClientKey: key, ServerHeartbeatInterval: "-1s", ClientHeartbeatInterval: "-1s"})
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		conn, err := topo.DialSOCKS5(ctx, echo.Addr())
		require.NoError(t, err)
		defer func() { _ = conn.Close() }()

		sizes := []int{1, 7, 64, 512, 4096, 16384, 32768}
		for round := 0; round < 6; round++ {
			for idx, sz := range sizes {
				p := DeterministicBytes(uint64(140100+round*10+idx), sz)
				t1DialAndEchoConn(t, conn, p)
			}
		}
		_ = conn.Close()

		sess := topo.Tap.WaitForSessions(t, 1, 5*time.Second)[0]
		require.True(t, sess.WaitClosed(3*time.Second))
		require.False(t, sess.HasSegmentOfExactSize(DirC2S, 2))
		require.False(t, sess.HasSegmentOfExactSize(DirC2S, 18))
		require.False(t, sess.HasSegmentOfExactSize(DirS2C, 2))
		require.False(t, sess.HasSegmentOfExactSize(DirS2C, 18))
		for _, seg := range sess.Segments() {
			require.GreaterOrEqual(t, seg.Size, 36)
		}
	})

	t.Run("T1-F14-02", func(t *testing.T) {
		mockSrv := StartSpecMockServer(t, SpecServerOptions{Key: key})
		cliPort := AllocFreeTCPPort(t)
		cliJSON, err := BuildClientJSON(TopologyConfig{
			ClientKey:               key,
			ServerHeartbeatInterval: "-1s", ClientHeartbeatInterval: "-1s",
		}, cliPort, "127.0.0.1", mockSrv.Port(), 0, "")
		require.NoError(t, err)
		cliBox, err := StartBox(t, cliJSON)
		require.NoError(t, err)
		t.Cleanup(func() { _ = cliBox.Close() })

		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		c, err := DialSOCKS5TCP(ctx, fmt.Sprintf("127.0.0.1:%d", cliPort), "127.0.0.1:9000")
		require.NoError(t, err)
		defer func() { _ = c.Close() }()
		for i := 0; i < 5; i++ {
			t1DialAndEchoConn(t, c, DeterministicBytes(uint64(14020+i), 300+i*100))
		}
		sess := mockSrv.WaitForSessions(t, 1, 5*time.Second)[0]
		frames := sess.C2SDataFrames()
		require.GreaterOrEqual(t, len(frames), 4)
		for _, f := range frames {
			require.GreaterOrEqual(t, int(f.PlainFrameLen), 2)
			require.LessOrEqual(t, int(f.PlainFrameLen), SpecMaxFramePlainSize)
		}
	})

	t.Run("T1-F14-03", func(t *testing.T) {
		mockSrv := StartSpecMockServer(t, SpecServerOptions{Key: key})
		cliPort := AllocFreeTCPPort(t)
		cliJSON, err := BuildClientJSON(TopologyConfig{
			ClientKey:            key,
			ServerDisableShaping: true, ClientDisableShaping: true,
			ServerHeartbeatInterval: "-1s", ClientHeartbeatInterval: "-1s",
		}, cliPort, "127.0.0.1", mockSrv.Port(), 0, "")
		require.NoError(t, err)
		cliBox, err := StartBox(t, cliJSON)
		require.NoError(t, err)
		t.Cleanup(func() { _ = cliBox.Close() })

		out, ok := cliBox.Box.Outbound().Outbound("aether-out")
		require.True(t, ok)
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		conn, err := out.DialContext(ctx, N.NetworkTCP, M.ParseSocksaddr("127.0.0.1:9001"))
		require.NoError(t, err)
		defer func() { _ = conn.Close() }()

		const chunkSize = 128 * 1024
		payload := DeterministicBytes(1403, chunkSize)
		errCh := make(chan error, 1)
		go func() {
			// Skip 0-RTT VarHeader burst with small prime write, then push 128 KiB aligned.
			if _, werr := conn.Write([]byte("go")); werr != nil {
				errCh <- werr
				return
			}
			_, werr := conn.Write(payload)
			errCh <- werr
		}()
		got := make([]byte, 2+chunkSize)
		_, err = io.ReadFull(conn, got)
		require.NoError(t, err)
		require.NoError(t, <-errCh)
		require.Equal(t, payload, got[2:])

		sess := mockSrv.WaitForSessions(t, 1, 5*time.Second)[0]
		frames := sess.C2SDataFrames()
		fullCount := 0
		for _, f := range frames {
			if len(f.Data) == SpecMaxFrameDataSize {
				require.Equal(t, uint16(SpecMaxFrameDataSize+2), f.PlainFrameLen)
				require.Equal(t, byte(0), f.PadLen)
				fullCount++
			}
		}
		require.GreaterOrEqual(t, fullCount, 8)
	})

	t.Run("T1-F14-04", func(t *testing.T) {
		root, err := RepoRoot()
		require.NoError(t, err)
		for _, legacy := range []string{"noise.go", "frame.go", "cipher.go", "probe_guard.go"} {
			_, statErr := os.Stat(filepath.Join(root, "protocol", "aether", legacy))
			require.True(t, errors.Is(statErr, os.ErrNotExist), "legacy file %s must be removed", legacy)
		}

		// Verify consecutive equal-sized frames have independent random 18B encrypted headers.
		echo := StartTCPEchoServer(t)
		topo := t1StartTopology(t, TopologyConfig{
			ServerKey:            key,
			ClientKey:            key,
			ServerDisableShaping: true, ClientDisableShaping: true,
			ServerHeartbeatInterval: "-1s", ClientHeartbeatInterval: "-1s",
		})
		out, ok := topo.Client.Box.Outbound().Outbound("aether-out")
		require.True(t, ok)
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		conn, err := out.DialContext(ctx, N.NetworkTCP, M.ParseSocksaddr(echo.Addr()))
		require.NoError(t, err)
		defer func() { _ = conn.Close() }()

		const framePayload = 128
		var segHeaders [][]byte
		for i := 0; i < 6; i++ {
			req := DeterministicBytes(1404, framePayload)
			t1DialAndEchoConn(t, conn, req)
			time.Sleep(15 * time.Millisecond)
		}
		sess := topo.Tap.WaitForSessions(t, 1, 5*time.Second)[0]
		for _, seg := range sess.SegmentsByDir(DirC2S) {
			if seg.Size == SpecEncryptedLengthSize+2+framePayload+16 {
				segHeaders = append(segHeaders, seg.Data[:SpecEncryptedLengthSize])
			}
		}
		require.GreaterOrEqual(t, len(segHeaders), 4)
		for i := 1; i < len(segHeaders); i++ {
			require.NotEqual(t, segHeaders[0], segHeaders[i])
		}
	})

	t.Run("T1-F14-05", func(t *testing.T) {
		for _, suite := range []string{"aes-256-gcm", "chacha20-poly1305"} {
			echo := StartTCPEchoServer(t)
			topo := t1StartTopology(t, TopologyConfig{
				ServerKey:    key,
				ClientKey:    key,
				ClientCipher: suite,
			})
			ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			conn, err := topo.DialSOCKS5(ctx, echo.Addr())
			cancel()
			require.NoError(t, err)

			chunkSizes := []int{1, 37, 1024, 16384, 65536}
			var totalSent, totalGot bytes.Buffer
			for round := 0; round < 6; round++ {
				for idx, sz := range chunkSizes {
					p := DeterministicBytes(uint64(140500+round*10+idx), sz)
					totalSent.Write(p)
					require.NoError(t, conn.SetDeadline(time.Now().Add(10*time.Second)))
					_, err := conn.Write(p)
					require.NoError(t, err)
					g := make([]byte, sz)
					_, err = io.ReadFull(conn, g)
					require.NoError(t, err)
					totalGot.Write(g)
				}
			}
			_ = conn.Close()
			require.Equal(t, sha256.Sum256(totalSent.Bytes()), sha256.Sum256(totalGot.Bytes()))
		}
	})
}

// =============================================================================
// F15: Traffic Shaping (Frame 0..5 Random Padding vs Frame 6+ <= 0.22%)
// =============================================================================

func runTier1F15(t *testing.T) {
	key := GenerateRandomKeyBase64(t)

	startShapingClientToSpec := func(t *testing.T, disableShaping bool) (*SpecMockServer, *box.Box) {
		t.Helper()
		mockSrv := StartSpecMockServer(t, SpecServerOptions{Key: key})
		cliPort := AllocFreeTCPPort(t)
		cliJSON, err := BuildClientJSON(TopologyConfig{
			ClientKey:            key,
			ServerDisableShaping: disableShaping, ClientDisableShaping: disableShaping,
			ServerHeartbeatInterval: "-1s", ClientHeartbeatInterval: "-1s",
		}, cliPort, "127.0.0.1", mockSrv.Port(), 0, "")
		require.NoError(t, err)
		cliBox, err := StartBox(t, cliJSON)
		require.NoError(t, err)
		t.Cleanup(func() { _ = cliBox.Close() })
		return mockSrv, cliBox.Box
	}

	t.Run("T1-F15-01", func(t *testing.T) {
		mockSrv, cliBox := startShapingClientToSpec(t, false)
		out, ok := cliBox.Outbound().Outbound("aether-out")
		require.True(t, ok)
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		conn, err := out.DialContext(ctx, N.NetworkTCP, M.ParseSocksaddr("127.0.0.1:8080"))
		require.NoError(t, err)
		defer func() { _ = conn.Close() }()

		// Flush 0-RTT VarHeader burst with tiny request, then 6 separate 200B Data frames (Seq 0..5).
		t1DialAndEchoConn(t, conn, []byte("init"))
		for i := 0; i < 6; i++ {
			t1DialAndEchoConn(t, conn, DeterministicBytes(uint64(15010+i), 200))
		}
		sess := mockSrv.WaitForSessions(t, 1, 5*time.Second)[0]
		frames := sess.C2SDataFrames()
		require.GreaterOrEqual(t, len(frames), 6)
		padLens := make(map[byte]struct{})
		for i := 0; i < 6; i++ {
			require.Equal(t, uint64(i), frames[i].Seq)
			require.GreaterOrEqual(t, int(frames[i].PadLen), 16)
			require.LessOrEqual(t, int(frames[i].PadLen), 255)
			padLens[frames[i].PadLen] = struct{}{}
		}
		require.GreaterOrEqual(t, len(padLens), 2)
	})

	t.Run("T1-F15-02", func(t *testing.T) {
		mockSrv, cliBox := startShapingClientToSpec(t, false)
		out, ok := cliBox.Outbound().Outbound("aether-out")
		require.True(t, ok)
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		conn, err := out.DialContext(ctx, N.NetworkTCP, M.ParseSocksaddr("127.0.0.1:8080"))
		require.NoError(t, err)
		defer func() { _ = conn.Close() }()

		t1DialAndEchoConn(t, conn, []byte("boot"))
		burst3600 := DeterministicBytes(1502, 3600)
		t1DialAndEchoConn(t, conn, burst3600)

		sess := mockSrv.WaitForSessions(t, 1, 5*time.Second)[0]
		frames := sess.C2SDataFrames()
		require.GreaterOrEqual(t, len(frames), 4)
		var reassembled bytes.Buffer
		splitCount := 0
		for _, f := range frames {
			require.LessOrEqual(t, len(f.Data), 1200)
			if len(f.Data) >= 512 {
				require.GreaterOrEqual(t, int(f.PadLen), 16)
				require.LessOrEqual(t, int(f.PadLen), 255)
				splitCount++
			}
			reassembled.Write(f.Data)
		}
		require.GreaterOrEqual(t, splitCount, 3)
		require.Equal(t, burst3600, reassembled.Bytes())
	})

	t.Run("T1-F15-03", func(t *testing.T) {
		mockSrv, cliBox := startShapingClientToSpec(t, false)
		out, ok := cliBox.Outbound().Outbound("aether-out")
		require.True(t, ok)
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		conn, err := out.DialContext(ctx, N.NetworkTCP, M.ParseSocksaddr("127.0.0.1:8080"))
		require.NoError(t, err)
		defer func() { _ = conn.Close() }()

		t1DialAndEchoConn(t, conn, []byte("init"))
		for i := 0; i < 12; i++ {
			t1DialAndEchoConn(t, conn, DeterministicBytes(uint64(15030+i), 128))
		}
		sess := mockSrv.WaitForSessions(t, 1, 5*time.Second)[0]
		frames := sess.C2SDataFrames()
		require.GreaterOrEqual(t, len(frames), 12)
		for i := 0; i < 6; i++ {
			require.GreaterOrEqual(t, int(frames[i].PadLen), 16)
			require.LessOrEqual(t, int(frames[i].PadLen), 255)
		}
		for i := 6; i < 12; i++ {
			require.Equal(t, byte(0), frames[i].PadLen)
		}
	})

	t.Run("T1-F15-04", func(t *testing.T) {
		echo := StartTCPEchoServer(t)
		topo := t1StartTopology(t, TopologyConfig{
			ServerKey:            key,
			ClientKey:            key,
			ServerDisableShaping: false, ClientDisableShaping: false,
			ServerHeartbeatInterval: "-1s", ClientHeartbeatInterval: "-1s",
		})
		out, ok := topo.Client.Box.Outbound().Outbound("aether-out")
		require.True(t, ok)
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		conn, err := out.DialContext(ctx, N.NetworkTCP, M.ParseSocksaddr(echo.Addr()))
		require.NoError(t, err)
		defer func() { _ = conn.Close() }()

		// Complete initial burst + 6 shaped frames so sendFrameIdx >= 6.
		t1DialAndEchoConn(t, conn, []byte("hs"))
		for i := 0; i < 6; i++ {
			t1DialAndEchoConn(t, conn, DeterministicBytes(uint64(15040+i), 64))
		}
		sess := topo.Tap.WaitForSessions(t, 1, 5*time.Second)[0]
		time.Sleep(30 * time.Millisecond)
		c2sBefore := sess.TotalBytes(DirC2S)

		const bulkLen = 4 * 1024 * 1024
		bulk := DeterministicBytes(15049, bulkLen)
		errCh := make(chan error, 1)
		go func() {
			_, werr := conn.Write(bulk)
			errCh <- werr
		}()
		got := make([]byte, bulkLen)
		_, err = io.ReadFull(conn, got)
		require.NoError(t, err)
		require.NoError(t, <-errCh)
		require.Equal(t, sha256.Sum256(bulk), sha256.Sum256(got))

		deltaWire := sess.TotalBytes(DirC2S) - c2sBefore
		overhead := float64(deltaWire-bulkLen) / float64(bulkLen)
		require.LessOrEqual(t, overhead, 0.0022)
	})

	t.Run("T1-F15-05", func(t *testing.T) {
		mockSrv, cliBox := startShapingClientToSpec(t, true)
		out, ok := cliBox.Outbound().Outbound("aether-out")
		require.True(t, ok)
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		conn, err := out.DialContext(ctx, N.NetworkTCP, M.ParseSocksaddr("127.0.0.1:8080"))
		require.NoError(t, err)
		defer func() { _ = conn.Close() }()

		t1DialAndEchoConn(t, conn, []byte("boot"))
		t1DialAndEchoConn(t, conn, DeterministicBytes(15051, 3600))
		t1DialAndEchoConn(t, conn, DeterministicBytes(15052, 200))

		sess := mockSrv.WaitForSessions(t, 1, 5*time.Second)[0]
		frames := sess.C2SDataFrames()
		require.Len(t, frames, 2)
		require.Equal(t, byte(0), frames[0].PadLen)
		require.Len(t, frames[0].Data, 3600)
		require.Equal(t, byte(0), frames[1].PadLen)
		require.Len(t, frames[1].Data, 200)
	})
}

// =============================================================================
// F16: Control & Framing (FrameData, Chaff, Ping/Pong, CloseWrite Half-Close)
// =============================================================================

func runTier1F16(t *testing.T) {
	key := GenerateRandomKeyBase64(t)

	t.Run("T1-F16-01", func(t *testing.T) {
		echo := StartTCPEchoServer(t)
		topo := t1StartTopology(t, TopologyConfig{ServerKey: key, ClientKey: key})
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		conn, err := topo.DialSOCKS5(ctx, echo.Addr())
		require.NoError(t, err)
		defer func() { _ = conn.Close() }()
		for i, sz := range []int{1, 17, 1024, 16384, 65536} {
			t1DialAndEchoConn(t, conn, DeterministicBytes(uint64(16010+i), sz))
		}
	})

	t.Run("T1-F16-02", func(t *testing.T) {
		// Client Box reads interleaved 0-len chaff FrameData from SpecMockServer.
		mockSrv := StartSpecMockServer(t, SpecServerOptions{
			Key: key,
			OnSession: func(sess *SpecServerSession) {
				if len(sess.VarHeader.InitialPayload) == 0 {
					if _, err := sess.ReadC2SFrame(5 * time.Second); err != nil {
						return
					}
				}
				_ = sess.WriteS2CFrame(SpecFrameData, 48, []byte("hello"))
				for i := 0; i < 5; i++ {
					_ = sess.WriteS2CFrame(SpecFrameData, byte(48+i*16), nil)
				}
				_ = sess.WriteS2CFrame(SpecFrameData, 64, []byte("world"))
				_ = sess.WriteS2CFrame(SpecFrameCloseWrite, 0, nil)
			},
		})
		cliPort := AllocFreeTCPPort(t)
		cliJSON, err := BuildClientJSON(TopologyConfig{ClientKey: key}, cliPort, "127.0.0.1", mockSrv.Port(), 0, "")
		require.NoError(t, err)
		cliBox, err := StartBox(t, cliJSON)
		require.NoError(t, err)
		t.Cleanup(func() { _ = cliBox.Close() })

		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		c, err := DialSOCKS5TCP(ctx, fmt.Sprintf("127.0.0.1:%d", cliPort), "127.0.0.1:80")
		require.NoError(t, err)
		defer func() { _ = c.Close() }()
		_, err = c.Write([]byte("trigger"))
		require.NoError(t, err)
		got, err := io.ReadAll(c)
		require.NoError(t, err)
		require.Equal(t, []byte("helloworld"), got)

		// Also verify Server Box skips client chaff frames seamlessly.
		echo := StartTCPEchoServer(t)
		srvTopo := t1StartTopology(t, TopologyConfig{ServerKey: key, ClientKey: key, DisableWireTap: true})
		sc, err := DialSpecClient(context.Background(), srvTopo.ServerAddr(), SpecDialOptions{
			Key:            key,
			TargetAddr:     echo.Addr(),
			InitialPayload: []byte("hello"),
		})
		require.NoError(t, err)
		defer func() { _ = sc.Close() }()
		_, err = sc.ReadServerResp(5 * time.Second)
		require.NoError(t, err)
		require.NoError(t, sc.SendChaff(5, 64))
		require.NoError(t, sc.WriteFrame(SpecFrameData, 32, []byte("world")))
		var recvBuf bytes.Buffer
		for recvBuf.Len() < len("helloworld") {
			fr, err := sc.ReadFrame(5 * time.Second)
			require.NoError(t, err)
			if fr.FrameType == SpecFrameData {
				recvBuf.Write(fr.Data)
			}
		}
		require.Equal(t, "helloworld", recvBuf.String())
	})

	t.Run("T1-F16-03", func(t *testing.T) {
		stalled := StartStalledTCPServer(t)
		topo := t1StartTopology(t, TopologyConfig{ServerKey: key, ClientKey: key, DisableWireTap: true})
		defer stalled.Release()
		sc, err := DialSpecClient(context.Background(), topo.ServerAddr(), SpecDialOptions{
			Key:        key,
			TargetAddr: stalled.Addr(),
		})
		require.NoError(t, err)
		defer func() { _ = sc.Close() }()
		_, err = sc.ReadServerResp(5 * time.Second)
		require.NoError(t, err)
		require.NoError(t, sc.SendPing(80))

		for {
			fr, err := sc.ReadFrame(5 * time.Second)
			require.NoError(t, err)
			if fr.FrameType == SpecFramePong {
				require.GreaterOrEqual(t, int(fr.PadLen), 32)
				require.LessOrEqual(t, int(fr.PadLen), 224)
				require.Empty(t, fr.Data)
				break
			}
		}
	})

	t.Run("T1-F16-04", func(t *testing.T) {
		trailer := DeterministicBytes(1604, 64*1024)
		hcTarget := StartTCPHalfCloseServer(t, trailer)
		topo := t1StartTopology(t, TopologyConfig{ServerKey: key, ClientKey: key, DisableWireTap: true})
		out, ok := topo.Client.Box.Outbound().Outbound("aether-out")
		require.True(t, ok)

		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		conn, err := out.DialContext(ctx, N.NetworkTCP, M.ParseSocksaddr(hcTarget.Addr()))
		require.NoError(t, err)
		defer func() { _ = conn.Close() }()
		wc, ok := conn.(N.WriteCloser)
		require.True(t, ok)

		_, err = conn.Write([]byte("REQ"))
		require.NoError(t, err)
		require.NoError(t, wc.CloseWrite())

		got, err := io.ReadAll(conn)
		require.NoError(t, err)
		require.Equal(t, trailer, got)
		require.True(t, hcTarget.EOFObserved.Load())
		require.Equal(t, int64(len("REQ")), hcTarget.ReceivedLen.Load())
		require.Equal(t, sha256.Sum256([]byte("REQ")), hcTarget.ReceivedHash)
	})

	t.Run("T1-F16-05", func(t *testing.T) {
		const banner = "BANNER\n"
		const upLen = 64 * 1024
		upExpected := DeterministicBytes(1605, upLen)

		ln, err := net.Listen("tcp", "127.0.0.1:0")
		require.NoError(t, err)
		t.Cleanup(func() { _ = ln.Close() })

		srvDone := make(chan error, 1)
		go func() {
			c, aerr := ln.Accept()
			if aerr != nil {
				srvDone <- aerr
				return
			}
			defer func() { _ = c.Close() }()
			if _, werr := c.Write([]byte(banner)); werr != nil {
				srvDone <- werr
				return
			}
			if tc, ok := c.(*net.TCPConn); ok {
				if cerr := tc.CloseWrite(); cerr != nil {
					srvDone <- cerr
					return
				}
			}
			gotUp, rerr := io.ReadAll(c)
			if rerr != nil {
				srvDone <- rerr
				return
			}
			if !bytes.Equal(upExpected, gotUp) {
				srvDone <- fmt.Errorf("uplink mismatch len=%d", len(gotUp))
				return
			}
			srvDone <- nil
		}()

		topo := t1StartTopology(t, TopologyConfig{ServerKey: key, ClientKey: key, DisableWireTap: true})
		out, ok := topo.Client.Box.Outbound().Outbound("aether-out")
		require.True(t, ok)
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		conn, err := out.DialContext(ctx, N.NetworkTCP, M.ParseSocksaddr(ln.Addr().String()))
		require.NoError(t, err)
		defer func() { _ = conn.Close() }()

		// Trigger 0-RTT dial so server sends banner then half-closes S2C direction.
		_, err = conn.Write(upExpected[:512])
		require.NoError(t, err)
		gotBanner, err := io.ReadAll(conn)
		require.NoError(t, err)
		require.Equal(t, banner, string(gotBanner))

		// Downlink already received FrameCloseWrite + EOF; uplink remains open!
		_, err = conn.Write(upExpected[512:])
		require.NoError(t, err)
		require.NoError(t, conn.(N.WriteCloser).CloseWrite())
		require.NoError(t, <-srvDone)
	})
}

// =============================================================================
// F17: Native UDP Proxy (CommandUDP = 0x02)
// =============================================================================

func runTier1F17(t *testing.T) {
	key := GenerateRandomKeyBase64(t)

	t.Run("T1-F17-01", func(t *testing.T) {
		udpEcho := StartUDPEchoServer(t)
		topo := t1StartTopology(t, TopologyConfig{ServerKey: key, ClientKey: key})
		out, ok := topo.Client.Box.Outbound().Outbound("aether-out")
		require.True(t, ok)

		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		conn, err := out.DialContext(ctx, N.NetworkUDP, M.ParseSocksaddr(udpEcho.Addr()))
		require.NoError(t, err)
		defer func() { _ = conn.Close() }()

		for i := 0; i < 20; i++ {
			sz := 64 + (i * 68)
			p := DeterministicBytes(uint64(17010+i), sz)
			t1DialAndEchoConn(t, conn, p)
		}
		sess := topo.Tap.WaitForSessions(t, 1, 5*time.Second)[0]
		insp, err := SpecInspectClientBurst(sess.Bytes(DirC2S), "", key, nil, "")
		require.NoError(t, err)
		require.Equal(t, SpecCommandUDP, insp.FixedHeader.Command)
	})

	t.Run("T1-F17-02", func(t *testing.T) {
		fc := StartFullConeUDPTargets(t)
		topo := t1StartTopology(t, TopologyConfig{ServerKey: key, ClientKey: key, DisableWireTap: true})
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		uconn, err := topo.OpenSOCKS5UDP(ctx)
		require.NoError(t, err)
		defer func() { _ = uconn.Close() }()
		require.NoError(t, uconn.SetDeadline(time.Now().Add(10*time.Second)))

		peers := []*UDPEchoTarget{fc.PeerA, fc.PeerB, fc.PeerC}
		bufRead := make([]byte, 2048)
		for idx, peer := range peers {
			msg := []byte(fmt.Sprintf("fullcone-peer-%d", idx))
			require.NoError(t, uconn.WriteToHostPort(msg, peer.Addr()))
			n, src, err := uconn.ReadFromHostPort(bufRead)
			require.NoError(t, err)
			require.Equal(t, msg, bufRead[:n])
			require.Equal(t, peer.Port(), M.ParseSocksaddr(src).Port)
		}
	})

	t.Run("T1-F17-03", func(t *testing.T) {
		udp6 := StartUDPEchoTargetOn(t, "udp6", "[::1]:0")
		topo := t1StartTopology(t, TopologyConfig{ServerKey: key, ClientKey: key, DisableWireTap: true})
		t1UDPEcho(t, topo, udp6.Addr(), DeterministicBytes(1703, 512))
	})

	t.Run("T1-F17-04", func(t *testing.T) {
		udpEcho := StartUDPEchoServer(t)
		topo := t1StartTopology(t, TopologyConfig{ServerKey: key, ClientKey: key, DisableWireTap: true})
		out, ok := topo.Client.Box.Outbound().Outbound("aether-out")
		require.True(t, ok)
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		rawPConn, err := out.ListenPacket(ctx, M.ParseSocksaddrHostPort("localhost", udpEcho.Port()))
		require.NoError(t, err)
		defer func() { _ = rawPConn.Close() }()
		pconn, ok := rawPConn.(N.PacketConn)
		require.True(t, ok)

		msg := DeterministicBytes(1704, 400)
		b := buf.NewPacket()
		_, err = b.Write(msg)
		require.NoError(t, err)
		require.NoError(t, pconn.WritePacket(b, M.ParseSocksaddrHostPort("localhost", udpEcho.Port())))

		rb := buf.NewPacket()
		defer rb.Release()
		_, err = pconn.ReadPacket(rb)
		require.NoError(t, err)
		require.Equal(t, msg, rb.Bytes())
	})

	t.Run("T1-F17-05", func(t *testing.T) {
		// Exercise 32768B (> 16384B single frame) multi-frame datagram via SpecMockServer tunnel
		// cleanly on both Darwin (where OS raw UDP caps at 9216B) and Linux.
		mockSrv := StartSpecMockServer(t, SpecServerOptions{Key: key})
		cliPort := AllocFreeTCPPort(t)
		cliJSON, err := BuildClientJSON(TopologyConfig{ClientKey: key}, cliPort, "127.0.0.1", mockSrv.Port(), 0, "")
		require.NoError(t, err)
		cliBox, err := StartBox(t, cliJSON)
		require.NoError(t, err)
		t.Cleanup(func() { _ = cliBox.Close() })

		out, ok := cliBox.Box.Outbound().Outbound("aether-out")
		require.True(t, ok)
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		dst := M.ParseSocksaddr("127.0.0.1:9999")
		rawPConn, err := out.ListenPacket(ctx, dst)
		require.NoError(t, err)
		defer func() { _ = rawPConn.Close() }()
		pconn, ok := rawPConn.(N.PacketConn)
		require.True(t, ok)

		const dgramSize = 32768
		large := DeterministicBytes(1705, dgramSize)
		wb := buf.NewSize(dgramSize + 64)
		_, err = wb.Write(large)
		require.NoError(t, err)
		require.NoError(t, pconn.WritePacket(wb, dst))

		rb := buf.NewSize(dgramSize + 1024)
		defer rb.Release()
		_, err = pconn.ReadPacket(rb)
		require.NoError(t, err)
		require.Equal(t, large, rb.Bytes())

		if runtime.GOOS != "darwin" {
			// On Linux / non-9216-capped OS, also verify full BoxPair end-to-end 32768B OS UDP echo.
			// Send a small warm-up datagram on the SOCKS5 UDP association first because upstream
			// sagernet/sing/protocol/socks/handshake.go reads packet #1 into a fixed 16 KiB buf.NewPacket()
			// before handing off subsequent packets to bufio.CopyPacket with CalculateMTU().
			udpEcho := StartUDPEchoServer(t)
			topo := t1StartTopology(t, TopologyConfig{ServerKey: key, ClientKey: key, DisableWireTap: true})
			s5Ctx, s5Cancel := context.WithTimeout(context.Background(), 12*time.Second)
			defer s5Cancel()
			uconn, uerr := topo.OpenSOCKS5UDP(s5Ctx)
			require.NoError(t, uerr)
			defer func() { _ = uconn.Close() }()
			require.NoError(t, uconn.SetDeadline(time.Now().Add(8*time.Second)))

			warmup := []byte("socks5-udp-warmup")
			require.NoError(t, uconn.WriteToHostPort(warmup, udpEcho.Addr()))
			warmBuf := make([]byte, 4096)
			wn, _, werr := uconn.ReadFromHostPort(warmBuf)
			require.NoError(t, werr)
			require.Equal(t, warmup, warmBuf[:wn])

			require.NoError(t, uconn.WriteToHostPort(large, udpEcho.Addr()))
			bufRead := make([]byte, len(large)+512)
			ln, _, lerr := uconn.ReadFromHostPort(bufRead)
			require.NoError(t, lerr)
			require.Equal(t, large, bufRead[:ln])
		}
	})
}

// =============================================================================
// F18: Timestamp Validation, Dual-Gen Sliding Bloom Filter & NTP
// =============================================================================

func runTier1F18(t *testing.T) {
	key := GenerateRandomKeyBase64(t)

	t.Run("T1-F18-01", func(t *testing.T) {
		const total = 300
		echo := StartTCPEchoServer(t)
		topo := t1StartTopology(t, TopologyConfig{
			ServerKey:               key,
			ClientKey:               key,
			DisableWireTap:          true,
			ServerHeartbeatInterval: "-1s", ClientHeartbeatInterval: "-1s",
		})

		jobs := make(chan int, total)
		for i := 0; i < total; i++ {
			jobs <- i
		}
		close(jobs)

		var errMu sync.Mutex
		var firstErr error
		var wg sync.WaitGroup
		for w := 0; w < t1DefaultBoundedWorkers; w++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for i := range jobs {
					ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
					c, err := topo.DialSOCKS5(ctx, echo.Addr())
					cancel()
					if err != nil {
						errMu.Lock()
						if firstErr == nil {
							firstErr = err
						}
						errMu.Unlock()
						return
					}
					msg := []byte{byte(i), byte(i >> 8), 'b', 'l', 'm'}
					_ = c.SetDeadline(time.Now().Add(6 * time.Second))
					_, werr := c.Write(msg)
					got := make([]byte, len(msg))
					_, rerr := io.ReadFull(c, got)
					_ = c.Close()
					if werr != nil || rerr != nil || !bytes.Equal(msg, got) {
						errMu.Lock()
						if firstErr == nil {
							firstErr = fmt.Errorf("i=%d werr=%v rerr=%v", i, werr, rerr)
						}
						errMu.Unlock()
						return
					}
				}
			}()
		}
		wg.Wait()
		require.NoError(t, firstErr)
		require.Equal(t, int64(total), echo.Connections())
	})

	t.Run("T1-F18-02", func(t *testing.T) {
		srvTS := NewFrozenMockTimeService(time.Now())
		cliTS := NewFrozenMockTimeService(srvTS.Now().Add(15 * time.Second))
		echo := StartTCPEchoServer(t)
		topo := t1StartTopology(t, TopologyConfig{
			ServerKey:         key,
			ClientKey:         key,
			ServerTimeService: srvTS,
			ClientTimeService: cliTS,
			DisableWireTap:    true,
		})
		t1TCPEcho(t, topo, echo.Addr(), []byte("skew-+15s-ok"))

		cliTS.Freeze(srvTS.Now().Add(-15 * time.Second))
		t1TCPEcho(t, topo, echo.Addr(), []byte("skew--15s-ok"))
	})

	t.Run("T1-F18-03", func(t *testing.T) {
		srvTS := NewFrozenMockTimeService(time.Now())
		cliTS := NewFrozenMockTimeService(srvTS.Now().Add(45 * time.Second))
		echo := StartTCPEchoServer(t)
		topo := t1StartTopology(t, TopologyConfig{
			ServerKey:         key,
			ClientKey:         key,
			ServerTimeWindow:  "60s",
			ServerTimeService: srvTS,
			ClientTimeService: cliTS,
			DisableWireTap:    true,
		})
		t1TCPEcho(t, topo, echo.Addr(), []byte("skew-+45s-custom-60s"))
	})

	t.Run("T1-F18-04", func(t *testing.T) {
		// Server uses frozen +45s MockTimeService; Client uses REAL JSON "ntp" synced +45s.
		// Handshake only passes within ±30s window if JSON ntp calibration actually overrides OS clock.
		srvTS := NewFrozenMockTimeService(time.Now().Add(45 * time.Second))
		cliOffset := 45 * time.Second
		echo := StartTCPEchoServer(t)
		topo := t1StartTopology(t, TopologyConfig{
			ServerKey:         key,
			ClientKey:         key,
			ServerTimeService: srvTS,
			ClientClockOffset: &cliOffset,
			DisableWireTap:    true,
		})
		t1WaitNTPSynced(t, topo, 5*time.Second)
		t1TCPEcho(t, topo, echo.Addr(), []byte("real-ntp-synced"))

		// Also verify symmetric SNTP on both Client & Server Box instances.
		bothOffset := 12 * time.Second
		topoBoth := t1StartTopology(t, TopologyConfig{
			ServerKey:         key,
			ClientKey:         key,
			ServerClockOffset: &bothOffset,
			ClientClockOffset: &bothOffset,
			DisableWireTap:    true,
		})
		t1WaitNTPSynced(t, topoBoth, 5*time.Second)
		t1TCPEcho(t, topoBoth, echo.Addr(), []byte("both-ntp-synced"))
	})

	t.Run("T1-F18-05", func(t *testing.T) {
		t0 := time.Now()
		srvTS := NewFrozenMockTimeService(t0)
		cliTS := NewFrozenMockTimeService(t0)
		echo := StartTCPEchoServer(t)
		topo := t1StartTopology(t, TopologyConfig{
			ServerKey:               key,
			ClientKey:               key,
			ServerTimeService:       srvTS,
			ClientTimeService:       cliTS,
			DisableWireTap:          true,
			ServerHeartbeatInterval: "-1s", ClientHeartbeatInterval: "-1s",
		})

		runWave := func(wave string, n int) {
			for i := 0; i < n; i++ {
				t1TCPEcho(t, topo, echo.Addr(), []byte(fmt.Sprintf("%s-%d", wave, i)))
			}
		}
		runWave("t0", 25)
		srvTS.Advance(35 * time.Second)
		cliTS.Advance(35 * time.Second)
		runWave("t35", 25)
		srvTS.Advance(30 * time.Second)
		cliTS.Advance(30 * time.Second)
		runWave("t65", 25)
		require.Equal(t, int64(75), echo.Connections())
	})
}

// =============================================================================
// F19: StealthDrain Anti-Probing, Handshake Semaphores & Security Logging
// =============================================================================

func runTier1F19(t *testing.T) {
	key := GenerateRandomKeyBase64(t)

	t.Run("T1-F19-01", func(t *testing.T) {
		const total = 64
		echo := StartTCPEchoServer(t)
		topo := t1StartTopology(t, TopologyConfig{
			ServerKey:               key,
			ClientKey:               key,
			DisableWireTap:          true,
			ServerHeartbeatInterval: "-1s", ClientHeartbeatInterval: "-1s",
		})

		startGate := make(chan struct{})
		errs := make(chan error, total)
		var wg sync.WaitGroup
		for i := 0; i < total; i++ {
			wg.Add(1)
			go func(idx int) {
				defer wg.Done()
				<-startGate
				ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
				defer cancel()
				c, err := topo.DialSOCKS5(ctx, echo.Addr())
				if err != nil {
					errs <- err
					return
				}
				defer func() { _ = c.Close() }()
				msg := DeterministicBytes(uint64(19010+idx), 256)
				_ = c.SetDeadline(time.Now().Add(8 * time.Second))
				if _, err := c.Write(msg); err != nil {
					errs <- err
					return
				}
				got := make([]byte, len(msg))
				if _, err := io.ReadFull(c, got); err != nil || !bytes.Equal(msg, got) {
					errs <- fmt.Errorf("idx=%d err=%v match=%v", idx, err, bytes.Equal(msg, got))
				}
			}(i)
		}
		close(startGate)
		wg.Wait()
		close(errs)
		for err := range errs {
			require.NoError(t, err)
		}
		require.Equal(t, int64(total), echo.Connections())
	})

	t.Run("T1-F19-02", func(t *testing.T) {
		topo := t1StartTopology(t, TopologyConfig{
			ServerKey:              key,
			ClientKey:              key,
			ServerHandshakeTimeout: "15s",
			DisableWireTap:         true,
		})
		probe := DeterministicBytes(1902, SpecClientPrefixNoEIHSize)
		res, err := SendRawProbe(topo.ServerAddr(), probe, false, 13*time.Second)
		require.NoError(t, err)
		require.Empty(t, res.BytesReceived)
		require.True(t, res.ClosedCleanEOF, "expected normal TCP FIN, err=%v rst=%v", res.Err, res.ClosedByRST)
		require.False(t, res.ClosedByRST)
		require.GreaterOrEqual(t, res.Elapsed, 2850*time.Millisecond)
		require.LessOrEqual(t, res.Elapsed, 10800*time.Millisecond)
	})

	t.Run("T1-F19-03", func(t *testing.T) {
		topo := t1StartTopology(t, TopologyConfig{
			ServerKey:              key,
			ClientKey:              key,
			ServerHandshakeTimeout: "15s",
			DisableWireTap:         true,
		})
		const k = 12
		results := make([]ProbeResult, k)
		errs := make([]error, k)
		var wg sync.WaitGroup
		for i := 0; i < k; i++ {
			wg.Add(1)
			go func(idx int) {
				defer wg.Done()
				p := DeterministicBytes(uint64(19030+idx), SpecClientPrefixNoEIHSize)
				results[idx], errs[idx] = SendRawProbe(topo.ServerAddr(), p, false, 13*time.Second)
			}(i)
		}
		wg.Wait()

		minEl := time.Hour
		var maxEl time.Duration
		for i := 0; i < k; i++ {
			require.NoError(t, errs[i])
			res := results[i]
			require.Empty(t, res.BytesReceived)
			require.True(t, res.ClosedCleanEOF, "probe %d not FIN: rst=%v err=%v", i, res.ClosedByRST, res.Err)
			require.False(t, res.ClosedByRST)
			require.GreaterOrEqual(t, res.Elapsed, 2850*time.Millisecond)
			require.LessOrEqual(t, res.Elapsed, 10800*time.Millisecond)
			if res.Elapsed < minEl {
				minEl = res.Elapsed
			}
			if res.Elapsed > maxEl {
				maxEl = res.Elapsed
			}
		}
		require.GreaterOrEqual(t, maxEl-minEl, 1000*time.Millisecond)
	})

	t.Run("T1-F19-04", func(t *testing.T) {
		echo := StartTCPEchoServer(t)
		topo := t1StartTopology(t, TopologyConfig{
			ServerKey:              key,
			ClientKey:              key,
			ServerHandshakeTimeout: "800ms",
			DisableWireTap:         true,
		})

		tValid := time.Now()
		t1TCPEcho(t, topo, echo.Addr(), []byte("fast-valid-client"))
		require.Less(t, time.Since(tValid), 2*time.Second)

		// 0B slowloris client triggers configurable 800ms handshake_timeout quickly (< 3s, well under default 6s).
		res, err := SendRawProbe(topo.ServerAddr(), nil, false, 4*time.Second)
		require.NoError(t, err)
		require.Empty(t, res.BytesReceived)
		require.True(t, res.ClosedCleanEOF)
		require.False(t, res.ClosedByRST)
		require.GreaterOrEqual(t, res.Elapsed, 650*time.Millisecond)
		require.Less(t, res.Elapsed, 3500*time.Millisecond)
	})

	t.Run("T1-F19-05", func(t *testing.T) {
		topo := t1StartTopology(t, TopologyConfig{
			ServerKey:              key,
			ClientKey:              key,
			ServerHandshakeTimeout: "500ms",
			ServerLogLevel:         "warn",
			CaptureLogs:            true,
			DisableWireTap:         true,
		})
		wrongKey := GenerateRandomKeyBase64(t)
		const nProbes = 50
		var wg sync.WaitGroup
		sem := make(chan struct{}, 25)
		for i := 0; i < nProbes; i++ {
			wg.Add(1)
			go func(idx int) {
				defer wg.Done()
				sem <- struct{}{}
				defer func() { <-sem }()
				// Send a wrong-key initial burst in short bursts; halfCloseWrite=false lets StealthDrain complete cleanly.
				burst, _, berr := BuildSpecClientInitialBurst(SpecDialOptions{
					Key:        wrongKey,
					TargetAddr: "127.0.0.1:80",
				})
				if berr == nil {
					_, _ = SendRawProbe(topo.ServerAddr(), burst, false, 12*time.Second)
				}
			}(i)
		}
		wg.Wait()

		logs := topo.Server.ReadLogs()
		var warnLines int
		for _, line := range strings.Split(logs, "\n") {
			if strings.Contains(line, "127.0.0.1") && (strings.Contains(strings.ToUpper(line), "WARN") || strings.Contains(strings.ToLower(line), "auth_failed") || strings.Contains(strings.ToLower(line), "stealth")) {
				warnLines++
			}
		}
		require.GreaterOrEqual(t, warnLines, 1, "expected rate-limited warning in server logs:\n%s", logs)
		require.Less(t, warnLines, nProbes, "expected rate-limiting (<50 lines) in server logs:\n%s", logs)
	})
}

// =============================================================================
// F20: Deadlock-Free Control Plane Coordinator (pongCh cap=1 & R-1)
// =============================================================================

func runTier1F20(t *testing.T) {
	key := GenerateRandomKeyBase64(t)

	t.Run("T1-F20-01", func(t *testing.T) {
		echo := StartTCPEchoServer(t)
		topo := t1StartTopology(t, TopologyConfig{
			ServerKey:               key,
			ClientKey:               key,
			ServerHeartbeatInterval: "200ms", ClientHeartbeatInterval: "200ms",
			DisableWireTap: true,
		})

		const each = 1024 * 1024
		var wg sync.WaitGroup
		errs := make(chan error, 2)
		for s := 0; s < 2; s++ {
			wg.Add(1)
			go func(idx int) {
				defer wg.Done()
				ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
				defer cancel()
				c, err := topo.DialSOCKS5(ctx, echo.Addr())
				if err != nil {
					errs <- err
					return
				}
				defer func() { _ = c.Close() }()
				p := DeterministicBytes(uint64(20010+idx), each)
				werrCh := make(chan error, 1)
				go func() {
					_, werr := c.Write(p)
					if werr == nil {
						_ = c.CloseWrite()
					}
					werrCh <- werr
				}()
				got, rerr := io.ReadAll(c)
				if rerr != nil {
					errs <- rerr
					return
				}
				if werr := <-werrCh; werr != nil {
					errs <- werr
					return
				}
				if sha256.Sum256(p) != sha256.Sum256(got) {
					errs <- errors.New("sha256 mismatch")
				}
			}(s)
		}
		wg.Wait()
		close(errs)
		for err := range errs {
			require.NoError(t, err)
		}
	})

	t.Run("T1-F20-02", func(t *testing.T) {
		echo := StartTCPEchoServer(t)
		topo := t1StartTopology(t, TopologyConfig{
			ServerKey:               key,
			ClientKey:               key,
			ServerHeartbeatInterval: "150ms", ClientHeartbeatInterval: "150ms",
			WireTapWindowSize: 8192,
		})
		topo.Tap.SetThrottle(500*time.Microsecond, 16384)

		const size = 256 * 1024
		payload := DeterministicBytes(2002, size)
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		c, err := topo.DialSOCKS5(ctx, echo.Addr())
		require.NoError(t, err)
		defer func() { _ = c.Close() }()

		require.NoError(t, c.SetDeadline(time.Now().Add(30*time.Second)))
		defer func() { _ = c.SetDeadline(time.Time{}) }()
		wErrCh := make(chan error, 1)
		go func() {
			_, wErr := c.Write(payload)
			wErrCh <- wErr
		}()
		got := make([]byte, len(payload))
		_, rErr := io.ReadFull(c, got)
		require.NoError(t, rErr)
		require.NoError(t, <-wErrCh)
		require.Equal(t, payload, got)
	})

	t.Run("T1-F20-03", func(t *testing.T) {
		echo := StartTCPEchoServer(t)
		topo := t1StartTopology(t, TopologyConfig{
			ServerKey:               key,
			ClientKey:               key,
			ServerHeartbeatInterval: "-1s", ClientHeartbeatInterval: "-1s",
			DisableWireTap: true,
		})
		sc, err := DialSpecClient(context.Background(), topo.ServerAddr(), SpecDialOptions{
			Key:        key,
			TargetAddr: echo.Addr(),
		})
		require.NoError(t, err)
		defer func() { _ = sc.Close() }()

		_, err = sc.ReadServerResp(5 * time.Second)
		require.NoError(t, err)
		for i := 0; i < 20; i++ {
			require.NoError(t, sc.SendPing(48))
		}

		require.NoError(t, sc.WriteFrame(SpecFrameData, 0, []byte("after-20-pings")))
		gotData := false
		sawPong := false
		for !gotData || !sawPong {
			fr, err := sc.ReadFrame(5 * time.Second)
			require.NoError(t, err)
			switch fr.FrameType {
			case SpecFramePong:
				sawPong = true
			case SpecFrameData:
				if len(fr.Data) == 0 {
					continue
				}
				require.Equal(t, []byte("after-20-pings"), fr.Data)
				gotData = true
			}
		}
		require.True(t, sawPong)
	})

	t.Run("T1-F20-04", func(t *testing.T) {
		echo := StartTCPEchoServer(t)
		topo := t1StartTopology(t, TopologyConfig{
			ServerKey:               key,
			ClientKey:               key,
			ServerHeartbeatInterval: "200ms", ClientHeartbeatInterval: "200ms",
			ServerMultiplex: &MultiplexServerSpec{Enabled: true},
			ClientMultiplex: &MultiplexClientSpec{Enabled: true, Protocol: "smux", MaxConnections: 2},
			DisableWireTap:  true,
		})

		const streams = 16
		const sz = 64 * 1024
		var wg sync.WaitGroup
		errs := make(chan error, streams)
		for i := 0; i < streams; i++ {
			wg.Add(1)
			go func(idx int) {
				defer wg.Done()
				ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
				defer cancel()
				c, err := topo.DialSOCKS5(ctx, echo.Addr())
				if err != nil {
					errs <- err
					return
				}
				defer func() { _ = c.Close() }()
				p := DeterministicBytes(uint64(20040+idx), sz)
				_ = c.SetDeadline(time.Now().Add(15 * time.Second))
				if _, err := c.Write(p); err != nil {
					errs <- err
					return
				}
				got := make([]byte, sz)
				if _, err := io.ReadFull(c, got); err != nil || sha256.Sum256(p) != sha256.Sum256(got) {
					errs <- fmt.Errorf("stream %d failed: %v", idx, err)
				}
			}(i)
		}
		wg.Wait()
		close(errs)
		for err := range errs {
			require.NoError(t, err)
		}
	})

	t.Run("T1-F20-05", func(t *testing.T) {
		// Server-initiated pings into Client Box under active transfer.
		mockSrv := StartSpecMockServer(t, SpecServerOptions{
			Key: key,
			OnSession: func(sess *SpecServerSession) {
				if len(sess.VarHeader.InitialPayload) > 0 {
					for i := 0; i < 4; i++ {
						if err := sess.WriteS2CFrame(SpecFramePing, 48, nil); err != nil {
							return
						}
					}
					if err := sess.WriteS2CFrame(SpecFrameData, 0, sess.VarHeader.InitialPayload); err != nil {
						return
					}
				}
				for {
					fr, err := sess.ReadC2SFrame(5 * time.Second)
					if err != nil {
						return
					}
					if fr.FrameType == SpecFrameData && len(fr.Data) > 0 {
						for i := 0; i < 4; i++ {
							if err := sess.WriteS2CFrame(SpecFramePing, 48, nil); err != nil {
								return
							}
						}
						if err := sess.WriteS2CFrame(SpecFrameData, 0, fr.Data); err != nil {
							return
						}
					}
				}
			},
		})
		cliPort := AllocFreeTCPPort(t)
		cliJSON, err := BuildClientJSON(TopologyConfig{
			ClientKey:               key,
			ServerHeartbeatInterval: "-1s", ClientHeartbeatInterval: "-1s",
		}, cliPort, "127.0.0.1", mockSrv.Port(), 0, "")
		require.NoError(t, err)
		cliBox, err := StartBox(t, cliJSON)
		require.NoError(t, err)
		t.Cleanup(func() { _ = cliBox.Close() })

		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		c, err := DialSOCKS5TCP(ctx, fmt.Sprintf("127.0.0.1:%d", cliPort), "127.0.0.1:80")
		require.NoError(t, err)
		defer func() { _ = c.Close() }()
		for round := 0; round < 3; round++ {
			t1DialAndEchoConn(t, c, DeterministicBytes(uint64(20050+round), 512))
		}
	})
}

// =============================================================================
// F21: Thread Safety, Scoped Deadlines & Atomic Error Fuse (R-2)
// =============================================================================

func runTier1F21(t *testing.T) {
	key := GenerateRandomKeyBase64(t)

	t.Run("T1-F21-01", func(t *testing.T) {
		echo := StartTCPEchoServer(t)
		topo := t1StartTopology(t, TopologyConfig{
			ServerKey:               key,
			ClientKey:               key,
			ServerHeartbeatInterval: "200ms", ClientHeartbeatInterval: "200ms",
			DisableWireTap: true,
		})
		out, ok := topo.Client.Box.Outbound().Outbound("aether-out")
		require.True(t, ok)

		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		conn, err := out.DialContext(ctx, N.NetworkTCP, M.ParseSocksaddr(echo.Addr()))
		require.NoError(t, err)
		defer func() { _ = conn.Close() }()

		require.NoError(t, conn.SetWriteDeadline(time.Now().Add(5*time.Second)))
		p := DeterministicBytes(2101, 64*1024)
		_, err = conn.Write(p)
		require.NoError(t, err)
		got := make([]byte, len(p))
		_, err = io.ReadFull(conn, got)
		require.NoError(t, err)
		require.Equal(t, p, got)
		require.NoError(t, conn.SetWriteDeadline(time.Time{}))

		time.Sleep(350 * time.Millisecond)
		t1DialAndEchoConn(t, conn, DeterministicBytes(21012, 4096))
	})

	t.Run("T1-F21-02", func(t *testing.T) {
		echo := StartTCPEchoServer(t)
		topo := t1StartTopology(t, TopologyConfig{
			ServerKey:               key,
			ClientKey:               key,
			ServerHeartbeatInterval: "-1s", ClientHeartbeatInterval: "-1s",
			DisableWireTap: true,
		})
		out, ok := topo.Client.Box.Outbound().Outbound("aether-out")
		require.True(t, ok)

		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		conn, err := out.DialContext(ctx, N.NetworkTCP, M.ParseSocksaddr(echo.Addr()))
		require.NoError(t, err)
		defer func() { _ = conn.Close() }()

		t1DialAndEchoConn(t, conn, []byte("warmup-before-timeout"))

		require.NoError(t, conn.SetReadDeadline(time.Now().Add(40*time.Millisecond)))
		var tmp [32]byte
		_, err = conn.Read(tmp[:])
		require.Error(t, err)
		require.ErrorIs(t, err, os.ErrDeadlineExceeded)

		require.NoError(t, conn.SetReadDeadline(time.Time{}))
		t1DialAndEchoConn(t, conn, DeterministicBytes(2102, 4096))
	})

	t.Run("T1-F21-03", func(t *testing.T) {
		echo := StartTCPEchoServer(t)
		topo := t1StartTopology(t, TopologyConfig{
			ServerKey:               key,
			ClientKey:               key,
			ServerHeartbeatInterval: "300ms", ClientHeartbeatInterval: "300ms",
			DisableWireTap: true,
		})
		out, ok := topo.Client.Box.Outbound().Outbound("aether-out")
		require.True(t, ok)

		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		conn, err := out.DialContext(ctx, N.NetworkTCP, M.ParseSocksaddr(echo.Addr()))
		require.NoError(t, err)
		defer func() { _ = conn.Close() }()

		t1DialAndEchoConn(t, conn, []byte("init"))
		for i := 0; i < 20; i++ {
			require.NoError(t, conn.SetWriteDeadline(time.Now().Add(40*time.Millisecond)))
			require.NoError(t, conn.SetWriteDeadline(time.Time{}))
		}
		time.Sleep(900 * time.Millisecond)
		t1DialAndEchoConn(t, conn, DeterministicBytes(2103, 4096))
	})

	t.Run("T1-F21-04", func(t *testing.T) {
		echo := StartTCPEchoServer(t)
		topo := t1StartTopology(t, TopologyConfig{
			ServerKey:               key,
			ClientKey:               key,
			ServerHeartbeatInterval: "1s", ClientHeartbeatInterval: "1s",
		})
		topo.Tap.SetAbortAfterBytes(DirC2S, 1024, true)

		ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
		defer cancel()
		c, err := topo.DialSOCKS5(ctx, echo.Addr())
		if err == nil {
			defer func() { _ = c.Close() }()
			_ = c.SetDeadline(time.Now().Add(4 * time.Second))
			payload := DeterministicBytes(2104, 16384)
			_, _ = c.Write(payload)
			bufRead := make([]byte, len(payload))
			_, rerr := io.ReadFull(c, bufRead)
			require.Error(t, rerr)
		}
	})

	t.Run("T1-F21-05", func(t *testing.T) {
		var recvTotal atomic.Int64
		pingStop := make(chan struct{})
		mockSrv := StartSpecMockServer(t, SpecServerOptions{
			Key: key,
			OnSession: func(sess *SpecServerSession) {
				if len(sess.VarHeader.InitialPayload) > 0 {
					recvTotal.Add(int64(len(sess.VarHeader.InitialPayload)))
					if err := sess.WriteS2CFrame(SpecFrameData, 0, sess.VarHeader.InitialPayload); err != nil {
						return
					}
				}
				go func() {
					ticker := time.NewTicker(50 * time.Millisecond)
					defer ticker.Stop()
					for {
						select {
						case <-pingStop:
							return
						case <-ticker.C:
							if err := sess.WriteS2CFrame(SpecFramePing, 40, nil); err != nil {
								return
							}
						}
					}
				}()
				for {
					fr, err := sess.ReadC2SFrame(8 * time.Second)
					if err != nil {
						return
					}
					if fr.FrameType == SpecFrameData && len(fr.Data) > 0 {
						recvTotal.Add(int64(len(fr.Data)))
						_ = sess.WriteS2CFrame(SpecFrameData, 0, fr.Data)
					}
				}
			},
		})
		defer close(pingStop)

		cliPort := AllocFreeTCPPort(t)
		cliJSON, err := BuildClientJSON(TopologyConfig{
			ClientKey:               key,
			ServerHeartbeatInterval: "200ms", ClientHeartbeatInterval: "200ms",
		}, cliPort, "127.0.0.1", mockSrv.Port(), 0, "")
		require.NoError(t, err)
		cliBox, err := StartBox(t, cliJSON)
		require.NoError(t, err)
		t.Cleanup(func() { _ = cliBox.Close() })

		out, ok := cliBox.Box.Outbound().Outbound("aether-out")
		require.True(t, ok)
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		conn, err := out.DialContext(ctx, N.NetworkTCP, M.ParseSocksaddr("127.0.0.1:8080"))
		require.NoError(t, err)
		defer func() { _ = conn.Close() }()

		const workers = 8
		const writesPerWorker = 16
		const chunkLen = 256
		const expectedBytes = workers * writesPerWorker * chunkLen

		var wg sync.WaitGroup
		writeErrs := make(chan error, workers)
		for w := 0; w < workers; w++ {
			wg.Add(1)
			go func(id int) {
				defer wg.Done()
				msg := DeterministicBytes(uint64(21050+id), chunkLen)
				for i := 0; i < writesPerWorker; i++ {
					if _, err := conn.Write(msg); err != nil {
						writeErrs <- err
						return
					}
				}
			}(w)
		}
		got := make([]byte, expectedBytes)
		_, rerr := io.ReadFull(conn, got)
		wg.Wait()
		close(writeErrs)
		require.NoError(t, rerr)
		for err := range writeErrs {
			require.NoError(t, err)
		}
		require.Equal(t, int64(expectedBytes), recvTotal.Load())
	})
}

// =============================================================================
// F22: Jittered Heartbeat & Last-Read Dead Peer Detection (R-3)
// =============================================================================

func runTier1F22(t *testing.T) {
	key := GenerateRandomKeyBase64(t)

	t.Run("T1-F22-01", func(t *testing.T) {
		var pingMu sync.Mutex
		var pingArrivals []time.Duration
		var baseTime atomic.Int64
		mockSrv := StartSpecMockServer(t, SpecServerOptions{
			Key: key,
			OnSession: func(sess *SpecServerSession) {
				if len(sess.VarHeader.InitialPayload) > 0 {
					if err := sess.WriteS2CFrame(SpecFrameData, 0, sess.VarHeader.InitialPayload); err != nil {
						return
					}
					baseTime.CompareAndSwap(0, time.Now().UnixNano())
				}
				for {
					fr, err := sess.ReadC2SFrame(5 * time.Second)
					if err != nil {
						return
					}
					switch fr.FrameType {
					case SpecFrameData:
						if len(fr.Data) > 0 {
							_ = sess.WriteS2CFrame(SpecFrameData, 0, fr.Data)
							baseTime.CompareAndSwap(0, time.Now().UnixNano())
						}
					case SpecFramePing:
						if bt := baseTime.Load(); bt > 0 {
							pingMu.Lock()
							pingArrivals = append(pingArrivals, time.Since(time.Unix(0, bt)))
							pingMu.Unlock()
						}
						_ = sess.WriteS2CFrame(SpecFramePong, 64, nil)
					}
				}
			},
		})
		cliPort := AllocFreeTCPPort(t)
		cliJSON, err := BuildClientJSON(TopologyConfig{
			ClientKey:               key,
			ServerHeartbeatInterval: "400ms", ClientHeartbeatInterval: "400ms",
		}, cliPort, "127.0.0.1", mockSrv.Port(), 0, "")
		require.NoError(t, err)
		cliBox, err := StartBox(t, cliJSON)
		require.NoError(t, err)
		t.Cleanup(func() { _ = cliBox.Close() })

		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		c, err := DialSOCKS5TCP(ctx, fmt.Sprintf("127.0.0.1:%d", cliPort), "127.0.0.1:80")
		require.NoError(t, err)
		defer func() { _ = c.Close() }()
		t1DialAndEchoConn(t, c, []byte("start-idle"))

		time.Sleep(1400 * time.Millisecond)
		pingMu.Lock()
		arrivals := slices.Clone(pingArrivals)
		pingMu.Unlock()
		require.NotEmpty(t, arrivals)
		// 400ms * [0.75, 1.25] = [300ms, 500ms] with small OS timer slack.
		require.GreaterOrEqual(t, arrivals[0], 260*time.Millisecond)
		require.LessOrEqual(t, arrivals[0], 600*time.Millisecond)
		t1DialAndEchoConn(t, c, []byte("still-alive"))
	})

	t.Run("T1-F22-02", func(t *testing.T) {
		var mu sync.Mutex
		var pingPads []byte
		mockSrv := StartSpecMockServer(t, SpecServerOptions{
			Key: key,
			OnSession: func(sess *SpecServerSession) {
				if len(sess.VarHeader.InitialPayload) > 0 {
					if err := sess.WriteS2CFrame(SpecFrameData, 0, sess.VarHeader.InitialPayload); err != nil {
						return
					}
				}
				for {
					fr, err := sess.ReadC2SFrame(5 * time.Second)
					if err != nil {
						return
					}
					switch fr.FrameType {
					case SpecFrameData:
						_ = sess.WriteS2CFrame(SpecFrameData, 0, fr.Data)
					case SpecFramePing:
						mu.Lock()
						pingPads = append(pingPads, fr.PadLen)
						mu.Unlock()
						_ = sess.WriteS2CFrame(SpecFramePong, byte(32+len(pingPads)*11), nil)
					}
				}
			},
		})
		cliPort := AllocFreeTCPPort(t)
		cliJSON, err := BuildClientJSON(TopologyConfig{
			ClientKey:               key,
			ServerHeartbeatInterval: "150ms", ClientHeartbeatInterval: "150ms",
		}, cliPort, "127.0.0.1", mockSrv.Port(), 0, "")
		require.NoError(t, err)
		cliBox, err := StartBox(t, cliJSON)
		require.NoError(t, err)
		t.Cleanup(func() { _ = cliBox.Close() })

		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		c, err := DialSOCKS5TCP(ctx, fmt.Sprintf("127.0.0.1:%d", cliPort), "127.0.0.1:80")
		require.NoError(t, err)
		defer func() { _ = c.Close() }()
		t1DialAndEchoConn(t, c, []byte("pad-audit"))

		deadline := time.Now().Add(4 * time.Second)
		for time.Now().Before(deadline) {
			mu.Lock()
			cnt := len(pingPads)
			mu.Unlock()
			if cnt >= 6 {
				break
			}
			time.Sleep(50 * time.Millisecond)
		}
		mu.Lock()
		padsCopy := slices.Clone(pingPads)
		mu.Unlock()
		require.GreaterOrEqual(t, len(padsCopy), 6)
		unique := make(map[byte]struct{}, len(padsCopy))
		for _, p := range padsCopy {
			require.GreaterOrEqual(t, int(p), 32)
			require.LessOrEqual(t, int(p), 224)
			unique[p] = struct{}{}
		}
		require.GreaterOrEqual(t, len(unique), 2)

		// Also verify Server Box Pong pads in [32, 224] across multiple Pings.
		stalled := StartStalledTCPServer(t)
		topo := t1StartTopology(t, TopologyConfig{ServerKey: key, ClientKey: key, DisableWireTap: true})
		defer stalled.Release()
		sc, err := DialSpecClient(context.Background(), topo.ServerAddr(), SpecDialOptions{Key: key, TargetAddr: stalled.Addr()})
		require.NoError(t, err)
		defer func() { _ = sc.Close() }()
		_, err = sc.ReadServerResp(5 * time.Second)
		require.NoError(t, err)
		pongPads := make(map[byte]struct{})
		for i := 0; i < 6; i++ {
			require.NoError(t, sc.SendPing(byte(40+i*10)))
			for {
				fr, err := sc.ReadFrame(5 * time.Second)
				require.NoError(t, err)
				if fr.FrameType == SpecFramePing {
					continue
				}
				require.Equal(t, SpecFramePong, fr.FrameType)
				require.GreaterOrEqual(t, int(fr.PadLen), 32)
				require.LessOrEqual(t, int(fr.PadLen), 224)
				pongPads[fr.PadLen] = struct{}{}
				break
			}
		}
		require.GreaterOrEqual(t, len(pongPads), 2)
	})

	t.Run("T1-F22-03", func(t *testing.T) {
		var pings atomic.Int32
		mockSrv := StartSpecMockServer(t, SpecServerOptions{
			Key: key,
			OnSession: func(sess *SpecServerSession) {
				if len(sess.VarHeader.InitialPayload) > 0 {
					if err := sess.WriteS2CFrame(SpecFrameData, 0, sess.VarHeader.InitialPayload); err != nil {
						return
					}
				}
				for {
					fr, err := sess.ReadC2SFrame(5 * time.Second)
					if err != nil {
						return
					}
					switch fr.FrameType {
					case SpecFrameData:
						_ = sess.WriteS2CFrame(SpecFrameData, 0, fr.Data)
					case SpecFramePing:
						pings.Add(1)
						_ = sess.WriteS2CFrame(SpecFramePong, 32, nil)
					}
				}
			},
		})
		cliPort := AllocFreeTCPPort(t)
		cliJSON, err := BuildClientJSON(TopologyConfig{
			ClientKey:               key,
			ServerHeartbeatInterval: "500ms", ClientHeartbeatInterval: "500ms",
		}, cliPort, "127.0.0.1", mockSrv.Port(), 0, "")
		require.NoError(t, err)
		cliBox, err := StartBox(t, cliJSON)
		require.NoError(t, err)
		t.Cleanup(func() { _ = cliBox.Close() })

		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		c, err := DialSOCKS5TCP(ctx, fmt.Sprintf("127.0.0.1:%d", cliPort), "127.0.0.1:80")
		require.NoError(t, err)
		defer func() { _ = c.Close() }()

		for i := 0; i < 10; i++ {
			t1DialAndEchoConn(t, c, DeterministicBytes(uint64(22030+i), 100))
			time.Sleep(100 * time.Millisecond)
		}
		require.Equal(t, int32(0), pings.Load())
	})

	t.Run("T1-F22-04", func(t *testing.T) {
		var pings atomic.Int32
		mockSrv := StartSpecMockServer(t, SpecServerOptions{
			Key: key,
			OnSession: func(sess *SpecServerSession) {
				if len(sess.VarHeader.InitialPayload) > 0 {
					if err := sess.WriteS2CFrame(SpecFrameData, 0, sess.VarHeader.InitialPayload); err != nil {
						return
					}
				}
				for {
					fr, err := sess.ReadC2SFrame(5 * time.Second)
					if err != nil {
						return
					}
					switch fr.FrameType {
					case SpecFrameData:
						_ = sess.WriteS2CFrame(SpecFrameData, 0, fr.Data)
					case SpecFramePing:
						pings.Add(1)
						_ = sess.WriteS2CFrame(SpecFramePong, 32, nil)
					}
				}
			},
		})
		cliPort := AllocFreeTCPPort(t)
		cliJSON, err := BuildClientJSON(TopologyConfig{
			ClientKey:               key,
			ServerHeartbeatInterval: "-1s", ClientHeartbeatInterval: "-1s",
		}, cliPort, "127.0.0.1", mockSrv.Port(), 0, "")
		require.NoError(t, err)
		cliBox, err := StartBox(t, cliJSON)
		require.NoError(t, err)
		t.Cleanup(func() { _ = cliBox.Close() })

		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		c, err := DialSOCKS5TCP(ctx, fmt.Sprintf("127.0.0.1:%d", cliPort), "127.0.0.1:80")
		require.NoError(t, err)
		defer func() { _ = c.Close() }()
		t1DialAndEchoConn(t, c, []byte("keepalive-off"))
		time.Sleep(800 * time.Millisecond)
		require.Equal(t, int32(0), pings.Load())
		t1DialAndEchoConn(t, c, []byte("still-connected"))
	})

	t.Run("T1-F22-05", func(t *testing.T) {
		stalled := StartStalledTCPServer(t)
		topo := t1StartTopology(t, TopologyConfig{
			ServerKey:               key,
			ClientKey:               key,
			ServerHeartbeatInterval: "400ms", ClientHeartbeatInterval: "400ms",
		})
		defer stalled.Release()

		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		c, err := topo.DialSOCKS5(ctx, stalled.Addr())
		require.NoError(t, err)
		defer func() { _ = c.Close() }()
		_, err = c.Write([]byte("trigger-handshake"))
		require.NoError(t, err)
		_ = topo.Tap.WaitForSessions(t, 1, 5*time.Second)

		topo.Tap.SetBlackhole(true, true)
		startDPD := time.Now()
		_ = c.SetReadDeadline(time.Now().Add(3 * time.Second))
		var one [16]byte
		_, rerr := c.Read(one[:])
		elapsed := time.Since(startDPD)
		require.Error(t, rerr)
		require.False(t, errors.Is(rerr, os.ErrDeadlineExceeded), "DPD should close dead conn before outer read deadline (%v)", elapsed)
		require.Less(t, elapsed, 2200*time.Millisecond)
	})
}

// =============================================================================
// F23: Full sing Interface Parity & Zero-Copy Buffer Management
// =============================================================================

func runTier1F23(t *testing.T) {
	key := GenerateRandomKeyBase64(t)

	t.Run("T1-F23-01", func(t *testing.T) {
		echo := StartTCPEchoServer(t)
		topo := t1StartTopology(t, TopologyConfig{ServerKey: key, ClientKey: key, DisableWireTap: true})
		out, ok := topo.Client.Box.Outbound().Outbound("aether-out")
		require.True(t, ok)

		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		conn, err := out.DialContext(ctx, N.NetworkTCP, M.ParseSocksaddr(echo.Addr()))
		require.NoError(t, err)
		defer func() { _ = conn.Close() }()

		_, ok = conn.(N.ExtendedConn)
		require.True(t, ok)
		_, ok = conn.(N.EarlyWriter)
		require.True(t, ok)
		_, ok = conn.(N.EarlyReader)
		require.True(t, ok)
		_, ok = conn.(N.WriteCloser)
		require.True(t, ok)
		fh, ok := conn.(N.FrontHeadroom)
		require.True(t, ok)
		require.Greater(t, fh.FrontHeadroom(), 0)
		rh, ok := conn.(N.RearHeadroom)
		require.True(t, ok)
		require.Greater(t, rh.RearHeadroom(), 0)
		mtu, ok := conn.(N.WriterWithMTU)
		require.True(t, ok)
		require.Equal(t, SpecMaxFrameDataSize, mtu.WriterMTU())
	})

	t.Run("T1-F23-02", func(t *testing.T) {
		echo := StartTCPEchoServer(t)
		topo := t1StartTopology(t, TopologyConfig{ServerKey: key, ClientKey: key, DisableWireTap: true})
		out, ok := topo.Client.Box.Outbound().Outbound("aether-out")
		require.True(t, ok)

		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		conn, err := out.DialContext(ctx, N.NetworkTCP, M.ParseSocksaddr(echo.Addr()))
		require.NoError(t, err)
		defer func() { _ = conn.Close() }()

		ext := conn.(N.ExtendedConn)
		ew := conn.(N.EarlyWriter)
		er := conn.(N.EarlyReader)
		require.True(t, ew.NeedHandshakeForWrite())
		require.True(t, er.NeedHandshakeForRead())

		wb := buf.NewPacket()
		_, err = wb.Write([]byte("handshake-transition"))
		require.NoError(t, err)
		require.NoError(t, ext.WriteBuffer(wb))
		require.False(t, ew.NeedHandshakeForWrite())

		rb := buf.NewPacket()
		defer rb.Release()
		require.NoError(t, ext.ReadBuffer(rb))
		require.False(t, er.NeedHandshakeForRead())
		require.Equal(t, []byte("handshake-transition"), rb.Bytes())
	})

	t.Run("T1-F23-03", func(t *testing.T) {
		echo := StartTCPEchoServer(t)
		topo := t1StartTopology(t, TopologyConfig{ServerKey: key, ClientKey: key, DisableWireTap: true})
		out, ok := topo.Client.Box.Outbound().Outbound("aether-out")
		require.True(t, ok)

		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		conn, err := out.DialContext(ctx, N.NetworkTCP, M.ParseSocksaddr(echo.Addr()))
		require.NoError(t, err)
		defer func() { _ = conn.Close() }()
		ext := conn.(N.ExtendedConn)
		fh := conn.(N.FrontHeadroom).FrontHeadroom()
		rh := conn.(N.RearHeadroom).RearHeadroom()

		const total = 128 * 1024
		payload := DeterministicBytes(2303, total)
		errCh := make(chan error, 1)
		go func() {
			for off := 0; off < len(payload); {
				end := min(off+8192, len(payload))
				chunk := payload[off:end]
				wb := buf.NewSize(fh + len(chunk) + rh)
				wb.Resize(fh, 0)
				if _, werr := wb.Write(chunk); werr != nil {
					wb.Release()
					errCh <- werr
					return
				}
				if werr := ext.WriteBuffer(wb); werr != nil {
					errCh <- werr
					return
				}
				off = end
			}
			errCh <- nil
		}()

		var got bytes.Buffer
		for got.Len() < total {
			rb := buf.NewPacket()
			rerr := ext.ReadBuffer(rb)
			if rb.Len() > 0 {
				got.Write(rb.Bytes())
			}
			rb.Release()
			require.NoError(t, rerr)
		}
		require.NoError(t, <-errCh)
		require.Equal(t, sha256.Sum256(payload), sha256.Sum256(got.Bytes()))
	})

	t.Run("T1-F23-04", func(t *testing.T) {
		echo := StartTCPEchoServer(t)
		topo := t1StartTopology(t, TopologyConfig{ServerKey: key, ClientKey: key, DisableWireTap: true})
		out, ok := topo.Client.Box.Outbound().Outbound("aether-out")
		require.True(t, ok)

		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		conn, err := out.DialContext(ctx, N.NetworkTCP, M.ParseSocksaddr(echo.Addr()))
		require.NoError(t, err)
		defer func() { _ = conn.Close() }()

		ru, ok := conn.(N.ReaderWithUpstream)
		require.True(t, ok)
		require.False(t, ru.ReaderReplaceable())
		wu, ok := conn.(N.WriterWithUpstream)
		require.True(t, ok)
		require.False(t, wu.WriterReplaceable())
		_, isRawTCP := N.UnwrapReader(conn).(*net.TCPConn)
		require.False(t, isRawTCP)
		_, isRawTCPW := N.UnwrapWriter(conn).(*net.TCPConn)
		require.False(t, isRawTCPW)
	})

	t.Run("T1-F23-05", func(t *testing.T) {
		udpEcho := StartUDPEchoServer(t)
		topo := t1StartTopology(t, TopologyConfig{ServerKey: key, ClientKey: key, DisableWireTap: true})
		out, ok := topo.Client.Box.Outbound().Outbound("aether-out")
		require.True(t, ok)

		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		dst := M.ParseSocksaddr(udpEcho.Addr())
		rawPConn, err := out.ListenPacket(ctx, dst)
		require.NoError(t, err)
		defer func() { _ = rawPConn.Close() }()
		pconn, ok := rawPConn.(N.PacketConn)
		require.True(t, ok)

		msg := DeterministicBytes(2305, 1024)
		wb := buf.NewPacket()
		_, err = wb.Write(msg)
		require.NoError(t, err)
		require.NoError(t, pconn.WritePacket(wb, dst))

		rb := buf.NewPacket()
		defer rb.Release()
		src, err := pconn.ReadPacket(rb)
		require.NoError(t, err)
		require.Equal(t, udpEcho.Port(), src.Port)
		require.Equal(t, msg, rb.Bytes())
	})
}

// =============================================================================
// F24: sing-box multiplex, udp_over_tcp, InjectableInbound & NetworkManager
// =============================================================================

func runTier1F24(t *testing.T) {
	key := GenerateRandomKeyBase64(t)

	t.Run("T1-F24-01", func(t *testing.T) {
		tcpEcho := StartTCPEchoServer(t)
		udpEcho := StartUDPEchoServer(t)
		for _, proto := range []string{"smux", "yamux", "h2mux"} {
			topo := t1StartTopology(t, TopologyConfig{
				ServerKey:       key,
				ClientKey:       key,
				DisableWireTap:  true,
				ServerMultiplex: &MultiplexServerSpec{Enabled: true, Padding: proto == "yamux"},
				ClientMultiplex: &MultiplexClientSpec{Enabled: true, Protocol: proto, MaxConnections: 2, Padding: proto == "yamux"},
			})
			t1TCPEcho(t, topo, tcpEcho.Addr(), DeterministicBytes(2401, 2048))
			t1UDPEcho(t, topo, udpEcho.Addr(), DeterministicBytes(24012, 700))
			topo.Close()
		}
	})

	t.Run("T1-F24-02", func(t *testing.T) {
		udpEcho := StartUDPEchoServer(t)
		for _, ver := range []int{2, 1} {
			topo := t1StartTopology(t, TopologyConfig{
				ServerKey:        key,
				ClientKey:        key,
				ClientUDPOverTCP: map[string]any{"enabled": true, "version": ver},
			})
			t1UDPEcho(t, topo, udpEcho.Addr(), DeterministicBytes(uint64(24020+ver), 600))
			sess := topo.Tap.WaitForSessions(t, 1, 5*time.Second)[0]
			insp, err := SpecInspectClientBurst(sess.Bytes(DirC2S), "", key, nil, "")
			require.NoError(t, err)
			require.Equal(t, SpecCommandUoT, insp.FixedHeader.Command)
			topo.Close()
		}
	})

	t.Run("T1-F24-03", func(t *testing.T) {
		srvPort := AllocFreeTCPPort(t)
		srvJSON, err := BuildServerJSON(TopologyConfig{ServerKey: key}, srvPort, 0, "")
		require.NoError(t, err)
		echo := StartTCPEchoServer(t)
		srvBox, err := StartBox(t, srvJSON)
		require.NoError(t, err)
		t.Cleanup(func() { _ = srvBox.Close() })

		inb, ok := srvBox.Box.Inbound().Get("aether-in")
		require.True(t, ok)
		inj, ok := inb.(adapter.TCPInjectableInbound)
		require.True(t, ok)

		srvEnd, cliEnd := net.Pipe()
		defer func() { _ = cliEnd.Close() }()
		doneCh := make(chan struct{})
		var closeOnce sync.Once
		go inj.NewConnection(context.Background(), srvEnd, adapter.InboundContext{
			Inbound:     "aether-in",
			InboundType: C.TypeAether,
			Network:     N.NetworkTCP,
			Source:      M.SocksaddrFrom(netip.MustParseAddr("127.0.0.1"), 23456),
		}, func(it error) {
			_ = it
			closeOnce.Do(func() { close(doneCh) })
		})

		msg := []byte("net-pipe-injected-0rtt")
		burst, sc, err := BuildSpecClientInitialBurst(SpecDialOptions{
			Key:            key,
			TargetAddr:     echo.Addr(),
			InitialPayload: msg,
		})
		require.NoError(t, err)
		sc.Conn = cliEnd
		_, err = cliEnd.Write(burst)
		require.NoError(t, err)
		_, err = sc.ReadServerResp(5 * time.Second)
		require.NoError(t, err)
		fr, err := sc.ReadFrame(5 * time.Second)
		require.NoError(t, err)
		require.Equal(t, msg, fr.Data)
		_ = cliEnd.Close()
		select {
		case <-doneCh:
		case <-time.After(3 * time.Second):
		}
	})

	t.Run("T1-F24-04", func(t *testing.T) {
		echo := StartTCPEchoServer(t)
		topo := t1StartTopology(t, TopologyConfig{
			ServerKey:       key,
			ClientKey:       key,
			ServerMultiplex: &MultiplexServerSpec{Enabled: true},
			ClientMultiplex: &MultiplexClientSpec{Enabled: true, Protocol: "h2mux", MaxConnections: 2},
		})
		t1TCPEcho(t, topo, echo.Addr(), []byte("before-reset"))
		_ = topo.Tap.WaitForSessions(t, 1, 5*time.Second)
		before := topo.Tap.SessionCount()

		topo.ResetClientNetwork(context.Background())
		t1TCPEcho(t, topo, echo.Addr(), []byte("after-reset"))
		require.Greater(t, topo.Tap.SessionCount(), before)
	})

	t.Run("T1-F24-05", func(t *testing.T) {
		echo := StartTCPEchoServer(t)
		topoMux := t1StartTopology(t, TopologyConfig{
			ServerKey:       key,
			ClientKey:       key,
			DisableWireTap:  true,
			ServerMultiplex: &MultiplexServerSpec{Enabled: true},
			ClientMultiplex: &MultiplexClientSpec{Enabled: true, Protocol: "smux", MaxConnections: 1},
		})
		muxEnabled, ok := topoMux.ClientMultiplexEnabled()
		require.True(t, ok)
		require.True(t, muxEnabled)

		topoNoMux := t1StartTopology(t, TopologyConfig{ServerKey: key, ClientKey: key, DisableWireTap: true})
		noMuxEnabled, ok := topoNoMux.ClientMultiplexEnabled()
		require.True(t, ok)
		require.False(t, noMuxEnabled)

		out, ok := topoNoMux.Client.Box.Outbound().Outbound("aether-out")
		require.True(t, ok)
		keeper, ok := out.(adapter.IdleConnectionKeeper)
		require.True(t, ok)
		keeper.SetKeepIdleConnections(false)
		require.True(t, topoNoMux.CloseClientIdleConnections())

		t1TCPEcho(t, topoNoMux, echo.Addr(), []byte("after-close-idle"))
	})
}

// =============================================================================
// F25: sing-box JSON Schema, Validation & Config CLI
// =============================================================================

func runTier1F25(t *testing.T) {
	findAetherVariant := func(t *testing.T, defs map[string]any, parentKey string) map[string]any {
		t.Helper()
		parent, ok := defs[parentKey].(map[string]any)
		require.True(t, ok, "schema $defs[%q] missing", parentKey)
		oneOf, ok := parent["oneOf"].([]any)
		require.True(t, ok, "schema $defs[%q].oneOf missing", parentKey)
		for _, item := range oneOf {
			m, ok := item.(map[string]any)
			if !ok {
				continue
			}
			props, _ := m["properties"].(map[string]any)
			typeObj, _ := props["type"].(map[string]any)
			if typeObj != nil && typeObj["const"] == C.TypeAether {
				return m
			}
		}
		t.Fatalf("aether variant missing under $defs[%q].oneOf", parentKey)
		return nil
	}

	t.Run("T1-F25-01", func(t *testing.T) {
		res := RunCLITimeout(t, 20*time.Second, "schema")
		require.NoError(t, res.Err, "stderr=%s", res.Stderr)
		require.Equal(t, 0, res.ExitCode)

		var root map[string]any
		require.NoError(t, json.Unmarshal([]byte(res.Stdout), &root))
		defs, ok := root["$defs"].(map[string]any)
		require.True(t, ok)
		require.NotEmpty(t, defs)
		require.Contains(t, defs, "AetherUser")
		require.NotNil(t, findAetherVariant(t, defs, "Inbound"))
		require.NotNil(t, findAetherVariant(t, defs, "Outbound"))

		outPath := filepath.Join(t.TempDir(), "schema.json")
		resOut := RunCLITimeout(t, 20*time.Second, "schema", "-o", outPath)
		require.NoError(t, resOut.Err, "stderr=%s", resOut.Stderr)
		require.Equal(t, 0, resOut.ExitCode)
		diskBytes, err := os.ReadFile(outPath)
		require.NoError(t, err)
		require.Equal(t, res.Stdout, string(diskBytes))
	})

	t.Run("T1-F25-02", func(t *testing.T) {
		res := RunCLITimeout(t, 20*time.Second, "schema")
		require.NoError(t, res.Err)
		var root map[string]any
		require.NoError(t, json.Unmarshal([]byte(res.Stdout), &root))
		defs := root["$defs"].(map[string]any)

		inDef := findAetherVariant(t, defs, "Inbound")
		outDef := findAetherVariant(t, defs, "Outbound")
		for _, def := range []map[string]any{inDef, outDef} {
			props, _ := def["properties"].(map[string]any)
			require.NotNil(t, props)
			require.NotContains(t, props, "tls")
			require.NotContains(t, props, "transport")
			require.NotContains(t, props, "fallback")
		}
		outProps := outDef["properties"].(map[string]any)
		cipherObj, ok := outProps["cipher"].(map[string]any)
		require.True(t, ok)
		enumAny, ok := cipherObj["enum"].([]any)
		require.True(t, ok)
		var enumStrs []string
		for _, item := range enumAny {
			enumStrs = append(enumStrs, fmt.Sprint(item))
		}
		require.ElementsMatch(t, []string{"auto", "aes-256-gcm", "chacha20-poly1305"}, enumStrs)
	})

	t.Run("T1-F25-03", func(t *testing.T) {
		iPSK := GenerateRandomKeyBase64(t)
		uAlice := GenerateRandomKeyBase64(t)
		priv, pub := GenerateX25519KeyPairBase64(t)

		fullCfg := map[string]any{
			"inbounds": []any{
				map[string]any{
					"type":               C.TypeAether,
					"tag":                "aether-in",
					"listen":             "127.0.0.1",
					"listen_port":        1443,
					"password":           iPSK,
					"users":              []any{map[string]any{"name": "alice", "key": uAlice}},
					"private_key":        priv,
					"time_window":        "45s",
					"handshake_timeout":  "4s",
					"heartbeat_interval": "15s",
					"disable_shaping":    false,
					"multiplex":          map[string]any{"enabled": true},
				},
			},
			"outbounds": []any{
				map[string]any{
					"type":               C.TypeAether,
					"tag":                "aether-out",
					"server":             "127.0.0.1",
					"server_port":        1443,
					"key":                iPSK + ":" + uAlice,
					"public_key":         pub,
					"cipher":             "chacha20-poly1305",
					"network":            []string{"tcp", "udp"},
					"heartbeat_interval": "15s",
					"disable_shaping":    true,
					"multiplex":          map[string]any{"enabled": true, "protocol": "h2mux"},
					"udp_over_tcp":       map[string]any{"enabled": true, "version": 2},
				},
			},
		}
		raw, err := json.Marshal(fullCfg)
		require.NoError(t, err)
		res := CheckConfigCLI(t, raw)
		require.NoError(t, res.Err, "stderr=%s", res.Stderr)
		require.Equal(t, 0, res.ExitCode)
	})

	t.Run("T1-F25-04", func(t *testing.T) {
		sameKey := GenerateRandomKeyBase64(t)
		sameUserKey := GenerateRandomKeyBase64(t)
		cfg := map[string]any{
			"inbounds": []any{
				map[string]any{
					"type":        C.TypeAether,
					"tag":         "aether-in",
					"listen":      "127.0.0.1",
					"listen_port": AllocFreeTCPPort(t),
					"password":    sameKey,
					"key":         sameKey,
					"users": []any{
						map[string]any{"name": "alice", "password": sameUserKey, "key": sameUserKey},
					},
				},
			},
			"outbounds": []any{
				map[string]any{
					"type":        C.TypeAether,
					"tag":         "aether-out",
					"server":      "127.0.0.1",
					"server_port": 443,
					"password":    sameKey + ":" + sameUserKey,
					"key":         sameKey + ":" + sameUserKey,
				},
			},
		}
		raw, err := json.Marshal(cfg)
		require.NoError(t, err)
		res := CheckConfigCLI(t, raw)
		require.NoError(t, res.Err, "stderr=%s", res.Stderr)
		require.Equal(t, 0, res.ExitCode)

		srvBox, err := StartBox(t, raw)
		require.NoError(t, err)
		require.NoError(t, srvBox.Close())
	})

	t.Run("T1-F25-05", func(t *testing.T) {
		key := GenerateRandomKeyBase64(t)
		dir := t.TempDir()
		inJSON, err := json.Marshal(map[string]any{
			"inbounds": []any{
				map[string]any{
					"type":        C.TypeAether,
					"tag":         "aether-in",
					"listen":      "127.0.0.1",
					"listen_port": 11443,
					"key":         key,
				},
			},
		})
		require.NoError(t, err)
		outJSON, err := json.Marshal(map[string]any{
			"outbounds": []any{
				map[string]any{
					"type":        C.TypeAether,
					"tag":         "aether-out",
					"server":      "127.0.0.1",
					"server_port": 11443,
					"key":         key,
				},
			},
		})
		require.NoError(t, err)
		require.NoError(t, os.WriteFile(filepath.Join(dir, "01_inbounds.json"), inJSON, 0o600))
		require.NoError(t, os.WriteFile(filepath.Join(dir, "02_outbounds.json"), outJSON, 0o600))

		res := RunCLITimeout(t, 15*time.Second, "check", "-C", dir)
		require.NoError(t, res.Err, "stderr=%s", res.Stderr)
		require.Equal(t, 0, res.ExitCode)
	})
}

// =============================================================================
// F26: Upstream Sync & Release Automation Workflow
// =============================================================================

func runTier1F26(t *testing.T) {
	const wfPath = ".github/workflows/upstream-sync-release.yml"

	stepByName := func(t *testing.T, steps []t1WorkflowStep, name string) t1WorkflowStep {
		t.Helper()
		for _, st := range steps {
			if st.Name == name {
				return st
			}
		}
		t.Fatalf("workflow step %q not found", name)
		return t1WorkflowStep{}
	}

	t.Run("T1-F26-01", func(t *testing.T) {
		raw := t1ReadRepoFile(t, wfPath)
		onSec := t1ExtractOnSection(raw)
		require.Contains(t, onSec, `cron: '0 2 * * 1'`)
		require.Contains(t, onSec, "workflow_dispatch:")
		require.Contains(t, raw, "permissions:\n  contents: write")
	})

	t.Run("T1-F26-02", func(t *testing.T) {
		raw := t1ReadRepoFile(t, wfPath)
		steps := t1ExtractWorkflowSteps(t, raw)
		require.NotEmpty(t, steps)
		for _, st := range steps {
			if st.Run != "" {
				t1BashSyntaxCheck(t, "upstream-sync-release.yml/"+st.Name, st.Run)
			}
		}
		// Single job (sync-and-release) avoids cross-job upload-artifact failure point.
		require.Contains(t, raw, "\n  sync-and-release:\n")
		require.Equal(t, 1, strings.Count(raw, "runs-on:"))
		require.NotContains(t, raw, "upload-artifact")
		require.NotContains(t, raw, "download-artifact")
	})

	setupDryRunGit := func(t *testing.T, releaseExists bool, latestJSON string) (repoDir, originDir, mockLog string, steps []t1WorkflowStep) {
		t.Helper()
		root := t.TempDir()
		originDir = filepath.Join(root, "origin.git")
		upstreamDir := filepath.Join(root, "upstream.git")
		workUp := filepath.Join(root, "work-upstream")
		repoDir = filepath.Join(root, "fork")
		binDir := filepath.Join(root, "mockbin")
		mockLog = filepath.Join(root, "mock.log")
		require.NoError(t, os.MkdirAll(binDir, 0o755))

		// Minimal bare upstream + v1.14.4 + v1.14.5.
		for _, bare := range []string{originDir, upstreamDir} {
			require.NoError(t, os.MkdirAll(bare, 0o755))
			_, errOut, err := t1RunGit(t, bare, "init", "--bare")
			require.NoError(t, err, errOut)
		}
		_, errOut, err := t1RunGit(t, root, "clone", upstreamDir, workUp)
		require.NoError(t, err, errOut)
		_, _, _ = t1RunGit(t, workUp, "config", "user.name", "Test")
		_, _, _ = t1RunGit(t, workUp, "config", "user.email", "test@example.com")

		writeTreeFile := func(dir, rel, content string) {
			p := filepath.Join(dir, rel)
			require.NoError(t, os.MkdirAll(filepath.Dir(p), 0o755))
			require.NoError(t, os.WriteFile(p, []byte(content), 0o644))
		}
		writeTreeFile(workUp, "constant/version.go", "package constant\n\nvar Version = \"1.14.4\"\n")
		writeTreeFile(workUp, "constant/proxy.go", "package constant\n\nconst TypeDirect = \"direct\"\n")
		writeTreeFile(workUp, ".github/workflows/docker.yml", "name: Upstream Docker\non:\n  release:\n")
		writeTreeFile(workUp, "LICENSE", "MIT\n")
		_, errOut, err = t1RunGit(t, workUp, "add", ".")
		require.NoError(t, err, errOut)
		_, errOut, err = t1RunGit(t, workUp, "commit", "-m", "upstream v1.14.4")
		require.NoError(t, err, errOut)
		_, errOut, err = t1RunGit(t, workUp, "tag", "-a", "v1.14.4", "-m", "v1.14.4")
		require.NoError(t, err, errOut)
		_, errOut, err = t1RunGit(t, workUp, "push", "origin", "HEAD", "refs/tags/v1.14.4")
		require.NoError(t, err, errOut)

		// Advance upstream to v1.14.5 with conflict-inducing workflow + proxy edits.
		writeTreeFile(workUp, "constant/version.go", "package constant\n\nvar Version = \"1.14.5\"\n")
		writeTreeFile(workUp, "constant/proxy.go", "package constant\n\n// upstream v1.14.5\nconst TypeDirect = \"direct\"\n")
		writeTreeFile(workUp, ".github/workflows/docker.yml", "name: Upstream v1.14.5 Docker\non:\n  release:\n")
		_, errOut, err = t1RunGit(t, workUp, "add", ".")
		require.NoError(t, err, errOut)
		_, errOut, err = t1RunGit(t, workUp, "commit", "-m", "upstream v1.14.5")
		require.NoError(t, err, errOut)
		_, errOut, err = t1RunGit(t, workUp, "tag", "-a", "v1.14.5", "-m", "v1.14.5")
		require.NoError(t, err, errOut)
		_, errOut, err = t1RunGit(t, workUp, "push", "origin", "HEAD", "refs/tags/v1.14.5")
		require.NoError(t, err, errOut)

		// Create fork based on v1.14.4 with custom workflows/version and push to bare originDir.
		_, errOut, err = t1RunGit(t, root, "clone", upstreamDir, "--branch", "v1.14.4", repoDir)
		require.NoError(t, err, errOut)
		_, _, _ = t1RunGit(t, repoDir, "checkout", "-b", "dev/aether-v2")
		_, _, _ = t1RunGit(t, repoDir, "config", "user.name", "Fork")
		_, _, _ = t1RunGit(t, repoDir, "config", "user.email", "fork@example.com")
		_, _, _ = t1RunGit(t, repoDir, "remote", "set-url", "origin", originDir)
		writeTreeFile(repoDir, "constant/version.go", "package constant\n\nvar Version = \"1.14.4-Custom-Aether\"\n")
		writeTreeFile(repoDir, ".github/workflows/docker.yml", "name: Fork Custom Docker\non:\n  workflow_dispatch:\n")
		writeTreeFile(repoDir, "release/LDFLAGS", "-checklinkname=0\n")
		writeTreeFile(repoDir, "release/DEFAULT_BUILD_TAGS_OTHERS", DefaultOfficialPureGoBuildTags+"\n")
		writeTreeFile(repoDir, "cmd/sing-box/cmd_schema.go", "package main\n")
		writeTreeFile(repoDir, "docs/schema.json", "{}\n")
		_, errOut, err = t1RunGit(t, repoDir, "add", ".")
		require.NoError(t, err, errOut)
		_, errOut, err = t1RunGit(t, repoDir, "commit", "-m", "fork customizations")
		require.NoError(t, err, errOut)
		_, errOut, err = t1RunGit(t, repoDir, "push", "-u", "origin", "HEAD")
		require.NoError(t, err, errOut)
		if releaseExists {
			_, errOut, err = t1RunGit(t, repoDir, "tag", "-a", "v1.14.4-Custom-Aether", "-m", "released")
			require.NoError(t, err, errOut)
			_, errOut, err = t1RunGit(t, repoDir, "push", "origin", "refs/tags/v1.14.4-Custom-Aether")
			require.NoError(t, err, errOut)
		}
		_, errOut, err = t1RunGit(t, repoDir, "tag", "-d", "v1.14.5")
		require.NoError(t, err, errOut)
		_, _, _ = t1RunGit(t, repoDir, "config", "url."+upstreamDir+".insteadOf", "https://github.com/SagerNet/sing-box.git")

		// Mock curl, gh, and go executables inside binDir.
		writeExec := func(name, body string) {
			p := filepath.Join(binDir, name)
			require.NoError(t, os.WriteFile(p, []byte("#!/usr/bin/env bash\nset -euo pipefail\n"+body), 0o755))
		}
		writeExec("curl", fmt.Sprintf("printf '%%s\\n' 'curl %%s' \"$*\" >> %q\ncat <<'JSON'\n%s\nJSON\n", mockLog, latestJSON))
		relViewCode := 1
		if releaseExists {
			relViewCode = 0
		}
		writeExec("gh", fmt.Sprintf("printf '%%s\\n' \"gh $*\" >> %q\nif [ \"${1:-}\" = \"release\" ] && [ \"${2:-}\" = \"view\" ]; then exit %d; fi\nexit 0\n", mockLog, relViewCode))
		writeExec("go", fmt.Sprintf(`printf '%%s\n' "go $*" >> %q
if [ "${1:-}" = "run" ]; then
  printf '{"ok":true}\n'
  exit 0
fi
if [ "${1:-}" = "test" ]; then
  exit 0
fi
if [ "${1:-}" = "build" ]; then
  out=""
  while [ "$#" -gt 0 ]; do
    if [ "$1" = "-o" ]; then
      out="$2"
      shift 2
      continue
    fi
    shift
  done
  printf 'stub-binary' > "${out}"
  exit 0
fi
exit 0
`, mockLog))

		rawWF := t1ReadRepoFile(t, wfPath)
		steps = t1ExtractWorkflowSteps(t, rawWF)
		t.Setenv("PATH", binDir+string(os.PathListSeparator)+os.Getenv("PATH"))
		return repoDir, originDir, mockLog, steps
	}

	runStepScript := func(t *testing.T, dir, script string, envMap map[string]string, outFile, envFile string) {
		t.Helper()
		cmd := exec.Command("bash", "-c", script)
		cmd.Dir = dir
		env := append([]string{}, os.Environ()...)
		env = append(env,
			"GITHUB_OUTPUT="+outFile,
			"GITHUB_ENV="+envFile,
			"GH_TOKEN=mock-token",
			"GIT_TERMINAL_PROMPT=0",
		)
		for k, v := range envMap {
			env = append(env, k+"="+v)
		}
		cmd.Env = env
		out, err := cmd.CombinedOutput()
		require.NoError(t, err, "script failed:\n%s\noutput:\n%s", script, string(out))
	}

	parseKVFile := func(t *testing.T, p string) map[string]string {
		t.Helper()
		b, err := os.ReadFile(p)
		require.NoError(t, err)
		res := make(map[string]string)
		sc := bufio.NewScanner(bytes.NewReader(b))
		for sc.Scan() {
			line := sc.Text()
			if k, v, ok := strings.Cut(line, "="); ok {
				res[k] = v
			}
		}
		return res
	}

	t.Run("T1-F26-03", func(t *testing.T) {
		repoDir, originDir, mockLog, steps := setupDryRunGit(t, false, `{"tag_name":"v1.14.5","draft":false,"prerelease":false}`)
		tmpEnv := filepath.Join(t.TempDir(), "env")
		tmpOut := filepath.Join(t.TempDir(), "out")
		require.NoError(t, os.WriteFile(tmpEnv, nil, 0o600))
		require.NoError(t, os.WriteFile(tmpOut, nil, 0o600))

		envVars := map[string]string{}
		stepNames := []string{
			"Discover Latest Upstream Stable Release",
			"Fetch Upstream Tag and Check Idempotency",
			"Merge Upstream Tag and Preserve Workflows",
			"Update Version and Regenerate Schema",
			"Run Mandatory -race Test Gate",
			"Build and Package Multi-Arch Static Binaries",
			"Commit Sync, Tag, Push, and Publish GitHub Release",
		}
		for _, name := range stepNames {
			st := stepByName(t, steps, name)
			runStepScript(t, repoDir, st.Run, envVars, tmpOut, tmpEnv)
			for k, v := range parseKVFile(t, tmpEnv) {
				envVars[k] = v
			}
		}

		wfDiff, errOut, err := t1RunGit(t, repoDir, "diff", "HEAD~1", "HEAD", "--", ".github/workflows/")
		require.NoError(t, err, errOut)
		require.Empty(t, strings.TrimSpace(wfDiff))

		verData, err := os.ReadFile(filepath.Join(repoDir, "constant/version.go"))
		require.NoError(t, err)
		require.Contains(t, string(verData), `var Version = "1.14.5-Custom-Aether"`)

		proxyData, err := os.ReadFile(filepath.Join(repoDir, "constant/proxy.go"))
		require.NoError(t, err)
		require.Contains(t, string(proxyData), "upstream v1.14.5")

		tagSHA, errOut, err := t1RunGit(t, originDir, "rev-parse", "--verify", "refs/tags/v1.14.5-Custom-Aether")
		require.NoError(t, err, errOut)
		require.NotEmpty(t, strings.TrimSpace(tagSHA))

		logData, err := os.ReadFile(mockLog)
		require.NoError(t, err)
		require.Contains(t, string(logData), "go test -race -count=1 ./cmd/sing-box/... ./option/... ./schema/... ./protocol/aether/...")
		require.Contains(t, string(logData), "gh release create v1.14.5-Custom-Aether")
	})

	t.Run("T1-F26-04", func(t *testing.T) {
		repoDir, _, _, steps := setupDryRunGit(t, true, `{"tag_name":"v1.14.4","draft":false,"prerelease":false}`)
		tmpEnv := filepath.Join(t.TempDir(), "env")
		tmpOut := filepath.Join(t.TempDir(), "out")
		require.NoError(t, os.WriteFile(tmpEnv, nil, 0o600))
		require.NoError(t, os.WriteFile(tmpOut, nil, 0o600))

		envVars := map[string]string{}
		runStepScript(t, repoDir, stepByName(t, steps, "Discover Latest Upstream Stable Release").Run, envVars, tmpOut, tmpEnv)
		outs := parseKVFile(t, tmpOut)
		require.Equal(t, "true", outs["should_sync"])
		for k, v := range parseKVFile(t, tmpEnv) {
			envVars[k] = v
		}

		require.NoError(t, os.WriteFile(tmpOut, nil, 0o600))
		runStepScript(t, repoDir, stepByName(t, steps, "Fetch Upstream Tag and Check Idempotency").Run, envVars, tmpOut, tmpEnv)
		idOuts := parseKVFile(t, tmpOut)
		require.Equal(t, "false", idOuts["should_proceed"])
		require.Equal(t, "false", parseKVFile(t, tmpEnv)["SHOULD_PROCEED"])

		// Also verify non-stable tag (v1.14.5-rc.1) is skipped safely.
		repoPre, _, _, stepsPre := setupDryRunGit(t, false, `{"tag_name":"v1.14.5-rc.1","draft":false,"prerelease":false}`)
		preOut := filepath.Join(t.TempDir(), "preout")
		preEnv := filepath.Join(t.TempDir(), "preenv")
		require.NoError(t, os.WriteFile(preOut, nil, 0o600))
		require.NoError(t, os.WriteFile(preEnv, nil, 0o600))
		runStepScript(t, repoPre, stepByName(t, stepsPre, "Discover Latest Upstream Stable Release").Run, nil, preOut, preEnv)
		require.Equal(t, "false", parseKVFile(t, preOut)["should_sync"])
	})

	t.Run("T1-F26-05", func(t *testing.T) {
		raw := t1ReadRepoFile(t, wfPath)
		steps := t1ExtractWorkflowSteps(t, raw)

		raceIdx := -1
		buildIdx := -1
		for idx, st := range steps {
			switch st.Name {
			case "Run Mandatory -race Test Gate":
				raceIdx = idx
				require.Equal(t, "1", st.Env["CGO_ENABLED"])
				require.Contains(t, st.Run, "go test -race")
				require.Contains(t, st.Run, "./protocol/aether/...")
			case "Build and Package Multi-Arch Static Binaries":
				buildIdx = idx
				require.Contains(t, st.Run, "release/DEFAULT_BUILD_TAGS_OTHERS")
				for _, tag := range strings.Split(DefaultOfficialPureGoBuildTags, ",") {
					require.Contains(t, st.Run, tag)
				}
				require.Contains(t, st.Run, "release/LDFLAGS")
				require.Contains(t, st.Run, "sha256sum")
			}
		}
		require.GreaterOrEqual(t, raceIdx, 0)
		require.Greater(t, buildIdx, raceIdx)
	})
}

// =============================================================================
// F27: Subprocess Daemons, Leak Audits, PCAP Entropy & -race Stress
// =============================================================================

func runTier1F27(t *testing.T) {
	key := GenerateRandomKeyBase64(t)

	t.Run("T1-F27-01", func(t *testing.T) {
		srvPort := AllocFreeTCPPort(t)
		cliPort := AllocFreeTCPPort(t)
		userA := GenerateRandomKeyBase64(t)
		userB := GenerateRandomKeyBase64(t)
		cfg1 := TopologyConfig{
			ServerKey: key,
			ServerUsers: []UserSpec{
				{Name: "alice", Key: userA},
			},
			ClientKey: key + ":" + userA,
		}
		srvJSON1, err := BuildServerJSON(cfg1, srvPort, 0, "")
		require.NoError(t, err)
		cliJSON, err := BuildClientJSON(cfg1, cliPort, "127.0.0.1", srvPort, 0, "")
		require.NoError(t, err)

		tcpEcho := StartTCPEchoServer(t)
		udpEcho := StartUDPEchoServer(t)
		srvProc := StartCLIDaemon(t, srvJSON1, srvPort)
		t.Cleanup(func() { _ = srvProc.Stop(5 * time.Second) })
		cliProc := StartCLIDaemon(t, cliJSON, cliPort)
		t.Cleanup(func() { _ = cliProc.Stop(5 * time.Second) })

		checkCycle := func(tag string) {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			tc, err := DialSOCKS5TCP(ctx, fmt.Sprintf("127.0.0.1:%d", cliPort), tcpEcho.Addr())
			require.NoError(t, err)
			t1DialAndEchoConn(t, tc, []byte("cli-daemon-tcp-"+tag))
			_ = tc.Close()

			uc, err := DialSOCKS5UDP(ctx, fmt.Sprintf("127.0.0.1:%d", cliPort))
			require.NoError(t, err)
			defer func() { _ = uc.Close() }()
			require.NoError(t, uc.WriteToHostPort([]byte("cli-daemon-udp-"+tag), udpEcho.Addr()))
			rb := make([]byte, 256)
			n, _, err := uc.ReadFromHostPort(rb)
			require.NoError(t, err)
			require.Equal(t, []byte("cli-daemon-udp-"+tag), rb[:n])
		}

		checkCycle("before-reload")

		// Add user bob on server config and reload via SIGHUP.
		cfg2 := TopologyConfig{
			ServerKey: key,
			ServerUsers: []UserSpec{
				{Name: "alice", Key: userA},
				{Name: "bob", Key: userB},
			},
		}
		srvJSON2, err := BuildServerJSON(cfg2, srvPort, 0, "")
		require.NoError(t, err)
		require.NoError(t, os.WriteFile(srvProc.ConfigPath(), srvJSON2, 0o600))
		require.NoError(t, srvProc.Signal(syscall.SIGHUP))
		time.Sleep(350 * time.Millisecond)

		checkCycle("after-reload")

		// New user bob succeeds via SpecClientConn post-SIGHUP.
		scBob, err := DialSpecClient(context.Background(), fmt.Sprintf("127.0.0.1:%d", srvPort), SpecDialOptions{
			Key:            key + ":" + userB,
			TargetAddr:     tcpEcho.Addr(),
			InitialPayload: []byte("bob-post-sighup"),
		})
		require.NoError(t, err)
		_, err = scBob.ReadServerResp(5 * time.Second)
		require.NoError(t, err)
		fr, err := scBob.ReadFrame(5 * time.Second)
		require.NoError(t, err)
		require.Equal(t, []byte("bob-post-sighup"), fr.Data)
		_ = scBob.Close()

		require.NoError(t, cliProc.Signal(syscall.SIGTERM))
		exitCli, err := cliProc.Wait(5 * time.Second)
		require.NoError(t, err)
		require.Equal(t, 0, exitCli)

		require.NoError(t, srvProc.Signal(syscall.SIGTERM))
		exitSrv, err := srvProc.Wait(5 * time.Second)
		require.NoError(t, err)
		require.Equal(t, 0, exitSrv)
	})

	t.Run("T1-F27-02", func(t *testing.T) {
		runtime.GC()
		time.Sleep(50 * time.Millisecond)
		baseline := runtime.NumGoroutine()

		tcpEcho := StartTCPEchoServer(t)
		udpEcho := StartUDPEchoServer(t)

		modes := []TopologyConfig{
			{ServerKey: key, ClientKey: key, DisableWireTap: true},
			{ServerKey: key, ClientKey: key, DisableWireTap: true, ClientUDPOverTCP: map[string]any{"enabled": true, "version": 2}},
			{ServerKey: key, ClientKey: key, DisableWireTap: true, ServerMultiplex: &MultiplexServerSpec{Enabled: true}, ClientMultiplex: &MultiplexClientSpec{Enabled: true, Protocol: "smux"}},
		}
		for round, cfg := range modes {
			topo := StartTopology(t, cfg)
			for j := 0; j < 17 && round*17+j < 50; j++ {
				t1TCPEcho(t, topo, tcpEcho.Addr(), []byte("leak-tcp"))
				if round != 2 {
					t1UDPEcho(t, topo, udpEcho.Addr(), []byte("leak-udp"))
				}
			}
			topo.Close()
		}

		deadline := time.Now().Add(2 * time.Second)
		for time.Now().Before(deadline) {
			runtime.GC()
			if runtime.NumGoroutine() <= baseline+2 {
				break
			}
			time.Sleep(30 * time.Millisecond)
		}
		require.LessOrEqual(t, runtime.NumGoroutine(), baseline+2)
	})

	t.Run("T1-F27-03", func(t *testing.T) {
		tcpEcho := StartTCPEchoServer(t)
		udpEcho := StartUDPEchoServer(t)
		fdBase, err := CountOpenFDs()
		require.NoError(t, err)

		topo := StartTopology(t, TopologyConfig{ServerKey: key, ClientKey: key, DisableWireTap: true, ServerHeartbeatInterval: "-1s", ClientHeartbeatInterval: "-1s"})
		for i := 0; i < 50; i++ {
			t1TCPEcho(t, topo, tcpEcho.Addr(), []byte("fd-tcp"))
			t1UDPEcho(t, topo, udpEcho.Addr(), []byte("fd-udp"))
		}
		topo.Close()

		fdAfter, err := WaitForOpenFDsAtMost(fdBase+4, 5*time.Second)
		require.NoError(t, err)
		require.LessOrEqual(t, fdAfter, fdBase+4, "FD leak: baseline=%d after=%d", fdBase, fdAfter)
	})

	t.Run("T1-F27-04", func(t *testing.T) {
		echo := StartTCPEchoServer(t)
		topo := t1StartTopology(t, TopologyConfig{ServerKey: key, ClientKey: key, ServerHeartbeatInterval: "-1s", ClientHeartbeatInterval: "-1s"})
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		c, err := topo.DialSOCKS5(ctx, echo.Addr())
		require.NoError(t, err)
		defer func() { _ = c.Close() }()

		const line = "GET /secret-domain.internal HTTP/1.1\r\n"
		unit := strings.Repeat(line, (1024*1024)/len(line)+1)[:1024*1024]
		payload := []byte(unit)
		errCh := make(chan error, 1)
		go func() {
			_, werr := c.Write(payload)
			if werr == nil {
				_ = c.CloseWrite()
			}
			errCh <- werr
		}()
		got, err := io.ReadAll(c)
		require.NoError(t, err)
		require.NoError(t, <-errCh)
		require.Equal(t, payload, got)

		sess := topo.Tap.WaitForSessions(t, 1, 5*time.Second)[0]
		require.True(t, sess.WaitClosed(3*time.Second))
		require.False(t, sess.ContainsBytes(DirC2S, []byte("secret-domain.internal")))
		require.Greater(t, sess.ShannonEntropy(DirC2S), 7.95)

		pcapPath := filepath.Join(t.TempDir(), "aether-v2-audit.pcap")
		require.NoError(t, topo.Tap.SavePCAP(pcapPath))
		pktCount, err := ValidatePCAPFile(pcapPath)
		require.NoError(t, err)
		require.GreaterOrEqual(t, pktCount, 4)
		fi, err := os.Stat(pcapPath)
		require.NoError(t, err)
		require.Greater(t, fi.Size(), int64(1024*1024))
	})

	t.Run("T1-F27-05", func(t *testing.T) {
		tcpEcho := StartTCPEchoServer(t)
		udpEcho := StartUDPEchoServer(t)

		nativeTopo := t1StartTopology(t, TopologyConfig{ServerKey: key, ClientKey: key, DisableWireTap: true})
		uotTopo := t1StartTopology(t, TopologyConfig{
			ServerKey:        key,
			ClientKey:        key,
			DisableWireTap:   true,
			ClientUDPOverTCP: map[string]any{"enabled": true, "version": 2},
		})
		muxTopo := t1StartTopology(t, TopologyConfig{
			ServerKey:       key,
			ClientKey:       key,
			DisableWireTap:  true,
			ServerMultiplex: &MultiplexServerSpec{Enabled: true},
			ClientMultiplex: &MultiplexClientSpec{Enabled: true, Protocol: "h2mux", MaxConnections: 2},
		})

		var wg sync.WaitGroup
		errs := make(chan error, 16)
		for i := 0; i < 16; i++ {
			wg.Add(1)
			go func(idx int) {
				defer wg.Done()
				ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
				defer cancel()
				switch idx % 4 {
				case 0:
					c, err := nativeTopo.DialSOCKS5(ctx, tcpEcho.Addr())
					if err != nil {
						errs <- err
						return
					}
					defer func() { _ = c.Close() }()
					p := DeterministicBytes(uint64(27050+idx), 16384)
					if _, err := c.Write(p); err != nil {
						errs <- err
						return
					}
					g := make([]byte, len(p))
					if _, err := io.ReadFull(c, g); err != nil || sha256.Sum256(p) != sha256.Sum256(g) {
						errs <- fmt.Errorf("native-tcp %d: %v", idx, err)
					}
				case 1:
					uc, err := nativeTopo.OpenSOCKS5UDP(ctx)
					if err != nil {
						errs <- err
						return
					}
					defer func() { _ = uc.Close() }()
					p := DeterministicBytes(uint64(27050+idx), 700)
					if err := uc.WriteToHostPort(p, udpEcho.Addr()); err != nil {
						errs <- err
						return
					}
					g := make([]byte, 2048)
					n, _, err := uc.ReadFromHostPort(g)
					if err != nil || !bytes.Equal(p, g[:n]) {
						errs <- fmt.Errorf("native-udp %d: %v", idx, err)
					}
				case 2:
					uc, err := uotTopo.OpenSOCKS5UDP(ctx)
					if err != nil {
						errs <- err
						return
					}
					defer func() { _ = uc.Close() }()
					p := DeterministicBytes(uint64(27050+idx), 700)
					if err := uc.WriteToHostPort(p, udpEcho.Addr()); err != nil {
						errs <- err
						return
					}
					g := make([]byte, 2048)
					n, _, err := uc.ReadFromHostPort(g)
					if err != nil || !bytes.Equal(p, g[:n]) {
						errs <- fmt.Errorf("uot %d: %v", idx, err)
					}
				case 3:
					c, err := muxTopo.DialSOCKS5(ctx, tcpEcho.Addr())
					if err != nil {
						errs <- err
						return
					}
					defer func() { _ = c.Close() }()
					p := DeterministicBytes(uint64(27050+idx), 16384)
					if _, err := c.Write(p); err != nil {
						errs <- err
						return
					}
					g := make([]byte, len(p))
					if _, err := io.ReadFull(c, g); err != nil || sha256.Sum256(p) != sha256.Sum256(g) {
						errs <- fmt.Errorf("h2mux %d: %v", idx, err)
					}
				}
			}(i)
		}
		wg.Wait()
		close(errs)
		for err := range errs {
			require.NoError(t, err)
		}
	})
}
