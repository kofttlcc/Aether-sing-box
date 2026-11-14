package e2e_test

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/sagernet/sing-box"
	"github.com/sagernet/sing-box/adapter"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/buf"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"golang.org/x/crypto/chacha20poly1305"
)

// TestTier2Boundaries exercises all 140 Tier 2 boundary, negative, and corner
// cases across Features F1..F27 using opaque black-box interfaces.
func TestTier2Boundaries(t *testing.T) {
	VerifyOpaqueImports(t)

	t2RunF01(t)
	t2RunF02(t)
	t2RunF03(t)
	t2RunF04(t)
	t2RunF05(t)
	t2RunF06(t)
	t2RunF07(t)
	t2RunF08(t)
	t2RunF09(t)
	t2RunF10(t)
	t2RunF11(t)
	t2RunF12(t)
	t2RunF13(t)
	t2RunF14(t)
	t2RunF15(t)
	t2RunF16(t)
	t2RunF17(t)
	t2RunF18(t)
	t2RunF19(t)
	t2RunF20(t)
	t2RunF21(t)
	t2RunF22(t)
	t2RunF23(t)
	t2RunF24(t)
	t2RunF25(t)
	t2RunF26(t)
	t2RunF27(t)
}

func t2RequireNoErr(t testing.TB, err error, format string, args ...any) {
	t.Helper()
	if err != nil {
		msg := format
		if len(args) > 0 {
			msg = fmt.Sprintf(format, args...)
		}
		t.Fatalf("%s: %v", msg, err)
	}
}

func t2RequireErr(t testing.TB, err error, format string, args ...any) {
	t.Helper()
	if err == nil {
		msg := format
		if len(args) > 0 {
			msg = fmt.Sprintf(format, args...)
		}
		t.Fatalf("expected error (%s), got nil", msg)
	}
}

func t2RequireTrue(t testing.TB, cond bool, format string, args ...any) {
	t.Helper()
	if !cond {
		t.Fatalf(format, args...)
	}
}

// t2WaitForNoAetherLeaks wraps WaitForNoAetherLeaks and ignores parent test-runner
// goroutines waiting inside testing.(*T).Run whose stack only mentions the e2e test file path.
func t2WaitForNoAetherLeaks(timeout time.Duration) []string {
	deadline := time.Now().Add(timeout)
	for {
		raw := ActiveAetherAndBoxGoroutines()
		var realLeaks []string
		for _, blk := range raw {
			isTestRunner := strings.Contains(blk, "testing.(*T).Run") || strings.Contains(blk, "testing.runTests")
			hasProdAether := strings.Contains(blk, "protocol/aether.") || strings.Contains(blk, "protocol/aether.(*")
			hasBoxSubsys := strings.Contains(blk, "sing-box/common/listener") ||
				strings.Contains(blk, "sing-box/route.") ||
				strings.Contains(blk, "sing-box/experimental/") ||
				strings.Contains(blk, "(*WireTapProxy).") ||
				strings.Contains(blk, "(*SpecMockServer).")
			if isTestRunner && !hasProdAether && !hasBoxSubsys {
				continue
			}
			realLeaks = append(realLeaks, blk)
		}
		if len(realLeaks) == 0 || time.Now().After(deadline) {
			return realLeaks
		}
		time.Sleep(50 * time.Millisecond)
	}
}

func t2EchoTCPViaSOCKS5(t testing.TB, proxyAddr, targetAddr string, payload []byte) error {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	conn, err := DialSOCKS5TCP(ctx, proxyAddr, targetAddr)
	if err != nil {
		return err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(8 * time.Second))
	if _, err := conn.Write(payload); err != nil {
		return err
	}
	got := make([]byte, len(payload))
	if _, err := io.ReadFull(conn, got); err != nil {
		return err
	}
	if !bytes.Equal(got, payload) {
		return fmt.Errorf("echo mismatch: sent sha256=%x, got sha256=%x", sha256.Sum256(payload), sha256.Sum256(got))
	}
	return nil
}

func t2EchoTCPViaSOCKS5Auth(t testing.TB, proxyAddr, user, pass, targetAddr string, payload []byte) error {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	conn, err := DialSOCKS5TCPAuth(ctx, proxyAddr, user, pass, targetAddr)
	if err != nil {
		return err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(8 * time.Second))
	if _, err := conn.Write(payload); err != nil {
		return err
	}
	got := make([]byte, len(payload))
	if _, err := io.ReadFull(conn, got); err != nil {
		return err
	}
	if !bytes.Equal(got, payload) {
		return fmt.Errorf("echo mismatch: sent sha256=%x, got sha256=%x", sha256.Sum256(payload), sha256.Sum256(got))
	}
	return nil
}

// t2AssertStealthDrain verifies that sending payload to addr yields zero server
// response bytes, does not send an RST, and cleanly EOFs after draining.
func t2AssertStealthDrain(t testing.TB, addr string, payload []byte, halfClose bool, minElapsed, maxWait time.Duration) ProbeResult {
	t.Helper()
	res, err := SendRawProbe(addr, payload, halfClose, maxWait)
	t2RequireNoErr(t, err, "SendRawProbe")
	if len(res.BytesReceived) != 0 {
		t.Fatalf("expected 0 response bytes during StealthDrain, got %d bytes (%x)", len(res.BytesReceived), res.BytesReceived)
	}
	if res.ClosedByRST {
		t.Fatalf("expected clean TCP FIN instead of RST during StealthDrain (elapsed=%v, err=%v)", res.Elapsed, res.Err)
	}
	if res.TimedOut {
		t.Fatalf("probe timed out at %v before StealthDrain completed (maxWait=%v)", res.Elapsed, maxWait)
	}
	if !res.ClosedCleanEOF {
		t.Fatalf("expected clean EOF after StealthDrain, got err=%v elapsed=%v", res.Err, res.Elapsed)
	}
	if minElapsed > 0 && res.Elapsed < minElapsed {
		t.Fatalf("StealthDrain closed too early (oracle risk): elapsed=%v < minElapsed=%v", res.Elapsed, minElapsed)
	}
	return res
}

func t2StartSingleAetherServer(t testing.TB, cfg TopologyConfig) (*BoxInstance, string) {
	t.Helper()
	var logPath string
	if cfg.CaptureLogs {
		logPath = filepath.Join(t.TempDir(), "server.log")
	}
	b, err := StartBoxFromJSONBuilder(t, logPath, func(port uint16) ([]byte, error) {
		return BuildServerJSON(cfg, port, 0, logPath)
	}, cfg.ServerTimeService)
	t2RequireNoErr(t, err, "StartBoxFromJSONBuilder(server)")
	t.Cleanup(func() { _ = b.Close() })
	return b, b.ListenAddr
}

func t2StartSingleAetherClient(t testing.TB, dialHost string, dialPort uint16, cfg TopologyConfig) (*BoxInstance, string) {
	t.Helper()
	var logPath string
	if cfg.CaptureLogs {
		logPath = filepath.Join(t.TempDir(), "client.log")
	}
	b, err := StartBoxFromJSONBuilder(t, logPath, func(port uint16) ([]byte, error) {
		return BuildClientJSON(cfg, port, dialHost, dialPort, 0, logPath)
	}, cfg.ClientTimeService)
	t2RequireNoErr(t, err, "StartBoxFromJSONBuilder(client)")
	t.Cleanup(func() { _ = b.Close() })
	return b, b.ListenAddr
}

func t2DialOutbound(t testing.TB, b *BoxInstance, tag string) adapter.Outbound {
	t.Helper()
	out, loaded := b.Box.Outbound().Outbound(tag)
	t2RequireTrue(t, loaded, "expected outbound %q to be loaded", tag)
	return out
}

// t2CaptureConn wraps a net.Conn so tests can record/withhold exact wire frames
// emitted by SpecClientConn or SpecServerSession without TCP coalescing ambiguity.
type t2CaptureConn struct {
	net.Conn
	mu       sync.Mutex
	capture  bool
	captured [][]byte
}

func (c *t2CaptureConn) Write(p []byte) (int, error) {
	c.mu.Lock()
	capMode := c.capture
	if capMode {
		cp := make([]byte, len(p))
		copy(cp, p)
		c.captured = append(c.captured, cp)
	}
	c.mu.Unlock()
	if capMode {
		return len(p), nil
	}
	return c.Conn.Write(p)
}

func (c *t2CaptureConn) startCapture() {
	c.mu.Lock()
	c.capture = true
	c.captured = nil
	c.mu.Unlock()
}

func (c *t2CaptureConn) stopAndDrain() [][]byte {
	c.mu.Lock()
	c.capture = false
	out := c.captured
	c.captured = nil
	c.mu.Unlock()
	return out
}

// t2BuildModifiedInitBurst constructs a valid FixedHeader+VarHeader AEAD burst
// with arbitrary salt, rawEPK, and epkMaskSalt (used to test low-order EPK & wrong salt).
func t2BuildModifiedInitBurst(t testing.TB, password string, salt, rawEPK, epkMaskSalt [32]byte, targetAddr string, payload []byte) ([]byte, *SpecClientConn) {
	t.Helper()
	creds, err := SpecParseCredentials(password, "")
	t2RequireNoErr(t, err, "SpecParseCredentials")
	maskedEPK := SpecMaskEPK(creds.UPSK, epkMaskSalt, rawEPK)
	initAEAD, err := SpecDeriveClientInitAEAD(creds.UPSK, salt, nil)
	t2RequireNoErr(t, err, "SpecDeriveClientInitAEAD")

	noise := DeterministicBytes(9001, 64)
	addrBytes, err := SpecEncodeSocksaddr(targetAddr)
	t2RequireNoErr(t, err, "SpecEncodeSocksaddr")
	varPlain := append(append(append([]byte{}, noise...), addrBytes...), payload...)

	fh := SpecFixedHeader{
		Version:      SpecProtocolVersion,
		Command:      SpecCommandTCP,
		CipherSuite:  SpecCipherChaCha20Poly1305,
		Reserved:     0,
		TimestampSec: time.Now().Unix(),
		NoiseLen:     uint16(len(noise)),
		VarHeaderLen: uint16(len(varPlain)),
	}
	fhRaw := SpecEncodeFixedHeader(fh)
	prefix := make([]byte, SpecClientPrefixNoEIHSize)
	copy(prefix[0:32], salt[:])
	copy(prefix[32:64], maskedEPK[:])
	n0 := SpecEncodeNonce(0)
	initAEAD.Seal(prefix[64:64], n0[:], fhRaw[:], prefix[0:64])

	n1 := SpecEncodeNonce(1)
	encVar := initAEAD.Seal(nil, n1[:], varPlain, fhRaw[:])
	burst := append(prefix, encVar...)
	return burst, &SpecClientConn{ClientSalt: salt, InitialWire: burst, Fixed: fh}
}

func t2WriteAllBytes(w io.Writer, data []byte) error {
	for len(data) > 0 {
		n, err := w.Write(data)
		if err != nil {
			return err
		}
		if n <= 0 {
			return io.ErrShortWrite
		}
		data = data[n:]
	}
	return nil
}

// t2ReflectiveMITM proxies a connection and reflects the first captured frame
// bytes from one direction directly onto the opposite stream right after prefix.
type t2ReflectiveMITM struct {
	addr     string
	ln       net.Listener
	wg       sync.WaitGroup
	reflectC chan []byte
}

func t2StartReflectiveMITM(t testing.TB, targetAddr string, reflectC2SToS2C bool) *t2ReflectiveMITM {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	t2RequireNoErr(t, err, "t2StartReflectiveMITM listen")
	m := &t2ReflectiveMITM{addr: ln.Addr().String(), ln: ln, reflectC: make(chan []byte, 1)}
	t.Cleanup(func() { _ = ln.Close(); m.wg.Wait() })
	m.wg.Add(1)
	go func() {
		defer m.wg.Done()
		cConn, err := ln.Accept()
		if err != nil {
			return
		}
		defer cConn.Close()
		sConn, err := net.DialTimeout("tcp", targetAddr, 5*time.Second)
		if err != nil {
			return
		}
		defer sConn.Close()

		if reflectC2SToS2C {
			// Forward C2S burst, read 84B server resp prefix to client, then capture next C2S write and reflect back to client!
			var wg sync.WaitGroup
			wg.Add(2)
			s2cReady := make(chan struct{})
			go func() {
				defer wg.Done()
				var resp84 [SpecServerRespPrefixSize]byte
				if _, err := io.ReadFull(sConn, resp84[:]); err != nil {
					return
				}
				_ = t2WriteAllBytes(cConn, resp84[:])
				close(s2cReady)
				reflected := <-m.reflectC
				if len(reflected) > 0 {
					_ = t2WriteAllBytes(cConn, reflected)
				}
			}()
			go func() {
				defer wg.Done()
				buf := make([]byte, 32*1024)
				// Forward burst header first.
				n, err := cConn.Read(buf)
				if err != nil || n == 0 {
					return
				}
				_ = t2WriteAllBytes(sConn, buf[:n])
				select {
				case <-s2cReady:
				case <-time.After(3 * time.Second):
					return
				}
				n2, err := cConn.Read(buf)
				if err != nil || n2 == 0 {
					return
				}
				cp := append([]byte(nil), buf[:n2]...)
				select {
				case m.reflectC <- cp:
				default:
				}
				_ = t2WriteAllBytes(sConn, cp)
				_, _ = io.Copy(sConn, cConn)
			}()
			wg.Wait()
		} else {
			// Forward C2S initial burst -> read S2C 84B + first S2C frame -> reflect S2C frame onto C2S toward server!
			var wg sync.WaitGroup
			wg.Add(2)
			go func() {
				defer wg.Done()
				buf := make([]byte, 32*1024)
				n, err := cConn.Read(buf)
				if err != nil || n == 0 {
					return
				}
				_ = t2WriteAllBytes(sConn, buf[:n])
				reflected := <-m.reflectC
				if len(reflected) > 0 {
					_ = t2WriteAllBytes(sConn, reflected)
				}
				_, _ = io.Copy(sConn, cConn)
			}()
			go func() {
				defer wg.Done()
				var resp84 [SpecServerRespPrefixSize]byte
				if _, err := io.ReadFull(sConn, resp84[:]); err != nil {
					return
				}
				_ = t2WriteAllBytes(cConn, resp84[:])
				buf := make([]byte, 32*1024)
				n, err := sConn.Read(buf)
				if err != nil || n == 0 {
					return
				}
				cp := append([]byte(nil), buf[:n]...)
				select {
				case m.reflectC <- cp:
				default:
				}
				_, _ = io.Copy(cConn, sConn)
			}()
			wg.Wait()
		}
	}()
	return m
}

func t2StartRawResetTarget(t testing.TB, resetAfterReadBytes int) (addr string, count *atomic.Int64, closeFn func()) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	t2RequireNoErr(t, err, "t2StartRawResetTarget listen")
	cnt := &atomic.Int64{}
	var once sync.Once
	var wg sync.WaitGroup
	var mu sync.Mutex
	active := make(map[net.Conn]struct{})
	closed := false

	closeFn = func() {
		once.Do(func() {
			mu.Lock()
			closed = true
			for c := range active {
				_ = c.Close()
			}
			mu.Unlock()
			_ = ln.Close()
			wg.Wait()
		})
	}
	t.Cleanup(closeFn)

	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			cnt.Add(1)
			mu.Lock()
			if closed {
				mu.Unlock()
				_ = c.Close()
				return
			}
			active[c] = struct{}{}
			mu.Unlock()

			wg.Add(1)
			go func(conn net.Conn) {
				defer wg.Done()
				defer func() {
					mu.Lock()
					delete(active, conn)
					mu.Unlock()
					_ = conn.Close()
				}()
				if tc, ok := conn.(*net.TCPConn); ok {
					_ = tc.SetLinger(0)
				}
				if resetAfterReadBytes > 0 {
					_, _ = io.CopyN(io.Discard, conn, int64(resetAfterReadBytes))
				}
			}(c)
		}
	}()
	return ln.Addr().String(), cnt, closeFn
}

// t2StartS2CByteSwapProxy relays TCP to dstAddr while swapping two adjacent S2C
// byte windows [offsetA : offsetA+lenA] and [offsetA+lenA : offsetA+lenA+lenB].
func t2StartS2CByteSwapProxy(t testing.TB, dstAddr string, offsetA, lenA, lenB int) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	t2RequireNoErr(t, err, "t2StartS2CByteSwapProxy listen")
	var wg sync.WaitGroup
	t.Cleanup(func() {
		_ = ln.Close()
		wg.Wait()
	})

	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			cConn, err := ln.Accept()
			if err != nil {
				return
			}
			wg.Add(1)
			go func(c net.Conn) {
				defer wg.Done()
				defer c.Close()
				sConn, dErr := net.DialTimeout("tcp", dstAddr, 3*time.Second)
				if dErr != nil {
					return
				}
				defer sConn.Close()
				var ioWG sync.WaitGroup
				ioWG.Add(2)
				go func() {
					defer ioWG.Done()
					_, _ = io.Copy(sConn, c)
					_ = sConn.Close()
				}()
				go func() {
					defer ioWG.Done()
					if offsetA > 0 {
						head := make([]byte, offsetA)
						if _, rErr := io.ReadFull(sConn, head); rErr != nil {
							_ = c.Close()
							return
						}
						if wErr := t2WriteAllBytes(c, head); wErr != nil {
							return
						}
					}
					win := make([]byte, lenA+lenB)
					if _, rErr := io.ReadFull(sConn, win); rErr != nil {
						_ = c.Close()
						return
					}
					if wErr := t2WriteAllBytes(c, win[lenA:]); wErr != nil {
						return
					}
					if wErr := t2WriteAllBytes(c, win[:lenA]); wErr != nil {
						return
					}
					_, _ = io.Copy(c, sConn)
					_ = c.Close()
				}()
				ioWG.Wait()
			}(cConn)
		}
	}()
	return ln.Addr().String()
}

// t2RelaySpecMockNativeUDP decodes framed CommandUDP datagrams from both 0-RTT
// VarHeader.InitialPayload and subsequent C2S DataFrames, echoing each datagram back.
func t2RelaySpecMockNativeUDP(sess *SpecServerSession) {
	var stream bytes.Buffer
	drainPackets := func() bool {
		for stream.Len() >= 9 {
			raw := stream.Bytes()
			// Expect IPv4 Socksaddr (1+4+2=7B) + 2B BE payload len.
			if raw[0] != 0x01 {
				return false
			}
			pktLen := int(binary.BigEndian.Uint16(raw[7:9]))
			if len(raw) < 9+pktLen {
				break
			}
			pkt := append([]byte(nil), raw[:9+pktLen]...)
			stream.Next(9 + pktLen)
			for off := 0; off < len(pkt); {
				end := off + SpecMaxFrameDataSize
				if end > len(pkt) {
					end = len(pkt)
				}
				if err := sess.WriteS2CFrame(SpecFrameData, 0, pkt[off:end]); err != nil {
					return false
				}
				off = end
			}
		}
		return true
	}

	if len(sess.VarHeader.InitialPayload) > 0 {
		stream.Write(sess.VarHeader.InitialPayload)
		if !drainPackets() {
			return
		}
	}
	for {
		f, err := sess.ReadC2SFrame(6 * time.Second)
		if err != nil {
			return
		}
		if f.FrameType != SpecFrameData {
			continue
		}
		stream.Write(f.Data)
		if !drainPackets() {
			return
		}
	}
}

func t2RunRawServerWithConn(t testing.TB, password string, rawConn net.Conn) ([]byte, error) {
	_ = password
	_ = rawConn
	return nil, nil
}

// t2ExtractWorkflowStepRun extracts the raw bash body of the first step matching
// stepName inside a GitHub Actions workflow file without requiring yaml.v3.
func t2ExtractWorkflowStepRun(t testing.TB, relPath, stepName string) string {
	t.Helper()
	root, err := RepoRoot()
	t2RequireNoErr(t, err, "RepoRoot")
	raw, err := os.ReadFile(filepath.Join(root, relPath))
	t2RequireNoErr(t, err, "read workflow %s", relPath)
	lines := strings.Split(strings.ReplaceAll(string(raw), "\r\n", "\n"), "\n")

	stepIdx := -1
	targetPrefix := "- name: " + stepName
	for i, line := range lines {
		if strings.TrimSpace(line) == targetPrefix {
			stepIdx = i
			break
		}
	}
	if stepIdx < 0 {
		t.Fatalf("step %q not found in %s", stepName, relPath)
	}

	runIdx := -1
	runIndent := 0
	for i := stepIdx + 1; i < len(lines); i++ {
		trimmed := strings.TrimSpace(lines[i])
		if strings.HasPrefix(trimmed, "- name:") && strings.Index(lines[i], "- name:") <= strings.Index(lines[stepIdx], "- name:") {
			break
		}
		if trimmed == "run: |" {
			runIdx = i
			runIndent = strings.Index(lines[i], "run:")
			break
		}
	}
	if runIdx < 0 {
		t.Fatalf("run: | block not found for step %q in %s", stepName, relPath)
	}

	var scriptLines []string
	bodyIndent := -1
	for i := runIdx + 1; i < len(lines); i++ {
		line := lines[i]
		if strings.TrimSpace(line) == "" {
			scriptLines = append(scriptLines, "")
			continue
		}
		leadingSpaces := len(line) - len(strings.TrimLeft(line, " "))
		if leadingSpaces <= runIndent {
			break
		}
		if bodyIndent < 0 {
			bodyIndent = leadingSpaces
		}
		if len(line) >= bodyIndent {
			scriptLines = append(scriptLines, line[bodyIndent:])
		} else {
			scriptLines = append(scriptLines, strings.TrimLeft(line, " "))
		}
	}
	return strings.TrimRight(strings.Join(scriptLines, "\n"), "\n") + "\n"
}

type t2GitSyncSandbox struct {
	RootDir     string
	BinDir      string
	HomeDir     string
	UpstreamGit string
	OriginGit   string
	WorkDir     string
}

func t2NewGitSyncSandbox(t testing.TB) *t2GitSyncSandbox {
	t.Helper()
	tmp := t.TempDir()
	binDir := filepath.Join(tmp, "bin")
	homeDir := filepath.Join(tmp, "home")
	upstreamGit := filepath.Join(tmp, "upstream.git")
	originGit := filepath.Join(tmp, "origin.git")
	workDir := filepath.Join(tmp, "work")
	t2RequireNoErr(t, os.MkdirAll(binDir, 0o755), "mkdir bin")
	t2RequireNoErr(t, os.MkdirAll(homeDir, 0o755), "mkdir home")

	sb := &t2GitSyncSandbox{
		RootDir:     tmp,
		BinDir:      binDir,
		HomeDir:     homeDir,
		UpstreamGit: upstreamGit,
		OriginGit:   originGit,
		WorkDir:     workDir,
	}

	sb.runGit(t, tmp, "init", "--bare", "-b", "main", upstreamGit)
	sb.runGit(t, tmp, "init", "--bare", "-b", "main", originGit)

	// Configure isolated HOME gitconfig rewriting upstream URL to local bare repo.
	gitConfig := fmt.Sprintf(`[user]
	name = Sandbox Bot
	email = sandbox@example.invalid
[init]
	defaultBranch = main
[url "file://%s"]
	insteadOf = https://github.com/SagerNet/sing-box.git
`, upstreamGit)
	t2RequireNoErr(t, os.WriteFile(filepath.Join(homeDir, ".gitconfig"), []byte(gitConfig), 0o644), "write .gitconfig")

	// Bootstrap upstream commit history and push initial base tag v1.14.4.
	seedDir := filepath.Join(tmp, "seed")
	sb.runGit(t, tmp, "clone", upstreamGit, seedDir)
	t2RequireNoErr(t, os.MkdirAll(filepath.Join(seedDir, "option"), 0o755), "mkdir seed option")
	t2RequireNoErr(t, os.MkdirAll(filepath.Join(seedDir, "constant"), 0o755), "mkdir seed constant")
	t2RequireNoErr(t, os.MkdirAll(filepath.Join(seedDir, "docs"), 0o755), "mkdir seed docs")
	t2RequireNoErr(t, os.MkdirAll(filepath.Join(seedDir, ".github", "workflows"), 0o755), "mkdir seed workflows")
	t2RequireNoErr(t, os.WriteFile(filepath.Join(seedDir, "README.md"), []byte("upstream base\n"), 0o644), "write seed README")
	t2RequireNoErr(t, os.WriteFile(filepath.Join(seedDir, "option", "aether.go"), []byte("package option\n// base\n"), 0o644), "write seed option/aether.go")
	t2RequireNoErr(t, os.WriteFile(filepath.Join(seedDir, "constant", "version.go"), []byte("package constant\nvar Version = \"1.14.4\"\n"), 0o644), "write seed constant/version.go")
	t2RequireNoErr(t, os.WriteFile(filepath.Join(seedDir, "docs", "schema.json"), []byte("{}\n"), 0o644), "write seed schema.json")
	t2RequireNoErr(t, os.WriteFile(filepath.Join(seedDir, ".github", "workflows", "docker.yml"), []byte("name: upstream docker\n"), 0o644), "write seed docker.yml")
	t2RequireNoErr(t, os.WriteFile(filepath.Join(seedDir, ".github", "workflows", "linux.yml"), []byte("name: upstream linux\n"), 0o644), "write seed linux.yml")
	t2RequireNoErr(t, os.WriteFile(filepath.Join(seedDir, ".github", "workflows", "build-linux-amd64.yml"), []byte("name: upstream build\n"), 0o644), "write seed build-linux-amd64.yml")
	sb.runGit(t, seedDir, "add", "-A")
	sb.runGit(t, seedDir, "commit", "-m", "v1.14.4 base")
	sb.runGit(t, seedDir, "branch", "-M", "main")
	sb.runGit(t, seedDir, "tag", "v1.14.4")
	sb.runGit(t, seedDir, "push", "-u", "origin", "main", "--tags")

	// Clone origin from seed and create fork dev/aether-v2 branch with fork workflows & changes.
	sb.runGit(t, tmp, "clone", upstreamGit, workDir)
	sb.runGit(t, workDir, "remote", "set-url", "origin", originGit)
	sb.runGit(t, workDir, "checkout", "-b", "dev/aether-v2")
	t2RequireNoErr(t, os.MkdirAll(filepath.Join(workDir, ".github", "workflows"), 0o755), "mkdir fork workflows")
	t2RequireNoErr(t, os.MkdirAll(filepath.Join(workDir, "option"), 0o755), "mkdir fork option")
	t2RequireNoErr(t, os.MkdirAll(filepath.Join(workDir, "constant"), 0o755), "mkdir fork constant")
	t2RequireNoErr(t, os.WriteFile(filepath.Join(workDir, ".github", "workflows", "docker.yml"), []byte("name: fork docker disabled\n"), 0o644), "write fork docker.yml")
	t2RequireNoErr(t, os.WriteFile(filepath.Join(workDir, ".github", "workflows", "linux.yml"), []byte("name: fork linux disabled\n"), 0o644), "write fork linux.yml")
	t2RequireNoErr(t, os.WriteFile(filepath.Join(workDir, ".github", "workflows", "build-linux-amd64.yml"), []byte("name: fork build\n"), 0o644), "write fork build-linux-amd64.yml")
	t2RequireNoErr(t, os.WriteFile(filepath.Join(workDir, ".github", "workflows", "upstream-sync-release.yml"), []byte("name: fork sync\n"), 0o644), "write fork upstream-sync-release.yml")
	t2RequireNoErr(t, os.WriteFile(filepath.Join(workDir, "option", "aether.go"), []byte("package option\n// fork v2 options\nvar ForkLine = 1\n"), 0o644), "write fork option/aether.go")
	t2RequireNoErr(t, os.WriteFile(filepath.Join(workDir, "constant", "version.go"), []byte("package constant\nvar Version = \"1.14.4-Custom-Aether\"\n"), 0o644), "write fork constant/version.go")
	sb.runGit(t, workDir, "add", "-A")
	sb.runGit(t, workDir, "commit", "-m", "fork dev/aether-v2 customizations")
	sb.runGit(t, workDir, "push", "-u", "origin", "dev/aether-v2")

	return sb
}

func (sb *t2GitSyncSandbox) env(extra ...string) []string {
	base := []string{
		"HOME=" + sb.HomeDir,
		"GIT_CONFIG_NOSYSTEM=1",
		"GIT_TERMINAL_PROMPT=0",
		"PATH=" + sb.BinDir + ":" + os.Getenv("PATH"),
	}
	return append(base, extra...)
}

func (sb *t2GitSyncSandbox) runGit(t testing.TB, dir string, args ...string) string {
	t.Helper()
	cmd := exec.Command("git", args...)
	cmd.Dir = dir
	cmd.Env = sb.env()
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git %v in %s failed: %v\n%s", args, dir, err, string(out))
	}
	return string(out)
}

func (sb *t2GitSyncSandbox) runBash(dir, script string, extraEnv ...string) (string, error) {
	cmd := exec.Command("bash", "-c", script)
	cmd.Dir = dir
	cmd.Env = sb.env(extraEnv...)
	out, err := cmd.CombinedOutput()
	return string(out), err
}

func (sb *t2GitSyncSandbox) writeMockBin(t testing.TB, name, script string) {
	t.Helper()
	p := filepath.Join(sb.BinDir, name)
	t2RequireNoErr(t, os.WriteFile(p, []byte("#!/usr/bin/env bash\n"+script+"\n"), 0o755), "write mock %s", name)
}

func t2RunF01(t *testing.T) {
	t.Run("T2-F01-01_VersionExtraArgRejected", func(t *testing.T) {
		res := RunCLI(t, nil, "version", "unexpected-arg")
		if res.ExitCode == 0 {
			t.Fatalf("expected non-zero exit code for extra arg on `version`, got 0 (stdout=%q stderr=%q)", res.Stdout, res.Stderr)
		}
	})

	t.Run("T2-F01-02_VersionUnknownFlagRejected", func(t *testing.T) {
		res := RunCLI(t, nil, "version", "--bad-flag")
		if res.ExitCode == 0 {
			t.Fatalf("expected non-zero exit code for unknown flag on `version`, got 0 (stdout=%q stderr=%q)", res.Stdout, res.Stderr)
		}
	})

	t.Run("T2-F01-03_BoxNewWithoutContextRegistriesErrors", func(t *testing.T) {
		_, err := box.New(box.Options{
			Context: context.Background(),
			Options: option.Options{},
		})
		t2RequireErr(t, err, "box.New without registries")
		if !strings.Contains(strings.ToLower(err.Error()), "registry") {
			t.Fatalf("expected registry error, got: %v", err)
		}
	})

	t.Run("T2-F01-04_BoxStartPortCollisionScopeRollback", func(t *testing.T) {
		occupiedLn, err := net.Listen("tcp", "127.0.0.1:0")
		t2RequireNoErr(t, err, "occupy port")
		defer occupiedLn.Close()
		occupiedPort := uint16(occupiedLn.Addr().(*net.TCPAddr).Port)

		freePort := AllocFreeTCPPort(t)
		rawJSON, err := json.Marshal(map[string]any{
			"log": map[string]any{"disabled": true},
			"inbounds": []any{
				map[string]any{
					"type":        C.TypeSOCKS,
					"tag":         "socks-rollback-test",
					"listen":      "127.0.0.1",
					"listen_port": freePort,
					"reuse_addr":  false,
				},
				map[string]any{
					"type":        C.TypeAether,
					"tag":         "aether-collide",
					"listen":      "127.0.0.1",
					"listen_port": occupiedPort,
					"reuse_addr":  false,
					"password":    "SixteenCharPass01",
				},
			},
			"outbounds": []any{
				map[string]any{"type": C.TypeDirect, "tag": "direct"},
			},
		})
		t2RequireNoErr(t, err, "marshal collision config")

		_, startErr := StartBox(t, rawJSON)
		t2RequireErr(t, startErr, "expected port collision on Start()")

		// Scope rollback must close socks-rollback-test so freePort can immediately be bound again.
		checkLn, rebindErr := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", freePort))
		t2RequireNoErr(t, rebindErr, "expected rollback to release prior inbound port %d", freePort)
		_ = checkLn.Close()

		leaks := t2WaitForNoAetherLeaks(3 * time.Second)
		if len(leaks) > 0 {
			t.Fatalf("unexpected goroutine leaks after Start rollback: %v", leaks)
		}
	})

	t.Run("T2-F01-05_BoxIdempotentDoubleClose", func(t *testing.T) {
		rawJSON, err := BuildServerJSON(TopologyConfig{
			ServerPassword:         "SixteenCharPass02",
			ServerHandshakeTimeout: "1s",
		}, AllocFreeTCPPort(t), 0, "")
		t2RequireNoErr(t, err, "BuildServerJSON")
		inst, err := StartBox(t, rawJSON)
		t2RequireNoErr(t, err, "StartBox")

		t2RequireNoErr(t, inst.Close(), "first Close()")
		_ = inst.Close() // second Close must not panic or deadlock

		var wg sync.WaitGroup
		for i := 0; i < 4; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				_ = inst.Close()
			}()
		}
		wg.Wait()
	})
}

func t2RunF02(t *testing.T) {
	t.Run("T2-F02-01_BuildLinuxResolveVersionTagRefStripV", func(t *testing.T) {
		script := t2ExtractWorkflowStepRun(t, ".github/workflows/build-linux-amd64.yml", "Resolve Version")
		tmp := t.TempDir()
		envFile := filepath.Join(tmp, "github_env")
		cmd := exec.Command("bash", "-c", script)
		cmd.Dir = tmp
		cmd.Env = []string{
			"PATH=" + os.Getenv("PATH"),
			"GITHUB_REF=refs/tags/v1.14.4-Custom-Aether",
			"GITHUB_REF_NAME=v1.14.4-Custom-Aether",
			"GITHUB_ENV=" + envFile,
		}
		out, err := cmd.CombinedOutput()
		t2RequireNoErr(t, err, "Resolve Version failed: %s", string(out))
		envRaw, err := os.ReadFile(envFile)
		t2RequireNoErr(t, err, "read GITHUB_ENV")
		if !strings.Contains(string(envRaw), "VERSION=1.14.4-Custom-Aether") || strings.Contains(string(envRaw), "VERSION=v") {
			t.Fatalf("expected stripped VERSION=1.14.4-Custom-Aether, got:\n%s", string(envRaw))
		}
	})

	t.Run("T2-F02-02_BuildLinuxResolveVersionEmptyVersionGoFails", func(t *testing.T) {
		script := t2ExtractWorkflowStepRun(t, ".github/workflows/build-linux-amd64.yml", "Resolve Version")
		tmp := t.TempDir()
		t2RequireNoErr(t, os.MkdirAll(filepath.Join(tmp, "constant"), 0o755), "mkdir constant")
		t2RequireNoErr(t, os.WriteFile(filepath.Join(tmp, "constant", "version.go"), []byte("package constant\nvar Version = \"\"\n"), 0o644), "write empty version.go")
		envFile := filepath.Join(tmp, "github_env")
		cmd := exec.Command("bash", "-c", script)
		cmd.Dir = tmp
		cmd.Env = []string{
			"PATH=" + os.Getenv("PATH"),
			"GITHUB_REF=refs/heads/main",
			"GITHUB_REF_NAME=main",
			"GITHUB_ENV=" + envFile,
		}
		out, err := cmd.CombinedOutput()
		t2RequireErr(t, err, "expected empty constant/version.go to fail")
		if !strings.Contains(string(out), "::error::Failed to resolve VERSION") {
			t.Fatalf("expected ::error::Failed to resolve VERSION, got:\n%s", string(out))
		}
	})

	t.Run("T2-F02-03_BuildLinuxReleaseGuardedToTagRefsOnly", func(t *testing.T) {
		root, err := RepoRoot()
		t2RequireNoErr(t, err, "RepoRoot")
		raw, err := os.ReadFile(filepath.Join(root, ".github/workflows/build-linux-amd64.yml"))
		t2RequireNoErr(t, err, "read build-linux-amd64.yml")
		lines := strings.Split(string(raw), "\n")
		foundRelease := false
		for i, line := range lines {
			if strings.Contains(line, "softprops/action-gh-release") || strings.Contains(line, "Release Binary") {
				foundRelease = true
				windowStart := i - 3
				if windowStart < 0 {
					windowStart = 0
				}
				windowEnd := i + 5
				if windowEnd > len(lines) {
					windowEnd = len(lines)
				}
				section := strings.Join(lines[windowStart:windowEnd], "\n")
				if strings.Contains(section, "startsWith(github.ref, 'refs/tags/v')") {
					return
				}
			}
		}
		if !foundRelease {
			t.Fatalf("Release Binary step not found in build-linux-amd64.yml")
		}
		t.Fatalf("Release Binary step missing guard `startsWith(github.ref, 'refs/tags/v')`")
	})

	t.Run("T2-F02-04_BuildLinuxPrereleaseTagClassification", func(t *testing.T) {
		root, err := RepoRoot()
		t2RequireNoErr(t, err, "RepoRoot")
		raw, err := os.ReadFile(filepath.Join(root, ".github/workflows/build-linux-amd64.yml"))
		t2RequireNoErr(t, err, "read build-linux-amd64.yml")
		txt := string(raw)
		for _, tok := range []string{"-alpha", "-beta", "-rc", "continue-on-error: true"} {
			if !strings.Contains(txt, tok) {
				t.Fatalf("expected %q in build-linux-amd64.yml", tok)
			}
		}
		evalPrerelease := func(tag string) bool {
			return strings.Contains(tag, "-alpha") || strings.Contains(tag, "-beta") || strings.Contains(tag, "-rc")
		}
		for _, pre := range []string{"v1.15.0-alpha.1", "v1.15.0-beta.2", "v1.15.0-rc.1"} {
			t2RequireTrue(t, evalPrerelease(pre), "expected %s classified as prerelease", pre)
		}
		t2RequireTrue(t, !evalPrerelease("v1.14.4-Custom-Aether"), "expected custom release tag not classified as prerelease")
	})

	t.Run("T2-F02-05_NoWorkflowPushesUpstreamSagernetRegistryOnRelease", func(t *testing.T) {
		root, err := RepoRoot()
		t2RequireNoErr(t, err, "RepoRoot")
		wfDir := filepath.Join(root, ".github", "workflows")
		entries, err := os.ReadDir(wfDir)
		t2RequireNoErr(t, err, "read .github/workflows")

		activeReleaseRe := regexp.MustCompile(`^\s*release\s*:`)
		for _, entry := range entries {
			if entry.IsDir() || (!strings.HasSuffix(entry.Name(), ".yml") && !strings.HasSuffix(entry.Name(), ".yaml")) {
				continue
			}
			raw, err := os.ReadFile(filepath.Join(wfDir, entry.Name()))
			t2RequireNoErr(t, err, "read %s", entry.Name())
			for idx, line := range strings.Split(strings.ReplaceAll(string(raw), "\r\n", "\n"), "\n") {
				if activeReleaseRe.MatchString(line) && !strings.HasPrefix(strings.TrimSpace(line), "#") {
					t.Fatalf("workflow %s has active uncommented `release:` trigger at line %d: %s", entry.Name(), idx+1, line)
				}
			}
		}
	})
}

func t2RunF03(t *testing.T) {
	t.Run("T2-F03-01_GenerateAetherKeyExtraArgFails", func(t *testing.T) {
		res := RunCLI(t, nil, "generate", "aether-key", "extra")
		if res.ExitCode == 0 {
			t.Fatalf("expected non-zero exit code for extra arg on `generate aether-key`")
		}
	})

	t.Run("T2-F03-02_GenerateAetherKeyUnknownFlagFails", func(t *testing.T) {
		res := RunCLI(t, nil, "generate", "aether-key", "--length=16")
		if res.ExitCode == 0 {
			t.Fatalf("expected non-zero exit code for unknown flag on `generate aether-key`")
		}
	})

	t.Run("T2-F03-03_GenerateAetherKeyHelpDoesNotEmitKey", func(t *testing.T) {
		res := RunCLI(t, nil, "generate", "aether-key", "--help")
		t2RequireTrue(t, res.ExitCode == 0, "expected --help exit 0, got %d (%s)", res.ExitCode, res.Stderr)
		t2RequireTrue(t, strings.Contains(strings.ToLower(res.Stdout), "usage"), "expected Usage in help stdout: %s", res.Stdout)
		for _, line := range strings.Split(res.Stdout, "\n") {
			trimmed := strings.TrimSpace(line)
			if len(trimmed) == 44 && strings.HasSuffix(trimmed, "=") {
				if dec, err := base64.StdEncoding.DecodeString(trimmed); err == nil && len(dec) == 32 {
					t.Fatalf("--help unexpectedly emitted generated 32B key line: %q", trimmed)
				}
			}
		}
	})

	t.Run("T2-F03-04_GenerateAetherKeyBrokenStdoutPipeFails", func(t *testing.T) {
		bin := CLIBinaryPath(t)
		r, w, err := os.Pipe()
		t2RequireNoErr(t, err, "os.Pipe")
		_ = r.Close() // Force EPIPE / SIGPIPE on write.

		cmd := exec.Command(bin, "generate", "aether-key")
		cmd.Stdout = w
		var stderr bytes.Buffer
		cmd.Stderr = &stderr
		runErr := cmd.Run()
		_ = w.Close()
		if runErr == nil {
			t.Fatalf("expected non-zero exit or SIGPIPE failure on broken stdout pipe, got exit 0")
		}
	})

	t.Run("T2-F03-05_GenerateAetherKeyTruncatedTo15CharsRejectedInCheck", func(t *testing.T) {
		key := GenerateAetherKeyCLI(t)
		t2RequireTrue(t, len(key) >= 16, "unexpected CLI key length %d", len(key))
		weak := key[:15]
		rawJSON, err := BuildServerJSON(TopologyConfig{ServerPassword: weak}, AllocFreeTCPPort(t), 0, "")
		t2RequireNoErr(t, err, "BuildServerJSON")

		t2RequireErr(t, CheckConfigInProcess(rawJSON), "CheckConfigInProcess must reject 15-char sliced key")
		res := CheckConfigCLI(t, rawJSON)
		t2RequireTrue(t, res.ExitCode != 0, "CLI check must reject 15-char sliced key, got 0")
	})
}

func t2RunF04(t *testing.T) {
	t.Run("T2-F04-01_GenerateAetherKeypairExtraArgFails", func(t *testing.T) {
		res := RunCLI(t, nil, "generate", "aether-keypair", "arg1")
		if res.ExitCode == 0 {
			t.Fatalf("expected non-zero exit code for extra arg on `generate aether-keypair`")
		}
	})

	t.Run("T2-F04-02_GenerateAetherKeypairUnknownFlagFails", func(t *testing.T) {
		res := RunCLI(t, nil, "generate", "aether-keypair", "--json")
		if res.ExitCode == 0 {
			t.Fatalf("expected non-zero exit code for unknown flag on `generate aether-keypair`")
		}
	})

	t.Run("T2-F04-03_GenerateAetherKeypairHelpOutput", func(t *testing.T) {
		res := RunCLI(t, nil, "generate", "aether-keypair", "--help")
		t2RequireTrue(t, res.ExitCode == 0, "expected --help exit 0, got %d (%s)", res.ExitCode, res.Stderr)
		t2RequireTrue(t, !strings.Contains(res.Stdout, "PrivateKey:"), "--help must not emit PrivateKey line")
		t2RequireTrue(t, !strings.Contains(res.Stdout, "PublicKey:"), "--help must not emit PublicKey line")
	})

	t.Run("T2-F04-04_MismatchedKeypairFailsHandshakeStealthDrain", func(t *testing.T) {
		priv1, _ := GenerateAetherKeyPairCLI(t)
		_, pub2 := GenerateAetherKeyPairCLI(t)
		pass := "MatchPassphrase16A"

		echo := StartTCPEchoTarget(t)
		topo := StartTopology(t, TopologyConfig{
			ServerPassword:         pass,
			ServerPrivateKey:       priv1,
			ServerHandshakeTimeout: "800ms",
			ClientPassword:         pass,
			ClientServerPublicKey:  pub2,
		})

		err := t2EchoTCPViaSOCKS5(t, topo.ClientProxyAddr(), echo.Addr(), []byte("must-not-succeed"))
		t2RequireErr(t, err, "mismatched static X25519 keypair must fail handshake")
		t2RequireTrue(t, echo.Connections() == 0, "target must receive 0 connections, got %d", echo.Connections())

		// Confirm StealthDrain directly on server port with half-open mismatched burst.
		burst, _, bErr := BuildSpecClientInitialBurst(SpecDialOptions{
			Password:        pass,
			ServerPublicKey: pub2,
			TargetAddr:      echo.Addr(),
		})
		t2RequireNoErr(t, bErr, "BuildSpecClientInitialBurst")
		t2AssertStealthDrain(t, topo.ServerAddr(), burst, false, 2800*time.Millisecond, 12*time.Second)
	})

	t.Run("T2-F04-05_UnstrippedLabelInKeypairConfigRejected", func(t *testing.T) {
		priv, pub := GenerateAetherKeyPairCLI(t)
		srvJSON, err := BuildServerJSON(TopologyConfig{
			ServerPassword:   "ValidPasswordFor0405",
			ServerPrivateKey: "PrivateKey: " + priv,
		}, AllocFreeTCPPort(t), 0, "")
		t2RequireNoErr(t, err, "BuildServerJSON")
		t2RequireErr(t, CheckConfigInProcess(srvJSON), "expected labeled PrivateKey rejected")
		res := CheckConfigCLI(t, srvJSON)
		t2RequireTrue(t, res.ExitCode != 0, "CLI check must reject labeled PrivateKey")

		cliJSON, err := BuildClientJSON(TopologyConfig{
			ClientPassword:        "ValidPasswordFor0405",
			ClientServerPublicKey: "PublicKey: " + pub,
		}, AllocFreeTCPPort(t), "127.0.0.1", AllocFreeTCPPort(t), 0, "")
		t2RequireNoErr(t, err, "BuildClientJSON")
		t2RequireErr(t, CheckConfigInProcess(cliJSON), "expected labeled PublicKey rejected")
		res2 := CheckConfigCLI(t, cliJSON)
		t2RequireTrue(t, res2.ExitCode != 0, "CLI check must reject labeled PublicKey")
	})
}

func t2RunF05(t *testing.T) {
	t.Run("T2-F05-01_EmptyPasswordAndKeyRejected", func(t *testing.T) {
		srvJSON, err := BuildServerJSON(TopologyConfig{}, AllocFreeTCPPort(t), 0, "")
		t2RequireNoErr(t, err, "BuildServerJSON")
		t2RequireErr(t, CheckConfigInProcess(srvJSON), "empty inbound credentials")
		t2RequireTrue(t, CheckConfigCLI(t, srvJSON).ExitCode != 0, "CLI empty inbound credentials")

		cliJSON, err := BuildClientJSON(TopologyConfig{}, AllocFreeTCPPort(t), "127.0.0.1", AllocFreeTCPPort(t), 0, "")
		t2RequireNoErr(t, err, "BuildClientJSON")
		t2RequireErr(t, CheckConfigInProcess(cliJSON), "empty outbound credentials")
		t2RequireTrue(t, CheckConfigCLI(t, cliJSON).ExitCode != 0, "CLI empty outbound credentials")
	})

	t.Run("T2-F05-02_FifteenCharPassphraseRejected", func(t *testing.T) {
		weak := "123456789012345"
		exact := "1234567890123456"

		srvWeak, err := BuildServerJSON(TopologyConfig{ServerPassword: weak}, AllocFreeTCPPort(t), 0, "")
		t2RequireNoErr(t, err, "BuildServerJSON weak")
		t2RequireErr(t, CheckConfigInProcess(srvWeak), "15-char server password must fail")
		t2RequireTrue(t, CheckConfigCLI(t, srvWeak).ExitCode != 0, "CLI 15-char server password")

		cliWeak, err := BuildClientJSON(TopologyConfig{ClientPassword: weak}, AllocFreeTCPPort(t), "127.0.0.1", AllocFreeTCPPort(t), 0, "")
		t2RequireNoErr(t, err, "BuildClientJSON weak")
		t2RequireErr(t, CheckConfigInProcess(cliWeak), "15-char client password must fail")

		srvExact, err := BuildServerJSON(TopologyConfig{ServerPassword: exact}, AllocFreeTCPPort(t), 0, "")
		t2RequireNoErr(t, err, "BuildServerJSON exact")
		t2RequireNoErr(t, CheckConfigInProcess(srvExact), "16-char password boundary must pass")
	})

	t.Run("T2-F05-03_AllZero32ByteBase64KeyRejected", func(t *testing.T) {
		allZeroStd := base64.StdEncoding.EncodeToString(make([]byte, 32))
		allZeroRaw := base64.RawStdEncoding.EncodeToString(make([]byte, 32))
		for _, badKey := range []string{allZeroStd, allZeroRaw} {
			srvJSON, err := BuildServerJSON(TopologyConfig{ServerKey: badKey}, AllocFreeTCPPort(t), 0, "")
			t2RequireNoErr(t, err, "BuildServerJSON")
			t2RequireErr(t, CheckConfigInProcess(srvJSON), "all-zero server key %s", badKey)

			cliJSON, err := BuildClientJSON(TopologyConfig{ClientPassword: badKey}, AllocFreeTCPPort(t), "127.0.0.1", AllocFreeTCPPort(t), 0, "")
			t2RequireNoErr(t, err, "BuildClientJSON")
			t2RequireErr(t, CheckConfigInProcess(cliJSON), "all-zero client key %s", badKey)
		}
	})

	t.Run("T2-F05-04_Base64WrongDecodedLength31BAnd33BHandling", func(t *testing.T) {
		b64Len31 := base64.StdEncoding.EncodeToString(DeterministicBytes(5041, 31))  // 44 chars, decodes 31B -> Argon2id
		b64Len11 := base64.StdEncoding.EncodeToString(DeterministicBytes(5042, 11))  // 16 chars, decodes 11B -> Argon2id
		b64Len33 := base64.StdEncoding.EncodeToString(DeterministicBytes(5043, 33))  // 44 chars, decodes 33B -> Argon2id
		b64Len9 := base64.RawStdEncoding.EncodeToString(DeterministicBytes(5044, 9)) // 12 chars (<16), decodes 9B -> rejected

		badJSON, err := BuildServerJSON(TopologyConfig{ServerPassword: b64Len9}, AllocFreeTCPPort(t), 0, "")
		t2RequireNoErr(t, err, "BuildServerJSON 9B")
		t2RequireErr(t, CheckConfigInProcess(badJSON), "12-char 9B base64 must be rejected")

		echo := StartTCPEchoTarget(t)
		for _, fallbackSecret := range []string{b64Len31, b64Len11, b64Len33} {
			topo := StartTopology(t, TopologyConfig{
				ServerPassword: fallbackSecret,
				ClientPassword: fallbackSecret,
				DisableWireTap: true,
			})
			t2RequireNoErr(t, t2EchoTCPViaSOCKS5(t, topo.ClientProxyAddr(), echo.Addr(), []byte("argon-fallback-ok")), "Argon2id fallback for %q", fallbackSecret)
			topo.Close()
		}
	})

	t.Run("T2-F05-05_MismatchedClientServerPassphraseStealthDrain", func(t *testing.T) {
		echo := StartTCPEchoTarget(t)
		topo := StartTopology(t, TopologyConfig{
			ServerPassword:         "CorrectHorseBattery1",
			ServerHandshakeTimeout: "800ms",
			ClientPassword:         "CorrectHorseBattery2",
		})

		err := t2EchoTCPViaSOCKS5(t, topo.ClientProxyAddr(), echo.Addr(), []byte("mismatch"))
		t2RequireErr(t, err, "mismatched passphrases must fail")
		t2RequireTrue(t, echo.Connections() == 0, "expected 0 target connections")

		burst, _, bErr := BuildSpecClientInitialBurst(SpecDialOptions{
			Password:   "CorrectHorseBattery2",
			TargetAddr: echo.Addr(),
		})
		t2RequireNoErr(t, bErr, "BuildSpecClientInitialBurst")
		t2AssertStealthDrain(t, topo.ServerAddr(), burst, false, 2800*time.Millisecond, 12*time.Second)
	})

	t.Run("T2-F05-06_ConflictingPasswordAndKeyFieldsRejected", func(t *testing.T) {
		srvJSON, err := BuildServerJSON(TopologyConfig{
			ServerPassword: "SixteenCharPassA",
			ServerKey:      "SixteenCharPassB",
		}, AllocFreeTCPPort(t), 0, "")
		t2RequireNoErr(t, err, "BuildServerJSON")
		errIn := CheckConfigInProcess(srvJSON)
		t2RequireErr(t, errIn, "conflicting server password and key")

		cliJSON, err := BuildClientJSON(TopologyConfig{
			ClientPassword: "SixteenCharPassA",
			ClientKey:      "SixteenCharPassB",
		}, AllocFreeTCPPort(t), "127.0.0.1", AllocFreeTCPPort(t), 0, "")
		t2RequireNoErr(t, err, "BuildClientJSON")
		errOut := CheckConfigInProcess(cliJSON)
		t2RequireErr(t, errOut, "conflicting client password and key")
		t2RequireTrue(t, CheckConfigCLI(t, cliJSON).ExitCode != 0, "CLI check conflicting password/key")
	})
}

func t2RunF06(t *testing.T) {
	pass := "Feature06HybridKEMPass"

	t.Run("T2-F06-01_BitFlipInMaskedClientEPKFailsAAD", func(t *testing.T) {
		echo := StartTCPEchoTarget(t)
		_, srvAddr := t2StartSingleAetherServer(t, TopologyConfig{
			ServerPassword:         pass,
			ServerHandshakeTimeout: "700ms",
		})

		burst, _, err := BuildSpecClientInitialBurst(SpecDialOptions{
			Password:   pass,
			TargetAddr: echo.Addr(),
		})
		t2RequireNoErr(t, err, "BuildSpecClientInitialBurst")
		burst[40] ^= 0x01 // Flip bit inside MaskedClientEPK[32:64] covered by FixedHeader AAD.

		t2AssertStealthDrain(t, srvAddr, burst, false, 2800*time.Millisecond, 12*time.Second)
		t2RequireTrue(t, echo.Connections() == 0, "flipped client EPK must not reach target")
	})

	t.Run("T2-F06-02_BitFlipInMaskedServerEPKFailsClientAAD", func(t *testing.T) {
		echo := StartTCPEchoTarget(t)
		topo := StartTopology(t, TopologyConfig{
			ServerPassword: pass,
			ClientPassword: pass,
		})
		topo.Tap.InstallSingleBitFlip(0, DirS2C, 63, 0x80) // Flip bit in MaskedServerEPK[32:64]

		err := t2EchoTCPViaSOCKS5(t, topo.ClientProxyAddr(), echo.Addr(), []byte("s2c-epk-flip"))
		t2RequireErr(t, err, "client must reject S2C response with flipped masked server EPK")
	})

	t.Run("T2-F06-03_AllZeroLowOrderClientEPKRejected", func(t *testing.T) {
		echo := StartTCPEchoTarget(t)
		_, srvAddr := t2StartSingleAetherServer(t, TopologyConfig{
			ServerPassword:         pass,
			ServerHandshakeTimeout: "700ms",
		})

		var salt [32]byte
		copy(salt[:], DeterministicBytes(603, 32))
		var lowOrderEPK [32]byte // all-zero RFC 7748 low-order X25519 point
		burst, _ := t2BuildModifiedInitBurst(t, pass, salt, lowOrderEPK, salt, echo.Addr(), []byte("low-order"))

		t2AssertStealthDrain(t, srvAddr, burst, false, 2800*time.Millisecond, 12*time.Second)
		t2RequireTrue(t, echo.Connections() == 0, "low-order client EPK must not connect target")
	})

	t.Run("T2-F06-04_AllZeroLowOrderServerEPKRejectedByClient", func(t *testing.T) {
		mockSrv := StartSpecMockServer(t, SpecServerOptions{
			Password:              pass,
			SendLowOrderServerEPK: true,
		})
		_, proxyAddr := t2StartSingleAetherClient(t, "127.0.0.1", mockSrv.Port(), TopologyConfig{
			ClientPassword: pass,
		})

		err := t2EchoTCPViaSOCKS5(t, proxyAddr, "127.0.0.1:80", []byte("reject-low-order-server-epk"))
		t2RequireErr(t, err, "client must reject all-zero server EPK")
	})

	t.Run("T2-F06-05_WrongSaltUsedForEPKMaskFailsSessionRatchet", func(t *testing.T) {
		echo := StartTCPEchoTarget(t)
		_, srvAddr := t2StartSingleAetherServer(t, TopologyConfig{
			ServerPassword:         pass,
			ServerHandshakeTimeout: "700ms",
		})

		var salt, wrongSalt [32]byte
		copy(salt[:], DeterministicBytes(6051, 32))
		copy(wrongSalt[:], DeterministicBytes(6052, 32))

		// Generate real keypair so client knows private key, but mask EPK using wrongSalt.
		decodeKey := func(s string) ([]byte, error) {
			for _, enc := range []*base64.Encoding{base64.StdEncoding, base64.RawURLEncoding, base64.RawStdEncoding, base64.URLEncoding} {
				if b, err := enc.DecodeString(s); err == nil {
					return b, nil
				}
			}
			return nil, fmt.Errorf("invalid base64 key %q", s)
		}
		privB64, pubB64 := GenerateX25519KeyPairBase64(t)
		privBytes, err := decodeKey(privB64)
		t2RequireNoErr(t, err, "decode gen priv")
		pubBytes, err := decodeKey(pubB64)
		t2RequireNoErr(t, err, "decode gen pub")
		clientPriv, err := ecdh.X25519().NewPrivateKey(privBytes)
		t2RequireNoErr(t, err, "parse client priv")
		var rawEPK [32]byte
		copy(rawEPK[:], pubBytes)

		burst, sc := t2BuildModifiedInitBurst(t, pass, salt, rawEPK, wrongSalt, echo.Addr(), []byte("wrong-salt-epk"))
		conn, err := net.DialTimeout("tcp", srvAddr, 5*time.Second)
		t2RequireNoErr(t, err, "dial server")
		defer conn.Close()
		t2RequireNoErr(t, t2WriteAllBytes(conn, burst), "write modified burst")

		// Either server stealth-drains (if unmasked EPK is low-order/rejected) OR server sends ServerResp
		// derived from a completely different unmasked EPK point so sc fails RespHeader verification.
		_ = conn.SetReadDeadline(time.Now().Add(4 * time.Second))
		var respPrefix [SpecServerRespPrefixSize]byte
		_, readErr := io.ReadFull(conn, respPrefix[:])
		if readErr == nil {
			sc.Conn = conn
			// Attempting full RespHeader verification against our client secret fails because EPK mismatch breaks ss_eph.
			creds, _ := SpecParseCredentials(pass, "")
			var srvSalt, maskedSrvEPK [32]byte
			copy(srvSalt[:], respPrefix[0:32])
			copy(maskedSrvEPK[:], respPrefix[32:64])
			srvPub, uErr := SpecUnmaskEPK(creds.UPSK, srvSalt, maskedSrvEPK)
			if uErr == nil && srvPub != nil {
				ssEph, eErr := clientPriv.ECDH(srvPub)
				t2RequireNoErr(t, eErr, "ECDH with server pub")
				var shared [32]byte
				copy(shared[:], ssEph)
				keys, _ := SpecDeriveSessionKeys(creds.UPSK, salt, srvSalt, shared, nil)
				respAEAD, _ := chacha20poly1305.New(keys.RespKey[:])
				var aad96 [96]byte
				copy(aad96[0:32], salt[:])
				copy(aad96[32:64], srvSalt[:])
				copy(aad96[64:96], maskedSrvEPK[:])
				n0 := SpecEncodeNonce(0)
				_, openErr := respAEAD.Open(nil, n0[:], respPrefix[64:84], aad96[:])
				t2RequireErr(t, openErr, "expected RespHeader tag verification to fail under mismatched EPK mask salt")
			}
		}
	})
}

func t2RunF07(t *testing.T) {
	pass := "Feature07StaticKeyPass"

	t.Run("T2-F07-01_InvalidBase64ServerPrivateKeyRejected", func(t *testing.T) {
		b16 := base64.StdEncoding.EncodeToString(DeterministicBytes(701, 16))
		for _, badPriv := range []string{"not-valid-base64!!!", b16} {
			srvJSON, err := BuildServerJSON(TopologyConfig{
				ServerPassword:   pass,
				ServerPrivateKey: badPriv,
			}, AllocFreeTCPPort(t), 0, "")
			t2RequireNoErr(t, err, "BuildServerJSON")
			t2RequireErr(t, CheckConfigInProcess(srvJSON), "invalid private_key %q", badPriv)
			t2RequireTrue(t, CheckConfigCLI(t, srvJSON).ExitCode != 0, "CLI invalid private_key %q", badPriv)
		}
	})

	t.Run("T2-F07-02_InvalidBase64ClientPublicKeyRejected", func(t *testing.T) {
		b31 := base64.StdEncoding.EncodeToString(DeterministicBytes(702, 31))
		for _, badPub := range []string{"short", b31} {
			cliJSON, err := BuildClientJSON(TopologyConfig{
				ClientPassword:        pass,
				ClientServerPublicKey: badPub,
			}, AllocFreeTCPPort(t), "127.0.0.1", AllocFreeTCPPort(t), 0, "")
			t2RequireNoErr(t, err, "BuildClientJSON")
			t2RequireErr(t, CheckConfigInProcess(cliJSON), "invalid public_key %q", badPub)
			t2RequireTrue(t, CheckConfigCLI(t, cliJSON).ExitCode != 0, "CLI invalid public_key %q", badPub)
		}
	})

	t.Run("T2-F07-03_AllZeroClientPublicKeyLowOrderRejected", func(t *testing.T) {
		allZeroPub := base64.StdEncoding.EncodeToString(make([]byte, 32))
		cliJSON, err := BuildClientJSON(TopologyConfig{
			ClientPassword:        pass,
			ClientServerPublicKey: allZeroPub,
		}, AllocFreeTCPPort(t), "127.0.0.1", AllocFreeTCPPort(t), 0, "")
		t2RequireNoErr(t, err, "BuildClientJSON")

		if checkErr := CheckConfigInProcess(cliJSON); checkErr == nil {
			// If accepted into runtime construction, handshake MUST reject low-order point without establishing a session.
			priv, _ := GenerateAetherKeyPairCLI(t)
			echo := StartTCPEchoTarget(t)
			topo := StartTopology(t, TopologyConfig{
				ServerPassword:        pass,
				ServerPrivateKey:      priv,
				ClientPassword:        pass,
				ClientServerPublicKey: allZeroPub,
			})
			dialErr := t2EchoTCPViaSOCKS5(t, topo.ClientProxyAddr(), echo.Addr(), []byte("should-fail"))
			t2RequireErr(t, dialErr, "all-zero public_key must fail ECDH")
			t2RequireTrue(t, echo.Connections() == 0, "expected 0 target connections")
		}
	})

	t.Run("T2-F07-04_ServerHasPrivateKeyButClientOmitsPublicKey", func(t *testing.T) {
		priv, _ := GenerateAetherKeyPairCLI(t)
		echo := StartTCPEchoTarget(t)
		topo := StartTopology(t, TopologyConfig{
			ServerPassword:         pass,
			ServerPrivateKey:       priv,
			ServerHandshakeTimeout: "700ms",
			ClientPassword:         pass,
			ClientServerPublicKey:  "",
		})

		err := t2EchoTCPViaSOCKS5(t, topo.ClientProxyAddr(), echo.Addr(), []byte("omit-pub"))
		t2RequireErr(t, err, "omitted client public_key must fail against server static private_key")
		t2RequireTrue(t, echo.Connections() == 0, "target must receive 0 connections")

		burst, _, bErr := BuildSpecClientInitialBurst(SpecDialOptions{
			Password:   pass,
			TargetAddr: echo.Addr(),
		})
		t2RequireNoErr(t, bErr, "BuildSpecClientInitialBurst")
		t2AssertStealthDrain(t, topo.ServerAddr(), burst, false, 2800*time.Millisecond, 12*time.Second)
	})

	t.Run("T2-F07-05_ClientHasPublicKeyButServerOmitsPrivateKey", func(t *testing.T) {
		_, pub := GenerateAetherKeyPairCLI(t)
		echo := StartTCPEchoTarget(t)
		topo := StartTopology(t, TopologyConfig{
			ServerPassword:         pass,
			ServerPrivateKey:       "",
			ServerHandshakeTimeout: "700ms",
			ClientPassword:         pass,
			ClientServerPublicKey:  pub,
		})

		err := t2EchoTCPViaSOCKS5(t, topo.ClientProxyAddr(), echo.Addr(), []byte("extra-pub"))
		t2RequireErr(t, err, "extra client public_key must fail against server without private_key")
		t2RequireTrue(t, echo.Connections() == 0, "target must receive 0 connections")

		burst, _, bErr := BuildSpecClientInitialBurst(SpecDialOptions{
			Password:        pass,
			ServerPublicKey: pub,
			TargetAddr:      echo.Addr(),
		})
		t2RequireNoErr(t, bErr, "BuildSpecClientInitialBurst")
		t2AssertStealthDrain(t, topo.ServerAddr(), burst, false, 2800*time.Millisecond, 12*time.Second)
	})
}

func t2RunF08(t *testing.T) {
	pass := "Feature08RatchetNonce"

	t.Run("T2-F08-01_BitFlipInClientSaltBreaksHandshake", func(t *testing.T) {
		echo := StartTCPEchoTarget(t)
		topo := StartTopology(t, TopologyConfig{
			ServerPassword:         pass,
			ServerHandshakeTimeout: "700ms",
			ClientPassword:         pass,
		})
		topo.Tap.InstallSingleBitFlip(0, DirC2S, 5, 0x01)

		err := t2EchoTCPViaSOCKS5(t, topo.ClientProxyAddr(), echo.Addr(), []byte("salt-c2s-flip"))
		t2RequireErr(t, err, "bit flip in ClientSalt must fail")
		t2RequireTrue(t, echo.Connections() == 0, "target must receive 0 connections")
	})

	t.Run("T2-F08-02_BitFlipInServerSaltBreaksClientRatchet", func(t *testing.T) {
		echo := StartTCPEchoTarget(t)
		topo := StartTopology(t, TopologyConfig{
			ServerPassword: pass,
			ClientPassword: pass,
		})
		topo.Tap.InstallSingleBitFlip(0, DirS2C, 5, 0x01)

		err := t2EchoTCPViaSOCKS5(t, topo.ClientProxyAddr(), echo.Addr(), []byte("salt-s2c-flip"))
		t2RequireErr(t, err, "bit flip in ServerSalt must fail client ratchet")
	})

	t.Run("T2-F08-03_CrossDirectionFrameReflectionAttackRejected", func(t *testing.T) {
		// Direction 1: Reflect Client FrameData back onto S2C stream right after 84B prefix toward real Box client.
		mockSrv := StartSpecMockServer(t, SpecServerOptions{
			Password: pass,
			OnSession: func(sess *SpecServerSession) {
				_, _ = sess.ReadC2SFrame(5 * time.Second)
				time.Sleep(2 * time.Second)
			},
		})
		mitmC2S := t2StartReflectiveMITM(t, mockSrv.Addr(), true)
		_, portStr, err := net.SplitHostPort(mitmC2S.addr)
		t2RequireNoErr(t, err, "split host port")
		p64, _ := strconv.ParseUint(portStr, 10, 16)
		_, proxyAddr := t2StartSingleAetherClient(t, "127.0.0.1", uint16(p64), TopologyConfig{
			ClientPassword:       pass,
			ClientDisableShaping: true,
		})

		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		c, err := DialSOCKS5TCP(ctx, proxyAddr, "127.0.0.1:80")
		t2RequireNoErr(t, err, "DialSOCKS5TCP")
		defer c.Close()
		_ = c.SetDeadline(time.Now().Add(4 * time.Second))
		_, _ = c.Write([]byte("reflect-c2s-frame-0"))
		_, _ = c.Write([]byte("trigger-frame-1"))
		bufRead := make([]byte, 256)
		_, rErr := c.Read(bufRead)
		t2RequireErr(t, rErr, "client must reject reflected C2S ciphertext on S2C stream")

		// Direction 2: Reflect Server S2C FrameData back onto C2S stream toward real Box server.
		echo := StartTCPEchoTarget(t)
		_, srvAddr := t2StartSingleAetherServer(t, TopologyConfig{ServerPassword: pass})
		mitmS2C := t2StartReflectiveMITM(t, srvAddr, false)
		sc, err := DialSpecClient(ctx, mitmS2C.addr, SpecDialOptions{
			Password:       pass,
			TargetAddr:     echo.Addr(),
			InitialPayload: []byte("ping-reflect-s2c"),
		})
		t2RequireNoErr(t, err, "DialSpecClient")
		defer sc.Close()
		_, err = sc.ReadServerResp(4 * time.Second)
		t2RequireNoErr(t, err, "ReadServerResp")
		// Wait briefly for MITM to reflect S2C frame back onto C2S; subsequent reads/writes must break.
		_, _ = sc.ReadFrame(2 * time.Second)
		_ = sc.WriteFrame(SpecFrameData, 0, []byte("after-s2c-reflect"))
		_, err = sc.ReadFrame(2 * time.Second)
		t2RequireErr(t, err, "server must close on reflected S2C frame")
	})

	t.Run("T2-F08-04_OutOfOrderFrameSequenceSwapRejected", func(t *testing.T) {
		// Server-side check: swap Frame #1 and Frame #2 C2S via t2CaptureConn.
		echo := StartTCPEchoTarget(t)
		_, srvAddr := t2StartSingleAetherServer(t, TopologyConfig{ServerPassword: pass})
		ctx, cancel := context.WithTimeout(context.Background(), 6*time.Second)
		defer cancel()
		sc, err := DialSpecClient(ctx, srvAddr, SpecDialOptions{
			Password:   pass,
			TargetAddr: echo.Addr(),
		})
		t2RequireNoErr(t, err, "DialSpecClient")
		defer sc.Close()
		_, err = sc.ReadServerResp(4 * time.Second)
		t2RequireNoErr(t, err, "ReadServerResp")

		rec := &t2CaptureConn{Conn: sc.Conn}
		sc.Conn = rec
		// Frame #0 normally delivered.
		t2RequireNoErr(t, sc.WriteFrame(SpecFrameData, 0, []byte("seq-0")), "write seq 0")
		f0, err := sc.ReadNextDataFrame(4 * time.Second)
		t2RequireNoErr(t, err, "read seq 0 echo")
		t2RequireTrue(t, string(f0.Data) == "seq-0", "expected seq-0")

		rec.startCapture()
		t2RequireNoErr(t, sc.WriteFrame(SpecFrameData, 0, []byte("seq-1")), "seal seq 1")
		t2RequireNoErr(t, sc.WriteFrame(SpecFrameData, 0, []byte("seq-2")), "seal seq 2")
		frames := rec.stopAndDrain()
		t2RequireTrue(t, len(frames) == 2, "expected 2 captured wire frames, got %d", len(frames))

		// Deliver Frame #2 BEFORE Frame #1 -> nonce=1 AEAD tag check fails immediately!
		t2RequireNoErr(t, t2WriteAllBytes(rec.Conn, frames[1]), "send swapped frame 2")
		t2RequireNoErr(t, t2WriteAllBytes(rec.Conn, frames[0]), "send swapped frame 1")
		t2RequireNoErr(t, sc.ExpectPeerClose(2*time.Second), "expected server to terminate connection on swapped C2S sequence")

		// Client-side check: swap S2C Frame #1 and #2 from SpecMockServer via wire swap proxy (no sess.Conn mutation).
		mockSrv := StartSpecMockServer(t, SpecServerOptions{
			Password: pass,
			OnSession: func(sess *SpecServerSession) {
				if len(sess.VarHeader.InitialPayload) == 0 {
					_, _ = sess.ReadC2SFrame(4 * time.Second)
				}
				_ = sess.WriteS2CFrame(SpecFrameData, 0, []byte("s2c-0"))
				_ = sess.WriteS2CFrame(SpecFrameData, 0, []byte("s2c-1"))
				_ = sess.WriteS2CFrame(SpecFrameData, 0, []byte("s2c-2"))
			},
		})
		const s2cFrameLen = SpecEncryptedLengthSize + 2 + 5 + 16 // 41B per "s2c-X" frame
		swapAddr := t2StartS2CByteSwapProxy(t, mockSrv.Addr(), SpecServerRespPrefixSize+s2cFrameLen, s2cFrameLen, s2cFrameLen)
		_, swapPortStr, err := net.SplitHostPort(swapAddr)
		t2RequireNoErr(t, err, "split swap addr")
		swapPort64, _ := strconv.ParseUint(swapPortStr, 10, 16)
		_, proxyAddr := t2StartSingleAetherClient(t, "127.0.0.1", uint16(swapPort64), TopologyConfig{
			ClientPassword:       pass,
			ClientDisableShaping: true,
		})
		sConn, err := DialSOCKS5TCP(ctx, proxyAddr, "127.0.0.1:80")
		t2RequireNoErr(t, err, "DialSOCKS5TCP client swap check")
		defer sConn.Close()
		_ = sConn.SetDeadline(time.Now().Add(4 * time.Second))
		_, _ = sConn.Write([]byte("go"))
		bufOut := make([]byte, 256)
		var total []byte
		for {
			n, rErr := sConn.Read(bufOut)
			if n > 0 {
				total = append(total, bufOut[:n]...)
			}
			if rErr != nil {
				break
			}
		}
		t2RequireTrue(t, !bytes.Contains(total, []byte("s2c-1")) && !bytes.Contains(total, []byte("s2c-2")), "swapped S2C frames must not decrypt: %q", string(total))
	})

	t.Run("T2-F08-05_DuplicateEncryptedFrameReplayWithinStreamRejected", func(t *testing.T) {
		echo := StartTCPEchoTarget(t)
		_, srvAddr := t2StartSingleAetherServer(t, TopologyConfig{ServerPassword: pass})
		ctx, cancel := context.WithTimeout(context.Background(), 6*time.Second)
		defer cancel()
		sc, err := DialSpecClient(ctx, srvAddr, SpecDialOptions{
			Password:   pass,
			TargetAddr: echo.Addr(),
		})
		t2RequireNoErr(t, err, "DialSpecClient")
		defer sc.Close()
		_, err = sc.ReadServerResp(4 * time.Second)
		t2RequireNoErr(t, err, "ReadServerResp")

		rec := &t2CaptureConn{Conn: sc.Conn}
		sc.Conn = rec
		rec.startCapture()
		t2RequireNoErr(t, sc.WriteFrame(SpecFrameData, 0, []byte("dup-frame")), "seal frame 0")
		frames := rec.stopAndDrain()
		t2RequireTrue(t, len(frames) == 1, "expected 1 wire frame")

		t2RequireNoErr(t, t2WriteAllBytes(rec.Conn, frames[0]), "send original frame 0")
		f0, err := sc.ReadNextDataFrame(4 * time.Second)
		t2RequireNoErr(t, err, "read echo of original frame 0")
		t2RequireTrue(t, string(f0.Data) == "dup-frame", "unexpected echo %q", string(f0.Data))

		// Replay exact bytes of Frame #0; server nonce=1 rejects Frame #0 (sealed with nonce=0).
		_ = t2WriteAllBytes(rec.Conn, frames[0])
		t2RequireNoErr(t, sc.ExpectPeerClose(2*time.Second), "expected server to reject replayed encrypted frame")
	})
}

func t2RunF09(t *testing.T) {
	pass := "Feature09CipherValidation"

	t.Run("T2-F09-01_InvalidCipherConfigStringRejected", func(t *testing.T) {
		for _, badCipher := range []string{"aes-128-gcm", "none", "rc4"} {
			cliJSON, err := BuildClientJSON(TopologyConfig{
				ClientPassword: pass,
				ClientCipher:   badCipher,
			}, AllocFreeTCPPort(t), "127.0.0.1", AllocFreeTCPPort(t), 0, "")
			t2RequireNoErr(t, err, "BuildClientJSON")
			t2RequireErr(t, CheckConfigInProcess(cliJSON), "cipher %q must be rejected", badCipher)
			t2RequireTrue(t, CheckConfigCLI(t, cliJSON).ExitCode != 0, "CLI cipher %q must fail", badCipher)
		}
	})

	t.Run("T2-F09-02_WireCipherSuiteZeroRejected", func(t *testing.T) {
		echo := StartTCPEchoTarget(t)
		_, srvAddr := t2StartSingleAetherServer(t, TopologyConfig{
			ServerPassword:         pass,
			ServerHandshakeTimeout: "700ms",
		})
		zero := uint8(0x00)
		burst, _, err := BuildSpecClientInitialBurst(SpecDialOptions{
			Password:    pass,
			TargetAddr:  echo.Addr(),
			CipherSuite: &zero,
		})
		t2RequireNoErr(t, err, "BuildSpecClientInitialBurst")
		t2AssertStealthDrain(t, srvAddr, burst, false, 2800*time.Millisecond, 12*time.Second)
		t2RequireTrue(t, echo.Connections() == 0, "cipher suite 0x00 must not dial target")
	})

	t.Run("T2-F09-03_WireCipherSuiteUnknown0x03Rejected", func(t *testing.T) {
		echo := StartTCPEchoTarget(t)
		_, srvAddr := t2StartSingleAetherServer(t, TopologyConfig{
			ServerPassword:         pass,
			ServerHandshakeTimeout: "700ms",
		})
		var wg sync.WaitGroup
		for _, suiteVal := range []uint8{0x03, 0xFF} {
			sv := suiteVal
			wg.Add(1)
			go func() {
				defer wg.Done()
				burst, _, err := BuildSpecClientInitialBurst(SpecDialOptions{
					Password:    pass,
					TargetAddr:  echo.Addr(),
					CipherSuite: &sv,
				})
				t2RequireNoErr(t, err, "BuildSpecClientInitialBurst 0x%02x", sv)
				t2AssertStealthDrain(t, srvAddr, burst, false, 2800*time.Millisecond, 12*time.Second)
			}()
		}
		wg.Wait()
		t2RequireTrue(t, echo.Connections() == 0, "unknown cipher suite must not dial target")
	})

	t.Run("T2-F09-04_ServerEchoesMismatchedCipherSuiteRejectedByClient", func(t *testing.T) {
		mockSrv := StartSpecMockServer(t, SpecServerOptions{
			Password:     pass,
			RespOverride: &[4]byte{SpecProtocolVersion, 0x00, SpecCipherAES256GCM, 0x00},
		})
		_, proxyAddr := t2StartSingleAetherClient(t, "127.0.0.1", mockSrv.Port(), TopologyConfig{
			ClientPassword: pass,
			ClientCipher:   "chacha20-poly1305",
		})
		err := t2EchoTCPViaSOCKS5(t, proxyAddr, "127.0.0.1:80", []byte("cipher-mismatch"))
		t2RequireErr(t, err, "client must reject mismatched cipher suite in RespHeader")
	})

	t.Run("T2-F09-05_CaseSensitiveCipherEnumValidation", func(t *testing.T) {
		cliJSON, err := BuildClientJSON(TopologyConfig{
			ClientPassword: pass,
			ClientCipher:   "AES-256-GCM",
		}, AllocFreeTCPPort(t), "127.0.0.1", AllocFreeTCPPort(t), 0, "")
		t2RequireNoErr(t, err, "BuildClientJSON")
		t2RequireErr(t, CheckConfigInProcess(cliJSON), "uppercase AES-256-GCM must be rejected")
		t2RequireTrue(t, CheckConfigCLI(t, cliJSON).ExitCode != 0, "CLI uppercase cipher must fail")
	})
}

func t2RunF10(t *testing.T) {
	ipsk := "ServerIPSKSecret16!"
	alicePass := "AliceUserSecret16!"
	malloryPass := "MalloryUserSec16!"

	t.Run("T2-F10-01_MultiUserEIHUnknownUserStealthDrain", func(t *testing.T) {
		echo := StartTCPEchoTarget(t)
		_, srvAddr := t2StartSingleAetherServer(t, TopologyConfig{
			ServerPassword:         ipsk,
			ServerUsers:            []UserSpec{{Name: "alice", Password: alicePass}},
			ServerHandshakeTimeout: "700ms",
		})

		// Client uses known iPSK but unknown user secret -> 112B EIH O(1) map miss -> StealthDrain.
		burst, _, err := BuildSpecClientInitialBurst(SpecDialOptions{
			Password:   ipsk + ":" + malloryPass,
			TargetAddr: echo.Addr(),
		})
		t2RequireNoErr(t, err, "BuildSpecClientInitialBurst")
		t2RequireTrue(t, burst != nil && len(burst) >= SpecClientPrefixEIHSize, "expected 112B+ EIH burst")

		t2AssertStealthDrain(t, srvAddr, burst, false, 2800*time.Millisecond, 12*time.Second)
		t2RequireTrue(t, echo.Connections() == 0, "unknown EIH user must not reach target")
	})

	t.Run("T2-F10-02_MultiUserEIHWrongServerIPSKStealthDrain", func(t *testing.T) {
		echo := StartTCPEchoTarget(t)
		_, srvAddr := t2StartSingleAetherServer(t, TopologyConfig{
			ServerPassword:         ipsk,
			ServerUsers:            []UserSpec{{Name: "alice", Password: alicePass}},
			ServerHandshakeTimeout: "700ms",
		})

		burst, _, err := BuildSpecClientInitialBurst(SpecDialOptions{
			Password:   "WrongServerIPSK16:" + alicePass,
			TargetAddr: echo.Addr(),
		})
		t2RequireNoErr(t, err, "BuildSpecClientInitialBurst")
		t2AssertStealthDrain(t, srvAddr, burst, false, 2800*time.Millisecond, 12*time.Second)
		t2RequireTrue(t, echo.Connections() == 0, "wrong iPSK must not reach target")
	})

	t.Run("T2-F10-03_MultiUserEIHSingleSecretClient96BMismatch", func(t *testing.T) {
		echo := StartTCPEchoTarget(t)
		_, srvAddr := t2StartSingleAetherServer(t, TopologyConfig{
			ServerPassword:         ipsk,
			ServerUsers:            []UserSpec{{Name: "alice", Password: alicePass}},
			ServerHandshakeTimeout: "700ms",
		})

		// Omit iPSK prefix -> single-user 96B prefix sent to 112B EIH server -> StealthDrain.
		burst, _, err := BuildSpecClientInitialBurst(SpecDialOptions{
			Password:   alicePass,
			TargetAddr: echo.Addr(),
			ForceNoEIH: true,
		})
		t2RequireNoErr(t, err, "BuildSpecClientInitialBurst")
		t2AssertStealthDrain(t, srvAddr, burst, false, 2800*time.Millisecond, 12*time.Second)
		t2RequireTrue(t, echo.Connections() == 0, "96B burst must fail on 112B EIH server")
	})

	t.Run("T2-F10-04_MultiUserDuplicateUserPasswordOrWeakUserRejected", func(t *testing.T) {
		weakJSON, err := BuildServerJSON(TopologyConfig{
			ServerPassword: ipsk,
			ServerUsers:    []UserSpec{{Name: "weak", Password: "weakpass10"}},
		}, AllocFreeTCPPort(t), 0, "")
		t2RequireNoErr(t, err, "BuildServerJSON weak user")
		t2RequireErr(t, CheckConfigInProcess(weakJSON), "weak user password must be rejected")
		t2RequireTrue(t, CheckConfigCLI(t, weakJSON).ExitCode != 0, "CLI weak user must fail")

		dupJSON, err := BuildServerJSON(TopologyConfig{
			ServerPassword: ipsk,
			ServerUsers: []UserSpec{
				{Name: "u1", Password: alicePass},
				{Name: "u2", Password: alicePass},
			},
		}, AllocFreeTCPPort(t), 0, "")
		t2RequireNoErr(t, err, "BuildServerJSON dup user")
		t2RequireErr(t, CheckConfigInProcess(dupJSON), "duplicate user credentials must be rejected")
		t2RequireTrue(t, CheckConfigCLI(t, dupJSON).ExitCode != 0, "CLI duplicate user must fail")
	})

	t.Run("T2-F10-05_MultiUserAuthUserRejectActionEnforcement", func(t *testing.T) {
		echo := StartTCPEchoTarget(t)
		udpEcho := StartUDPEchoTarget(t)
		_, srvAddr := t2StartSingleAetherServer(t, TopologyConfig{
			ServerPassword: ipsk,
			ServerUsers: []UserSpec{
				{Name: "alice", Password: alicePass},
				{Name: "mallory", Password: malloryPass},
			},
			ServerExtraRouteRules: []map[string]any{
				{"auth_user": []string{"mallory"}, "action": C.RuleActionTypeReject},
			},
		})
		_, portStr, _ := net.SplitHostPort(srvAddr)
		srvPort64, _ := strconv.ParseUint(portStr, 10, 16)
		srvPort := uint16(srvPort64)

		_, aliceProxy := t2StartSingleAetherClient(t, "127.0.0.1", srvPort, TopologyConfig{
			ClientPassword: ipsk + ":" + alicePass,
		})
		_, malloryProxy := t2StartSingleAetherClient(t, "127.0.0.1", srvPort, TopologyConfig{
			ClientPassword: ipsk + ":" + malloryPass,
		})

		t2RequireNoErr(t, t2EchoTCPViaSOCKS5(t, aliceProxy, echo.Addr(), []byte("alice-tcp-ok")), "alice TCP must pass")

		errTCP := t2EchoTCPViaSOCKS5(t, malloryProxy, echo.Addr(), []byte("mallory-tcp-blocked"))
		t2RequireErr(t, errTCP, "mallory TCP must be rejected by auth_user route rule")

		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		udpConn, err := DialSOCKS5UDP(ctx, malloryProxy)
		if err == nil {
			defer udpConn.Close()
			_ = udpConn.SetDeadline(time.Now().Add(1200 * time.Millisecond))
			_ = udpConn.WriteToHostPort([]byte("mallory-udp-blocked"), udpEcho.Addr())
			buf := make([]byte, 512)
			_, _, uErr := udpConn.ReadFromHostPort(buf)
			t2RequireErr(t, uErr, "mallory UDP must not receive echo response")
		}
		t2RequireTrue(t, udpEcho.Packets() == 0, "blocked mallory UDP must never hit UDP target, got %d", udpEcho.Packets())
	})
}

func t2RunF11(t *testing.T) {
	pass := "Feature11FixedHeader"

	t.Run("T2-F11-01_FixedHeaderInvalidVersion0x01And0x03", func(t *testing.T) {
		echo := StartTCPEchoTarget(t)
		_, srvAddr := t2StartSingleAetherServer(t, TopologyConfig{
			ServerPassword:         pass,
			ServerHandshakeTimeout: "700ms",
		})
		var wg sync.WaitGroup
		for _, badVer := range []uint8{0x01, 0x03} {
			v := badVer
			wg.Add(1)
			go func() {
				defer wg.Done()
				burst, _, err := BuildSpecClientInitialBurst(SpecDialOptions{
					Password:   pass,
					TargetAddr: echo.Addr(),
					Version:    &v,
				})
				t2RequireNoErr(t, err, "BuildSpecClientInitialBurst ver=0x%02x", v)
				t2AssertStealthDrain(t, srvAddr, burst, false, 2800*time.Millisecond, 12*time.Second)
			}()
		}
		wg.Wait()
		t2RequireTrue(t, echo.Connections() == 0, "invalid version must not reach target")
	})

	t.Run("T2-F11-02_FixedHeaderInvalidCommand0x00And0x05", func(t *testing.T) {
		echo := StartTCPEchoTarget(t)
		_, srvAddr := t2StartSingleAetherServer(t, TopologyConfig{
			ServerPassword:         pass,
			ServerHandshakeTimeout: "700ms",
		})
		var wg sync.WaitGroup
		for _, badCmd := range []uint8{0x00, 0x05} {
			cmd := badCmd
			wg.Add(1)
			go func() {
				defer wg.Done()
				burst, _, err := BuildSpecClientInitialBurst(SpecDialOptions{
					Password:   pass,
					TargetAddr: echo.Addr(),
					Command:    &cmd,
				})
				t2RequireNoErr(t, err, "BuildSpecClientInitialBurst cmd=0x%02x", cmd)
				t2AssertStealthDrain(t, srvAddr, burst, false, 2800*time.Millisecond, 12*time.Second)
			}()
		}
		wg.Wait()
		t2RequireTrue(t, echo.Connections() == 0, "invalid command must not reach target")
	})

	t.Run("T2-F11-03_FixedHeaderNonZeroReservedByteRejected", func(t *testing.T) {
		echo := StartTCPEchoTarget(t)
		_, srvAddr := t2StartSingleAetherServer(t, TopologyConfig{
			ServerPassword:         pass,
			ServerHandshakeTimeout: "700ms",
		})
		rsv := uint8(0x01)
		burst, _, err := BuildSpecClientInitialBurst(SpecDialOptions{
			Password:   pass,
			TargetAddr: echo.Addr(),
			Reserved:   &rsv,
		})
		t2RequireNoErr(t, err, "BuildSpecClientInitialBurst")
		t2AssertStealthDrain(t, srvAddr, burst, false, 2800*time.Millisecond, 12*time.Second)
		t2RequireTrue(t, echo.Connections() == 0, "non-zero reserved must not reach target")
	})

	t.Run("T2-F11-04_NoiseLenBoundaries31_32_384_385", func(t *testing.T) {
		echo := StartTCPEchoTarget(t)
		_, srvAddr := t2StartSingleAetherServer(t, TopologyConfig{
			ServerPassword:         pass,
			ServerHandshakeTimeout: "700ms",
		})
		ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
		defer cancel()

		// Valid exact boundaries: 32 and 384.
		for _, validNoiseLen := range []int{SpecNoiseMin, SpecNoiseMax} {
			sc, err := DialSpecClient(ctx, srvAddr, SpecDialOptions{
				Password:       pass,
				TargetAddr:     echo.Addr(),
				CustomNoise:    DeterministicBytes(uint64(validNoiseLen), validNoiseLen),
				InitialPayload: []byte("noise-ok"),
			})
			t2RequireNoErr(t, err, "DialSpecClient noise=%d", validNoiseLen)
			_, err = sc.ReadServerResp(4 * time.Second)
			t2RequireNoErr(t, err, "ReadServerResp noise=%d", validNoiseLen)
			f, err := sc.ReadFrame(4 * time.Second)
			t2RequireNoErr(t, err, "ReadFrame noise=%d", validNoiseLen)
			t2RequireTrue(t, string(f.Data) == "noise-ok", "noise=%d echo mismatch %q", validNoiseLen, string(f.Data))
			_ = sc.Close()
		}

		// Invalid boundaries: 31 and 385 -> concurrent StealthDrain.
		var wg sync.WaitGroup
		for _, invalidLen := range []int{31, 385} {
			nl := invalidLen
			wg.Add(1)
			go func() {
				defer wg.Done()
				burst, _, err := BuildSpecClientInitialBurst(SpecDialOptions{
					Password:    pass,
					TargetAddr:  echo.Addr(),
					CustomNoise: DeterministicBytes(uint64(nl), nl),
				})
				t2RequireNoErr(t, err, "BuildSpecClientInitialBurst noise=%d", nl)
				t2AssertStealthDrain(t, srvAddr, burst, false, 2800*time.Millisecond, 12*time.Second)
			}()
		}
		wg.Wait()
	})

	t.Run("T2-F11-05_VarHeaderLenBoundariesAndZeroLengthOracleProof", func(t *testing.T) {
		echo := StartTCPEchoTarget(t)
		_, srvAddr := t2StartSingleAetherServer(t, TopologyConfig{
			ServerPassword:         pass,
			ServerHandshakeTimeout: "700ms",
		})
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()

		// Pass 1: NoiseLen + 7 (exact min 32 + 7 = 39B, 0B InitialPayload).
		scMin, err := DialSpecClient(ctx, srvAddr, SpecDialOptions{
			Password:    pass,
			CustomNoise: DeterministicBytes(1151, 32),
			TargetAddr:  echo.Addr(),
		})
		t2RequireNoErr(t, err, "DialSpecClient VarLen=NoiseLen+7")
		_, err = scMin.ReadServerResp(4 * time.Second)
		t2RequireNoErr(t, err, "ReadServerResp VarLen=NoiseLen+7")
		t2RequireNoErr(t, scMin.WriteFrame(SpecFrameData, 0, []byte("min-var")), "write min-var")
		fMin, err := scMin.ReadNextDataFrame(4 * time.Second)
		t2RequireNoErr(t, err, "read min-var")
		t2RequireTrue(t, string(fMin.Data) == "min-var", "expected min-var")
		_ = scMin.Close()

		// Pass 2: VarHeaderLen = 16384 max valid (32 noise + 7 ipv4 + 16345 initial payload).
		maxPayload := DeterministicBytes(1152, 16384-32-7)
		scMax, err := DialSpecClient(ctx, srvAddr, SpecDialOptions{
			Password:       pass,
			CustomNoise:    DeterministicBytes(1153, 32),
			TargetAddr:     echo.Addr(),
			InitialPayload: maxPayload,
		})
		t2RequireNoErr(t, err, "DialSpecClient VarLen=16384")
		_, err = scMax.ReadServerResp(4 * time.Second)
		t2RequireNoErr(t, err, "ReadServerResp VarLen=16384")
		var echoed []byte
		for len(echoed) < len(maxPayload) {
			f, err := scMax.ReadNextDataFrame(4 * time.Second)
			t2RequireNoErr(t, err, "ReadFrame VarLen=16384 (%d/%d)", len(echoed), len(maxPayload))
			echoed = append(echoed, f.Data...)
		}
		t2RequireTrue(t, bytes.Equal(echoed, maxPayload), "VarLen=16384 payload mismatch")
		_ = scMax.Close()

		// Invalid boundaries + zero-byte oracle proof concurrently.
		tooSmallVar, _, err := BuildSpecClientInitialBurst(SpecDialOptions{
			Password:       pass,
			CustomNoise:    DeterministicBytes(1154, 32),
			RawTargetBytes: DeterministicBytes(1155, 6), // NoiseLen + 6 < NoiseLen + 7
		})
		t2RequireNoErr(t, err, "build VarLen=NoiseLen+6")

		tooLargeVar, _, err := BuildSpecClientInitialBurst(SpecDialOptions{
			Password:       pass,
			CustomNoise:    DeterministicBytes(1156, 32),
			TargetAddr:     echo.Addr(),
			InitialPayload: DeterministicBytes(1157, 16385-32-7),
		})
		t2RequireNoErr(t, err, "build VarLen=16385")

		badTag65535 := DeterministicBytes(1158, SpecClientPrefixNoEIHSize)
		// Send invalid-tag 96B prefix with zero trailing VarHeader bytes.

		noiseZero := uint16(0)
		zeroNoise, _, err := BuildSpecClientInitialBurst(SpecDialOptions{
			Password:         pass,
			CustomNoise:      DeterministicBytes(1159, 32),
			TargetAddr:       echo.Addr(),
			NoiseLenOverride: &noiseZero,
		})
		t2RequireNoErr(t, err, "build NoiseLen=0")

		probes := [][]byte{tooSmallVar, tooLargeVar, badTag65535, zeroNoise}
		results := make([]ProbeResult, len(probes))
		var wg sync.WaitGroup
		for i, p := range probes {
			idx := i
			payload := p
			wg.Add(1)
			go func() {
				defer wg.Done()
				results[idx] = t2AssertStealthDrain(t, srvAddr, payload, false, 2800*time.Millisecond, 12*time.Second)
			}()
		}
		wg.Wait()
		for i, r := range results {
			t2RequireTrue(t, r.Elapsed >= 2800*time.Millisecond, "oracle leak probe[%d] closed too early: %v", i, r.Elapsed)
		}
	})
}

func t2RunF12(t *testing.T) {
	pass := "Feature12VarHeader0RTT"

	t.Run("T2-F12-01_OversizedZeroRTT32KiBInitialWriteSplitsCleanly", func(t *testing.T) {
		echo := StartTCPEchoTarget(t)
		topo := StartTopology(t, TopologyConfig{
			ServerPassword:     pass,
			ClientPassword:     pass,
			ClientSniffTimeout: "80ms",
		})
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		c, err := DialSOCKS5TCP(ctx, topo.ClientProxyAddr(), echo.Addr())
		t2RequireNoErr(t, err, "DialSOCKS5TCP")
		defer c.Close()
		_ = c.SetDeadline(time.Now().Add(10 * time.Second))

		payload := DeterministicBytes(1201, 32*1024)
		t2RequireNoErr(t, t2WriteAllBytes(c, payload), "write 32KiB 0-RTT payload")
		got := make([]byte, len(payload))
		_, err = io.ReadFull(c, got)
		t2RequireNoErr(t, err, "read 32KiB echo")
		t2RequireTrue(t, sha256.Sum256(got) == sha256.Sum256(payload), "32KiB SHA-256 mismatch")
	})

	t.Run("T2-F12-02_TruncatedEncryptedVarHeaderEOF", func(t *testing.T) {
		echo := StartTCPEchoTarget(t)
		_, srvAddr := t2StartSingleAetherServer(t, TopologyConfig{
			ServerPassword:         pass,
			ServerHandshakeTimeout: "700ms",
		})

		// Build valid burst with VarHeaderLen=200 (EncVarLen=216), truncate to 96 + 100 = 196 bytes + half-close.
		burst, _, err := BuildSpecClientInitialBurst(SpecDialOptions{
			Password:       pass,
			CustomNoise:    DeterministicBytes(1202, 64),
			TargetAddr:     echo.Addr(),
			InitialPayload: DeterministicBytes(1203, 200-64-7),
		})
		t2RequireNoErr(t, err, "BuildSpecClientInitialBurst")
		t2RequireTrue(t, len(burst) == SpecClientPrefixNoEIHSize+200+16, "unexpected burst len %d", len(burst))

		t2AssertStealthDrain(t, srvAddr, burst[:SpecClientPrefixNoEIHSize+100], true, 0, 12*time.Second)
		t2RequireTrue(t, echo.Connections() == 0, "truncated VarHeader must not reach target")
	})

	t.Run("T2-F12-03_BitFlipInEncryptedVarHeaderTagFails", func(t *testing.T) {
		echo := StartTCPEchoTarget(t)
		_, srvAddr := t2StartSingleAetherServer(t, TopologyConfig{
			ServerPassword:         pass,
			ServerHandshakeTimeout: "700ms",
		})

		burst, _, err := BuildSpecClientInitialBurst(SpecDialOptions{
			Password:       pass,
			TargetAddr:     echo.Addr(),
			InitialPayload: []byte("tampered-var-tag"),
		})
		t2RequireNoErr(t, err, "BuildSpecClientInitialBurst")
		burst[len(burst)-1] ^= 0x01 // Flip last bit of VarHeader AEAD tag.

		t2AssertStealthDrain(t, srvAddr, burst, false, 2800*time.Millisecond, 12*time.Second)
		t2RequireTrue(t, echo.Connections() == 0, "VarHeader AEAD failure must never dial target")
	})

	t.Run("T2-F12-04_MalformedTargetSocksaddrInVarHeader", func(t *testing.T) {
		echo := StartTCPEchoTarget(t)
		_, srvAddr := t2StartSingleAetherServer(t, TopologyConfig{
			ServerPassword:         pass,
			ServerHandshakeTimeout: "700ms",
		})

		// Case A: Invalid SOCKS5 address family byte 0x99.
		badFamily, _, err := BuildSpecClientInitialBurst(SpecDialOptions{
			Password:       pass,
			CustomNoise:    DeterministicBytes(12041, 32),
			RawTargetBytes: []byte{0x99, 1, 2, 3, 4, 0, 80, 0, 0, 0},
		})
		t2RequireNoErr(t, err, "build badFamily")

		// Case B: Domain family 0x03 declaring length 250 inside a 10B trailer.
		truncFQDN, _, err := BuildSpecClientInitialBurst(SpecDialOptions{
			Password:       pass,
			CustomNoise:    DeterministicBytes(12042, 32),
			RawTargetBytes: []byte{0x03, 250, 'a', 'b', 'c', 'd', 'e', 'f', 0, 80},
		})
		t2RequireNoErr(t, err, "build truncFQDN")

		var wg sync.WaitGroup
		for _, p := range [][]byte{badFamily, truncFQDN} {
			payload := p
			wg.Add(1)
			go func() {
				defer wg.Done()
				res, rErr := SendRawProbe(srvAddr, payload, false, 12*time.Second)
				t2RequireNoErr(t, rErr, "SendRawProbe")
				t2RequireTrue(t, len(res.BytesReceived) == 0 && !res.ClosedByRST, "expected clean drop without response/RST")
			}()
		}
		wg.Wait()
		t2RequireTrue(t, echo.Connections() == 0, "malformed socksaddr must never dial target")
	})

	t.Run("T2-F12-05_Max253CharFQDNTargetInVarHeader", func(t *testing.T) {
		echo := StartTCPEchoTarget(t)
		// Exact 253-character valid FQDN: 63 + "." + 63 + "." + 63 + "." + 53 + ".invalid" = 253.
		fqdnInvalid := strings.Repeat("a", 63) + "." + strings.Repeat("b", 63) + "." + strings.Repeat("c", 63) + "." + strings.Repeat("d", 53) + ".invalid"
		t2RequireTrue(t, len(fqdnInvalid) == 253, "expected 253-char FQDN, got %d", len(fqdnInvalid))

		_, srvAddr := t2StartSingleAetherServer(t, TopologyConfig{
			ServerPassword:        pass,
			ServerPredefinedHosts: map[string]string{fqdnInvalid: "127.0.0.1"},
		})
		_, portStr, _ := net.SplitHostPort(srvAddr)
		srvPort64, _ := strconv.ParseUint(portStr, 10, 16)
		_, proxyAddr := t2StartSingleAetherClient(t, "127.0.0.1", uint16(srvPort64), TopologyConfig{
			ClientPassword: pass,
		})

		_, targetPortStr, _ := net.SplitHostPort(echo.Addr())
		// PredefinedHosts verifies all 253 chars unmarshaled without truncation end-to-end.
		t2RequireNoErr(t, t2EchoTCPViaSOCKS5(t, proxyAddr, fqdnInvalid+":"+targetPortStr, []byte("fqdn-253-full-roundtrip")), "253-char FQDN through PredefinedHosts")

		// Unmapped 253-char FQDN on router without matching host must return clean error without crash.
		unmapped := strings.Repeat("x", 63) + "." + strings.Repeat("y", 63) + "." + strings.Repeat("z", 63) + "." + strings.Repeat("w", 53) + ".invalid"
		t2RequireTrue(t, len(unmapped) == 253, "expected unmapped 253-char FQDN, got %d", len(unmapped))
		err := t2EchoTCPViaSOCKS5(t, proxyAddr, unmapped+":443", []byte("unmapped-253"))
		t2RequireErr(t, err, "unresolvable 253-char FQDN must return clean error without panic")
	})
}

func t2RunF13(t *testing.T) {
	pass := "Feature13ServerResp"

	t.Run("T2-F13-01_TruncatedServerResponsePrefix0B_40B_83B", func(t *testing.T) {
		for _, truncLen := range []int{0, 40, 83} {
			tl := truncLen
			var mockSrv *SpecMockServer
			var ln net.Listener
			var srvPort uint16
			if tl == 0 {
				var err error
				ln, err = net.Listen("tcp", "127.0.0.1:0")
				t2RequireNoErr(t, err, "listen 0B server")
				t.Cleanup(func() { _ = ln.Close() })
				srvPort = uint16(ln.Addr().(*net.TCPAddr).Port)
				go func() {
					for {
						c, lErr := ln.Accept()
						if lErr != nil {
							return
						}
						go func(conn net.Conn) {
							buf := make([]byte, 512)
							_, _ = conn.Read(buf)
							_ = conn.Close()
						}(c)
					}
				}()
			} else {
				mockSrv = StartSpecMockServer(t, SpecServerOptions{
					Password:                pass,
					TruncateRespPrefixBytes: tl,
				})
				srvPort = mockSrv.Port()
			}
			_, proxyAddr := t2StartSingleAetherClient(t, "127.0.0.1", srvPort, TopologyConfig{
				ClientPassword: pass,
			})
			err := t2EchoTCPViaSOCKS5(t, proxyAddr, "127.0.0.1:80", []byte("trunc-resp"))
			t2RequireErr(t, err, "expected truncated ServerResponsePrefix (%dB) to fail", tl)
			if mockSrv != nil {
				mockSrv.Close()
			}
			if ln != nil {
				_ = ln.Close()
			}
		}
	})

	t.Run("T2-F13-02_CorruptedEncryptedRespHeaderTag", func(t *testing.T) {
		echo := StartTCPEchoTarget(t)
		topo := StartTopology(t, TopologyConfig{
			ServerPassword: pass,
			ClientPassword: pass,
		})
		topo.Tap.InstallSingleBitFlip(0, DirS2C, 75, 0x01) // Within bytes [64..84] AEAD RespHeader ciphertext/tag

		err := t2EchoTCPViaSOCKS5(t, topo.ClientProxyAddr(), echo.Addr(), []byte("corrupt-resp-tag"))
		t2RequireErr(t, err, "client must reject corrupted RespHeader AEAD tag")
	})

	t.Run("T2-F13-03_InvalidRespHeaderVersionByte", func(t *testing.T) {
		mockSrv := StartSpecMockServer(t, SpecServerOptions{
			Password:     pass,
			RespOverride: &[4]byte{0x01, 0x00, SpecCipherChaCha20Poly1305, 0x00},
		})
		_, proxyAddr := t2StartSingleAetherClient(t, "127.0.0.1", mockSrv.Port(), TopologyConfig{
			ClientPassword: pass,
			ClientCipher:   "chacha20-poly1305",
		})
		err := t2EchoTCPViaSOCKS5(t, proxyAddr, "127.0.0.1:80", []byte("bad-resp-ver"))
		t2RequireErr(t, err, "client must reject RespHeader Version=0x01")
	})

	t.Run("T2-F13-04_NonZeroRespHeaderStatusByte", func(t *testing.T) {
		mockSrv := StartSpecMockServer(t, SpecServerOptions{
			Password:     pass,
			RespOverride: &[4]byte{SpecProtocolVersion, 0x01, SpecCipherChaCha20Poly1305, 0x00},
		})
		_, proxyAddr := t2StartSingleAetherClient(t, "127.0.0.1", mockSrv.Port(), TopologyConfig{
			ClientPassword: pass,
			ClientCipher:   "chacha20-poly1305",
		})
		err := t2EchoTCPViaSOCKS5(t, proxyAddr, "127.0.0.1:80", []byte("bad-resp-status"))
		t2RequireErr(t, err, "client must reject RespHeader Status=0x01")
	})

	t.Run("T2-F13-05_NonZeroRespHeaderReservedByte", func(t *testing.T) {
		mockSrv := StartSpecMockServer(t, SpecServerOptions{
			Password:     pass,
			RespOverride: &[4]byte{SpecProtocolVersion, 0x00, SpecCipherChaCha20Poly1305, 0xFF},
		})
		_, proxyAddr := t2StartSingleAetherClient(t, "127.0.0.1", mockSrv.Port(), TopologyConfig{
			ClientPassword: pass,
			ClientCipher:   "chacha20-poly1305",
		})
		err := t2EchoTCPViaSOCKS5(t, proxyAddr, "127.0.0.1:80", []byte("bad-resp-rsv"))
		t2RequireErr(t, err, "client must reject RespHeader Reserved=0xFF")
	})
}

func t2RunF14(t *testing.T) {
	pass := "Feature14FrameBounds"

	t.Run("T2-F14-01_PlainFrameLenZeroAndOneRejected", func(t *testing.T) {
		echo := StartTCPEchoTarget(t)
		_, srvAddr := t2StartSingleAetherServer(t, TopologyConfig{ServerPassword: pass})
		ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
		defer cancel()

		for _, tc := range []struct {
			plainLen uint16
			body     []byte
		}{
			{0, nil},
			{1, []byte{SpecFrameData}},
		} {
			sc, err := DialSpecClient(ctx, srvAddr, SpecDialOptions{
				Password:   pass,
				TargetAddr: echo.Addr(),
			})
			t2RequireNoErr(t, err, "DialSpecClient plainLen=%d", tc.plainLen)
			_, err = sc.ReadServerResp(4 * time.Second)
			t2RequireNoErr(t, err, "ReadServerResp plainLen=%d", tc.plainLen)
			t2RequireNoErr(t, sc.WriteRawBodyFrame(tc.plainLen, tc.body), "WriteRawBodyFrame plainLen=%d", tc.plainLen)
			t2RequireNoErr(t, sc.ExpectPeerClose(2*time.Second), "server must close on PlainFrameLen=%d", tc.plainLen)
			_ = sc.Close()
		}
	})

	t.Run("T2-F14-02_PlainFrameLenMaxBoundary16641Vs16642", func(t *testing.T) {
		echo := StartTCPEchoTarget(t)
		_, srvAddr := t2StartSingleAetherServer(t, TopologyConfig{ServerPassword: pass})
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		// 16641 valid: 2 + PadLen(255) + Data(16384) = 16641.
		scValid, err := DialSpecClient(ctx, srvAddr, SpecDialOptions{
			Password:   pass,
			TargetAddr: echo.Addr(),
		})
		t2RequireNoErr(t, err, "DialSpecClient 16641")
		_, err = scValid.ReadServerResp(4 * time.Second)
		t2RequireNoErr(t, err, "ReadServerResp 16641")
		data16K := DeterministicBytes(14021, 16384)
		t2RequireNoErr(t, scValid.WriteFrame(SpecFrameData, 255, data16K), "WriteFrame 16641")
		var echoed []byte
		for len(echoed) < len(data16K) {
			f, err := scValid.ReadNextDataFrame(4 * time.Second)
			t2RequireNoErr(t, err, "ReadFrame 16641")
			echoed = append(echoed, f.Data...)
		}
		t2RequireTrue(t, bytes.Equal(echoed, data16K), "16384B data mismatch")
		_ = scValid.Close()

		// 16642 overflow: rejected immediately on 18B header decode.
		scBad, err := DialSpecClient(ctx, srvAddr, SpecDialOptions{
			Password:   pass,
			TargetAddr: echo.Addr(),
		})
		t2RequireNoErr(t, err, "DialSpecClient 16642")
		_, err = scBad.ReadServerResp(4 * time.Second)
		t2RequireNoErr(t, err, "ReadServerResp 16642")
		t2RequireNoErr(t, scBad.WriteCustomFrame(16642, SpecFrameData, 255, DeterministicBytes(14022, 16385)), "WriteCustomFrame 16642")
		t2RequireNoErr(t, scBad.ExpectPeerClose(2*time.Second), "expected server close on PlainFrameLen=16642")
		_ = scBad.Close()
	})

	t.Run("T2-F14-03_PadLenExceedingPlainFrameLenRejected", func(t *testing.T) {
		echo := StartTCPEchoTarget(t)
		_, srvAddr := t2StartSingleAetherServer(t, TopologyConfig{ServerPassword: pass})
		ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
		defer cancel()

		sc, err := DialSpecClient(ctx, srvAddr, SpecDialOptions{
			Password:   pass,
			TargetAddr: echo.Addr(),
		})
		t2RequireNoErr(t, err, "DialSpecClient")
		_, err = sc.ReadServerResp(4 * time.Second)
		t2RequireNoErr(t, err, "ReadServerResp")
		// Write RawBodyFrame: plainLen=10, body[0]=FrameData, body[1]=PadLen(9) -> 2+9=11 > 10.
		badBody := []byte{SpecFrameData, 9, 0, 0, 0, 0, 0, 0, 0, 0}
		t2RequireNoErr(t, sc.WriteRawBodyFrame(10, badBody), "WriteRawBodyFrame invalid PadLen")
		t2RequireNoErr(t, sc.ExpectPeerClose(2*time.Second), "server must close on 2+PadLen > PlainFrameLen")
		_ = sc.Close()
	})

	t.Run("T2-F14-04_BitFlipIn18ByteLengthHeaderCiphertext", func(t *testing.T) {
		echo := StartTCPEchoTarget(t)
		_, srvAddr := t2StartSingleAetherServer(t, TopologyConfig{ServerPassword: pass})
		ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
		defer cancel()

		sc, err := DialSpecClient(ctx, srvAddr, SpecDialOptions{
			Password:   pass,
			TargetAddr: echo.Addr(),
		})
		t2RequireNoErr(t, err, "DialSpecClient")
		_, err = sc.ReadServerResp(4 * time.Second)
		t2RequireNoErr(t, err, "ReadServerResp")

		// Frame #0 & #1 cleanly pass.
		for i := 0; i < 2; i++ {
			t2RequireNoErr(t, sc.WriteFrame(SpecFrameData, 0, []byte("ok")), "write clean frame %d", i)
			f, fErr := sc.ReadNextDataFrame(4 * time.Second)
			t2RequireNoErr(t, fErr, "read clean frame %d", i)
			t2RequireTrue(t, string(f.Data) == "ok", "unexpected clean echo")
		}

		// Frame #2: capture wire bytes and flip bit inside the 18B encrypted length header [0:18].
		rec := &t2CaptureConn{Conn: sc.Conn}
		sc.Conn = rec
		rec.startCapture()
		t2RequireNoErr(t, sc.WriteFrame(SpecFrameData, 0, []byte("flip-len-hdr")), "seal frame #2")
		captured := rec.stopAndDrain()
		t2RequireTrue(t, len(captured) == 1 && len(captured[0]) > SpecEncryptedLengthSize, "expected single captured frame")
		captured[0][3] ^= 0x40
		t2RequireNoErr(t, t2WriteAllBytes(rec.Conn, captured[0]), "send tampered length header")
		t2RequireNoErr(t, sc.ExpectPeerClose(2*time.Second), "server must reject flipped 18B length header")
		_ = sc.Close()
	})

	t.Run("T2-F14-05_BitFlipInEncryptedFrameBodyTag", func(t *testing.T) {
		mockSrv := StartSpecMockServer(t, SpecServerOptions{
			Password: pass,
			OnSession: func(sess *SpecServerSession) {
				if len(sess.VarHeader.InitialPayload) == 0 {
					_, _ = sess.ReadC2SFrame(4 * time.Second)
				}
				_ = sess.WriteS2CFrame(SpecFrameData, 0, []byte("body-0"))
				_ = sess.WriteS2CFrame(SpecFrameData, 0, []byte("body-1"))
				_ = sess.WriteS2CFrame(SpecFrameData, 0, []byte("TAMPERED_SECRET"))
			},
		})
		tap := StartWireTapProxy(t, mockSrv.Addr())
		// Frame #0 ("body-0", 6B) = 42B, Frame #1 ("body-1", 6B) = 42B, Frame #2 ("TAMPERED_SECRET", 15B) = 51B.
		// Flip the last bit in Frame #2's body AEAD tag without mutating sess.Conn.
		frame0Len := int64(SpecEncryptedLengthSize + 2 + len("body-0") + 16)
		frame1Len := int64(SpecEncryptedLengthSize + 2 + len("body-1") + 16)
		frame2TagLast := int64(SpecEncryptedLengthSize + 2 + len("TAMPERED_SECRET") + 15)
		tap.InstallSingleBitFlip(0, DirS2C, int64(SpecServerRespPrefixSize)+frame0Len+frame1Len+frame2TagLast, 0x80)
		_, proxyAddr := t2StartSingleAetherClient(t, "127.0.0.1", tap.Port(), TopologyConfig{
			ClientPassword:       pass,
			ClientDisableShaping: true,
		})
		ctx, cancel := context.WithTimeout(context.Background(), 6*time.Second)
		defer cancel()
		c, err := DialSOCKS5TCP(ctx, proxyAddr, "127.0.0.1:80")
		t2RequireNoErr(t, err, "DialSOCKS5TCP")
		defer c.Close()
		_ = c.SetDeadline(time.Now().Add(4 * time.Second))
		_, _ = c.Write([]byte("trigger"))
		allBytes, rErr := io.ReadAll(c)
		// Expect read failure or clean drop without ever leaking corrupted Frame #2 data.
		_ = rErr
		t2RequireTrue(t, !bytes.Contains(allBytes, []byte("TAMPERED_SECRET")), "corrupted frame body must never reach caller: %q", string(allBytes))
	})
}

func t2RunF15(t *testing.T) {
	pass := "Feature15Shaping"

	t.Run("T2-F15-01_ShapingSplitThreshold1200BVs1201B", func(t *testing.T) {
		newShapingPair := func() (*SpecMockServer, string) {
			ms := StartSpecMockServer(t, SpecServerOptions{
				Password: pass,
				OnSession: func(sess *SpecServerSession) {
					if len(sess.VarHeader.InitialPayload) > 0 {
						_ = sess.WriteS2CFrame(SpecFrameData, 0, []byte("K"))
					}
					for {
						f, err := sess.ReadC2SFrame(5 * time.Second)
						if err != nil {
							return
						}
						if f.FrameType == SpecFrameData && len(f.Data) > 0 {
							_ = sess.WriteS2CFrame(SpecFrameData, 0, []byte("K"))
						}
					}
				},
			})
			_, proxy := t2StartSingleAetherClient(t, "127.0.0.1", ms.Port(), TopologyConfig{
				ClientPassword:       pass,
				ClientDisableShaping: false,
			})
			return ms, proxy
		}

		// Case A: Exact 1200B write fits in 1 padded frame.
		ms1, proxy1 := newShapingPair()
		ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
		defer cancel()
		c1, err := DialSOCKS5TCP(ctx, proxy1, "127.0.0.1:80")
		t2RequireNoErr(t, err, "DialSOCKS5TCP 1200B")
		_ = c1.SetDeadline(time.Now().Add(6 * time.Second))
		t2RequireNoErr(t, t2WriteAllBytes(c1, []byte("I")), "init frame")
		ack := make([]byte, 1)
		if _, err := io.ReadFull(c1, ack); err == nil {
			// OK
		}
		// Now write exact 1200B payload as next single write.
		p1200 := DeterministicBytes(15011, 1200)
		t2RequireNoErr(t, t2WriteAllBytes(c1, p1200), "write 1200B")
		_, _ = io.ReadFull(c1, ack)
		_ = c1.Close()
		sessions1 := ms1.WaitForSessions(t, 1, 3*time.Second)
		frames1 := sessions1[0].C2SDataFrames()
		var got1200 *SpecDecodedFrame
		for i := range frames1 {
			if len(frames1[i].Data) == 1200 {
				got1200 = &frames1[i]
				break
			}
		}
		t2RequireTrue(t, got1200 != nil, "expected single 1200B C2S DataFrame (got %d frames)", len(frames1))
		t2RequireTrue(t, got1200.PadLen >= 16 && got1200.PadLen <= 255, "expected 16<=PadLen<=255 for 1200B shaped frame, got %d", got1200.PadLen)

		// Case B: Exact 1201B write splits into >= 2 shaped frames (non-final chunks in 512..1100).
		ms2, proxy2 := newShapingPair()
		c2, err := DialSOCKS5TCP(ctx, proxy2, "127.0.0.1:80")
		t2RequireNoErr(t, err, "DialSOCKS5TCP 1201B")
		_ = c2.SetDeadline(time.Now().Add(6 * time.Second))
		t2RequireNoErr(t, t2WriteAllBytes(c2, []byte("I")), "init frame 2")
		_, _ = io.ReadFull(c2, ack)
		p1201 := DeterministicBytes(15012, 1201)
		t2RequireNoErr(t, t2WriteAllBytes(c2, p1201), "write 1201B")
		// Wait until SpecMockServer reconstructs full 1201B across split frames.
		deadline := time.Now().Add(3 * time.Second)
		sessions2 := ms2.WaitForSessions(t, 1, 3*time.Second)
		var splitFrames []SpecDecodedFrame
		for time.Now().Before(deadline) {
			fs := sessions2[0].C2SDataFrames()
			sum := 0
			splitFrames = nil
			for _, f := range fs {
				if bytes.Equal(f.Data, []byte("I")) {
					continue
				}
				splitFrames = append(splitFrames, f)
				sum += len(f.Data)
			}
			if sum == 1201 {
				break
			}
			time.Sleep(15 * time.Millisecond)
		}
		_ = c2.Close()
		t2RequireTrue(t, len(splitFrames) >= 2, "expected 1201B to split into >= 2 frames, got %d", len(splitFrames))
		for i, sf := range splitFrames {
			if i < len(splitFrames)-1 {
				t2RequireTrue(t, len(sf.Data) >= 512 && len(sf.Data) <= 1100, "non-final split chunk[%d] len=%d outside [512,1100]", i, len(sf.Data))
			}
			t2RequireTrue(t, sf.PadLen >= 16 && sf.PadLen <= 255, "split chunk[%d] PadLen=%d outside [16,255]", i, sf.PadLen)
		}
	})

	t.Run("T2-F15-02_ExactFrame5ToFrame6TransitionBoundary", func(t *testing.T) {
		ms := StartSpecMockServer(t, SpecServerOptions{
			Password: pass,
			OnSession: func(sess *SpecServerSession) {
				if len(sess.VarHeader.InitialPayload) > 0 {
					_ = sess.WriteS2CFrame(SpecFrameData, 0, []byte("R"))
				}
				for {
					f, err := sess.ReadC2SFrame(5 * time.Second)
					if err != nil {
						return
					}
					if f.FrameType == SpecFrameData && len(f.Data) > 0 {
						_ = sess.WriteS2CFrame(SpecFrameData, 0, []byte("R"))
					}
				}
			},
		})
		_, proxy := t2StartSingleAetherClient(t, "127.0.0.1", ms.Port(), TopologyConfig{
			ClientPassword:       pass,
			ClientDisableShaping: false,
		})
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		c, err := DialSOCKS5TCP(ctx, proxy, "127.0.0.1:80")
		t2RequireNoErr(t, err, "DialSOCKS5TCP")
		defer c.Close()
		_ = c.SetDeadline(time.Now().Add(8 * time.Second))

		ack := make([]byte, 1)
		// Send 10 paced 300B writes (waiting for echo after each so TCP never merges them).
		for i := 0; i < 10; i++ {
			t2RequireNoErr(t, t2WriteAllBytes(c, DeterministicBytes(uint64(15020+i), 300)), "write %d", i)
			_, err = io.ReadFull(c, ack)
			t2RequireNoErr(t, err, "read ack %d", i)
		}
		sessions := ms.WaitForSessions(t, 1, 3*time.Second)
		frames := sessions[0].C2SDataFrames()
		t2RequireTrue(t, len(frames) >= 8, "expected >= 8 C2S frames, got %d", len(frames))
		t2RequireTrue(t, frames[5].PadLen >= 16 && frames[5].PadLen <= 255, "Frame 5 must have 16<=PadLen<=255, got %d", frames[5].PadLen)
		t2RequireTrue(t, frames[6].PadLen == 0, "Frame 6 must have exact PadLen==0, got %d", frames[6].PadLen)
	})

	t.Run("T2-F15-03_AsymmetricDisableShapingClientTrueServerFalse", func(t *testing.T) {
		echo := StartTCPEchoTarget(t)
		topoA := StartTopology(t, TopologyConfig{
			ServerPassword:       pass,
			ServerDisableShaping: false,
			ClientPassword:       pass,
			ClientDisableShaping: true,
		})
		t2RequireNoErr(t, t2EchoTCPViaSOCKS5(t, topoA.ClientProxyAddr(), echo.Addr(), DeterministicBytes(15031, 4096)), "client disable_shaping=true -> server false")
		topoA.Close()

		topoB := StartTopology(t, TopologyConfig{
			ServerPassword:       pass,
			ServerDisableShaping: true,
			ClientPassword:       pass,
			ClientDisableShaping: false,
		})
		t2RequireNoErr(t, t2EchoTCPViaSOCKS5(t, topoB.ClientProxyAddr(), echo.Addr(), DeterministicBytes(15032, 4096)), "client disable_shaping=false -> server true")

		// Verify Server with disable_shaping=false actually shapes Frame 0..5 on S2C to unshaped SpecClientConn.
		_, srvAddr := t2StartSingleAetherServer(t, TopologyConfig{
			ServerPassword:       pass,
			ServerDisableShaping: false,
		})
		ctx, cancel := context.WithTimeout(context.Background(), 6*time.Second)
		defer cancel()
		sc, err := DialSpecClient(ctx, srvAddr, SpecDialOptions{
			Password:   pass,
			TargetAddr: echo.Addr(),
		})
		t2RequireNoErr(t, err, "DialSpecClient")
		defer sc.Close()
		_, err = sc.ReadServerResp(4 * time.Second)
		t2RequireNoErr(t, err, "ReadServerResp")
		t2RequireNoErr(t, sc.WriteFrame(SpecFrameData, 0, []byte("shape-my-echo")), "write unpadded C2S")
		s2cFrame, err := sc.ReadNextDataFrame(4 * time.Second)
		t2RequireNoErr(t, err, "ReadFrame S2C")
		t2RequireTrue(t, string(s2cFrame.Data) == "shape-my-echo", "expected S2C echo data, got frameType=0x%02x data=%q", s2cFrame.FrameType, string(s2cFrame.Data))
		t2RequireTrue(t, s2cFrame.PadLen >= 16 && s2cFrame.PadLen <= 255, "server disable_shaping=false must pad S2C frame 0, got PadLen=%d", s2cFrame.PadLen)
	})

	t.Run("T2-F15-04_OneByteMicroWritesDuringShapingAndSteadyState", func(t *testing.T) {
		echo := StartTCPEchoTarget(t)
		topo := StartTopology(t, TopologyConfig{
			ServerPassword:       pass,
			ServerDisableShaping: false,
			ClientPassword:       pass,
			ClientDisableShaping: false,
		})
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		c, err := DialSOCKS5TCP(ctx, topo.ClientProxyAddr(), echo.Addr())
		t2RequireNoErr(t, err, "DialSOCKS5TCP")
		defer c.Close()
		_ = c.SetDeadline(time.Now().Add(8 * time.Second))

		want := DeterministicBytes(1504, 20)
		got := make([]byte, 20)
		for i := 0; i < 20; i++ {
			_, wErr := c.Write(want[i : i+1])
			t2RequireNoErr(t, wErr, "1-byte Write[%d]", i)
			_, rErr := io.ReadFull(c, got[i:i+1])
			t2RequireNoErr(t, rErr, "1-byte Read[%d]", i)
		}
		t2RequireTrue(t, bytes.Equal(got, want), "20x 1-byte echo mismatch: got=%x want=%x", got, want)
	})

	t.Run("T2-F15-05_Exact16384BAnd16385BWritesAtSteadyState", func(t *testing.T) {
		ms := StartSpecMockServer(t, SpecServerOptions{
			Password: pass,
			OnSession: func(sess *SpecServerSession) {
				if len(sess.VarHeader.InitialPayload) > 0 {
					_ = sess.WriteS2CFrame(SpecFrameData, 0, sess.VarHeader.InitialPayload)
				}
				for {
					f, err := sess.ReadC2SFrame(6 * time.Second)
					if err != nil {
						return
					}
					if f.FrameType == SpecFrameData && len(f.Data) > 0 {
						_ = sess.WriteS2CFrame(SpecFrameData, 0, f.Data)
					}
				}
			},
		})
		_, proxy := t2StartSingleAetherClient(t, "127.0.0.1", ms.Port(), TopologyConfig{
			ClientPassword:       pass,
			ClientDisableShaping: false,
		})
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		c, err := DialSOCKS5TCP(ctx, proxy, "127.0.0.1:80")
		t2RequireNoErr(t, err, "DialSOCKS5TCP")
		defer c.Close()
		_ = c.SetDeadline(time.Now().Add(8 * time.Second))

		// Advance past all 6 shaping frames into steady state (Frame >= 6), accounting for optional 0-RTT write 0.
		pingBuf := []byte("P")
		ackBuf := make([]byte, 1)
		for i := 0; i < 8; i++ {
			t2RequireNoErr(t, t2WriteAllBytes(c, pingBuf), "warm %d", i)
			_, err = io.ReadFull(c, ackBuf)
			t2RequireNoErr(t, err, "warm ack %d", i)
		}

		// Exact 16384B single steady-state write -> 1 frame with PadLen==0.
		b16384 := DeterministicBytes(15051, 16384)
		t2RequireNoErr(t, t2WriteAllBytes(c, b16384), "write 16384B")
		r16384 := make([]byte, 16384)
		_, err = io.ReadFull(c, r16384)
		t2RequireNoErr(t, err, "read 16384B")
		t2RequireTrue(t, bytes.Equal(r16384, b16384), "16384B mismatch")

		// Exact 16385B write -> splits cleanly into 16384B + 1B.
		b16385 := DeterministicBytes(15052, 16385)
		t2RequireNoErr(t, t2WriteAllBytes(c, b16385), "write 16385B")
		r16385 := make([]byte, 16385)
		_, err = io.ReadFull(c, r16385)
		t2RequireNoErr(t, err, "read 16385B")
		t2RequireTrue(t, bytes.Equal(r16385, b16385), "16385B mismatch")

		sessions := ms.WaitForSessions(t, 1, 3*time.Second)
		fs := sessions[0].C2SDataFrames()
		var idx16K = -1
		for i, f := range fs {
			if len(f.Data) == 16384 && bytes.Equal(f.Data, b16384) {
				idx16K = i
				t2RequireTrue(t, f.PadLen == 0, "expected steady-state 16384B frame PadLen==0, got %d", f.PadLen)
				break
			}
		}
		t2RequireTrue(t, idx16K >= 0, "expected 16384B single frame at steady state")
		var post []int
		for _, f := range fs[idx16K+1:] {
			post = append(post, len(f.Data))
			t2RequireTrue(t, f.PadLen == 0, "expected steady-state split PadLen==0, got %d", f.PadLen)
		}
		t2RequireTrue(t, len(post) == 2 && post[0] == 16384 && post[1] == 1, "expected [16384, 1] split for 16385B, got %v", post)
	})
}

func t2RunF16(t *testing.T) {
	pass := "Feature16ControlFrames"

	t.Run("T2-F16-01_HundredConsecutiveZeroLenChaffFramesNoErrNoProgress", func(t *testing.T) {
		mockSrv := StartSpecMockServer(t, SpecServerOptions{
			Password: pass,
			OnSession: func(sess *SpecServerSession) {
				if len(sess.VarHeader.InitialPayload) == 0 {
					_, _ = sess.ReadC2SFrame(4 * time.Second)
				}
				for i := 0; i < 105; i++ {
					pad := byte(16 + (i % 180))
					if err := sess.WriteS2CFrame(SpecFrameData, pad, nil); err != nil {
						return
					}
				}
				_ = sess.WriteS2CFrame(SpecFrameData, 0, []byte("OK_AFTER_105_CHAFF"))
				_ = sess.WriteS2CFrame(SpecFrameCloseWrite, 0, nil)
			},
		})
		clientBox, _ := t2StartSingleAetherClient(t, "127.0.0.1", mockSrv.Port(), TopologyConfig{
			ClientPassword: pass,
		})
		out := t2DialOutbound(t, clientBox, "aether-out")
		ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
		defer cancel()
		conn, err := out.DialContext(ctx, "tcp", M.ParseSocksaddrHostPort("127.0.0.1", 80))
		t2RequireNoErr(t, err, "DialContext")
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(6 * time.Second))
		t2RequireNoErr(t, t2WriteAllBytes(conn, []byte("go")), "trigger handshake")

		var dst bytes.Buffer
		_, copyErr := io.Copy(&dst, conn)
		t2RequireNoErr(t, copyErr, "io.Copy must NOT fail with io.ErrNoProgress across 105 chaff frames")
		t2RequireTrue(t, dst.String() == "OK_AFTER_105_CHAFF", "expected OK_AFTER_105_CHAFF, got %q", dst.String())
	})

	t.Run("T2-F16-02_UnknownFrameTypes0x00_0x05_0xFFRejected", func(t *testing.T) {
		echo := StartTCPEchoTarget(t)
		_, srvAddr := t2StartSingleAetherServer(t, TopologyConfig{ServerPassword: pass})
		ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
		defer cancel()

		for _, badType := range []byte{0x00, 0x05, 0xFF} {
			sc, err := DialSpecClient(ctx, srvAddr, SpecDialOptions{
				Password:   pass,
				TargetAddr: echo.Addr(),
			})
			t2RequireNoErr(t, err, "DialSpecClient frameType=0x%02x", badType)
			_, err = sc.ReadServerResp(4 * time.Second)
			t2RequireNoErr(t, err, "ReadServerResp")
			t2RequireNoErr(t, sc.WriteFrame(badType, 0, nil), "WriteFrame badType=0x%02x", badType)
			t2RequireNoErr(t, sc.ExpectPeerClose(2*time.Second), "server must close on unknown frameType=0x%02x", badType)
			_ = sc.Close()
		}
	})

	t.Run("T2-F16-03_MalformedPingPongPadLenOrNonEmptyData", func(t *testing.T) {
		echo := StartTCPEchoTarget(t)
		_, srvAddr := t2StartSingleAetherServer(t, TopologyConfig{ServerPassword: pass})
		ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
		defer cancel()

		cases := []struct {
			ft   byte
			pad  byte
			data []byte
		}{
			{SpecFramePing, 0, nil},
			{SpecFramePong, 250, nil},
			{SpecFramePing, 32, []byte("0123456789")},
			{SpecFramePong, 32, []byte("0123456789")},
		}
		for idx, c := range cases {
			sc, err := DialSpecClient(ctx, srvAddr, SpecDialOptions{
				Password:   pass,
				TargetAddr: echo.Addr(),
			})
			t2RequireNoErr(t, err, "DialSpecClient case %d", idx)
			_, err = sc.ReadServerResp(4 * time.Second)
			t2RequireNoErr(t, err, "ReadServerResp case %d", idx)
			t2RequireNoErr(t, sc.WriteFrame(c.ft, c.pad, c.data), "WriteFrame malformed control case %d", idx)
			t2RequireNoErr(t, sc.ExpectPeerClose(2*time.Second), "server must close on malformed ping/pong case %d (ft=%d pad=%d dataLen=%d)", idx, c.ft, c.pad, len(c.data))
			_ = sc.Close()
		}
	})

	t.Run("T2-F16-04_WriteAfterLocalCloseWriteReturnsError", func(t *testing.T) {
		hcTarget := StartTCPHalfCloseTarget(t, []byte("TRAILER_OK"))
		topo := StartTopology(t, TopologyConfig{
			ServerPassword: pass,
			ClientPassword: pass,
		})
		out := t2DialOutbound(t, topo.Client, "aether-out")
		ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
		defer cancel()
		conn, err := out.DialContext(ctx, "tcp", M.ParseSocksaddrHostPort("127.0.0.1", hcTarget.Port()))
		t2RequireNoErr(t, err, "DialContext")
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(6 * time.Second))

		t2RequireNoErr(t, t2WriteAllBytes(conn, []byte("payload-before-close-write")), "write pre-CloseWrite")
		wc, ok := conn.(N.WriteCloser)
		t2RequireTrue(t, ok, "aether conn must implement network.WriteCloser")
		t2RequireNoErr(t, wc.CloseWrite(), "CloseWrite()")

		_, lateErr := conn.Write([]byte("late"))
		t2RequireErr(t, lateErr, "Write after CloseWrite must fail immediately")

		trailer, err := io.ReadAll(conn)
		t2RequireNoErr(t, err, "read server trailer after CloseWrite")
		t2RequireTrue(t, string(trailer) == "TRAILER_OK", "expected TRAILER_OK, got %q", string(trailer))
	})

	t.Run("T2-F16-05_SimultaneousBidirectionalCloseWriteEOF", func(t *testing.T) {
		hcTarget := StartTCPHalfCloseTarget(t, DeterministicBytes(1605, 16*1024))
		topo := StartTopology(t, TopologyConfig{
			ServerPassword: pass,
			ClientPassword: pass,
		})
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		c, err := DialSOCKS5TCP(ctx, topo.ClientProxyAddr(), hcTarget.Addr())
		t2RequireNoErr(t, err, "DialSOCKS5TCP")
		defer c.Close()
		_ = c.SetDeadline(time.Now().Add(8 * time.Second))

		sent := DeterministicBytes(16051, 16*1024)
		var wg sync.WaitGroup
		var writeErr, readErr error
		var got []byte
		wg.Add(2)
		go func() {
			defer wg.Done()
			writeErr = t2WriteAllBytes(c, sent)
			if writeErr == nil {
				writeErr = c.CloseWrite()
			}
		}()
		go func() {
			defer wg.Done()
			got, readErr = io.ReadAll(c)
		}()
		wg.Wait()
		t2RequireNoErr(t, writeErr, "client upload+CloseWrite")
		t2RequireNoErr(t, readErr, "client ReadAll until EOF")
		t2RequireTrue(t, sha256.Sum256(got) == sha256.Sum256(DeterministicBytes(1605, 16*1024)), "trailer SHA-256 mismatch")
		t2RequireTrue(t, hcTarget.ReceivedLen.Load() == int64(len(sent)), "server received %d != %d", hcTarget.ReceivedLen.Load(), len(sent))
	})
}

func t2RunF17(t *testing.T) {
	pass := "Feature17NativeUDP"

	t.Run("T2-F17-01_NativeUDPSingleByteAndEmptyDatagram", func(t *testing.T) {
		udpEcho := StartUDPEchoTarget(t)
		topo := StartTopology(t, TopologyConfig{
			ServerPassword: pass,
			ClientPassword: pass,
		})
		out := t2DialOutbound(t, topo.Client, "aether-out")
		ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
		defer cancel()
		dest := M.ParseSocksaddrHostPort("127.0.0.1", udpEcho.Port())
		rawPC, err := out.ListenPacket(ctx, dest)
		t2RequireNoErr(t, err, "ListenPacket")
		pc, ok := rawPC.(N.PacketConn)
		t2RequireTrue(t, ok, "expected net.PacketConn from ListenPacket to implement N.PacketConn")
		defer pc.Close()
		_ = pc.SetDeadline(time.Now().Add(6 * time.Second))

		// 1-byte datagram.
		b1 := buf.NewPacket()
		_, _ = b1.Write([]byte{0x42})
		t2RequireNoErr(t, pc.WritePacket(b1, dest), "WritePacket 1B")
		r1 := buf.NewPacket()
		defer r1.Release()
		_, err = pc.ReadPacket(r1)
		t2RequireNoErr(t, err, "ReadPacket 1B")
		t2RequireTrue(t, bytes.Equal(r1.Bytes(), []byte{0x42}), "expected [0x42], got %x", r1.Bytes())

		// 0-byte empty datagram must be handled cleanly without breaking stream alignment.
		bEmpty := buf.NewPacket()
		_ = pc.WritePacket(bEmpty, dest)

		// Follow-up 1-byte datagram must succeed promptly.
		b2 := buf.NewPacket()
		_, _ = b2.Write([]byte{0x99})
		t2RequireNoErr(t, pc.WritePacket(b2, dest), "WritePacket follow-up 1B")
		_ = pc.SetReadDeadline(time.Now().Add(4 * time.Second))
		for {
			r2 := buf.NewPacket()
			_, rErr := pc.ReadPacket(r2)
			got := append([]byte(nil), r2.Bytes()...)
			r2.Release()
			t2RequireNoErr(t, rErr, "ReadPacket follow-up 1B")
			if len(got) == 0 {
				continue // empty datagram echoed cleanly before [0x99]
			}
			t2RequireTrue(t, bytes.Equal(got, []byte{0x99}), "expected [0x99], got %x", got)
			break
		}
	})

	t.Run("T2-F17-02_NativeUDP16384BFrameBoundaryDatagram", func(t *testing.T) {
		// Use SpecMockServer OnSession so macOS net.inet.udp.maxdgram=9216 does not block 16KB+ testing,
		// while verifying real Client Box CommandUDP framing across 16384B boundaries.
		ms := StartSpecMockServer(t, SpecServerOptions{
			Password:  pass,
			OnSession: t2RelaySpecMockNativeUDP,
		})
		clientBox, _ := t2StartSingleAetherClient(t, "127.0.0.1", ms.Port(), TopologyConfig{
			ClientPassword: pass,
		})
		out := t2DialOutbound(t, clientBox, "aether-out")
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		dest := M.ParseSocksaddrHostPort("127.0.0.1", 5353)
		rawPC, err := out.ListenPacket(ctx, dest)
		t2RequireNoErr(t, err, "ListenPacket")
		pc, ok := rawPC.(N.PacketConn)
		t2RequireTrue(t, ok, "expected net.PacketConn from ListenPacket to implement N.PacketConn")
		defer pc.Close()
		_ = pc.SetDeadline(time.Now().Add(8 * time.Second))

		for _, sz := range []int{16100, 16375, 16384} {
			payload := DeterministicBytes(uint64(17020+sz), sz)
			wb := buf.NewSize(len(payload))
			_, _ = wb.Write(payload)
			t2RequireNoErr(t, pc.WritePacket(wb, dest), "WritePacket %dB", sz)
			rb := buf.NewPacket()
			_, rErr := pc.ReadPacket(rb)
			got := append([]byte(nil), rb.Bytes()...)
			rb.Release()
			t2RequireNoErr(t, rErr, "ReadPacket %dB", sz)
			t2RequireTrue(t, len(got) == sz && sha256.Sum256(got) == sha256.Sum256(payload), "CommandUDP %dB mismatch (got %dB)", sz, len(got))
		}
	})

	t.Run("T2-F17-03_NativeUDPMaxLoopback64KBDatagram", func(t *testing.T) {
		ms := StartSpecMockServer(t, SpecServerOptions{
			Password:  pass,
			OnSession: t2RelaySpecMockNativeUDP,
		})
		clientBox, _ := t2StartSingleAetherClient(t, "127.0.0.1", ms.Port(), TopologyConfig{
			ClientPassword: pass,
		})
		out := t2DialOutbound(t, clientBox, "aether-out")
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		dest := M.ParseSocksaddrHostPort("127.0.0.1", 5353)
		rawPC, err := out.ListenPacket(ctx, dest)
		t2RequireNoErr(t, err, "ListenPacket")
		pc, ok := rawPC.(N.PacketConn)
		t2RequireTrue(t, ok, "expected net.PacketConn from ListenPacket to implement N.PacketConn")
		defer pc.Close()
		_ = pc.SetDeadline(time.Now().Add(8 * time.Second))

		payload := DeterministicBytes(1703, 65507)
		wb := buf.NewSize(len(payload))
		_, _ = wb.Write(payload)
		t2RequireNoErr(t, pc.WritePacket(wb, dest), "WritePacket 65507B")

		rb := buf.NewSize(65536)
		defer rb.Release()
		_, rErr := pc.ReadPacket(rb)
		t2RequireNoErr(t, rErr, "ReadPacket 65507B")
		t2RequireTrue(t, rb.Len() == 65507 && sha256.Sum256(rb.Bytes()) == sha256.Sum256(payload), "65507B CommandUDP SHA-256 mismatch (got len=%d)", rb.Len())
	})

	t.Run("T2-F17-04_NativeUDPOversized65536BWriteRejected", func(t *testing.T) {
		udpEcho := StartUDPEchoTarget(t)
		topo := StartTopology(t, TopologyConfig{
			ServerPassword: pass,
			ClientPassword: pass,
		})
		out := t2DialOutbound(t, topo.Client, "aether-out")
		ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
		defer cancel()
		dest := M.ParseSocksaddrHostPort("127.0.0.1", udpEcho.Port())
		rawPC, err := out.ListenPacket(ctx, dest)
		t2RequireNoErr(t, err, "ListenPacket")
		pc, ok := rawPC.(N.PacketConn)
		t2RequireTrue(t, ok, "expected net.PacketConn from ListenPacket to implement N.PacketConn")
		defer pc.Close()
		_ = pc.SetDeadline(time.Now().Add(6 * time.Second))

		oversized := buf.NewSize(65536)
		oversized.WriteZeroN(65536)
		wErr := pc.WritePacket(oversized, dest)
		t2RequireErr(t, wErr, "expected WritePacket 65536B (> uint16 max 65535) rejected")

		// Session remains intact for normal valid datagrams afterward.
		valid := buf.NewPacket()
		_, _ = valid.Write([]byte("after-oversized"))
		if pc.WritePacket(valid, dest) == nil {
			rb := buf.NewPacket()
			defer rb.Release()
			if _, rErr := pc.ReadPacket(rb); rErr == nil {
				t2RequireTrue(t, string(rb.Bytes()) == "after-oversized", "expected intact session echo")
			}
		}
	})

	t.Run("T2-F17-05_NativeUDPTruncatedStreamMidDatagram", func(t *testing.T) {
		udpEcho := StartUDPEchoTarget(t)
		_, srvAddr := t2StartSingleAetherServer(t, TopologyConfig{ServerPassword: pass})
		ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
		defer cancel()

		cmdUDP := SpecCommandUDP
		sc, err := DialSpecClient(ctx, srvAddr, SpecDialOptions{
			Password:   pass,
			Command:    &cmdUDP,
			TargetAddr: udpEcho.Addr(),
		})
		t2RequireNoErr(t, err, "DialSpecClient UDP")
		defer sc.Close()
		_, err = sc.ReadServerResp(4 * time.Second)
		t2RequireNoErr(t, err, "ReadServerResp UDP")

		fakeLen := uint16(5000)
		t2RequireNoErr(t, sc.SendUDPDatagram(udpEcho.Addr(), DeterministicBytes(1705, 1000), &fakeLen), "send truncated UDP stream")
		_ = sc.SendCloseWrite()
		t2RequireNoErr(t, sc.ExpectPeerClose(3*time.Second), "server must close cleanly on truncated mid-datagram UDP stream")
		t2RequireTrue(t, udpEcho.Packets() == 0, "incomplete datagram must never dispatch to UDP target")
	})

	t.Run("T2-F17-06_NativeUDPMalformedSocksaddrInStream", func(t *testing.T) {
		udpEcho := StartUDPEchoTarget(t)
		_, srvAddr := t2StartSingleAetherServer(t, TopologyConfig{ServerPassword: pass})
		ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
		defer cancel()

		cmdUDP := SpecCommandUDP
		sc, err := DialSpecClient(ctx, srvAddr, SpecDialOptions{
			Password:   pass,
			Command:    &cmdUDP,
			TargetAddr: udpEcho.Addr(),
		})
		t2RequireNoErr(t, err, "DialSpecClient UDP")
		defer sc.Close()
		_, err = sc.ReadServerResp(4 * time.Second)
		t2RequireNoErr(t, err, "ReadServerResp UDP")

		t2RequireNoErr(t, sc.WriteFrame(SpecFrameData, 0, []byte{0x77, 1, 2, 3, 4, 0, 53, 0, 4, 't', 'e', 's', 't'}), "write invalid ATYP 0x77")
		t2RequireNoErr(t, sc.ExpectPeerClose(3*time.Second), "server must close cleanly on invalid UDP stream Socksaddr")
		t2RequireTrue(t, udpEcho.Packets() == 0, "malformed UDP stream must never reach target")
	})
}

func t2RunF18(t *testing.T) {
	pass := "Feature18AntiReplay"

	t.Run("T2-F18-01_ClockSkewBoundaryPlusMinus29sAccepted", func(t *testing.T) {
		echo := StartTCPEchoTarget(t)
		t0 := time.Date(2026, 11, 14, 12, 0, 0, 0, time.UTC)
		for _, skew := range []time.Duration{29 * time.Second, -29 * time.Second} {
			tsSrv := NewFrozenMockTimeService(t0)
			tsCli := NewFrozenMockTimeService(t0.Add(skew))
			topo := StartTopology(t, TopologyConfig{
				ServerPassword:    pass,
				ServerTimeService: tsSrv,
				ClientPassword:    pass,
				ClientTimeService: tsCli,
				DisableWireTap:    true,
			})
			t2RequireNoErr(t, t2EchoTCPViaSOCKS5(t, topo.ClientProxyAddr(), echo.Addr(), []byte("skew-29s-ok")), "expected %v clock skew accepted", skew)
			topo.Close()
		}
	})

	t.Run("T2-F18-02_ClockSkewBoundaryPlusMinus35sRejected", func(t *testing.T) {
		echo := StartTCPEchoTarget(t)
		t0 := time.Date(2026, 11, 14, 12, 0, 0, 0, time.UTC)
		tsSrv := NewFrozenMockTimeService(t0)
		_, srvAddr := t2StartSingleAetherServer(t, TopologyConfig{
			ServerPassword:         pass,
			ServerTimeService:      tsSrv,
			ServerHandshakeTimeout: "700ms",
		})

		var wg sync.WaitGroup
		for _, skewSec := range []int64{35, -35} {
			tsVal := t0.Unix() + skewSec
			wg.Add(1)
			go func() {
				defer wg.Done()
				burst, _, err := BuildSpecClientInitialBurst(SpecDialOptions{
					Password:     pass,
					TargetAddr:   echo.Addr(),
					TimestampSec: &tsVal,
				})
				t2RequireNoErr(t, err, "BuildSpecClientInitialBurst")
				t2AssertStealthDrain(t, srvAddr, burst, false, 2800*time.Millisecond, 12*time.Second)
			}()
		}
		wg.Wait()
		t2RequireTrue(t, echo.Connections() == 0, "stale timestamps must not dial target")
	})

	t.Run("T2-F18-03_ExactClientInitialBurstReplayRejected", func(t *testing.T) {
		echo := StartTCPEchoTarget(t)
		_, srvAddr := t2StartSingleAetherServer(t, TopologyConfig{
			ServerPassword:         pass,
			ServerHandshakeTimeout: "700ms",
		})

		burst, sc, err := BuildSpecClientInitialBurst(SpecDialOptions{
			Password:       pass,
			TargetAddr:     echo.Addr(),
			InitialPayload: []byte("first-once"),
		})
		t2RequireNoErr(t, err, "BuildSpecClientInitialBurst")

		ctx, cancel := context.WithTimeout(context.Background(), 6*time.Second)
		defer cancel()
		var d net.Dialer
		conn, err := d.DialContext(ctx, "tcp", srvAddr)
		t2RequireNoErr(t, err, "dial server")
		sc.Conn = conn
		t2RequireNoErr(t, t2WriteAllBytes(conn, burst), "write first burst")
		_, err = sc.ReadServerResp(4 * time.Second)
		t2RequireNoErr(t, err, "first burst must succeed")
		f, err := sc.ReadFrame(4 * time.Second)
		t2RequireNoErr(t, err, "read echo")
		t2RequireTrue(t, string(f.Data) == "first-once", "unexpected first echo")
		_ = sc.Close()

		t2RequireTrue(t, echo.Connections() == 1, "expected 1 target conn before replay")
		t2AssertStealthDrain(t, srvAddr, burst, false, 2800*time.Millisecond, 12*time.Second)
		t2RequireTrue(t, echo.Connections() == 1, "replayed initial burst must NOT reach target (conns=%d)", echo.Connections())
	})

	t.Run("T2-F18-04_CrossGenerationBoundaryReplayAtPlus31sAnd58sRejected", func(t *testing.T) {
		echo := StartTCPEchoTarget(t)
		t0 := time.Date(2026, 11, 14, 12, 0, 0, 0, time.UTC)
		tsSrv := NewFrozenMockTimeService(t0)
		_, srvAddr := t2StartSingleAetherServer(t, TopologyConfig{
			ServerPassword:         pass,
			ServerTimeWindow:       "30s",
			ServerTimeService:      tsSrv,
			ServerHandshakeTimeout: "700ms",
		})

		// Client burst timestamp is t0 + 29s (valid at t0, t0+31s, and t0+58s under +-30s skew).
		tsBurst := t0.Add(29 * time.Second).Unix()
		burst, sc, err := BuildSpecClientInitialBurst(SpecDialOptions{
			Password:       pass,
			TargetAddr:     echo.Addr(),
			TimestampSec:   &tsBurst,
			InitialPayload: []byte("gen-cross-valid"),
		})
		t2RequireNoErr(t, err, "BuildSpecClientInitialBurst")

		conn, err := net.DialTimeout("tcp", srvAddr, 5*time.Second)
		t2RequireNoErr(t, err, "dial valid")
		sc.Conn = conn
		t2RequireNoErr(t, t2WriteAllBytes(conn, burst), "send valid burst")
		_, err = sc.ReadServerResp(4 * time.Second)
		t2RequireNoErr(t, err, "initial burst at t0 must succeed")
		_ = sc.Close()

		// Advance server clock to t0 + 31s (crosses 30s mark) -> still rejected by Bloom!
		tsSrv.Advance(31 * time.Second)
		t2AssertStealthDrain(t, srvAddr, burst, false, 2800*time.Millisecond, 12*time.Second)

		// Advance server clock to t0 + 58s (within 2*TimeWindow=60s previous generation) -> still rejected!
		tsSrv.Advance(27 * time.Second)
		t2AssertStealthDrain(t, srvAddr, burst, false, 2800*time.Millisecond, 12*time.Second)
		t2RequireTrue(t, echo.Connections() == 1, "replays across generations must never reach target, conns=%d", echo.Connections())
	})

	t.Run("T2-F18-05_UnauthenticatedGarbageCannotPoisonBloomFilter", func(t *testing.T) {
		echo := StartTCPEchoTarget(t)
		_, srvAddr := t2StartSingleAetherServer(t, TopologyConfig{
			ServerPassword:         pass,
			ServerHandshakeTimeout: "700ms",
		})

		var chosenSalt [32]byte
		copy(chosenSalt[:], DeterministicBytes(1805, 32))

		// Unauthenticated garbage prefix carrying chosen ClientSalt = S* with invalid AEAD tag.
		poisonProbe := make([]byte, SpecClientPrefixNoEIHSize)
		copy(poisonProbe[0:32], chosenSalt[:])
		copy(poisonProbe[32:], DeterministicBytes(18051, SpecClientPrefixNoEIHSize-32))
		t2AssertStealthDrain(t, srvAddr, poisonProbe, true, 0, 12*time.Second)

		// Legitimate handshake using the EXACT same ClientSalt = S* MUST succeed!
		ctx, cancel := context.WithTimeout(context.Background(), 6*time.Second)
		defer cancel()
		sc, err := DialSpecClient(ctx, srvAddr, SpecDialOptions{
			Password:         pass,
			TargetAddr:       echo.Addr(),
			CustomClientSalt: &chosenSalt,
			InitialPayload:   []byte("unpoisoned-ok"),
		})
		t2RequireNoErr(t, err, "DialSpecClient with previously probed salt")
		defer sc.Close()
		_, err = sc.ReadServerResp(4 * time.Second)
		t2RequireNoErr(t, err, "valid handshake with S* must NOT be blocked by Bloom poison")
		f, err := sc.ReadFrame(4 * time.Second)
		t2RequireNoErr(t, err, "read echo")
		t2RequireTrue(t, string(f.Data) == "unpoisoned-ok", "unexpected echo %q", string(f.Data))
	})

	t.Run("T2-F18-06_CustomTightTimeWindow10sBoundaryPlusMinus9sVs13s", func(t *testing.T) {
		echo := StartTCPEchoTarget(t)
		t0 := time.Date(2026, 11, 14, 12, 0, 0, 0, time.UTC)
		tsSrv := NewFrozenMockTimeService(t0)
		_, srvAddr := t2StartSingleAetherServer(t, TopologyConfig{
			ServerPassword:         pass,
			ServerTimeWindow:       "10s",
			ServerTimeService:      tsSrv,
			ServerHandshakeTimeout: "700ms",
		})

		ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
		defer cancel()
		for _, okSkew := range []int64{9, -9} {
			ts := t0.Unix() + okSkew
			sc, err := DialSpecClient(ctx, srvAddr, SpecDialOptions{
				Password:       pass,
				TargetAddr:     echo.Addr(),
				TimestampSec:   &ts,
				InitialPayload: []byte("9s-ok"),
			})
			t2RequireNoErr(t, err, "DialSpecClient %ds", okSkew)
			_, err = sc.ReadServerResp(4 * time.Second)
			t2RequireNoErr(t, err, "expected %ds accepted within 10s window", okSkew)
			_ = sc.Close()
		}

		var wg sync.WaitGroup
		for _, badSkew := range []int64{13, -13} {
			ts := t0.Unix() + badSkew
			wg.Add(1)
			go func() {
				defer wg.Done()
				burst, _, err := BuildSpecClientInitialBurst(SpecDialOptions{
					Password:     pass,
					TargetAddr:   echo.Addr(),
					TimestampSec: &ts,
				})
				t2RequireNoErr(t, err, "build %ds", badSkew)
				t2AssertStealthDrain(t, srvAddr, burst, false, 2800*time.Millisecond, 12*time.Second)
			}()
		}
		wg.Wait()
	})
}

func t2RunF19(t *testing.T) {
	pass := "Feature19StealthDrain"

	t.Run("T2-F19-01_ZeroByteSlowlorisProbeTimeoutAndFIN", func(t *testing.T) {
		_, srvAddr := t2StartSingleAetherServer(t, TopologyConfig{
			ServerPassword:         pass,
			ServerHandshakeTimeout: "700ms",
		})
		res, err := SendRawProbe(srvAddr, nil, false, 15*time.Second)
		t2RequireNoErr(t, err, "SendRawProbe 0B")
		t2RequireTrue(t, len(res.BytesReceived) == 0, "expected 0 S2C bytes, got %d", len(res.BytesReceived))
		t2RequireTrue(t, !res.ClosedByRST, "expected clean TCP FIN, never RST")
		t2RequireTrue(t, !res.TimedOut && res.ClosedCleanEOF, "expected clean EOF after timeout/drain (timedOut=%v err=%v elapsed=%v)", res.TimedOut, res.Err, res.Elapsed)
		t2RequireTrue(t, res.Elapsed >= 600*time.Millisecond, "closed too early (<HandshakeTimeout 700ms): %v", res.Elapsed)
	})

	t.Run("T2-F19-02_Truncated34BAnd95BSingleUserProbes", func(t *testing.T) {
		_, srvAddr := t2StartSingleAetherServer(t, TopologyConfig{
			ServerPassword:         pass,
			ServerHandshakeTimeout: "700ms",
		})
		var wg sync.WaitGroup
		for _, sz := range []int{34, 95} {
			szCopy := sz
			wg.Add(1)
			go func() {
				defer wg.Done()
				res, err := SendRawProbe(srvAddr, DeterministicBytes(uint64(19020+szCopy), szCopy), false, 15*time.Second)
				t2RequireNoErr(t, err, "SendRawProbe %dB", szCopy)
				t2RequireTrue(t, len(res.BytesReceived) == 0, "probe %dB must get 0 S2C bytes", szCopy)
				t2RequireTrue(t, !res.ClosedByRST, "probe %dB got RST instead of FIN", szCopy)
				t2RequireTrue(t, !res.TimedOut && res.ClosedCleanEOF, "probe %dB expected clean EOF (elapsed=%v)", szCopy, res.Elapsed)
				t2RequireTrue(t, res.Elapsed >= 600*time.Millisecond, "probe %dB closed early: %v", szCopy, res.Elapsed)
			}()
		}
		wg.Wait()
	})

	t.Run("T2-F19-03_Truncated111BMultiUserEIHProbe", func(t *testing.T) {
		_, srvAddr := t2StartSingleAetherServer(t, TopologyConfig{
			ServerPassword:         "IPSKSecret1903!!",
			ServerUsers:            []UserSpec{{Name: "u1", Password: "UserSecret1903!!"}},
			ServerHandshakeTimeout: "700ms",
		})
		res, err := SendRawProbe(srvAddr, DeterministicBytes(1903, 111), false, 15*time.Second)
		t2RequireNoErr(t, err, "SendRawProbe 111B")
		t2RequireTrue(t, len(res.BytesReceived) == 0, "111B probe must get 0 S2C bytes")
		t2RequireTrue(t, !res.ClosedByRST, "111B probe got RST instead of FIN")
		t2RequireTrue(t, !res.TimedOut && res.ClosedCleanEOF, "111B probe expected clean EOF")
		t2RequireTrue(t, res.Elapsed >= 600*time.Millisecond, "111B probe closed early (oracle!): %v", res.Elapsed)
	})

	t.Run("T2-F19-04_Garbage512BActiveScannerProbesStealthDrain", func(t *testing.T) {
		_, srvAddr := t2StartSingleAetherServer(t, TopologyConfig{
			ServerPassword:         pass,
			ServerHandshakeTimeout: "700ms",
		})
		httpProbe := append([]byte("GET / HTTP/1.1\r\nHost: example.com\r\nUser-Agent: scanner\r\n\r\n"), DeterministicBytes(19041, 512)...)[:512]
		tlsProbe := append([]byte{0x16, 0x03, 0x01, 0x01, 0xfb, 0x01, 0x00, 0x01, 0xf7, 0x03, 0x03}, DeterministicBytes(19042, 512)...)[:512]
		randProbe := DeterministicBytes(19043, 512)

		var wg sync.WaitGroup
		for i, probe := range [][]byte{httpProbe, tlsProbe, randProbe} {
			idx := i
			p := probe
			wg.Add(1)
			go func() {
				defer wg.Done()
				res, err := SendRawProbe(srvAddr, p, false, 13*time.Second)
				t2RequireNoErr(t, err, "SendRawProbe scanner[%d]", idx)
				t2RequireTrue(t, len(res.BytesReceived) == 0, "scanner[%d] must get 0 response bytes", idx)
				t2RequireTrue(t, !res.ClosedByRST, "scanner[%d] received RST", idx)
				t2RequireTrue(t, !res.TimedOut && res.ClosedCleanEOF, "scanner[%d] expected clean EOF (elapsed=%v)", idx, res.Elapsed)
				t2RequireTrue(t, res.Elapsed >= 2800*time.Millisecond && res.Elapsed <= 11*time.Second, "scanner[%d] drain elapsed=%v outside [2.8s,11s]", idx, res.Elapsed)
			}()
		}
		wg.Wait()
	})

	t.Run("T2-F19-05_Over256ConcurrentStalledHandshakeFlood", func(t *testing.T) {
		echo := StartTCPEchoTarget(t)
		topo := StartTopology(t, TopologyConfig{
			ServerPassword:         pass,
			ServerHandshakeTimeout: "800ms",
			ClientPassword:         pass,
			DisableWireTap:         true,
		})

		const floodCount = 300
		conns := make([]net.Conn, 0, floodCount)
		var mu sync.Mutex
		var wg sync.WaitGroup
		for i := 0; i < floodCount; i++ {
			wg.Add(1)
			go func(idx int) {
				defer wg.Done()
				c, dErr := net.DialTimeout("tcp", topo.ServerAddr(), 2*time.Second)
				if dErr != nil {
					return
				}
				_, _ = c.Write(DeterministicBytes(uint64(19050+idx), 16))
				mu.Lock()
				conns = append(conns, c)
				mu.Unlock()
			}(i)
		}
		wg.Wait()
		t.Cleanup(func() {
			mu.Lock()
			for _, c := range conns {
				_ = c.Close()
			}
			mu.Unlock()
		})

		// Wait past HandshakeTimeout so server sheds stalled slots cleanly, or verify responsiveness.
		time.Sleep(950 * time.Millisecond)
		t2RequireNoErr(t, t2EchoTCPViaSOCKS5(t, topo.ClientProxyAddr(), echo.Addr(), []byte("legit-after-300-stalled")), "legitimate handshake must succeed")

		mu.Lock()
		for _, c := range conns {
			_ = c.Close()
		}
		conns = nil
		mu.Unlock()

		topo.Close()
		echo.Close()

		leaks := t2WaitForNoAetherLeaks(5 * time.Second)
		if len(leaks) > 0 {
			t.Fatalf("goroutine leaks after 300 stalled flood: %v", leaks)
		}
	})

	t.Run("T2-F19-06_Over512ConcurrentDrainFloodDoesNotStarveHandshakes", func(t *testing.T) {
		echo := StartTCPEchoTarget(t)
		topo := StartTopology(t, TopologyConfig{
			ServerPassword:         pass,
			ServerHandshakeTimeout: "800ms",
			ClientPassword:         pass,
			DisableWireTap:         true,
		})

		const floodCount = 560
		conns := make([]net.Conn, 0, floodCount)
		var mu sync.Mutex
		var wg sync.WaitGroup
		for i := 0; i < floodCount; i++ {
			wg.Add(1)
			go func(idx int) {
				defer wg.Done()
				c, dErr := net.DialTimeout("tcp", topo.ServerAddr(), 2*time.Second)
				if dErr != nil {
					return
				}
				_, _ = c.Write(DeterministicBytes(uint64(19060+idx), SpecClientPrefixNoEIHSize))
				mu.Lock()
				conns = append(conns, c)
				mu.Unlock()
			}(i)
		}
		wg.Wait()
		t.Cleanup(func() {
			mu.Lock()
			for _, c := range conns {
				_ = c.Close()
			}
			mu.Unlock()
		})

		// Because handshakeSem releases before drainSem (512 cap), 5 legitimate clients must succeed swiftly!
		var legitWG sync.WaitGroup
		for i := 0; i < 5; i++ {
			idx := i
			legitWG.Add(1)
			go func() {
				defer legitWG.Done()
				start := time.Now()
				t2RequireNoErr(t, t2EchoTCPViaSOCKS5(t, topo.ClientProxyAddr(), echo.Addr(), []byte(fmt.Sprintf("legit-%d", idx))), "legit[%d] starved by drain flood", idx)
				if el := time.Since(start); el > 1500*time.Millisecond {
					t.Errorf("legitimate handshake[%d] took %v during drain flood (expected fast)", idx, el)
				}
			}()
		}
		legitWG.Wait()

		mu.Lock()
		for _, c := range conns {
			_ = c.Close()
		}
		conns = nil
		mu.Unlock()
	})
}

func t2RunF20(t *testing.T) {
	pass := "Feature20DeadlockFree"

	t.Run("T2-F20-01_PeerNeverReadsWhileFlooding1000FramePings", func(t *testing.T) {
		hcTarget := StartTCPHalfCloseTarget(t, []byte("HCDONE"))
		_, srvAddr := t2StartSingleAetherServer(t, TopologyConfig{ServerPassword: pass})

		ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
		defer cancel()
		sc, err := DialSpecClient(ctx, srvAddr, SpecDialOptions{
			Password:   pass,
			TargetAddr: hcTarget.Addr(),
		})
		t2RequireNoErr(t, err, "DialSpecClient")
		defer sc.Close()
		_, err = sc.ReadServerResp(4 * time.Second)
		t2RequireNoErr(t, err, "ReadServerResp")

		// Stop reading S2C completely! Flood 1000 FramePing interleaved with FrameData payloads.
		_ = sc.Conn.SetWriteDeadline(time.Now().Add(6 * time.Second))
		sentData := 0
		for i := 0; i < 1000; i++ {
			if err := sc.SendPing(32); err != nil {
				break
			}
			if i%50 == 0 {
				msg := []byte("0123456789")
				if err := sc.WriteFrame(SpecFrameData, 0, msg); err != nil {
					break
				}
				sentData += len(msg)
			}
		}
		_ = sc.WriteFrame(SpecFrameData, 0, []byte("FINAL"))
		sentData += 5
		_ = sc.SendCloseWrite()
		_ = sc.Close()

		deadline := time.Now().Add(3 * time.Second)
		for time.Now().Before(deadline) && hcTarget.ReceivedLen.Load() < int64(sentData) {
			time.Sleep(20 * time.Millisecond)
		}
		t2RequireTrue(t, hcTarget.ReceivedLen.Load() >= 5, "server Read loop must continue delivering FrameData without pongCh deadlock (got %dB)", hcTarget.ReceivedLen.Load())
	})

	t.Run("T2-F20-02_PingArrivalDuringConcurrentClose", func(t *testing.T) {
		echo := StartTCPEchoTarget(t)
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()

		for iter := 0; iter < 20; iter++ {
			srvBox, srvAddr := t2StartSingleAetherServer(t, TopologyConfig{ServerPassword: pass})
			sc, err := DialSpecClient(ctx, srvAddr, SpecDialOptions{
				Password:   pass,
				TargetAddr: echo.Addr(),
			})
			t2RequireNoErr(t, err, "DialSpecClient iter %d", iter)
			_, err = sc.ReadServerResp(3 * time.Second)
			t2RequireNoErr(t, err, "ReadServerResp iter %d", iter)

			var wg sync.WaitGroup
			wg.Add(2)
			go func() {
				defer wg.Done()
				for j := 0; j < 20; j++ {
					if sc.SendPing(32) != nil {
						return
					}
					time.Sleep(2 * time.Millisecond)
				}
			}()
			go func() {
				defer wg.Done()
				time.Sleep(8 * time.Millisecond)
				_ = sc.Close()
				_ = srvBox.Close()
			}()
			wg.Wait()
		}
	})

	t.Run("T2-F20-03_TinySocketBufferBidirectionalMuxTorture", func(t *testing.T) {
		echo := StartTCPEchoTarget(t)
		topo := StartTopology(t, TopologyConfig{
			ServerPassword:          pass,
			ServerHeartbeatInterval: "150ms",
			ServerMultiplex:         &MultiplexServerSpec{Enabled: true, Padding: true},
			ClientPassword:          pass,
			ClientHeartbeatInterval: "150ms",
			ClientMultiplex: &MultiplexClientSpec{
				Enabled:        true,
				Protocol:       "yamux",
				MaxConnections: 1,
				MinStreams:     1,
				Padding:        true,
			},
			WireTapWindowSize: 4096,
		})

		const streams = 8
		const sizePerStream = 256 * 1024
		var wg sync.WaitGroup
		errCh := make(chan error, streams)
		for i := 0; i < streams; i++ {
			idx := i
			wg.Add(1)
			go func() {
				defer wg.Done()
				err := t2EchoTCPViaSOCKS5(t, topo.ClientProxyAddr(), echo.Addr(), DeterministicBytes(uint64(20030+idx), sizePerStream))
				if err != nil {
					errCh <- fmt.Errorf("stream %d: %w", idx, err)
				}
			}()
		}
		wg.Wait()
		close(errCh)
		for e := range errCh {
			t.Fatalf("yamux tiny-buffer bidirectional error: %v", e)
		}
	})

	t.Run("T2-F20-04_PongCoordinatorExitsCleanlyOnWriteError", func(t *testing.T) {
		echo := StartTCPEchoTarget(t)
		srvBox, srvAddr := t2StartSingleAetherServer(t, TopologyConfig{ServerPassword: pass})
		tap := StartWireTapProxy(t, srvAddr)
		defer tap.Close()

		ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
		defer cancel()
		sc, err := DialSpecClient(ctx, tap.Addr(), SpecDialOptions{
			Password:   pass,
			TargetAddr: echo.Addr(),
		})
		t2RequireNoErr(t, err, "DialSpecClient")
		defer sc.Close()
		_, err = sc.ReadServerResp(4 * time.Second)
		t2RequireNoErr(t, err, "ReadServerResp")

		// Abort S2C with RST right after 84B prefix as Ping arrives so pong writer observes write error.
		tap.SetAbortAfterBytes(DirS2C, SpecServerRespPrefixSize+4, true)
		_ = sc.SendPing(32)
		time.Sleep(150 * time.Millisecond)
		_ = sc.Close()
		tap.Close()
		_ = srvBox.Close()
		echo.Close()

		leaks := t2WaitForNoAetherLeaks(4 * time.Second)
		if len(leaks) > 0 {
			t.Fatalf("pong coordinator leaked goroutines on write error: %v", leaks)
		}
	})

	t.Run("T2-F20-05_RapidAlternatingChaffAndPingUnderBackpressure", func(t *testing.T) {
		echo := StartTCPEchoTarget(t)
		_, srvAddr := t2StartSingleAetherServer(t, TopologyConfig{ServerPassword: pass})
		tap := StartWireTapProxy(t, srvAddr)
		defer tap.Close()
		tap.SetThrottle(500*time.Microsecond, 1024)

		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		sc, err := DialSpecClient(ctx, tap.Addr(), SpecDialOptions{
			Password:   pass,
			TargetAddr: echo.Addr(),
		})
		t2RequireNoErr(t, err, "DialSpecClient")
		defer sc.Close()
		_, err = sc.ReadServerResp(4 * time.Second)
		t2RequireNoErr(t, err, "ReadServerResp")

		payload := DeterministicBytes(2005, 512*1024)
		var readBuf bytes.Buffer
		var readErr error
		var wg sync.WaitGroup
		wg.Add(1)
		go func() {
			defer wg.Done()
			for readBuf.Len() < len(payload) {
				f, rErr := sc.ReadFrame(15 * time.Second)
				if rErr != nil {
					readErr = rErr
					return
				}
				if f.FrameType == SpecFrameData && len(f.Data) > 0 {
					readBuf.Write(f.Data)
				}
			}
		}()

		const chunkSize = 8192
		chunks := len(payload) / chunkSize
		for i := 0; i < chunks; i++ {
			if i%2 == 0 {
				t2RequireNoErr(t, sc.SendChaff(1, 32), "SendChaff %d", i)
				t2RequireNoErr(t, sc.SendPing(32), "SendPing %d", i)
			}
			t2RequireNoErr(t, sc.WriteFrame(SpecFrameData, 0, payload[i*chunkSize:(i+1)*chunkSize]), "WriteFrame %d", i)
		}
		// Pad remaining chaff+pings to guarantee >= 50 each.
		for i := chunks / 2; i < 50; i++ {
			t2RequireNoErr(t, sc.SendChaff(1, 32), "extra chaff")
			t2RequireNoErr(t, sc.SendPing(32), "extra ping")
		}
		wg.Wait()
		t2RequireNoErr(t, readErr, "reader failed under alternating chaff+ping backpressure")
		t2RequireTrue(t, sha256.Sum256(readBuf.Bytes()) == sha256.Sum256(payload), "512 KiB echo SHA-256 mismatch")
	})
}

func t2RunF21(t *testing.T) {
	pass := "Feature21AtomicFuse"

	t.Run("T2-F21-01_ExpiredPastWriteDeadlineFusesConnection", func(t *testing.T) {
		echo := StartTCPEchoTarget(t)
		topo := StartTopology(t, TopologyConfig{
			ServerPassword: pass,
			ClientPassword: pass,
		})
		out := t2DialOutbound(t, topo.Client, "aether-out")
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		conn, err := out.DialContext(ctx, "tcp", M.ParseSocksaddrHostPort("127.0.0.1", echo.Port()))
		t2RequireNoErr(t, err, "DialContext")
		defer conn.Close()

		t2RequireNoErr(t, t2WriteAllBytes(conn, []byte("fuse-warm")), "warm write")
		warmAck := make([]byte, 9)
		_, err = io.ReadFull(conn, warmAck)
		t2RequireNoErr(t, err, "warm read")

		// Pause C2S reads on WireTap so client TCP send buffer fills and hits short WriteDeadline.
		topo.Tap.SetReadPaused(DirC2S, true)
		chunk := DeterministicBytes(2101, 128*1024)
		var deadlineErr error
		for i := 0; i < 64; i++ {
			_ = conn.SetWriteDeadline(time.Now().Add(5 * time.Millisecond))
			_, wErr := conn.Write(chunk)
			if wErr != nil {
				deadlineErr = wErr
				break
			}
		}
		t2RequireErr(t, deadlineErr, "expected Write to fail once send buffer stalled and deadline expired")

		// Even after clearing deadline and unpausing socket, writeBroken fuse MUST fail future writes!
		_ = conn.SetWriteDeadline(time.Time{})
		topo.Tap.SetReadPaused(DirC2S, false)
		_, postErr := conn.Write([]byte("next"))
		t2RequireErr(t, postErr, "writeBroken fuse must permanently reject subsequent writes")
	})

	t.Run("T2-F21-02_AlreadyInPastWriteDeadlineImmediateFail", func(t *testing.T) {
		echo := StartTCPEchoTarget(t)
		topo := StartTopology(t, TopologyConfig{
			ServerPassword: pass,
			ClientPassword: pass,
			DisableWireTap: true,
		})
		out := t2DialOutbound(t, topo.Client, "aether-out")
		ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
		defer cancel()
		conn, err := out.DialContext(ctx, "tcp", M.ParseSocksaddrHostPort("127.0.0.1", echo.Port()))
		t2RequireNoErr(t, err, "DialContext")
		defer conn.Close()

		t2RequireNoErr(t, t2WriteAllBytes(conn, []byte("ok")), "warm")
		tmp := make([]byte, 2)
		_, err = io.ReadFull(conn, tmp)
		t2RequireNoErr(t, err, "warm read")

		_ = conn.SetWriteDeadline(time.Now().Add(-1 * time.Second))
		_, pastErr := conn.Write([]byte("x"))
		t2RequireErr(t, pastErr, "past WriteDeadline must fail immediately")

		_ = conn.SetWriteDeadline(time.Time{})
		_, nextErr := conn.Write([]byte("y"))
		t2RequireErr(t, nextErr, "subsequent write must fail on fused/broken state or clean close")
	})

	t.Run("T2-F21-03_ShortWriteOrMidFrameResetFusesImmediately", func(t *testing.T) {
		echo := StartTCPEchoTarget(t)
		topo := StartTopology(t, TopologyConfig{
			ServerPassword: pass,
			ClientPassword: pass,
		})
		out := t2DialOutbound(t, topo.Client, "aether-out")
		ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
		defer cancel()
		conn, err := out.DialContext(ctx, "tcp", M.ParseSocksaddrHostPort("127.0.0.1", echo.Port()))
		t2RequireNoErr(t, err, "DialContext")
		defer conn.Close()

		t2RequireNoErr(t, t2WriteAllBytes(conn, []byte("init")), "init")
		tmp := make([]byte, 4)
		_, err = io.ReadFull(conn, tmp)
		t2RequireNoErr(t, err, "init read")

		sessions := topo.Tap.WaitForSessions(t, 1, 3*time.Second)
		curC2S := sessions[0].TotalBytes(DirC2S)
		topo.Tap.SetAbortAfterBytes(DirC2S, curC2S+10, true)

		var sawErr bool
		buf4k := DeterministicBytes(2103, 4096)
		for i := 0; i < 20; i++ {
			if _, wErr := conn.Write(buf4k); wErr != nil {
				sawErr = true
				break
			}
			time.Sleep(10 * time.Millisecond)
		}
		t2RequireTrue(t, sawErr, "expected mid-frame socket reset to fail Write")

		_, fusedErr := conn.Write([]byte("after-reset"))
		t2RequireErr(t, fusedErr, "subsequent Write after mid-frame failure must fail immediately")
	})

	t.Run("T2-F21-04_SetDeadlinePastBreaksBothReadAndWriteCleanly", func(t *testing.T) {
		stalled := StartStalledTCPServer(t)
		topo := StartTopology(t, TopologyConfig{
			ServerPassword: pass,
			ClientPassword: pass,
			DisableWireTap: true,
		})
		out := t2DialOutbound(t, topo.Client, "aether-out")
		ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
		defer cancel()
		conn, err := out.DialContext(ctx, "tcp", M.ParseSocksaddrHostPort("127.0.0.1", stalled.Port()))
		t2RequireNoErr(t, err, "DialContext")
		defer conn.Close()

		t2RequireNoErr(t, t2WriteAllBytes(conn, []byte("stalled-req")), "write")
		readErrCh := make(chan error, 1)
		go func() {
			b := make([]byte, 64)
			_, rErr := conn.Read(b)
			readErrCh <- rErr
		}()
		time.Sleep(30 * time.Millisecond)
		_ = conn.SetDeadline(time.Now().Add(-1 * time.Second))

		select {
		case rErr := <-readErrCh:
			t2RequireErr(t, rErr, "Read must abort immediately on past SetDeadline")
		case <-time.After(2 * time.Second):
			t.Fatalf("Read remained blocked after SetDeadline(past)")
		}
		_, wErr := conn.Write([]byte("after-deadline"))
		t2RequireErr(t, wErr, "Write must fail immediately on past SetDeadline")
		_ = conn.Close()
		stalled.Release()
	})

	t.Run("T2-F21-05_ParallelWritersDuringMidWriteSocketFailure", func(t *testing.T) {
		echo := StartTCPEchoTarget(t)
		topo := StartTopology(t, TopologyConfig{
			ServerPassword: pass,
			ClientPassword: pass,
		})
		out := t2DialOutbound(t, topo.Client, "aether-out")
		ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
		defer cancel()
		conn, err := out.DialContext(ctx, "tcp", M.ParseSocksaddrHostPort("127.0.0.1", echo.Port()))
		t2RequireNoErr(t, err, "DialContext")
		defer conn.Close()

		t2RequireNoErr(t, t2WriteAllBytes(conn, []byte("warm")), "warm")
		tmp := make([]byte, 4)
		_, err = io.ReadFull(conn, tmp)
		t2RequireNoErr(t, err, "warm read")

		sessions := topo.Tap.WaitForSessions(t, 1, 3*time.Second)
		cur := sessions[0].TotalBytes(DirC2S)

		const writers = 10
		var wg sync.WaitGroup
		errs := make(chan error, writers)
		payload := DeterministicBytes(2105, 1024)
		for i := 0; i < writers; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for j := 0; j < 200; j++ {
					if _, wErr := conn.Write(payload); wErr != nil {
						errs <- wErr
						return
					}
					time.Sleep(2 * time.Millisecond)
				}
				errs <- nil
			}()
		}
		time.Sleep(25 * time.Millisecond)
		topo.Tap.SetAbortAfterBytes(DirC2S, cur+512, true)
		wg.Wait()
		close(errs)
		for e := range errs {
			t2RequireErr(t, e, "every concurrent writer must exit with clean error on socket RST")
		}
	})
}

func t2RunF22(t *testing.T) {
	pass := "Feature22DPDKeepalive"

	t.Run("T2-F22-01_OneWayBlackholeServerToClientDroppedTriggersDPD", func(t *testing.T) {
		echo := StartTCPEchoTarget(t)
		topo := StartTopology(t, TopologyConfig{
			ServerPassword:          pass,
			ServerHeartbeatInterval: "10s",
			ClientPassword:          pass,
			ClientHeartbeatInterval: "350ms",
		})
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		c, err := DialSOCKS5TCP(ctx, topo.ClientProxyAddr(), echo.Addr())
		t2RequireNoErr(t, err, "DialSOCKS5TCP")
		defer c.Close()
		t2RequireNoErr(t, t2WriteAllBytes(c, []byte("dpd-ready")), "warm")
		tmp := make([]byte, 9)
		_, err = io.ReadFull(c, tmp)
		t2RequireNoErr(t, err, "warm echo")

		start := time.Now()
		topo.Tap.SetBlackhole(false, true) // C->S FramePing reaches server, S->C FramePong dropped!
		_ = c.SetReadDeadline(time.Now().Add(4 * time.Second))
		bufRead := make([]byte, 64)
		_, rErr := c.Read(bufRead)
		el := time.Since(start)
		t2RequireErr(t, rErr, "expected client DPD teardown when S2C Pongs are blackholed")
		t2RequireTrue(t, el < 2500*time.Millisecond, "client DPD took too long (%v >= 2.5s)", el)
	})

	t.Run("T2-F22-02_OneWayBlackholeClientToServerDroppedTriggersServerDPD", func(t *testing.T) {
		echo := StartTCPEchoTarget(t)
		topo := StartTopology(t, TopologyConfig{
			ServerPassword:          pass,
			ServerHeartbeatInterval: "350ms",
			ClientPassword:          pass,
			ClientHeartbeatInterval: "10s",
		})
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		c, err := DialSOCKS5TCP(ctx, topo.ClientProxyAddr(), echo.Addr())
		t2RequireNoErr(t, err, "DialSOCKS5TCP")
		defer c.Close()
		t2RequireNoErr(t, t2WriteAllBytes(c, []byte("srv-dpd")), "warm")
		tmp := make([]byte, 7)
		_, err = io.ReadFull(c, tmp)
		t2RequireNoErr(t, err, "warm echo")

		start := time.Now()
		topo.Tap.SetBlackhole(true, false) // Drop C->S Pongs so Server DPD detects dead peer and sends FIN!
		_ = c.SetReadDeadline(time.Now().Add(4 * time.Second))
		bufRead := make([]byte, 64)
		_, rErr := c.Read(bufRead)
		el := time.Since(start)
		t2RequireErr(t, rErr, "expected server DPD teardown when C2S Pongs are blackholed")
		t2RequireTrue(t, el < 2500*time.Millisecond, "server DPD took too long (%v >= 2.5s)", el)
	})

	t.Run("T2-F22-03_ContinuousUplinkOnlyWithoutDownlinkDataSavedByPong", func(t *testing.T) {
		hcTarget := StartTCPHalfCloseTarget(t, []byte("HEALTHY_DOWNLINK_SILENT"))
		topo := StartTopology(t, TopologyConfig{
			ServerPassword:          pass,
			ServerHeartbeatInterval: "350ms",
			ClientPassword:          pass,
			ClientHeartbeatInterval: "350ms",
		})
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		// Healthy phase: continuous uplink while target returns 0 downlink bytes for 1.2s (> Heartbeat+PongTimeout).
		c1, err := DialSOCKS5TCP(ctx, topo.ClientProxyAddr(), hcTarget.Addr())
		t2RequireNoErr(t, err, "DialSOCKS5TCP healthy uplink")
		defer c1.Close()
		chunk := DeterministicBytes(2203, 4096)
		for i := 0; i < 12; i++ {
			t2RequireNoErr(t, t2WriteAllBytes(c1, chunk), "uplink write %d must stay healthy via Pong", i)
			time.Sleep(100 * time.Millisecond)
		}
		t2RequireNoErr(t, c1.CloseWrite(), "CloseWrite")
		trailer, err := io.ReadAll(c1)
		t2RequireNoErr(t, err, "read trailer after healthy uplink-only stream")
		t2RequireTrue(t, string(trailer) == "HEALTHY_DOWNLINK_SILENT", "unexpected trailer %q", string(trailer))

		// Blackhole S2C phase: uplink continues, S2C Pong lost -> DPD closes stream!
		c2, err := DialSOCKS5TCP(ctx, topo.ClientProxyAddr(), hcTarget.Addr())
		t2RequireNoErr(t, err, "DialSOCKS5TCP blackhole uplink")
		defer c2.Close()
		t2RequireNoErr(t, t2WriteAllBytes(c2, chunk), "initial write")
		time.Sleep(50 * time.Millisecond)

		start := time.Now()
		topo.Tap.SetBlackhole(false, true)
		_ = c2.SetReadDeadline(time.Now().Add(4 * time.Second))
		readDead := make(chan error, 1)
		go func() {
			b := make([]byte, 32)
			_, rErr := c2.Read(b)
			readDead <- rErr
		}()
		select {
		case rErr := <-readDead:
			t2RequireErr(t, rErr, "expected DPD abort when S2C blackholed even during active uplink")
			t2RequireTrue(t, time.Since(start) < 2500*time.Millisecond, "DPD blackhole took %v", time.Since(start))
		case <-time.After(3 * time.Second):
			t.Fatalf("DPD failed to terminate S2C-blackholed uplink stream")
		}
	})

	t.Run("T2-F22-04_VeryShortSubSecondHeartbeatIntervalScaling", func(t *testing.T) {
		echo := StartTCPEchoTarget(t)
		topo := StartTopology(t, TopologyConfig{
			ServerPassword:          pass,
			ServerHeartbeatInterval: "200ms",
			ClientPassword:          pass,
			ClientHeartbeatInterval: "200ms",
		})
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		c, err := DialSOCKS5TCP(ctx, topo.ClientProxyAddr(), echo.Addr())
		t2RequireNoErr(t, err, "DialSOCKS5TCP")
		defer c.Close()

		// 6 cycles at 150ms interval (=900ms > 4x heartbeat_interval) must NOT falsely disconnect.
		for i := 0; i < 6; i++ {
			msg := []byte(fmt.Sprintf("beat-%d", i))
			t2RequireNoErr(t, t2WriteAllBytes(c, msg), "write beat %d", i)
			got := make([]byte, len(msg))
			_, err = io.ReadFull(c, got)
			t2RequireNoErr(t, err, "no premature self-disconnect at 200ms heartbeat (iter %d)", i)
			t2RequireTrue(t, bytes.Equal(got, msg), "mismatch beat %d", i)
			time.Sleep(150 * time.Millisecond)
		}

		// Now blackhole S2C -> fast teardown under scaled PongTimeout (>=500ms).
		start := time.Now()
		topo.Tap.SetBlackhole(false, true)
		_ = c.SetReadDeadline(time.Now().Add(4 * time.Second))
		b := make([]byte, 32)
		_, rErr := c.Read(b)
		t2RequireErr(t, rErr, "expected fast DPD teardown on blackhole")
		t2RequireTrue(t, time.Since(start) < 2*time.Second, "200ms heartbeat DPD teardown took %v", time.Since(start))
	})

	t.Run("T2-F22-05_CloseDuringPendingPongTimeoutTimer", func(t *testing.T) {
		echo := StartTCPEchoTarget(t)
		topo := StartTopology(t, TopologyConfig{
			ServerPassword:          pass,
			ServerHeartbeatInterval: "250ms",
			ClientPassword:          pass,
			ClientHeartbeatInterval: "250ms",
		})
		ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
		defer cancel()
		c, err := DialSOCKS5TCP(ctx, topo.ClientProxyAddr(), echo.Addr())
		t2RequireNoErr(t, err, "DialSOCKS5TCP")
		t2RequireNoErr(t, t2WriteAllBytes(c, []byte("arm-pong")), "write")
		ack := make([]byte, 8)
		_, err = io.ReadFull(c, ack)
		t2RequireNoErr(t, err, "read")

		// Blackhole S2C and wait right around heartbeat firing so PongTimeout timer is armed.
		topo.Tap.SetBlackhole(false, true)
		time.Sleep(320 * time.Millisecond)

		closeStart := time.Now()
		_ = c.Close()
		t2RequireNoErr(t, topo.Client.Close(), "Client.Close() during pending PongTimeout")
		t2RequireNoErr(t, topo.Server.Close(), "Server.Close() during pending PongTimeout")
		el := time.Since(closeStart)
		t2RequireTrue(t, el < 500*time.Millisecond, "Close() stalled waiting for PongTimeout timer: %v", el)
	})
}

func t2RunF23(t *testing.T) {
	pass := "Feature23BufLifecycle"

	t.Run("T2-F23-01_ZeroByteWriteAndEmptyWriteBufferOwnership", func(t *testing.T) {
		echo := StartTCPEchoTarget(t)
		topo := StartTopology(t, TopologyConfig{
			ServerPassword: pass,
			ClientPassword: pass,
			DisableWireTap: true,
		})
		out := t2DialOutbound(t, topo.Client, "aether-out")
		ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
		defer cancel()
		conn, err := out.DialContext(ctx, "tcp", M.ParseSocksaddrHostPort("127.0.0.1", echo.Port()))
		t2RequireNoErr(t, err, "DialContext")
		defer conn.Close()

		n, err := conn.Write(nil)
		t2RequireTrue(t, n == 0 && err == nil, "Write(nil) got (%d, %v)", n, err)
		n, err = conn.Write([]byte{})
		t2RequireTrue(t, n == 0 && err == nil, "Write([]byte{}) got (%d, %v)", n, err)

		ec, ok := conn.(N.ExtendedConn)
		t2RequireTrue(t, ok, "aether conn must implement network.ExtendedConn")
		t2RequireNoErr(t, ec.WriteBuffer(buf.NewSize(0)), "WriteBuffer(empty) must succeed and release")

		t2RequireNoErr(t, t2WriteAllBytes(conn, []byte("still-alive")), "follow-up write")
		got := make([]byte, 11)
		_, err = io.ReadFull(conn, got)
		t2RequireNoErr(t, err, "follow-up read")
		t2RequireTrue(t, string(got) == "still-alive", "got %q", string(got))
	})

	t.Run("T2-F23-02_WriteBufferOnClosedConnReleasesBuffer", func(t *testing.T) {
		echo := StartTCPEchoTarget(t)
		topo := StartTopology(t, TopologyConfig{
			ServerPassword: pass,
			ClientPassword: pass,
			DisableWireTap: true,
		})
		out := t2DialOutbound(t, topo.Client, "aether-out")
		ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
		defer cancel()
		conn, err := out.DialContext(ctx, "tcp", M.ParseSocksaddrHostPort("127.0.0.1", echo.Port()))
		t2RequireNoErr(t, err, "DialContext")
		t2RequireNoErr(t, t2WriteAllBytes(conn, []byte("ok")), "warm")
		tmp := make([]byte, 2)
		_, _ = io.ReadFull(conn, tmp)
		t2RequireNoErr(t, conn.Close(), "Close()")

		ec := conn.(N.ExtendedConn)
		b := buf.NewSize(256)
		b.WriteZeroN(100)
		wErr := ec.WriteBuffer(b)
		t2RequireErr(t, wErr, "WriteBuffer on closed conn must return error and release buffer under -race")
	})

	t.Run("T2-F23-03_WritePacketOnClosedPacketConnReleasesBuffer", func(t *testing.T) {
		udpEcho := StartUDPEchoTarget(t)
		topo := StartTopology(t, TopologyConfig{
			ServerPassword: pass,
			ClientPassword: pass,
			DisableWireTap: true,
		})
		out := t2DialOutbound(t, topo.Client, "aether-out")
		ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
		defer cancel()
		dest := M.ParseSocksaddrHostPort("127.0.0.1", udpEcho.Port())
		rawPC, err := out.ListenPacket(ctx, dest)
		t2RequireNoErr(t, err, "ListenPacket")
		pc, ok := rawPC.(N.PacketConn)
		t2RequireTrue(t, ok, "expected net.PacketConn from ListenPacket to implement N.PacketConn")

		bWarm := buf.NewPacket()
		_, _ = bWarm.Write([]byte("warm"))
		t2RequireNoErr(t, pc.WritePacket(bWarm, dest), "warm WritePacket")
		rWarm := buf.NewPacket()
		_, err = pc.ReadPacket(rWarm)
		rWarm.Release()
		t2RequireNoErr(t, err, "warm ReadPacket")

		t2RequireNoErr(t, pc.Close(), "PacketConn.Close()")
		bLate := buf.NewPacket()
		_, _ = bLate.Write([]byte("closed-pkt"))
		wErr := pc.WritePacket(bLate, dest)
		t2RequireErr(t, wErr, "WritePacket on closed PacketConn must fail and release buffer cleanly under -race")
	})

	t.Run("T2-F23-04_ReadBufferWithZeroHeadroomCallerBuffer", func(t *testing.T) {
		payload := DeterministicBytes(2304, 4096)
		banner := StartServerSpeaksFirstTarget(t, payload)
		topo := StartTopology(t, TopologyConfig{
			ServerPassword: pass,
			ClientPassword: pass,
			DisableWireTap: true,
		})
		out := t2DialOutbound(t, topo.Client, "aether-out")
		ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
		defer cancel()
		conn, err := out.DialContext(ctx, "tcp", M.ParseSocksaddrHostPort("127.0.0.1", banner.Port()))
		t2RequireNoErr(t, err, "DialContext")
		defer conn.Close()

		// Trigger 0-RTT connect toward server-speaks-first target.
		_, _ = conn.Write(nil)
		ec := conn.(N.ExtendedConn)

		var got bytes.Buffer
		for got.Len() < len(payload) {
			tight := buf.NewSize(64) // zero front headroom, small 64B capacity
			rErr := ec.ReadBuffer(tight)
			if tight.Len() > 0 {
				got.Write(tight.Bytes())
			}
			tight.Release()
			if rErr != nil {
				break
			}
		}
		t2RequireTrue(t, sha256.Sum256(got.Bytes()) == sha256.Sum256(payload), "4096B zero-headroom ReadBuffer stream mismatch (got %dB)", got.Len())

		// On closed conn error path, ReadBuffer must NOT release caller's buffer.
		_ = conn.Close()
		callerBuf := buf.NewSize(64)
		rErr := ec.ReadBuffer(callerBuf)
		t2RequireErr(t, rErr, "ReadBuffer after Close must return error")
		t2RequireTrue(t, callerBuf.IsEmpty(), "caller buffer should still be safely accessible")
		callerBuf.Release()
	})

	t.Run("T2-F23-05_FailedDialEarlyConnHandshakeReleasesRawSocket", func(t *testing.T) {
		rstAddr, rstCnt, rstClose := t2StartRawResetTarget(t, 0)
		host, portStr, _ := net.SplitHostPort(rstAddr)
		port64, _ := strconv.ParseUint(portStr, 10, 16)
		clientBox, _ := t2StartSingleAetherClient(t, host, uint16(port64), TopologyConfig{
			ClientPassword: pass,
		})
		out := t2DialOutbound(t, clientBox, "aether-out")

		// Warm one attempt before capturing baseline FDs.
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		cWarm, err := out.DialContext(ctx, "tcp", M.ParseSocksaddrHostPort("127.0.0.1", 80))
		if err == nil {
			_ = cWarm.(N.ExtendedConn).WriteBuffer(buf.NewSize(16))
			_ = cWarm.Close()
		}

		baseFDs, fdErr := CountOpenFDs()
		t2RequireNoErr(t, fdErr, "CountOpenFDs baseline")

		for i := 0; i < 10; i++ {
			c, dErr := out.DialContext(ctx, "tcp", M.ParseSocksaddrHostPort("127.0.0.1", 80))
			if dErr == nil {
				b := buf.NewSize(128)
				_, _ = b.Write([]byte("early-0rtt-reset"))
				if wErr := c.(N.ExtendedConn).WriteBuffer(b); wErr == nil {
					rb := make([]byte, 64)
					_, rErr := c.Read(rb)
					t2RequireErr(t, rErr, "expected handshake failure on immediate RST")
				}
				_ = c.Close()
			}
		}
		t2RequireTrue(t, rstCnt.Load() > 0, "expected connections to hit RST server")
		time.Sleep(150 * time.Millisecond)

		afterFDs, fdErr := CountOpenFDs()
		t2RequireNoErr(t, fdErr, "CountOpenFDs after")
		if afterFDs > baseFDs+4 {
			t.Fatalf("FD leak detected after failed EarlyConn handshakes: before=%d after=%d", baseFDs, afterFDs)
		}
		_ = clientBox.Close()
		rstClose()
		leaks := t2WaitForNoAetherLeaks(3 * time.Second)
		if len(leaks) > 0 {
			t.Fatalf("goroutine leak after failed EarlyConn handshakes: %v", leaks)
		}
	})
}

func t2RunF24(t *testing.T) {
	pass := "Feature24MuxNetwork"

	t.Run("T2-F24-01_InboundRejectsCommandMuxWhenMultiplexDisabled", func(t *testing.T) {
		echo := StartTCPEchoTarget(t)
		topo := StartTopology(t, TopologyConfig{
			ServerPassword: pass,
			ServerMultiplex: &MultiplexServerSpec{
				Enabled: false,
			},
			ClientPassword: pass,
			ClientMultiplex: &MultiplexClientSpec{
				Enabled:        true,
				Protocol:       "h2mux",
				MaxConnections: 1,
			},
			CaptureLogs: true,
		})
		err := t2EchoTCPViaSOCKS5(t, topo.ClientProxyAddr(), echo.Addr(), []byte("mux-when-disabled"))
		t2RequireErr(t, err, "client with multiplex enabled must fail against server with multiplex disabled")
		t2RequireTrue(t, echo.Connections() == 0, "target must receive 0 connections")

		// Also probe CommandMux directly via SpecRefCodec targeting sp.mux.sing-box.arpa:444.
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		cmdMux := SpecCommandMux
		sc, dErr := DialSpecClient(ctx, topo.ServerAddr(), SpecDialOptions{
			Password:   pass,
			Command:    &cmdMux,
			TargetAddr: "sp.mux.sing-box.arpa:444",
		})
		if dErr == nil {
			_, rErr := sc.ReadServerResp(2 * time.Second)
			if rErr == nil {
				t2RequireNoErr(t, sc.ExpectPeerClose(2*time.Second), "server must close stream when CommandMux is disabled")
			}
			_ = sc.Close()
		}
		srvLogs := topo.Server.ReadLogs()
		t2RequireTrue(t, !strings.Contains(srvLogs, "dial tcp") || !strings.Contains(srvLogs, "sp.mux.sing-box.arpa"), "server must never dial sp.mux.sing-box.arpa out direct: %s", srvLogs)
	})

	t.Run("T2-F24-02_OutboundTCPOnlyNetworkBlocksUDP", func(t *testing.T) {
		echo := StartTCPEchoTarget(t)
		udpEcho := StartUDPEchoTarget(t)
		topo := StartTopology(t, TopologyConfig{
			ServerPassword: pass,
			ClientPassword: pass,
			ClientNetwork:  []string{"tcp"},
			DisableWireTap: true,
		})
		t2RequireNoErr(t, t2EchoTCPViaSOCKS5(t, topo.ClientProxyAddr(), echo.Addr(), []byte("tcp-allowed")), "TCP should pass when network=[tcp]")

		out := t2DialOutbound(t, topo.Client, "aether-out")
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_, uErr := out.ListenPacket(ctx, M.ParseSocksaddrHostPort("127.0.0.1", udpEcho.Port()))
		t2RequireErr(t, uErr, "UDP ListenPacket must be rejected when network=[tcp]")
	})

	t.Run("T2-F24-03_OutboundUDPOnlyNetworkBlocksTCP", func(t *testing.T) {
		echo := StartTCPEchoTarget(t)
		udpEcho := StartUDPEchoTarget(t)
		topo := StartTopology(t, TopologyConfig{
			ServerPassword: pass,
			ClientPassword: pass,
			ClientNetwork:  []string{"udp"},
			DisableWireTap: true,
		})
		t2RequireErr(t, t2EchoTCPViaSOCKS5(t, topo.ClientProxyAddr(), echo.Addr(), []byte("tcp-blocked")), "TCP must fail when network=[udp]")
		t2RequireTrue(t, echo.Connections() == 0, "TCP target must receive 0 connections")

		out := t2DialOutbound(t, topo.Client, "aether-out")
		ctx, cancel := context.WithTimeout(context.Background(), 6*time.Second)
		defer cancel()
		dest := M.ParseSocksaddrHostPort("127.0.0.1", udpEcho.Port())
		rawPC, err := out.ListenPacket(ctx, dest)
		t2RequireNoErr(t, err, "UDP ListenPacket must pass when network=[udp]")
		pc, ok := rawPC.(N.PacketConn)
		t2RequireTrue(t, ok, "expected net.PacketConn from ListenPacket to implement N.PacketConn")
		defer pc.Close()
		_ = pc.SetDeadline(time.Now().Add(4 * time.Second))
		wb := buf.NewPacket()
		_, _ = wb.Write([]byte("udp-allowed"))
		t2RequireNoErr(t, pc.WritePacket(wb, dest), "WritePacket")
		rb := buf.NewPacket()
		defer rb.Release()
		_, err = pc.ReadPacket(rb)
		t2RequireNoErr(t, err, "ReadPacket")
		t2RequireTrue(t, string(rb.Bytes()) == "udp-allowed", "unexpected UDP echo %q", string(rb.Bytes()))
	})

	t.Run("T2-F24-04_OutboundDialUnknownNetworkICMP", func(t *testing.T) {
		topo := StartTopology(t, TopologyConfig{
			ServerPassword: pass,
			ClientPassword: pass,
			DisableWireTap: true,
		})
		out := t2DialOutbound(t, topo.Client, "aether-out")
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_, err := out.DialContext(ctx, "icmp", M.ParseSocksaddrHostPort("127.0.0.1", 80))
		t2RequireErr(t, err, "expected error dialing unknown network icmp")
		t2RequireTrue(t, errors.Is(err, N.ErrUnknownNetwork), "expected errors.Is(err, N.ErrUnknownNetwork), got: %v", err)
	})

	t.Run("T2-F24-05_ResetNetworkDuringActiveMultiplexTransfer", func(t *testing.T) {
		echo := StartTCPEchoTarget(t)
		topo := StartTopology(t, TopologyConfig{
			ServerPassword:  pass,
			ServerMultiplex: &MultiplexServerSpec{Enabled: true},
			ClientPassword:  pass,
			ClientMultiplex: &MultiplexClientSpec{
				Enabled:        true,
				Protocol:       "h2mux",
				MaxConnections: 1,
				MinStreams:     1,
			},
		})
		topo.Tap.SetThrottle(2*time.Millisecond, 1024)

		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		c, err := DialSOCKS5TCP(ctx, topo.ClientProxyAddr(), echo.Addr())
		t2RequireNoErr(t, err, "DialSOCKS5TCP initial h2mux stream")

		var wg sync.WaitGroup
		wg.Add(1)
		go func() {
			defer wg.Done()
			defer c.Close()
			payload := DeterministicBytes(2405, 512*1024)
			for off := 0; off < len(payload); off += 4096 {
				end := off + 4096
				if end > len(payload) {
					end = len(payload)
				}
				if _, wErr := c.Write(payload[off:end]); wErr != nil {
					return
				}
			}
		}()

		time.Sleep(80 * time.Millisecond)
		topo.ResetClientNetwork(ctx)
		wg.Wait()

		// Remove throttle and verify new h2mux stream establishes fresh Aether session cleanly!
		topo.Tap.SetThrottle(0, 0)
		t2RequireNoErr(t, t2EchoTCPViaSOCKS5(t, topo.ClientProxyAddr(), echo.Addr(), DeterministicBytes(24052, 16*1024)), "new h2mux stream after ResetNetwork must succeed")
	})
}

func t2RunF25(t *testing.T) {
	pass := "Feature25StrictJSON"

	checkRejected := func(t *testing.T, desc string, raw []byte) {
		t.Helper()
		t2RequireErr(t, CheckConfigInProcess(raw), "CheckConfigInProcess must reject %s", desc)
		res := CheckConfigCLI(t, raw)
		t2RequireTrue(t, res.ExitCode != 0, "sing-box check must reject %s", desc)
	}

	marshalIn := func(in map[string]any) []byte {
		b, err := json.Marshal(map[string]any{
			"log":       map[string]any{"disabled": true},
			"inbounds":  []any{in},
			"outbounds": []any{map[string]any{"type": C.TypeDirect, "tag": "direct"}},
		})
		t2RequireNoErr(t, err, "marshal inbound")
		return b
	}
	marshalOut := func(out map[string]any) []byte {
		b, err := json.Marshal(map[string]any{
			"log":       map[string]any{"disabled": true},
			"inbounds":  []any{},
			"outbounds": []any{out},
		})
		t2RequireNoErr(t, err, "marshal outbound")
		return b
	}

	t.Run("T2-F25-01_LegacyTLSAndTransportJSONFieldsRejected", func(t *testing.T) {
		for _, field := range []struct {
			k string
			v any
		}{
			{"tls", map[string]any{"enabled": true}},
			{"transport", map[string]any{"type": "ws"}},
			{"fallback", "127.0.0.1:80"},
		} {
			in := map[string]any{
				"type":        C.TypeAether,
				"tag":         "aether-in",
				"listen":      "127.0.0.1",
				"listen_port": 10800,
				"password":    pass,
				field.k:       field.v,
			}
			checkRejected(t, "inbound."+field.k, marshalIn(in))

			out := map[string]any{
				"type":        C.TypeAether,
				"tag":         "aether-out",
				"server":      "127.0.0.1",
				"server_port": 10800,
				"password":    pass,
				field.k:       field.v,
			}
			checkRejected(t, "outbound."+field.k, marshalOut(out))
		}
	})

	t.Run("T2-F25-02_UnknownArbitraryJSONPropertyRejected", func(t *testing.T) {
		in := map[string]any{
			"type":        C.TypeAether,
			"tag":         "aether-in",
			"listen":      "127.0.0.1",
			"listen_port": 10800,
			"password":    pass,
			"typo_field":  true,
		}
		checkRejected(t, "inbound.typo_field", marshalIn(in))

		out := map[string]any{
			"type":        C.TypeAether,
			"tag":         "aether-out",
			"server":      "127.0.0.1",
			"server_port": 10800,
			"password":    pass,
			"typo_field":  true,
		}
		checkRejected(t, "outbound.typo_field", marshalOut(out))

		userUnknown := map[string]any{
			"type":        C.TypeAether,
			"tag":         "aether-in",
			"listen":      "127.0.0.1",
			"listen_port": 10800,
			"users": []any{
				map[string]any{"name": "u1", "password": pass, "typo_field": true},
			},
		}
		checkRejected(t, "user.typo_field", marshalIn(userUnknown))
	})

	t.Run("T2-F25-03_MalformedDurationStringsRejected", func(t *testing.T) {
		for _, pair := range []struct {
			k, v string
		}{
			{"time_window", "30sec"},
			{"handshake_timeout", "forever"},
			{"heartbeat_interval", "100"},
		} {
			in := map[string]any{
				"type":        C.TypeAether,
				"tag":         "aether-in",
				"listen":      "127.0.0.1",
				"listen_port": 10800,
				"password":    pass,
				pair.k:        pair.v,
			}
			checkRejected(t, "duration "+pair.k+"="+pair.v, marshalIn(in))
		}
	})

	t.Run("T2-F25-04_MissingServerAddressOrZeroServerPortRejected", func(t *testing.T) {
		noServer := map[string]any{
			"type":        C.TypeAether,
			"tag":         "aether-out",
			"server":      "",
			"server_port": 10800,
			"password":    pass,
		}
		checkRejected(t, "missing server address", marshalOut(noServer))

		zeroPort := map[string]any{
			"type":        C.TypeAether,
			"tag":         "aether-out",
			"server":      "127.0.0.1",
			"server_port": 0,
			"password":    pass,
		}
		checkRejected(t, "zero server_port", marshalOut(zeroPort))
	})

	t.Run("T2-F25-05_InboundWithEmptyPasswordAndEmptyUsersRejected", func(t *testing.T) {
		in := map[string]any{
			"type":        C.TypeAether,
			"tag":         "aether-in",
			"listen":      "127.0.0.1",
			"listen_port": 10800,
			"password":    "",
			"key":         "",
			"users":       []any{},
		}
		checkRejected(t, "empty password and empty users", marshalIn(in))
	})

	t.Run("T2-F25-06_UserWithConflictingPasswordAndKeyRejected", func(t *testing.T) {
		in := map[string]any{
			"type":        C.TypeAether,
			"tag":         "aether-in",
			"listen":      "127.0.0.1",
			"listen_port": 10800,
			"users": []any{
				map[string]any{
					"name":     "u1",
					"password": "SixteenCharPass1",
					"key":      "SixteenCharPass2",
				},
			},
		}
		checkRejected(t, "user conflicting password and key", marshalIn(in))
	})
}

func t2RunF26(t *testing.T) {
	t.Run("T2-F26-01_UpstreamSyncRejectsPrereleaseAlphaBetaRCAndDraft", func(t *testing.T) {
		discoverScript := t2ExtractWorkflowStepRun(t, ".github/workflows/upstream-sync-release.yml", "Discover Latest Upstream Stable Release")

		payloads := []struct {
			name string
			json string
		}{
			{"alpha", `{"tag_name":"v1.15.0-alpha.13","draft":false,"prerelease":false}`},
			{"beta", `{"tag_name":"v1.15.0-beta.2","draft":false,"prerelease":false}`},
			{"rc", `{"tag_name":"v1.15.0-rc.1","draft":false,"prerelease":true}`},
			{"draft", `{"tag_name":"v1.15.0","draft":true,"prerelease":false}`},
			{"prerelease_flag", `{"tag_name":"v1.15.0","draft":false,"prerelease":true}`},
		}
		for _, tc := range payloads {
			sb := t2NewGitSyncSandbox(t)
			jsonFile := filepath.Join(sb.RootDir, "api.json")
			t2RequireNoErr(t, os.WriteFile(jsonFile, []byte(tc.json), 0o644), "write api json")
			sb.writeMockBin(t, "curl", fmt.Sprintf("cat %q", jsonFile))

			ghEnv := filepath.Join(sb.RootDir, "gh_env")
			ghOut := filepath.Join(sb.RootDir, "gh_out")
			out, err := sb.runBash(sb.WorkDir, discoverScript, "GITHUB_ENV="+ghEnv, "GITHUB_OUTPUT="+ghOut, "GH_TOKEN=")
			t2RequireNoErr(t, err, "discover script (%s) failed: %s", tc.name, out)

			outRaw, _ := os.ReadFile(ghOut)
			t2RequireTrue(t, strings.Contains(string(outRaw), "should_sync=false"), "expected should_sync=false for %s, got:\n%s\noutput:%s", tc.name, string(outRaw), out)
		}
	})

	t.Run("T2-F26-02_UpstreamSyncMalformedAPIJSONFailsFast", func(t *testing.T) {
		discoverScript := t2ExtractWorkflowStepRun(t, ".github/workflows/upstream-sync-release.yml", "Discover Latest Upstream Stable Release")

		for i, badPayload := range []string{"<html>502 Bad Gateway</html>", "", "{broken", "{}"} {
			sb := t2NewGitSyncSandbox(t)
			jsonFile := filepath.Join(sb.RootDir, fmt.Sprintf("bad_%d.json", i))
			t2RequireNoErr(t, os.WriteFile(jsonFile, []byte(badPayload), 0o644), "write bad json")
			sb.writeMockBin(t, "curl", fmt.Sprintf("cat %q", jsonFile))

			ghEnv := filepath.Join(sb.RootDir, "gh_env")
			ghOut := filepath.Join(sb.RootDir, "gh_out")
			_, err := sb.runBash(sb.WorkDir, discoverScript, "GITHUB_ENV="+ghEnv, "GITHUB_OUTPUT="+ghOut, "GH_TOKEN=")
			t2RequireErr(t, err, "malformed API payload %q must fail fast", badPayload)
		}
	})

	t.Run("T2-F26-03_UpstreamSyncSourceMergeConflictAbortsCleanly", func(t *testing.T) {
		mergeScript := t2ExtractWorkflowStepRun(t, ".github/workflows/upstream-sync-release.yml", "Merge Upstream Tag and Preserve Workflows")
		sb := t2NewGitSyncSandbox(t)

		// Push conflicting edit to option/aether.go in upstream tag v1.14.6.
		upSeed := filepath.Join(sb.RootDir, "up_conflict")
		sb.runGit(t, sb.RootDir, "clone", sb.UpstreamGit, upSeed)
		t2RequireNoErr(t, os.WriteFile(filepath.Join(upSeed, "option", "aether.go"), []byte("package option\n// conflicting upstream line!\nvar ForkLine = 999\n"), 0o644), "write conflicting option/aether.go")
		sb.runGit(t, upSeed, "add", "-A")
		sb.runGit(t, upSeed, "commit", "-m", "v1.14.6 conflicting option edit")
		sb.runGit(t, upSeed, "tag", "v1.14.6")
		sb.runGit(t, upSeed, "push", "origin", "HEAD:main", "--tags")

		out, err := sb.runBash(sb.WorkDir, mergeScript, "UPSTREAM_TAG=v1.14.6")
		t2RequireErr(t, err, "expected merge conflict step to exit non-zero, output:\n%s", out)
		t2RequireTrue(t, strings.Contains(out, "Unresolved merge conflicts"), "expected unresolved merge conflict error banner, got:\n%s", out)

		status := strings.TrimSpace(sb.runGit(t, sb.WorkDir, "status", "--porcelain"))
		t2RequireTrue(t, status == "", "expected clean aborted working tree, got git status:\n%s", status)

		checkCmd := exec.Command("git", "rev-parse", "-q", "--verify", "MERGE_HEAD")
		checkCmd.Dir = sb.WorkDir
		checkCmd.Env = sb.env()
		t2RequireErr(t, checkCmd.Run(), "MERGE_HEAD must not linger after git merge --abort")
	})

	t.Run("T2-F26-04_UpstreamSyncPreservesWorkflowsPreventingTokenPushRejection", func(t *testing.T) {
		mergeScript := t2ExtractWorkflowStepRun(t, ".github/workflows/upstream-sync-release.yml", "Merge Upstream Tag and Preserve Workflows")
		sb := t2NewGitSyncSandbox(t)

		// Upstream tag v1.14.6 edits docker.yml & linux.yml, deletes build-linux-amd64.yml, and updates README.md.
		upSeed := filepath.Join(sb.RootDir, "up_wf")
		sb.runGit(t, sb.RootDir, "clone", sb.UpstreamGit, upSeed)
		t2RequireNoErr(t, os.WriteFile(filepath.Join(upSeed, "README.md"), []byte("upstream v1.14.6 release notes\n"), 0o644), "write upstream README.md")
		t2RequireNoErr(t, os.WriteFile(filepath.Join(upSeed, ".github", "workflows", "docker.yml"), []byte("name: modified upstream docker\n"), 0o644), "write upstream docker.yml")
		t2RequireNoErr(t, os.WriteFile(filepath.Join(upSeed, ".github", "workflows", "linux.yml"), []byte("name: modified upstream linux\n"), 0o644), "write upstream linux.yml")
		_ = os.Remove(filepath.Join(upSeed, ".github", "workflows", "build-linux-amd64.yml"))
		sb.runGit(t, upSeed, "add", "-A")
		sb.runGit(t, upSeed, "commit", "-m", "v1.14.6 modify workflows + readme")
		sb.runGit(t, upSeed, "tag", "v1.14.6")
		sb.runGit(t, upSeed, "push", "origin", "HEAD:main", "--tags")

		out, err := sb.runBash(sb.WorkDir, mergeScript, "UPSTREAM_TAG=v1.14.6")
		t2RequireNoErr(t, err, "workflow-preserving merge failed:\n%s", out)
		sb.runGit(t, sb.WorkDir, "commit", "--no-edit")

		wfDiff := strings.TrimSpace(sb.runGit(t, sb.WorkDir, "diff", "HEAD~1", "--", ".github/workflows/"))
		t2RequireTrue(t, wfDiff == "", "expected empty .github/workflows/ diff vs pre-merge HEAD~1, got:\n%s", wfDiff)

		// Confirm README.md DID merge while fork workflows stayed intact.
		readmeRaw, err := os.ReadFile(filepath.Join(sb.WorkDir, "README.md"))
		t2RequireNoErr(t, err, "read merged README")
		t2RequireTrue(t, strings.Contains(string(readmeRaw), "v1.14.6"), "expected upstream README merged")
		buildRaw, err := os.ReadFile(filepath.Join(sb.WorkDir, ".github", "workflows", "build-linux-amd64.yml"))
		t2RequireNoErr(t, err, "deleted upstream build-linux-amd64.yml must stay restored on fork")
		t2RequireTrue(t, strings.Contains(string(buildRaw), "fork build"), "fork workflow modified unexpectedly")
	})

	t.Run("T2-F26-05_UpstreamSyncAbortsReleaseWhenGoTestRaceFails", func(t *testing.T) {
		testGateScript := t2ExtractWorkflowStepRun(t, ".github/workflows/upstream-sync-release.yml", "Run Mandatory -race Test Gate")
		buildScript := t2ExtractWorkflowStepRun(t, ".github/workflows/upstream-sync-release.yml", "Build and Package Multi-Arch Static Binaries")
		releaseScript := t2ExtractWorkflowStepRun(t, ".github/workflows/upstream-sync-release.yml", "Commit Sync, Tag, Push, and Publish GitHub Release")

		sb := t2NewGitSyncSandbox(t)
		callLog := filepath.Join(sb.RootDir, "calls.log")
		sb.writeMockBin(t, "go", fmt.Sprintf(`echo "go $*" >> %q
if [ "${1:-}" = "test" ]; then
  echo "simulated -race failure" >&2
  exit 1
fi
exit 0`, callLog))
		sb.writeMockBin(t, "gh", fmt.Sprintf(`echo "gh $*" >> %q
exit 0`, callLog))

		pipeline := "set -euo pipefail\n" + testGateScript + "\n" + buildScript + "\n" + releaseScript
		out, err := sb.runBash(sb.WorkDir, pipeline, "UPSTREAM_VER=1.14.6", "UPSTREAM_TAG=v1.14.6", "RELEASE_TAG=v1.14.6-Custom-Aether", "DRY_RUN=false")
		t2RequireErr(t, err, "expected failing -race test gate to abort pipeline:\n%s", out)

		callsRaw, err := os.ReadFile(callLog)
		t2RequireNoErr(t, err, "read mock call log")
		calls := string(callsRaw)
		t2RequireTrue(t, strings.Contains(calls, "go test"), "expected `go test` called")
		t2RequireTrue(t, !strings.Contains(calls, "go build"), "binary `go build` must NEVER run after test gate failure:\n%s", calls)
		t2RequireTrue(t, !strings.Contains(calls, "gh "), "`gh release` must NEVER run after test gate failure:\n%s", calls)
	})
}

func t2RunF27(t *testing.T) {
	pass := "Feature27ProcessLifecycle"

	t.Run("T2-F27-01_CLIRunMissingOrInvalidConfigExitsNonZero", func(t *testing.T) {
		missingPath := filepath.Join(t.TempDir(), "does-not-exist.json")
		res1 := RunCLITimeout(t, 4*time.Second, "run", "-c", missingPath)
		t2RequireTrue(t, res1.ExitCode != 0, "expected non-zero exit for missing config file")

		weakCfg, err := BuildServerJSON(TopologyConfig{ServerPassword: "short"}, AllocFreeTCPPort(t), 0, "")
		t2RequireNoErr(t, err, "BuildServerJSON")
		weakPath := filepath.Join(t.TempDir(), "weak.json")
		t2RequireNoErr(t, os.WriteFile(weakPath, weakCfg, 0o600), "write weak.json")
		res2 := RunCLITimeout(t, 4*time.Second, "run", "-c", weakPath)
		t2RequireTrue(t, res2.ExitCode != 0, "expected non-zero exit for invalid weak config")
		t2RequireTrue(t, strings.TrimSpace(res2.Stderr+res2.Stdout) != "", "expected error diagnostic on stdout/stderr")
	})

	t.Run("T2-F27-02_CLIRunSIGHUPWithCorruptedConfigSurvives", func(t *testing.T) {
		echo := StartTCPEchoTarget(t)
		_, srvAddr := t2StartSingleAetherServer(t, TopologyConfig{ServerPassword: pass})
		_, portStr, _ := net.SplitHostPort(srvAddr)
		srvPort64, _ := strconv.ParseUint(portStr, 10, 16)

		proxyPort := AllocFreeTCPPort(t)
		clientCfg, err := BuildClientJSON(TopologyConfig{ClientPassword: pass}, proxyPort, "127.0.0.1", uint16(srvPort64), 0, "")
		t2RequireNoErr(t, err, "BuildClientJSON")
		proc := StartCLIDaemon(t, clientCfg, proxyPort)
		proxyAddr := fmt.Sprintf("127.0.0.1:%d", proxyPort)

		t2RequireNoErr(t, t2EchoTCPViaSOCKS5(t, proxyAddr, echo.Addr(), []byte("before-sighup")), "pre-SIGHUP traffic must succeed")

		// Overwrite running daemon's config file with invalid JSON, then send SIGHUP.
		t2RequireNoErr(t, os.WriteFile(proc.ConfigPath(), []byte("{corrupted_json"), 0o600), "corrupt daemon config")
		t2RequireNoErr(t, proc.Signal(syscall.SIGHUP), "send SIGHUP")
		time.Sleep(350 * time.Millisecond)

		// Process must still be alive and actively proxying new connections despite invalid reload config.
		t2RequireNoErr(t, t2EchoTCPViaSOCKS5(t, proxyAddr, echo.Addr(), []byte("after-bad-sighup")), "daemon must survive bad SIGHUP and keep proxying")
	})

	t.Run("T2-F27-03_RapidBoxCloseMidHandshakeAndTransferNoPanic", func(t *testing.T) {
		echo := StartTCPEchoTarget(t)
		payload := DeterministicBytes(2703, 1024*1024)
		for iter := 0; iter < 5; iter++ {
			topo := StartTopology(t, TopologyConfig{
				ServerPassword: pass,
				ClientPassword: pass,
				DisableWireTap: true,
			})
			var wg sync.WaitGroup
			for i := 0; i < 20; i++ {
				wg.Add(1)
				go func() {
					defer wg.Done()
					ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
					defer cancel()
					c, dErr := DialSOCKS5TCP(ctx, topo.ClientProxyAddr(), echo.Addr())
					if dErr != nil {
						return
					}
					defer c.Close()
					_ = c.SetDeadline(time.Now().Add(2 * time.Second))
					_, _ = c.Write(payload[:64*1024])
					tmp := make([]byte, 4096)
					_, _ = c.Read(tmp)
				}()
			}
			time.Sleep(15 * time.Millisecond)
			closeStart := time.Now()
			_ = topo.Client.Close()
			_ = topo.Server.Close()
			if el := time.Since(closeStart); el > 3*time.Second {
				t.Fatalf("iter %d Close() stalled: %v", iter, el)
			}
			wg.Wait()
			topo.Close()
		}
		echo.Close()
		leaks := t2WaitForNoAetherLeaks(4 * time.Second)
		if len(leaks) > 0 {
			t.Fatalf("goroutine leak after rapid Box.Close(): %v", leaks)
		}
	})

	t.Run("T2-F27-04_OpaqueRandomByteStreamFuzzBurstAgainstLiveInbound", func(t *testing.T) {
		echo := StartTCPEchoTarget(t)
		udpEcho := StartUDPEchoTarget(t)
		topo := StartTopology(t, TopologyConfig{
			ServerPassword:         pass,
			ServerHandshakeTimeout: "600ms",
			ClientPassword:         pass,
			DisableWireTap:         true,
		})

		const fuzzSockets = 100
		var fuzzWG sync.WaitGroup
		for i := 0; i < fuzzSockets; i++ {
			idx := i
			fuzzWG.Add(1)
			go func() {
				defer fuzzWG.Done()
				c, dErr := net.DialTimeout("tcp", topo.ServerAddr(), 2*time.Second)
				if dErr != nil {
					return
				}
				defer c.Close()
				_ = c.SetDeadline(time.Now().Add(2 * time.Second))
				sz := (idx * 173) % (16 * 1024)
				if sz > 0 {
					_, _ = c.Write(DeterministicBytes(uint64(27040+idx), sz))
				}
				if idx%2 == 0 {
					if tc, ok := c.(*net.TCPConn); ok {
						_ = tc.CloseWrite()
					}
					_, _ = io.Copy(io.Discard, c)
				} else {
					time.Sleep(80 * time.Millisecond)
				}
			}()
		}

		// Concurrently run 10 legitimate TCP + 10 legitimate UDP echoes cleanly.
		var legitWG sync.WaitGroup
		legitErrs := make(chan error, 20)
		for i := 0; i < 10; i++ {
			idx := i
			legitWG.Add(2)
			go func() {
				defer legitWG.Done()
				if err := t2EchoTCPViaSOCKS5(t, topo.ClientProxyAddr(), echo.Addr(), DeterministicBytes(uint64(27041+idx), 4096)); err != nil {
					legitErrs <- fmt.Errorf("tcp[%d]: %w", idx, err)
				}
			}()
			go func() {
				defer legitWG.Done()
				ctx, cancel := context.WithTimeout(context.Background(), 6*time.Second)
				defer cancel()
				uc, uErr := topo.OpenSOCKS5UDP(ctx)
				if uErr != nil {
					legitErrs <- fmt.Errorf("udp dial[%d]: %w", idx, uErr)
					return
				}
				defer uc.Close()
				_ = uc.SetDeadline(time.Now().Add(5 * time.Second))
				msg := DeterministicBytes(uint64(27042+idx), 512)
				if wErr := uc.WriteToHostPort(msg, udpEcho.Addr()); wErr != nil {
					legitErrs <- fmt.Errorf("udp write[%d]: %w", idx, wErr)
					return
				}
				buf := make([]byte, 2048)
				n, _, rErr := uc.ReadFromHostPort(buf)
				if rErr != nil {
					legitErrs <- fmt.Errorf("udp read[%d]: %w", idx, rErr)
					return
				}
				if !bytes.Equal(buf[:n], msg) {
					legitErrs <- fmt.Errorf("udp mismatch[%d]", idx)
				}
			}()
		}
		legitWG.Wait()
		fuzzWG.Wait()
		close(legitErrs)
		for e := range legitErrs {
			t.Fatalf("legit traffic failed under fuzz bombardment: %v", e)
		}
		topo.Close()
		echo.Close()
		udpEcho.Close()
		leaks := t2WaitForNoAetherLeaks(5 * time.Second)
		if len(leaks) > 0 {
			t.Fatalf("goroutine leak after fuzz bombardment: %v", leaks)
		}
	})

	t.Run("T2-F27-05_MidStreamAbruptClientAndTargetDisconnectsNoLeak", func(t *testing.T) {
		echo := StartTCPEchoTarget(t)
		rstTarget, _, rstClose := t2StartRawResetTarget(t, 2048)
		topo := StartTopology(t, TopologyConfig{
			ServerPassword: pass,
			ClientPassword: pass,
			DisableWireTap: true,
		})

		// Warm once before FD baseline check.
		t2RequireNoErr(t, t2EchoTCPViaSOCKS5(t, topo.ClientProxyAddr(), echo.Addr(), []byte("warm")), "warm")
		baseFDs, fdErr := CountOpenFDs()
		t2RequireNoErr(t, fdErr, "CountOpenFDs")

		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		chunk := DeterministicBytes(2705, 8192)

		// 15 abrupt client-side RST disconnects mid-stream.
		for i := 0; i < 15; i++ {
			c, dErr := DialSOCKS5TCP(ctx, topo.ClientProxyAddr(), echo.Addr())
			t2RequireNoErr(t, dErr, "DialSOCKS5TCP client RST iter %d", i)
			_, _ = c.Write(chunk)
			_ = c.SetLinger(0)
			_ = c.Close()
		}

		// 15 abrupt target-side RST disconnects mid-stream.
		for i := 0; i < 15; i++ {
			c, dErr := DialSOCKS5TCP(ctx, topo.ClientProxyAddr(), rstTarget)
			if dErr == nil {
				_ = c.SetDeadline(time.Now().Add(2 * time.Second))
				_, _ = c.Write(chunk)
				tmp := make([]byte, 512)
				_, _ = c.Read(tmp)
				_ = c.Close()
			}
		}

		time.Sleep(250 * time.Millisecond)
		afterFDs, fdErr := CountOpenFDs()
		t2RequireNoErr(t, fdErr, "CountOpenFDs after")
		if afterFDs > baseFDs+8 {
			t.Fatalf("FD leak across 30 abrupt mid-stream disconnects: before=%d after=%d", baseFDs, afterFDs)
		}
		topo.Close()
		echo.Close()
		rstClose()
		leaks := t2WaitForNoAetherLeaks(5 * time.Second)
		if len(leaks) > 0 {
			t.Fatalf("goroutine leak after 30 abrupt mid-stream disconnects: %v", leaks)
		}
	})
}
