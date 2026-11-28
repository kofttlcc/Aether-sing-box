package group_test

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	box "github.com/sagernet/sing-box"
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/daemon"
	"github.com/sagernet/sing-box/include"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/protocol/group"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/service"
	"google.golang.org/protobuf/proto"
)

// miniSOCKS5Upstream implements a minimal SOCKS5 TCP CONNECT + UDP ASSOCIATE server
// that tags responses with its node ID and allows toggling online/offline at runtime.
type miniSOCKS5Upstream struct {
	id         string
	tcpLn      net.Listener
	udpConn    *net.UDPConn
	rejectAll  atomic.Bool
	tcpHandled atomic.Int32
	udpHandled atomic.Int32

	mu         sync.Mutex
	activeTCP  []net.Conn
}

func startMiniSOCKS5Upstream(t *testing.T, id string) *miniSOCKS5Upstream {
	t.Helper()
	tcpLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen tcp socks5 %s: %v", id, err)
	}
	udpAddr, err := net.ResolveUDPAddr("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("resolve udp %s: %v", id, err)
	}
	udpConn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		_ = tcpLn.Close()
		t.Fatalf("listen udp socks5 %s: %v", id, err)
	}
	s := &miniSOCKS5Upstream{
		id:      id,
		tcpLn:   tcpLn,
		udpConn: udpConn,
	}
	t.Cleanup(func() {
		_ = tcpLn.Close()
		_ = udpConn.Close()
		s.closeActiveTCP()
	})
	go s.serveTCP()
	go s.serveUDP()
	return s
}

func (s *miniSOCKS5Upstream) port() uint16 {
	return uint16(s.tcpLn.Addr().(*net.TCPAddr).Port)
}

func (s *miniSOCKS5Upstream) setDown(down bool) {
	s.rejectAll.Store(down)
	if down {
		s.closeActiveTCP()
	}
}

func (s *miniSOCKS5Upstream) closeActiveTCP() {
	s.mu.Lock()
	conns := s.activeTCP
	s.activeTCP = nil
	s.mu.Unlock()
	for _, c := range conns {
		_ = c.Close()
	}
}

func (s *miniSOCKS5Upstream) serveTCP() {
	for {
		conn, err := s.tcpLn.Accept()
		if err != nil {
			return
		}
		if s.rejectAll.Load() {
			_ = conn.Close()
			continue
		}
		go s.handleSOCKS5Conn(conn)
	}
}

func (s *miniSOCKS5Upstream) handleSOCKS5Conn(conn net.Conn) {
	defer conn.Close()
	hdr := make([]byte, 2)
	if _, err := io.ReadFull(conn, hdr); err != nil || hdr[0] != 0x05 {
		return
	}
	methods := make([]byte, int(hdr[1]))
	if _, err := io.ReadFull(conn, methods); err != nil {
		return
	}
	if _, err := conn.Write([]byte{0x05, 0x00}); err != nil {
		return
	}
	req := make([]byte, 4)
	if _, err := io.ReadFull(conn, req); err != nil || req[0] != 0x05 {
		return
	}
	cmd := req[1]
	var dstHost string
	switch req[3] {
	case 0x01:
		ipBuf := make([]byte, 4)
		if _, err := io.ReadFull(conn, ipBuf); err != nil {
			return
		}
		dstHost = net.IP(ipBuf).String()
	case 0x03:
		lenBuf := make([]byte, 1)
		if _, err := io.ReadFull(conn, lenBuf); err != nil {
			return
		}
		dom := make([]byte, int(lenBuf[0]))
		if _, err := io.ReadFull(conn, dom); err != nil {
			return
		}
		dstHost = string(dom)
	case 0x04:
		ipBuf := make([]byte, 16)
		if _, err := io.ReadFull(conn, ipBuf); err != nil {
			return
		}
		dstHost = net.IP(ipBuf).String()
	default:
		return
	}
	portBuf := make([]byte, 2)
	if _, err := io.ReadFull(conn, portBuf); err != nil {
		return
	}
	dstPort := binary.BigEndian.Uint16(portBuf)

	if s.rejectAll.Load() {
		return
	}

	switch cmd {
	case 0x01: // CONNECT
		targetAddr := net.JoinHostPort(dstHost, fmt.Sprintf("%d", dstPort))
		// Probe traffic connects to local httptest server; echo traffic connects to local echo server.
		upstream, err := net.DialTimeout("tcp", targetAddr, 2*time.Second)
		if err != nil {
			_, _ = conn.Write([]byte{0x05, 0x05, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
			return
		}
		defer upstream.Close()
		s.tcpHandled.Add(1)
		s.mu.Lock()
		s.activeTCP = append(s.activeTCP, conn)
		s.mu.Unlock()
		if _, err := conn.Write([]byte{0x05, 0x00, 0x00, 0x01, 127, 0, 0, 1, 0, 0}); err != nil {
			return
		}
		done := make(chan struct{}, 2)
		go func() { _, _ = io.Copy(upstream, conn); _ = upstream.Close(); done <- struct{}{} }()
		go func() { _, _ = io.Copy(conn, upstream); _ = conn.Close(); done <- struct{}{} }()
		<-done
	case 0x03: // UDP ASSOCIATE
		uPort := uint16(s.udpConn.LocalAddr().(*net.UDPAddr).Port)
		resp := []byte{0x05, 0x00, 0x00, 0x01, 127, 0, 0, 1, byte(uPort >> 8), byte(uPort)}
		if _, err := conn.Write(resp); err != nil {
			return
		}
		s.mu.Lock()
		s.activeTCP = append(s.activeTCP, conn)
		s.mu.Unlock()
		_, _ = io.Copy(io.Discard, conn)
	}
}

func (s *miniSOCKS5Upstream) serveUDP() {
	buf := make([]byte, 4096)
	for {
		n, clientAddr, err := s.udpConn.ReadFromUDP(buf)
		if err != nil {
			return
		}
		if s.rejectAll.Load() || n < 10 || buf[0] != 0 || buf[1] != 0 || buf[2] != 0 {
			continue
		}
		offset := 4
		switch buf[3] {
		case 0x01:
			offset += 4
		case 0x03:
			if n < 5 {
				continue
			}
			offset += 1 + int(buf[4])
		case 0x04:
			offset += 16
		default:
			continue
		}
		offset += 2
		if n < offset {
			continue
		}
		s.udpHandled.Add(1)
		payload := append([]byte(nil), buf[:offset]...)
		payload = append(payload, []byte(s.id+":")...)
		payload = append(payload, buf[offset:n]...)
		_, _ = s.udpConn.WriteToUDP(payload, clientAddr)
	}
}

func TestBoxEndToEndRoutedFallbackTCPAndUDPFailoverFailbackAndInterrupt(t *testing.T) {
	probeSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	defer probeSrv.Close()

	// TCP echo server that keeps connections open until client/proxy closes.
	echoLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen echo: %v", err)
	}
	defer echoLn.Close()
	go func() {
		for {
			c, acceptErr := echoLn.Accept()
			if acceptErr != nil {
				return
			}
			go func(conn net.Conn) {
				defer conn.Close()
				_, _ = io.Copy(conn, conn)
			}(c)
		}
	}()
	echoAddr := echoLn.Addr().(*net.TCPAddr)

	primaryNode := startMiniSOCKS5Upstream(t, "primary")
	backupNode := startMiniSOCKS5Upstream(t, "backup")

	// Reserve free local port for sing-box mixed inbound.
	tmpLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserve port: %v", err)
	}
	inboundPort := uint16(tmpLn.Addr().(*net.TCPAddr).Port)
	_ = tmpLn.Close()

	rawConfig := fmt.Sprintf(`{
  "log": { "level": "error" },
  "inbounds": [
    {
      "type": "socks",
      "tag": "socks-in",
      "listen": "127.0.0.1",
      "listen_port": %d
    }
  ],
  "outbounds": [
    {
      "type": "selector",
      "tag": "top-sel",
      "outbounds": ["auto-fb", "direct-out"],
      "default": "auto-fb",
      "interrupt_exist_connections": true
    },
    {
      "type": "fallback",
      "tag": "auto-fb",
      "outbounds": ["node-primary", "node-backup"],
      "url": %q,
      "interval": "80ms",
      "idle_timeout": "5s",
      "fail_times": 2,
      "recover_times": 2,
      "interrupt_exist_connections": true
    },
    {
      "type": "socks",
      "tag": "node-primary",
      "server": "127.0.0.1",
      "server_port": %d
    },
    {
      "type": "socks",
      "tag": "node-backup",
      "server": "127.0.0.1",
      "server_port": %d
    },
    {
      "type": "direct",
      "tag": "direct-out"
    }
  ],
  "route": {
    "final": "top-sel"
  }
}`, inboundPort, probeSrv.URL, primaryNode.port(), backupNode.port())

	baseCtx := include.Context(context.Background())
	var opts option.Options
	if err := opts.UnmarshalJSONContext(baseCtx, []byte(rawConfig)); err != nil {
		t.Fatalf("UnmarshalJSONContext failed: %v", err)
	}
	instance, err := box.New(box.Options{
		Context: baseCtx,
		Options: opts,
	})
	if err != nil {
		t.Fatalf("box.New failed: %v", err)
	}
	if err := instance.Start(); err != nil {
		_ = instance.Close()
		t.Fatalf("instance.Start failed: %v", err)
	}
	defer instance.Close()

	outMgr := service.FromContext[adapter.OutboundManager](baseCtx)
	fbRaw, ok := outMgr.Outbound("auto-fb")
	if !ok {
		t.Fatalf("auto-fb outbound not found")
	}
	fb := fbRaw.(*group.Fallback)
	selRaw, ok := outMgr.Outbound("top-sel")
	if !ok {
		t.Fatalf("top-sel outbound not found")
	}
	sel := selRaw.(*group.Selector)

	dialViaBoxSOCKS5 := func() (net.Conn, error) {
		c, dialErr := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", inboundPort), 2*time.Second)
		if dialErr != nil {
			return nil, dialErr
		}
		if _, dialErr = c.Write([]byte{0x05, 0x01, 0x00}); dialErr != nil {
			_ = c.Close()
			return nil, dialErr
		}
		resp2 := make([]byte, 2)
		if _, dialErr = io.ReadFull(c, resp2); dialErr != nil {
			_ = c.Close()
			return nil, dialErr
		}
		req := []byte{0x05, 0x01, 0x00, 0x01, 127, 0, 0, 1, byte(echoAddr.Port >> 8), byte(echoAddr.Port)}
		if _, dialErr = c.Write(req); dialErr != nil {
			_ = c.Close()
			return nil, dialErr
		}
		reply := make([]byte, 10)
		if _, dialErr = io.ReadFull(c, reply); dialErr != nil {
			_ = c.Close()
			return nil, dialErr
		}
		if reply[1] != 0x00 {
			_ = c.Close()
			return nil, fmt.Errorf("socks5 connect failed code=%d", reply[1])
		}
		return c, nil
	}

	assertEcho := func(c net.Conn, msg string) {
		t.Helper()
		_ = c.SetDeadline(time.Now().Add(2 * time.Second))
		if _, wErr := c.Write([]byte(msg)); wErr != nil {
			t.Fatalf("echo write failed: %v", wErr)
		}
		got := make([]byte, len(msg))
		if _, rErr := io.ReadFull(c, got); rErr != nil {
			t.Fatalf("echo read failed: %v", rErr)
		}
		if string(got) != msg {
			t.Fatalf("echo mismatch: got %q want %q", got, msg)
		}
		_ = c.SetDeadline(time.Time{})
	}

	// 1. Healthy routed TCP traffic goes through node-primary.
	beforePrimary := primaryNode.tcpHandled.Load()
	cPrimary, err := dialViaBoxSOCKS5()
	if err != nil {
		t.Fatalf("initial routed TCP connection failed: %v", err)
	}
	defer cPrimary.Close()
	assertEcho(cPrimary, "hello-primary")
	if primaryNode.tcpHandled.Load() <= beforePrimary {
		t.Fatalf("expected routed TCP handled by node-primary")
	}

	// 2. Kill node-primary! Routed inbound connection MUST NOT bypass Fallback:
	// the VERY FIRST new client connection must be rescued in-flight onto node-backup!
	primaryNode.setDown(true)
	beforeBackup := backupNode.tcpHandled.Load()
	cRescued1, err := dialViaBoxSOCKS5()
	if err != nil {
		t.Fatalf("expected 1st routed TCP connection rescued in-flight onto backup, got %v", err)
	}
	assertEcho(cRescued1, "rescued-1")
	_ = cRescued1.Close()
	if backupNode.tcpHandled.Load() <= beforeBackup {
		t.Fatalf("expected in-flight rescue to route through node-backup")
	}

	// 2nd routed connection hits fail_times=2 and demotes auto-fb to node-backup.
	cBackupLong, err := dialViaBoxSOCKS5()
	if err != nil {
		t.Fatalf("expected 2nd routed TCP connection rescued onto backup, got %v", err)
	}
	defer cBackupLong.Close()
	assertEcho(cBackupLong, "on-backup")

	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) && fb.Selected(N.NetworkTCP).Tag() != "node-backup" {
		time.Sleep(15 * time.Millisecond)
	}
	if got := fb.Selected(N.NetworkTCP).Tag(); got != "node-backup" {
		t.Fatalf("expected auto-fb demoted to node-backup, got %s", got)
	}

	// 3. Test routed UDP over SOCKS5 UDP ASSOCIATE while primary is down (and rescue if needed).
	udpCtrl, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", inboundPort), 2*time.Second)
	if err != nil {
		t.Fatalf("udp associate tcp dial: %v", err)
	}
	defer udpCtrl.Close()
	_, _ = udpCtrl.Write([]byte{0x05, 0x01, 0x00})
	_, _ = io.ReadFull(udpCtrl, make([]byte, 2))
	_, _ = udpCtrl.Write([]byte{0x05, 0x03, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
	assocReply := make([]byte, 10)
	if _, err := io.ReadFull(udpCtrl, assocReply); err != nil || assocReply[1] != 0x00 {
		t.Fatalf("udp associate reply failed: err=%v reply=%v", err, assocReply)
	}
	relayPort := binary.BigEndian.Uint16(assocReply[8:10])
	udpClient, err := net.DialUDP("udp", nil, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: int(relayPort)})
	if err != nil {
		t.Fatalf("dial udp relay: %v", err)
	}
	defer udpClient.Close()
	_ = udpClient.SetDeadline(time.Now().Add(2 * time.Second))
	pkt := append([]byte{0, 0, 0, 0x01, 198, 51, 100, 10, 0x00, 0x35}, []byte("ping-udp")...)
	if _, err := udpClient.Write(pkt); err != nil {
		t.Fatalf("udp write: %v", err)
	}
	udpResp := make([]byte, 256)
	n, err := udpClient.Read(udpResp)
	if err != nil {
		t.Fatalf("udp read: %v", err)
	}
	if !bytes.Contains(udpResp[:n], []byte("backup:ping-udp")) {
		t.Fatalf("expected UDP routed via backup, got %q", udpResp[:n])
	}

	// 4. Bring node-primary back up: after recover_times=2 probes (interval=80ms),
	// auto-fb MUST fail back to node-primary AND interrupt cBackupLong!
	primaryNode.setDown(false)
	deadline = time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) && fb.Selected(N.NetworkTCP).Tag() != "node-primary" {
		time.Sleep(20 * time.Millisecond)
	}
	if got := fb.Selected(N.NetworkTCP).Tag(); got != "node-primary" {
		t.Fatalf("expected automatic failback to node-primary, got %s", got)
	}

	_ = cBackupLong.SetReadDeadline(time.Now().Add(1 * time.Second))
	if _, err := cBackupLong.Read(make([]byte, 1)); err == nil {
		t.Fatalf("expected backup connection cBackupLong to be interrupted on failback")
	}

	// 5. Verify parent Selector -> Fallback interrupt propagation!
	cViaSel, err := dialViaBoxSOCKS5()
	if err != nil {
		t.Fatalf("dial via selector->fallback failed: %v", err)
	}
	defer cViaSel.Close()
	assertEcho(cViaSel, "via-selector")
	if !sel.SelectOutbound("direct-out") {
		t.Fatalf("Selector.SelectOutbound(direct-out) failed")
	}
	_ = cViaSel.SetReadDeadline(time.Now().Add(1 * time.Second))
	if _, err := cViaSel.Read(make([]byte, 1)); err == nil {
		t.Fatalf("expected switching parent Selector to interrupt connection routed through child Fallback")
	}

	// 6. Verify daemon.Group protobuf Pinned + PinSupported round-trip & descriptor integrity!
	fb.SelectOutbound("node-backup")
	pbGroup := &daemon.Group{
		Tag:          fb.Tag(),
		Type:         fb.Type(),
		Selectable:   true,
		Selected:     fb.Selected(N.NetworkTCP).Tag(),
		Pinned:       fb.PinnedTag(),
		PinSupported: true,
	}
	wireBytes, err := proto.Marshal(pbGroup)
	if err != nil {
		t.Fatalf("proto.Marshal(daemon.Group) failed: %v", err)
	}
	var decoded daemon.Group
	if err := proto.Unmarshal(wireBytes, &decoded); err != nil {
		t.Fatalf("proto.Unmarshal(daemon.Group) failed: %v", err)
	}
	if decoded.GetPinned() != "node-backup" || !decoded.GetPinSupported() {
		t.Fatalf("unexpected decoded Group pin state: pinned=%q pinSupported=%v", decoded.GetPinned(), decoded.GetPinSupported())
	}
	// Trigger ProtoReflect descriptor decompression to validate rawDesc varint length!
	if desc := decoded.ProtoReflect().Descriptor(); desc.Fields().ByName("pinned") == nil || desc.Fields().ByName("pinSupported") == nil {
		t.Fatalf("ProtoReflect descriptor missing pinned / pinSupported fields")
	}
}
