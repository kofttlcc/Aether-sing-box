package group

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/outbound"
	"github.com/sagernet/sing-box/common/interrupt"
	"github.com/sagernet/sing-box/common/urltest"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/json/badoption"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/service"
)

type trackingConn struct {
	net.Conn
	peer   net.Conn
	closed atomic.Bool
}

func newTrackingConn() *trackingConn {
	c1, c2 := net.Pipe()
	return &trackingConn{Conn: c1, peer: c2}
}

func (c *trackingConn) Close() error {
	c.closed.Store(true)
	_ = c.peer.Close()
	return c.Conn.Close()
}

func (c *trackingConn) IsClosed() bool {
	return c.closed.Load()
}

type trackingPacketConn struct {
	closed atomic.Bool
}

func (p *trackingPacketConn) ReadFrom(b []byte) (int, net.Addr, error) {
	return 0, nil, net.ErrClosed
}

func (p *trackingPacketConn) WriteTo(b []byte, addr net.Addr) (int, error) {
	return len(b), nil
}

func (p *trackingPacketConn) Close() error {
	p.closed.Store(true)
	return nil
}

func (p *trackingPacketConn) LocalAddr() net.Addr                { return &net.UDPAddr{} }
func (p *trackingPacketConn) SetDeadline(t time.Time) error      { return nil }
func (p *trackingPacketConn) SetReadDeadline(t time.Time) error  { return nil }
func (p *trackingPacketConn) SetWriteDeadline(t time.Time) error { return nil }

type mockFallbackOutbound struct {
	outbound.Adapter
	probeAddr string

	mu           sync.Mutex
	probeDelay   time.Duration
	probeFail    bool
	trafficFail  bool
	udpFail      bool
	openedConns  []*trackingConn
	openedPacket []*trackingPacketConn

	dialCount   atomic.Int32
	packetCount atomic.Int32
}

func newMockFallbackOutbound(tag string, probeAddr string, networks ...string) *mockFallbackOutbound {
	if len(networks) == 0 {
		networks = []string{N.NetworkTCP, N.NetworkUDP}
	}
	return &mockFallbackOutbound{
		Adapter:   outbound.NewAdapter("mock", tag, networks, nil),
		probeAddr: probeAddr,
	}
}

func (m *mockFallbackOutbound) setProbe(delay time.Duration, fail bool) {
	m.mu.Lock()
	m.probeDelay = delay
	m.probeFail = fail
	m.mu.Unlock()
}

func (m *mockFallbackOutbound) setTrafficFail(fail bool) {
	m.mu.Lock()
	m.trafficFail = fail
	m.mu.Unlock()
}

func (m *mockFallbackOutbound) setUDPFail(fail bool) {
	m.mu.Lock()
	m.udpFail = fail
	m.mu.Unlock()
}

func (m *mockFallbackOutbound) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	m.dialCount.Add(1)
	if destination.String() == m.probeAddr {
		m.mu.Lock()
		delay := m.probeDelay
		fail := m.probeFail
		m.mu.Unlock()
		if delay > 0 {
			timer := time.NewTimer(delay)
			select {
			case <-timer.C:
			case <-ctx.Done():
				timer.Stop()
				return nil, ctx.Err()
			}
		}
		if fail {
			return nil, errors.New("probe failed on " + m.Tag())
		}
		var d net.Dialer
		return d.DialContext(ctx, "tcp", m.probeAddr)
	}
	m.mu.Lock()
	fail := m.trafficFail
	m.mu.Unlock()
	if fail {
		return nil, errors.New("traffic dial failed on " + m.Tag())
	}
	conn := newTrackingConn()
	m.mu.Lock()
	m.openedConns = append(m.openedConns, conn)
	m.mu.Unlock()
	return conn, nil
}

func (m *mockFallbackOutbound) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	m.packetCount.Add(1)
	m.mu.Lock()
	fail := m.udpFail
	m.mu.Unlock()
	if fail {
		return nil, errors.New("udp listen failed on " + m.Tag())
	}
	pc := &trackingPacketConn{}
	m.mu.Lock()
	m.openedPacket = append(m.openedPacket, pc)
	m.mu.Unlock()
	return pc, nil
}

type mockOutboundManager struct {
	mu        sync.RWMutex
	outbounds map[string]adapter.Outbound
	order     []adapter.Outbound
}

func newMockOutboundManager(items ...adapter.Outbound) *mockOutboundManager {
	m := &mockOutboundManager{
		outbounds: make(map[string]adapter.Outbound, len(items)),
		order:     append([]adapter.Outbound(nil), items...),
	}
	for _, it := range items {
		m.outbounds[it.Tag()] = it
	}
	return m
}

func (m *mockOutboundManager) Start(stage adapter.StartStage, scope *adapter.Scope) error { return nil }
func (m *mockOutboundManager) Close() error                                              { return nil }
func (m *mockOutboundManager) Outbounds() []adapter.Outbound {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return append([]adapter.Outbound(nil), m.order...)
}
func (m *mockOutboundManager) Outbound(tag string) (adapter.Outbound, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	it, ok := m.outbounds[tag]
	return it, ok
}
func (m *mockOutboundManager) Default() adapter.Outbound {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if len(m.order) == 0 {
		return nil
	}
	return m.order[0]
}
func (m *mockOutboundManager) Create(ctx context.Context, router adapter.Router, logger log.ContextLogger, tag string, outboundType string, options any) error {
	return nil
}

func startProbeServer(t *testing.T) (*httptest.Server, string, string) {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(srv.Close)
	u, err := url.Parse(srv.URL)
	if err != nil {
		t.Fatalf("parse probe url: %v", err)
	}
	return srv, srv.URL, u.Host
}

func newTestFallback(t *testing.T, opts option.FallbackOutboundOptions, members ...adapter.Outbound) (*Fallback, *urltest.HistoryStorage) {
	t.Helper()
	ctx := context.Background()
	history := urltest.NewHistoryStorage()
	mgr := newMockOutboundManager(members...)
	ctx = service.ContextWithPtr(ctx, history)
	ctx = service.ContextWith[adapter.OutboundManager](ctx, mgr)

	out, err := NewFallback(ctx, nil, log.NewNOPFactory().Logger(), "fb-group", opts)
	if err != nil {
		t.Fatalf("NewFallback failed: %v", err)
	}
	fb := out.(*Fallback)
	if err := fb.Start(adapter.StartStateStart, nil); err != nil {
		t.Fatalf("Fallback.Start failed: %v", err)
	}
	t.Cleanup(func() {
		_ = fb.group.Close()
		_ = history.Close()
	})
	return fb, history
}

func waitUntil(t *testing.T, timeout time.Duration, desc string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for: %s", desc)
}

func TestFallbackStrictPriorityOverLatency(t *testing.T) {
	_, probeURL, probeAddr := startProbeServer(t)
	primary := newMockFallbackOutbound("primary", probeAddr)
	backup := newMockFallbackOutbound("backup", probeAddr)
	primary.setProbe(120*time.Millisecond, false)
	backup.setProbe(10*time.Millisecond, false)

	fb, history := newTestFallback(t, option.FallbackOutboundOptions{
		Outbounds: []string{"primary", "backup"},
		URL:       probeURL,
	}, primary, backup)

	res, err := fb.URLTest(context.Background())
	if err != nil {
		t.Fatalf("URLTest error: %v", err)
	}
	if _, ok := res["primary"]; !ok {
		t.Fatalf("expected primary in URLTest result: %v", res)
	}
	if _, ok := res["backup"]; !ok {
		t.Fatalf("expected backup in URLTest result: %v", res)
	}
	if got := fb.Selected(N.NetworkTCP).Tag(); got != "primary" {
		t.Fatalf("expected strict priority primary despite higher latency, got %s", got)
	}
	if got := fb.Selected(N.NetworkUDP).Tag(); got != "primary" {
		t.Fatalf("expected strict priority primary for UDP, got %s", got)
	}
	if h := history.LoadURLTestHistory("primary"); h == nil || h.Delay < 100 {
		t.Fatalf("expected primary history delay >= 100ms, got %+v", h)
	}

	// Periodic check should also stay strictly on primary.
	fb.group.CheckOutbounds(context.Background(), false)
	if got := fb.Selected(N.NetworkTCP).Tag(); got != "primary" {
		t.Fatalf("expected primary after periodic check, got %s", got)
	}
}

func TestFallbackMaxDelayDemotion(t *testing.T) {
	_, probeURL, probeAddr := startProbeServer(t)
	primary := newMockFallbackOutbound("primary", probeAddr)
	backup := newMockFallbackOutbound("backup", probeAddr)
	primary.setProbe(15*time.Millisecond, false)
	backup.setProbe(10*time.Millisecond, false)

	fb, history := newTestFallback(t, option.FallbackOutboundOptions{
		Outbounds: []string{"primary", "backup"},
		URL:       probeURL,
		MaxDelay:  70,
	}, primary, backup)

	_, _ = fb.URLTest(context.Background())
	if got := fb.Selected(N.NetworkTCP).Tag(); got != "primary" {
		t.Fatalf("expected primary initially, got %s", got)
	}

	extCtx := interrupt.ContextWithIsExternalConnection(context.Background(), true)
	conn, err := fb.DialContext(extCtx, N.NetworkTCP, M.ParseSocksaddr("example.com:443"))
	if err != nil {
		t.Fatalf("DialContext failed: %v", err)
	}
	defer conn.Close()
	underlying := primary.openedConns[len(primary.openedConns)-1]

	// Degrade primary latency beyond max_delay.
	primary.setProbe(120*time.Millisecond, false)
	fb.group.CheckOutbounds(context.Background(), false)

	if got := fb.Selected(N.NetworkTCP).Tag(); got != "backup" {
		t.Fatalf("expected demotion to backup when primary delay > max_delay, got %s", got)
	}
	if !underlying.IsClosed() {
		t.Fatalf("expected active connection on primary to be interrupted on max_delay demotion")
	}
	if h := history.LoadURLTestHistory("primary"); h == nil || h.Delay <= 70 {
		t.Fatalf("expected high delay still recorded in history for UI visibility, got %+v", h)
	}
}

func TestFallbackPassiveInFlightRescueAndFastDemotion(t *testing.T) {
	_, probeURL, probeAddr := startProbeServer(t)
	primary := newMockFallbackOutbound("primary", probeAddr)
	backup1 := newMockFallbackOutbound("backup-1", probeAddr)
	backup2 := newMockFallbackOutbound("backup-2", probeAddr)
	primary.setProbe(5*time.Millisecond, false)
	backup1.setProbe(5*time.Millisecond, false)
	backup2.setProbe(5*time.Millisecond, false)

	fb, _ := newTestFallback(t, option.FallbackOutboundOptions{
		Outbounds: []string{"primary", "backup-1", "backup-2"},
		URL:       probeURL,
		FailTimes: 2,
	}, primary, backup1, backup2)

	_, _ = fb.URLTest(context.Background())
	if got := fb.Selected(N.NetworkTCP).Tag(); got != "primary" {
		t.Fatalf("expected primary selected, got %s", got)
	}

	// Open a live external connection on primary.
	extCtx := interrupt.ContextWithIsExternalConnection(context.Background(), true)
	liveConn, err := fb.DialContext(extCtx, N.NetworkTCP, M.ParseSocksaddr("example.com:443"))
	if err != nil {
		t.Fatalf("initial DialContext failed: %v", err)
	}
	defer liveConn.Close()
	livePrimaryConn := primary.openedConns[0]

	// First test false-positive protection: target fails while probe still succeeds.
	primary.setTrafficFail(true)
	c1, err := fb.DialContext(extCtx, N.NetworkTCP, M.ParseSocksaddr("target-down.example:443"))
	if err != nil {
		t.Fatalf("expected in-flight rescue on backup-1, got error: %v", err)
	}
	_ = c1.Close()
	if backup1.dialCount.Load() == 0 {
		t.Fatalf("expected backup-1 to handle rescued dial")
	}
	c2, err := fb.DialContext(extCtx, N.NetworkTCP, M.ParseSocksaddr("target-down.example:443"))
	if err != nil {
		t.Fatalf("expected 2nd in-flight rescue on backup-1, got error: %v", err)
	}
	_ = c2.Close()
	// Wait for verifyAndFailover to complete; primary probe succeeds so primary must remain selected.
	waitUntil(t, 2*time.Second, "verifyAndFailover finishes for healthy primary", func() bool {
		return !fb.group.stateByTag["primary"].verifying.Load()
	})
	if got := fb.Selected(N.NetworkTCP).Tag(); got != "primary" {
		t.Fatalf("expected primary to remain active when verify probe succeeds, got %s", got)
	}
	if livePrimaryConn.IsClosed() {
		t.Fatalf("did not expect live connection on primary to be closed on false positive")
	}

	// Now simulate real primary failure (both traffic & probe fail).
	primary.setProbe(5*time.Millisecond, true)
	backup1.setTrafficFail(true) // force 2nd rescue hop to backup-2!

	rescued1, err := fb.DialContext(extCtx, N.NetworkTCP, M.ParseSocksaddr("example.com:443"))
	if err != nil {
		t.Fatalf("expected rescue to hop over backup-1 to backup-2, got %v", err)
	}
	_ = rescued1.Close()
	if backup2.dialCount.Load() == 0 {
		t.Fatalf("expected backup-2 to rescue connection when backup-1 also failed")
	}
	// Restore backup-1 so group failover lands on backup-1.
	backup1.setTrafficFail(false)

	// Second failure hits fail_times=2 and triggers async verifyAndFailover.
	rescued2, err := fb.DialContext(extCtx, N.NetworkTCP, M.ParseSocksaddr("example.com:443"))
	if err != nil {
		t.Fatalf("expected 2nd rescue on backup-1, got %v", err)
	}
	_ = rescued2.Close()

	waitUntil(t, 2*time.Second, "primary demoted to backup-1", func() bool {
		return fb.Selected(N.NetworkTCP).Tag() == "backup-1"
	})
	if !livePrimaryConn.IsClosed() {
		t.Fatalf("expected active connection on dead primary to be interrupted on failover")
	}

	// Verify UDP ListenPacket rescue as well.
	backup1.setUDPFail(true)
	pc, err := fb.ListenPacket(extCtx, M.ParseSocksaddr("8.8.8.8:53"))
	if err != nil {
		t.Fatalf("expected UDP ListenPacket in-flight rescue to backup-2, got %v", err)
	}
	_ = pc.Close()
	if backup2.packetCount.Load() == 0 {
		t.Fatalf("expected backup-2 to handle rescued UDP packet conn")
	}
}

func TestFallbackAntiFlappingRecoverTimesAndBidirectionalInterrupt(t *testing.T) {
	_, probeURL, probeAddr := startProbeServer(t)
	primary := newMockFallbackOutbound("primary", probeAddr)
	backup := newMockFallbackOutbound("backup", probeAddr)
	primary.setProbe(5*time.Millisecond, true)
	backup.setProbe(5*time.Millisecond, false)

	fb, _ := newTestFallback(t, option.FallbackOutboundOptions{
		Outbounds:    []string{"primary", "backup"},
		URL:          probeURL,
		RecoverTimes: 2,
		// InterruptExistConnections omitted -> defaults to true
	}, primary, backup)

	// Cold start: primary is down, backup is up -> switches to backup immediately.
	_, _ = fb.URLTest(context.Background())
	if got := fb.Selected(N.NetworkTCP).Tag(); got != "backup" {
		t.Fatalf("expected backup after primary failed initial probe, got %s", got)
	}

	// Open active connections on backup (both DialContext and AttachConnection).
	extCtx := interrupt.ContextWithIsExternalConnection(context.Background(), true)
	backupDialConn, err := fb.DialContext(extCtx, N.NetworkTCP, M.ParseSocksaddr("example.com:443"))
	if err != nil {
		t.Fatalf("DialContext on backup failed: %v", err)
	}
	defer backupDialConn.Close()
	underlyingBackupConn := backup.openedConns[len(backup.openedConns)-1]

	attachedConn := newTrackingConn()
	detach := fb.AttachConnection(attachedConn)
	defer detach()

	// Bring primary back online.
	primary.setProbe(5*time.Millisecond, false)

	// Periodic probe #1: streak = 1 < recover_times(2) -> must NOT switch back yet!
	fb.group.CheckOutbounds(context.Background(), false)
	if got := fb.Selected(N.NetworkTCP).Tag(); got != "backup" {
		t.Fatalf("expected anti-flapping hold on backup after 1st healthy probe, got %s", got)
	}
	if underlyingBackupConn.IsClosed() || attachedConn.IsClosed() {
		t.Fatalf("backup connections must remain open while waiting for recover_times streak")
	}

	// Simulate flapping: primary fails once -> streak resets to 0.
	primary.setProbe(5*time.Millisecond, true)
	fb.group.CheckOutbounds(context.Background(), false)
	primary.setProbe(5*time.Millisecond, false)
	fb.group.CheckOutbounds(context.Background(), false)
	if got := fb.Selected(N.NetworkTCP).Tag(); got != "backup" {
		t.Fatalf("expected streak reset after flap to still hold on backup, got %s", got)
	}

	// Periodic probe #2 consecutive success: streak = 2 >= recover_times(2) -> failback to primary!
	fb.group.CheckOutbounds(context.Background(), false)
	if got := fb.Selected(N.NetworkTCP).Tag(); got != "primary" {
		t.Fatalf("expected failback to primary after 2 consecutive healthy probes, got %s", got)
	}
	if !underlyingBackupConn.IsClosed() {
		t.Fatalf("expected bidirectional interrupt to close backup DialContext connection on failback")
	}
	if !attachedConn.IsClosed() {
		t.Fatalf("expected bidirectional interrupt to close attached backup connection on failback")
	}

	// Verify explicit manual URLTest bypasses recover_times streak wait.
	primary.setProbe(5*time.Millisecond, true)
	fb.group.CheckOutbounds(context.Background(), false)
	if got := fb.Selected(N.NetworkTCP).Tag(); got != "backup" {
		t.Fatalf("expected demotion to backup, got %s", got)
	}
	primary.setProbe(5*time.Millisecond, false)
	_, _ = fb.URLTest(context.Background())
	if got := fb.Selected(N.NetworkTCP).Tag(); got != "primary" {
		t.Fatalf("expected manual URLTest to bypass recover_times streak and restore primary, got %s", got)
	}
}

func TestFallbackInterruptExistConnectionsFalse(t *testing.T) {
	_, probeURL, probeAddr := startProbeServer(t)
	primary := newMockFallbackOutbound("primary", probeAddr)
	backup := newMockFallbackOutbound("backup", probeAddr)
	primary.setProbe(5*time.Millisecond, false)
	backup.setProbe(5*time.Millisecond, false)

	interruptFalse := false
	fb, _ := newTestFallback(t, option.FallbackOutboundOptions{
		Outbounds:                 []string{"primary", "backup"},
		URL:                       probeURL,
		InterruptExistConnections: &interruptFalse,
	}, primary, backup)

	_, _ = fb.URLTest(context.Background())
	extCtx := interrupt.ContextWithIsExternalConnection(context.Background(), true)
	conn, err := fb.DialContext(extCtx, N.NetworkTCP, M.ParseSocksaddr("example.com:443"))
	if err != nil {
		t.Fatalf("DialContext failed: %v", err)
	}
	defer conn.Close()
	underlying := primary.openedConns[0]

	if !fb.SelectOutbound("backup") {
		t.Fatalf("expected pin to backup to succeed")
	}
	if underlying.IsClosed() {
		t.Fatalf("expected existing connection to remain open when interrupt_exist_connections is false")
	}
}

func TestFallbackPinAndUnpin(t *testing.T) {
	_, probeURL, probeAddr := startProbeServer(t)
	primary := newMockFallbackOutbound("primary", probeAddr)
	backup := newMockFallbackOutbound("backup", probeAddr)
	primary.setProbe(5*time.Millisecond, false)
	backup.setProbe(5*time.Millisecond, false)

	fb, _ := newTestFallback(t, option.FallbackOutboundOptions{
		Outbounds: []string{"primary", "backup"},
		URL:       probeURL,
	}, primary, backup)

	_, _ = fb.URLTest(context.Background())
	if fb.IsPinned() || fb.PinnedTag() != "" {
		t.Fatalf("expected initially unpinned")
	}

	extCtx := interrupt.ContextWithIsExternalConnection(context.Background(), true)
	cPrimary, err := fb.DialContext(extCtx, N.NetworkTCP, M.ParseSocksaddr("example.com:443"))
	if err != nil {
		t.Fatalf("DialContext primary failed: %v", err)
	}
	defer cPrimary.Close()
	underlyingPrimary := primary.openedConns[0]

	if fb.SelectOutbound("nonexistent") {
		t.Fatalf("expected SelectOutbound on unknown tag to return false")
	}
	if !fb.SelectOutbound("backup") {
		t.Fatalf("expected SelectOutbound(backup) to return true")
	}
	if !fb.IsPinned() || fb.PinnedTag() != "backup" {
		t.Fatalf("expected pinned to backup, got pinned=%v tag=%q", fb.IsPinned(), fb.PinnedTag())
	}
	if got := fb.Selected(N.NetworkTCP).Tag(); got != "backup" {
		t.Fatalf("expected selected backup when pinned, got %s", got)
	}
	if !underlyingPrimary.IsClosed() {
		t.Fatalf("expected active connection on primary to be interrupted when pinning to backup")
	}

	// While pinned, failing dials must NOT trigger in-flight rescue.
	backup.setTrafficFail(true)
	if _, err := fb.DialContext(extCtx, N.NetworkTCP, M.ParseSocksaddr("example.com:443")); err == nil {
		t.Fatalf("expected error without rescue while pinned")
	}
	backup.setTrafficFail(false)

	cBackup, err := fb.DialContext(extCtx, N.NetworkTCP, M.ParseSocksaddr("example.com:443"))
	if err != nil {
		t.Fatalf("DialContext backup failed: %v", err)
	}
	defer cBackup.Close()
	underlyingBackup := backup.openedConns[len(backup.openedConns)-1]

	// Unpin with empty string.
	if !fb.SelectOutbound("") {
		t.Fatalf("expected SelectOutbound('') to unpin and return true")
	}
	if fb.IsPinned() || fb.PinnedTag() != "" {
		t.Fatalf("expected unpinned state after SelectOutbound('')")
	}
	if got := fb.Selected(N.NetworkTCP).Tag(); got != "primary" {
		t.Fatalf("expected primary after unpin, got %s", got)
	}
	if !underlyingBackup.IsClosed() {
		t.Fatalf("expected active connection on backup to be interrupted when unpinning back to primary")
	}
}

func TestFallbackAllDownSafetyNet(t *testing.T) {
	_, probeURL, probeAddr := startProbeServer(t)
	primary := newMockFallbackOutbound("primary", probeAddr)
	backup := newMockFallbackOutbound("backup", probeAddr)
	primary.setProbe(5*time.Millisecond, true)
	backup.setProbe(5*time.Millisecond, true)

	fb, _ := newTestFallback(t, option.FallbackOutboundOptions{
		Outbounds: []string{"primary", "backup"},
		URL:       probeURL,
	}, primary, backup)

	_, _ = fb.URLTest(context.Background())

	selTCP := fb.Selected(N.NetworkTCP)
	selUDP := fb.Selected(N.NetworkUDP)
	if selTCP == nil || selTCP.Tag() != "primary" {
		t.Fatalf("expected safety net fallback to #1 primary for TCP, got %v", selTCP)
	}
	if selUDP == nil || selUDP.Tag() != "primary" {
		t.Fatalf("expected safety net fallback to #1 primary for UDP, got %v", selUDP)
	}
}

func TestFallbackValidationAndNestedURLTest(t *testing.T) {
	ctx := context.Background()
	history := urltest.NewHistoryStorage()
	defer history.Close()
	ctx = service.ContextWithPtr(ctx, history)

	if _, err := NewFallback(ctx, nil, log.NewNOPFactory().Logger(), "empty", option.FallbackOutboundOptions{}); err == nil {
		t.Fatalf("expected error for empty outbounds")
	}
	if _, err := NewFallback(ctx, nil, log.NewNOPFactory().Logger(), "dup", option.FallbackOutboundOptions{
		Outbounds: []string{"a", "a"},
	}); err == nil {
		t.Fatalf("expected error for duplicate outbounds")
	}

	_, probeURL, probeAddr := startProbeServer(t)
	n1 := newMockFallbackOutbound("n1", probeAddr)
	n2 := newMockFallbackOutbound("n2", probeAddr)
	n1.setProbe(5*time.Millisecond, false)
	n2.setProbe(5*time.Millisecond, false)

	mgr := newMockOutboundManager(n1, n2)
	ctx = service.ContextWith[adapter.OutboundManager](ctx, mgr)
	badFB, err := NewFallback(ctx, nil, log.NewNOPFactory().Logger(), "bad-interval", option.FallbackOutboundOptions{
		Outbounds:   []string{"n1", "n2"},
		Interval:    badoption.Duration(10 * time.Minute),
		IdleTimeout: badoption.Duration(5 * time.Minute),
	})
	if err != nil {
		t.Fatalf("NewFallback unexpected error: %v", err)
	}
	if err := badFB.(*Fallback).Start(adapter.StartStateStart, nil); err == nil {
		t.Fatalf("expected error when interval > idle_timeout")
	}

	// Nested *Fallback inside *URLTest batch test.
	fbOut, err := NewFallback(ctx, nil, log.NewNOPFactory().Logger(), "nested-fb", option.FallbackOutboundOptions{
		Outbounds: []string{"n1", "n2"},
		URL:       probeURL,
	})
	if err != nil {
		t.Fatalf("NewFallback failed: %v", err)
	}
	fb := fbOut.(*Fallback)
	if err := fb.Start(adapter.StartStateStart, nil); err != nil {
		t.Fatalf("fb.Start failed: %v", err)
	}
	defer fb.group.Close()

	mgrWithFB := newMockOutboundManager(n1, n2, fb)
	ctx2 := service.ContextWith[adapter.OutboundManager](ctx, mgrWithFB)
	utOut, err := NewURLTest(ctx2, nil, log.NewNOPFactory().Logger(), "outer-ut", option.URLTestOutboundOptions{
		Outbounds: []string{"nested-fb"},
		URL:       probeURL,
	})
	if err != nil {
		t.Fatalf("NewURLTest failed: %v", err)
	}
	ut := utOut.(*URLTest)
	if err := ut.Start(adapter.StartStateStart, nil); err != nil {
		t.Fatalf("ut.Start failed: %v", err)
	}
	defer ut.group.Close()

	res, err := ut.URLTest(context.Background())
	if err != nil {
		t.Fatalf("nested URLTest failed: %v", err)
	}
	if _, ok := res["n1"]; !ok {
		t.Fatalf("expected n1 in nested URLTest result: %v", res)
	}
	if _, ok := res["nested-fb"]; !ok {
		t.Fatalf("expected nested-fb in nested URLTest result: %v", res)
	}
}

func TestFallbackConcurrentRace(t *testing.T) {
	_, probeURL, probeAddr := startProbeServer(t)
	nodes := make([]adapter.Outbound, 0, 4)
	tags := make([]string, 0, 4)
	mocks := make([]*mockFallbackOutbound, 0, 4)
	for i := range 4 {
		tag := "node-" + strconv.Itoa(i+1)
		m := newMockFallbackOutbound(tag, probeAddr)
		m.setProbe(time.Duration(i+1)*2*time.Millisecond, false)
		nodes = append(nodes, m)
		tags = append(tags, tag)
		mocks = append(mocks, m)
	}

	fb, _ := newTestFallback(t, option.FallbackOutboundOptions{
		Outbounds:    tags,
		URL:          probeURL,
		Interval:     badoption.Duration(50 * time.Millisecond),
		IdleTimeout:  badoption.Duration(5 * time.Second),
		FailTimes:    2,
		RecoverTimes: 2,
	}, nodes...)
	fb.group.PostStart()

	var wg sync.WaitGroup
	stop := make(chan struct{})
	extCtx := interrupt.ContextWithIsExternalConnection(context.Background(), true)

	// Dialer workers
	for range 4 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				if c, err := fb.DialContext(extCtx, N.NetworkTCP, M.ParseSocksaddr("example.com:443")); err == nil {
					_ = c.Close()
				}
				if pc, err := fb.ListenPacket(extCtx, M.ParseSocksaddr("8.8.8.8:53")); err == nil {
					_ = pc.Close()
				}
				_ = fb.Selected(N.NetworkTCP)
				_ = fb.References()
			}
		}()
	}

	// Probe + fault injection + pin/unpin workers
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < 20; i++ {
			mocks[0].setProbe(3*time.Millisecond, i%2 == 0)
			mocks[0].setTrafficFail(i%3 == 0)
			if i%4 == 0 {
				fb.SelectOutbound("node-2")
			} else if i%4 == 2 {
				fb.SelectOutbound("")
			}
			fb.group.CheckOutbounds(context.Background(), false)
			fb.PerformUpdateCheck()
			fb.InterfaceUpdated(context.Background())
		}
		close(stop)
	}()

	wg.Wait()
	if err := fb.group.Close(); err != nil {
		t.Fatalf("Close error: %v", err)
	}
	if C.ProxyDisplayName(C.TypeFallback) != "Fallback" {
		t.Fatalf("unexpected ProxyDisplayName: %s", C.ProxyDisplayName(C.TypeFallback))
	}
}
