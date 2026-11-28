package group

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/dialer"
	"github.com/sagernet/sing-box/common/interrupt"
	"github.com/sagernet/sing-box/common/urltest"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/json/badoption"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/service"
)

type mockParallelFallbackOutbound struct {
	*mockFallbackOutbound
	parallelCalls atomic.Int32
}

var _ dialer.ParallelNetworkDialer = (*mockParallelFallbackOutbound)(nil)

func newMockParallelFallbackOutbound(tag string, probeAddr string) *mockParallelFallbackOutbound {
	return &mockParallelFallbackOutbound{
		mockFallbackOutbound: newMockFallbackOutbound(tag, probeAddr),
	}
}

func (m *mockParallelFallbackOutbound) DialParallelNetwork(
	ctx context.Context,
	network string,
	destination M.Socksaddr,
	destinationAddresses []netip.Addr,
	strategy *C.NetworkStrategy,
	interfaceType []C.InterfaceType,
	fallbackInterfaceType []C.InterfaceType,
	fallbackDelay time.Duration,
) (net.Conn, error) {
	m.parallelCalls.Add(1)
	m.mu.Lock()
	fail := m.trafficFail
	m.mu.Unlock()
	if fail {
		return nil, errors.New("parallel dial failed across all IPs on " + m.Tag())
	}
	conn := newTrackingConn()
	m.mu.Lock()
	m.openedConns = append(m.openedConns, conn)
	m.mu.Unlock()
	return conn, nil
}

func (m *mockParallelFallbackOutbound) ListenSerialNetworkPacket(
	ctx context.Context,
	destination M.Socksaddr,
	destinationAddresses []netip.Addr,
	strategy *C.NetworkStrategy,
	interfaceType []C.InterfaceType,
	fallbackInterfaceType []C.InterfaceType,
	fallbackDelay time.Duration,
) (net.PacketConn, netip.Addr, error) {
	m.packetCount.Add(1)
	m.mu.Lock()
	fail := m.udpFail
	m.mu.Unlock()
	if fail {
		return nil, netip.Addr{}, errors.New("parallel packet failed on " + m.Tag())
	}
	pc := &trackingPacketConn{}
	m.mu.Lock()
	m.openedPacket = append(m.openedPacket, pc)
	m.mu.Unlock()
	return pc, destinationAddresses[0], nil
}

func TestFallbackMultiIPDialNoAmplificationAndPreservesLeafParallelDialer(t *testing.T) {
	_, probeURL, probeAddr := startProbeServer(t)
	primary := newMockParallelFallbackOutbound("primary", probeAddr)
	backup := newMockParallelFallbackOutbound("backup", probeAddr)
	primary.setProbe(5*time.Millisecond, true)
	backup.setProbe(5*time.Millisecond, false)
	primary.setTrafficFail(true)

	fb, _ := newTestFallback(t, option.FallbackOutboundOptions{
		Outbounds: []string{"primary", "backup"},
		URL:       probeURL,
		FailTimes: 2,
	}, primary, backup)

	addrs := []netip.Addr{
		netip.MustParseAddr("2001:db8::1"),
		netip.MustParseAddr("2001:db8::2"),
		netip.MustParseAddr("198.51.100.1"),
		netip.MustParseAddr("198.51.100.2"),
	}

	// Single multi-IP connection via dialer.DialSerialNetwork must delegate to Fallback.DialParallelNetwork:
	// 1. Preserves leaf ParallelNetworkDialer (1 call on primary, 1 rescue call on backup).
	// 2. Increments primary.consecutiveDialFail by 1 (NOT 4!), so fail_times=2 does NOT trip on 1 connection.
	conn, err := dialer.DialSerialNetwork(
		context.Background(),
		fb,
		N.NetworkTCP,
		M.ParseSocksaddr("example.com:443"),
		addrs,
		nil, nil, nil, 0,
	)
	if err != nil {
		t.Fatalf("expected multi-IP dial rescued on backup, got %v", err)
	}
	_ = conn.Close()

	if got := primary.parallelCalls.Load(); got != 1 {
		t.Fatalf("expected leaf ParallelNetworkDialer called once on primary, got %d", got)
	}
	if got := backup.parallelCalls.Load(); got != 1 {
		t.Fatalf("expected leaf ParallelNetworkDialer called once on backup, got %d", got)
	}
	if got := fb.group.stateByTag["primary"].consecutiveDialFail.Load(); got != 1 {
		t.Fatalf("expected consecutiveDialFail=1 after 1 multi-IP connection, got %d", got)
	}
	if got := fb.Selected(N.NetworkTCP).Tag(); got != "primary" {
		t.Fatalf("expected primary still selected before 2nd connection reaches fail_times=2, got %s", got)
	}

	// Multi-IP UDP packet connection also counts at most 1 failure on primary and rescues onto backup -> hits fail_times=2!
	primary.setUDPFail(true)
	pc, selectedAddr, err := dialer.ListenSerialNetworkPacket(
		context.Background(),
		fb,
		M.ParseSocksaddr("example.com:53"),
		addrs,
		nil, nil, nil, 0,
	)
	if err != nil {
		t.Fatalf("expected multi-IP packet rescued on backup, got %v", err)
	}
	_ = pc.Close()
	if selectedAddr != addrs[0] {
		t.Fatalf("expected returned destination address %s, got %s", addrs[0], selectedAddr)
	}

	waitUntil(t, 2*time.Second, "primary demoted after 2nd connection failure", func() bool {
		return fb.Selected(N.NetworkTCP).Tag() == "backup"
	})
}

type earlyHandshakeConn struct {
	net.Conn
	needHandshake bool
}

func (c *earlyHandshakeConn) NeedHandshakeForWrite() bool {
	return c.needHandshake
}

type earlyHandshakeOutbound struct {
	*mockFallbackOutbound
}

func (m *earlyHandshakeOutbound) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	if destination.String() == m.probeAddr {
		return m.mockFallbackOutbound.DialContext(ctx, network, destination)
	}
	c1, c2 := net.Pipe()
	_ = c2.Close()
	return &earlyHandshakeConn{Conn: c1, needHandshake: true}, nil
}

func TestFallbackEarlyHandshakeFailureTriggersVerifyAndDoesNotPrematurelyResetCounter(t *testing.T) {
	_, probeURL, probeAddr := startProbeServer(t)
	primary := &earlyHandshakeOutbound{mockFallbackOutbound: newMockFallbackOutbound("primary", probeAddr)}
	backup := newMockFallbackOutbound("backup", probeAddr)
	primary.setProbe(5*time.Millisecond, true)
	backup.setProbe(5*time.Millisecond, false)

	fb, _ := newTestFallback(t, option.FallbackOutboundOptions{
		Outbounds: []string{"primary", "backup"},
		URL:       probeURL,
		FailTimes: 2,
	}, primary, backup)

	// Pre-seed 1 prior dial failure; if DialContext mistakenly reset consecutiveDialFail=0 on NeedHandshakeForWrite conn,
	// a single subsequent early-handshake failure would only reach 1 instead of 2!
	fb.group.stateByTag["primary"].consecutiveDialFail.Store(1)

	conn, err := fb.DialContext(context.Background(), N.NetworkTCP, M.ParseSocksaddr("example.com:443"))
	if err != nil {
		t.Fatalf("DialContext unexpected error: %v", err)
	}
	defer conn.Close()

	// Must NOT have reset consecutiveDialFail before handshake completes.
	if got := fb.group.stateByTag["primary"].consecutiveDialFail.Load(); got != 1 {
		t.Fatalf("expected consecutiveDialFail preserved at 1 while handshake pending, got %d", got)
	}

	observer, ok := common.Cast[adapter.HandshakeResultObserver](conn)
	if !ok {
		t.Fatalf("expected conn to expose HandshakeResultObserver via common.Cast")
	}
	observer.OnHandshakeFailure(errors.New("tls handshake reset"))

	waitUntil(t, 2*time.Second, "early handshake failure triggers verifyAndFailover demotion", func() bool {
		return fb.Selected(N.NetworkTCP).Tag() == "backup"
	})
}

func TestFallbackDemoteGenPreventsStaleURLTestBatchFromOverwritingDemotion(t *testing.T) {
	_, probeURL, probeAddr := startProbeServer(t)
	primary := newMockFallbackOutbound("primary", probeAddr)
	backup := newMockFallbackOutbound("backup", probeAddr)

	probeStarted := make(chan struct{})
	releaseStaleProbe := make(chan struct{})
	var blockedFirst atomic.Bool

	blockingPrimary := &blockingProbeOutbound{
		mockFallbackOutbound: primary,
		onProbe: func(ctx context.Context) error {
			if blockedFirst.CompareAndSwap(false, true) {
				close(probeStarted)
				select {
				case <-releaseStaleProbe:
				case <-ctx.Done():
				}
			}
			return nil
		},
	}
	primary.setProbe(2*time.Millisecond, false)
	backup.setProbe(2*time.Millisecond, false)

	fb, _ := newTestFallback(t, option.FallbackOutboundOptions{
		Outbounds:    []string{"primary", "backup"},
		URL:          probeURL,
		FailTimes:    1,
		RecoverTimes: 2,
	}, blockingPrimary, backup)

	// Start a periodic probe batch that stalls on primary before primary breaks.
	batchDone := make(chan struct{})
	go func() {
		defer close(batchDone)
		fb.group.CheckOutbounds(context.Background(), false)
	}()

	<-probeStarted

	// While the stale batch is in-flight, primary breaks and verifyAndFailover demotes primary (incrementing demoteGen).
	primary.setProbe(2*time.Millisecond, true)
	blockingPrimary.setTrafficFail(true)
	c, err := fb.DialContext(context.Background(), N.NetworkTCP, M.ParseSocksaddr("example.com:443"))
	if err != nil {
		t.Fatalf("expected rescue on backup, got %v", err)
	}
	_ = c.Close()

	waitUntil(t, 2*time.Second, "verifyAndFailover demotes primary", func() bool {
		return fb.Selected(N.NetworkTCP).Tag() == "backup"
	})

	// Now let the stale pre-demotion probe succeed and finish: demoteGen must block it from restoring primary!
	primary.setProbe(2*time.Millisecond, false)
	close(releaseStaleProbe)
	<-batchDone

	if got := fb.Selected(N.NetworkTCP).Tag(); got != "backup" {
		t.Fatalf("stale urlTest batch overwrote verifyAndFailover demotion: got %s, want backup", got)
	}
}

type blockingProbeOutbound struct {
	*mockFallbackOutbound
	onProbe func(ctx context.Context) error
}

func (b *blockingProbeOutbound) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	if destination.String() == b.probeAddr && b.onProbe != nil {
		if err := b.onProbe(ctx); err != nil {
			return nil, err
		}
	}
	return b.mockFallbackOutbound.DialContext(ctx, network, destination)
}

func TestFallbackAllDownSafetyNetRecoversOnFirstPassingProbe(t *testing.T) {
	_, probeURL, probeAddr := startProbeServer(t)
	primary := newMockFallbackOutbound("primary", probeAddr)
	backup := newMockFallbackOutbound("backup", probeAddr)
	primary.setProbe(3*time.Millisecond, true)
	backup.setProbe(3*time.Millisecond, true)

	fb, _ := newTestFallback(t, option.FallbackOutboundOptions{
		Outbounds:    []string{"primary", "backup"},
		URL:          probeURL,
		RecoverTimes: 3,
	}, primary, backup)

	// Initial probe: all nodes unhealthy -> safety net selects primary (#1) with healthy=false.
	_, _ = fb.URLTest(context.Background())
	if got := fb.Selected(N.NetworkTCP).Tag(); got != "primary" {
		t.Fatalf("expected safety net #1 primary, got %s", got)
	}

	// Backup comes online while primary stays down: 1st periodic probe MUST promote backup immediately (not wait 3 intervals!).
	backup.setProbe(3*time.Millisecond, false)
	fb.group.CheckOutbounds(context.Background(), false)
	if got := fb.Selected(N.NetworkTCP).Tag(); got != "backup" {
		t.Fatalf("expected immediate recovery from all-down safety net onto backup on 1st passing probe, got %s", got)
	}

	// Now backup IS healthy, so primary recovering MUST still respect recover_times=3!
	primary.setProbe(3*time.Millisecond, false)
	fb.group.CheckOutbounds(context.Background(), false)
	if got := fb.Selected(N.NetworkTCP).Tag(); got != "backup" {
		t.Fatalf("expected hold on healthy backup after 1/3 primary probes, got %s", got)
	}
	fb.group.CheckOutbounds(context.Background(), false)
	if got := fb.Selected(N.NetworkTCP).Tag(); got != "backup" {
		t.Fatalf("expected hold on healthy backup after 2/3 primary probes, got %s", got)
	}
	fb.group.CheckOutbounds(context.Background(), false)
	if got := fb.Selected(N.NetworkTCP).Tag(); got != "primary" {
		t.Fatalf("expected failback to primary on 3/3 probes, got %s", got)
	}
}

func TestFallbackBootCollisionCanceledInterfaceUpdateStillCompletesBootProbe(t *testing.T) {
	_, probeURL, probeAddr := startProbeServer(t)
	primary := newMockFallbackOutbound("primary", probeAddr)
	backup := newMockFallbackOutbound("backup", probeAddr)

	ifProbeEntered := make(chan struct{})
	var slowFirst atomic.Bool
	slowPrimary := &blockingProbeOutbound{
		mockFallbackOutbound: primary,
		onProbe: func(ctx context.Context) error {
			if slowFirst.CompareAndSwap(false, true) {
				close(ifProbeEntered)
				<-ctx.Done()
				return ctx.Err()
			}
			return nil
		},
	}
	primary.setProbe(3*time.Millisecond, true)
	backup.setProbe(3*time.Millisecond, false)

	fb, _ := newTestFallback(t, option.FallbackOutboundOptions{
		Outbounds: []string{"primary", "backup"},
		URL:       probeURL,
	}, slowPrimary, backup)

	ifCtx, ifCancel := context.WithCancel(context.Background())
	fb.InterfaceUpdated(ifCtx)
	<-ifProbeEntered

	// PostStart collides with in-flight InterfaceUpdated, then InterfaceUpdated's ctx is canceled!
	fb.group.PostStart()
	ifCancel()

	waitUntil(t, 2*time.Second, "coalesced PostStart probe demotes dead primary to backup", func() bool {
		return fb.Selected(N.NetworkTCP).Tag() == "backup"
	})
}

func TestFallbackConcurrentManualURLTestWaitsForFreshResults(t *testing.T) {
	_, probeURL, probeAddr := startProbeServer(t)
	primary := newMockFallbackOutbound("primary", probeAddr)
	backup := newMockFallbackOutbound("backup", probeAddr)
	primary.setProbe(40*time.Millisecond, false)
	backup.setProbe(40*time.Millisecond, false)

	fb, _ := newTestFallback(t, option.FallbackOutboundOptions{
		Outbounds: []string{"primary", "backup"},
		URL:       probeURL,
	}, primary, backup)

	go fb.group.CheckOutbounds(context.Background(), false)
	time.Sleep(10 * time.Millisecond)

	delays, err := fb.URLTest(context.Background())
	if err != nil {
		t.Fatalf("URLTest error: %v", err)
	}
	if len(delays) != 2 {
		t.Fatalf("expected non-empty fresh delays from concurrent URLTest, got %v", delays)
	}
}

func TestFallbackDegradedKeepsProbingPastIdleTimeoutAndFailsBackUnattended(t *testing.T) {
	_, probeURL, probeAddr := startProbeServer(t)
	primary := newMockFallbackOutbound("primary", probeAddr)
	backup := newMockFallbackOutbound("backup", probeAddr)
	primary.setProbe(2*time.Millisecond, true)
	backup.setProbe(2*time.Millisecond, false)

	fb, _ := newTestFallback(t, option.FallbackOutboundOptions{
		Outbounds:    []string{"primary", "backup"},
		URL:          probeURL,
		Interval:     badoption.Duration(40 * time.Millisecond),
		IdleTimeout:  badoption.Duration(40 * time.Millisecond), // interval == idle_timeout boundary!
		RecoverTimes: 2,
	}, primary, backup)

	fb.group.PostStart()
	waitUntil(t, 2*time.Second, "boot probe demotes primary to backup", func() bool {
		return fb.Selected(N.NetworkTCP).Tag() == "backup"
	})

	// Wait longer than idle_timeout with ZERO client traffic, then restore primary.
	// Unattended Linux server MUST keep loopCheck alive while degraded and fail back to primary!
	time.Sleep(100 * time.Millisecond)
	primary.setProbe(2*time.Millisecond, false)

	waitUntil(t, 2*time.Second, "unattended failback to primary past idle_timeout", func() bool {
		return fb.Selected(N.NetworkTCP).Tag() == "primary"
	})
}

func TestFallbackPinnedTCPOnlyDoesNotLeakUDPAndInternalConnInterrupts(t *testing.T) {
	_, probeURL, probeAddr := startProbeServer(t)
	tcpOnly := newMockFallbackOutbound("tcp-only", probeAddr, N.NetworkTCP)
	dualBackup := newMockFallbackOutbound("dual-backup", probeAddr, N.NetworkTCP, N.NetworkUDP)
	tcpOnly.setProbe(2*time.Millisecond, false)
	dualBackup.setProbe(2*time.Millisecond, false)

	interruptFalse := false
	fb, _ := newTestFallback(t, option.FallbackOutboundOptions{
		Outbounds:                 []string{"dual-backup", "tcp-only"},
		URL:                       probeURL,
		InterruptExistConnections: &interruptFalse,
	}, dualBackup, tcpOnly)

	// Open an internal connection (isExternal=false) on dual-backup.
	internalConn, err := fb.DialContext(context.Background(), N.NetworkTCP, M.ParseSocksaddr("example.com:443"))
	if err != nil {
		t.Fatalf("DialContext internal failed: %v", err)
	}
	defer internalConn.Close()
	underlyingInternal := dualBackup.openedConns[0]

	// Pin to tcp-only:
	// 1. Internal connection MUST still be interrupted even when interrupt_exist_connections=false.
	// 2. Selected("udp") and ListenPacket MUST return nil / error instead of leaking UDP onto dual-backup!
	if !fb.SelectOutbound("tcp-only") {
		t.Fatalf("SelectOutbound(tcp-only) failed")
	}
	if !underlyingInternal.IsClosed() {
		t.Fatalf("expected internal connection to be interrupted even when interrupt_exist_connections=false")
	}
	if gotUDP := fb.Selected(N.NetworkUDP); gotUDP != nil {
		t.Fatalf("expected Selected(udp) == nil when pinned to TCP-only outbound, got %v", gotUDP.Tag())
	}
	if _, err := fb.ListenPacket(interrupt.ContextWithIsExternalConnection(context.Background(), true), M.ParseSocksaddr("8.8.8.8:53")); err == nil {
		t.Fatalf("expected ListenPacket to fail instead of leaking UDP when pinned to TCP-only outbound")
	}

	// Unstarted Fallback nil-group guards must never panic.
	unstarted := &Fallback{tags: []string{"a"}}
	if _, err := unstarted.DialContext(context.Background(), N.NetworkTCP, M.ParseSocksaddr("1.1.1.1:80")); err == nil {
		t.Fatalf("expected error on unstarted Fallback.DialContext")
	}
	if _, err := unstarted.ListenPacket(context.Background(), M.ParseSocksaddr("1.1.1.1:53")); err == nil {
		t.Fatalf("expected error on unstarted Fallback.ListenPacket")
	}
}

type aetherStyleLazyOutbound struct {
	*mockFallbackOutbound
	rejectOnRead atomic.Bool
}

type aetherStyleLazyConn struct {
	net.Conn
	peer         net.Conn
	rejectOnRead bool
	written      atomic.Bool
	readDone     atomic.Bool
}

func (c *aetherStyleLazyConn) NeedHandshakeForWrite() bool {
	return !c.written.Load()
}

func (c *aetherStyleLazyConn) NeedHandshakeForRead() bool {
	return !c.readDone.Load()
}

func (c *aetherStyleLazyConn) Write(p []byte) (int, error) {
	c.written.Store(true)
	return len(p), nil // simulates kernel TCP send-buffer acceptance before remote auth!
}

func (c *aetherStyleLazyConn) Read(p []byte) (int, error) {
	if c.rejectOnRead {
		return 0, errors.New("unexpected EOF reading 84B ServerResponsePrefix")
	}
	c.readDone.Store(true)
	if len(p) == 0 {
		return 0, nil
	}
	p[0] = 'K'
	return 1, nil
}

func (m *aetherStyleLazyOutbound) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	if destination.String() == m.probeAddr {
		return m.mockFallbackOutbound.DialContext(ctx, network, destination)
	}
	c1, c2 := net.Pipe()
	return &aetherStyleLazyConn{Conn: c1, peer: c2, rejectOnRead: m.rejectOnRead.Load()}, nil
}

func TestFallbackLazyHandshakeWriteBufferDoesNotPrematurelyResetAndReadFailureDemotes(t *testing.T) {
	_, probeURL, probeAddr := startProbeServer(t)
	primary := &aetherStyleLazyOutbound{mockFallbackOutbound: newMockFallbackOutbound("aether-primary", probeAddr)}
	backup := newMockFallbackOutbound("aether-backup", probeAddr)
	primary.rejectOnRead.Store(true)
	primary.setProbe(3*time.Millisecond, true)
	backup.setProbe(3*time.Millisecond, false)

	fb, _ := newTestFallback(t, option.FallbackOutboundOptions{
		Outbounds: []string{"aether-primary", "aether-backup"},
		URL:       probeURL,
		FailTimes: 2,
	}, primary, backup)

	fb.group.stateByTag["aether-primary"].consecutiveDialFail.Store(1)

	conn, err := fb.DialContext(context.Background(), N.NetworkTCP, M.ParseSocksaddr("example.com:443"))
	if err != nil {
		t.Fatalf("DialContext failed: %v", err)
	}
	defer conn.Close()

	// Writing initial burst into TCP send buffer MUST NOT prematurely reset consecutiveDialFail to 0!
	if _, err := conn.Write([]byte("initial-burst")); err != nil {
		t.Fatalf("Write failed: %v", err)
	}
	if got := fb.group.stateByTag["aether-primary"].consecutiveDialFail.Load(); got != 1 {
		t.Fatalf("expected consecutiveDialFail still 1 before ServerResponsePrefix read, got %d", got)
	}

	// Reading rejected ServerResponsePrefix MUST trigger OnHandshakeFailure -> fail_times=2 -> verifyAndFailover demotion!
	if _, err := conn.Read(make([]byte, 16)); err == nil {
		t.Fatalf("expected Read error on rejected ServerResponsePrefix")
	}
	waitUntil(t, 2*time.Second, "lazy read handshake rejection demotes primary", func() bool {
		return fb.Selected(N.NetworkTCP).Tag() == "aether-backup"
	})
}

func TestFallbackMidBatchPerformUpdateCheckDoesNotDoubleCountRecoveryStreak(t *testing.T) {
	_, probeURL, probeAddr := startProbeServer(t)
	primary := newMockFallbackOutbound("primary", probeAddr)
	slowThird := newMockFallbackOutbound("slow-third", probeAddr)
	backup := newMockFallbackOutbound("backup", probeAddr)

	primary.setProbe(2*time.Millisecond, true)
	backup.setProbe(2*time.Millisecond, false)

	slowEntered := make(chan struct{})
	releaseSlow := make(chan struct{})
	var once sync.Once
	blockingThird := &blockingProbeOutbound{
		mockFallbackOutbound: slowThird,
		onProbe: func(ctx context.Context) error {
			var wait bool
			once.Do(func() {
				wait = true
			})
			if wait {
				close(slowEntered)
				select {
				case <-releaseSlow:
				case <-ctx.Done():
				}
			}
			return errors.New("slow-third down")
		},
	}

	fb, history := newTestFallback(t, option.FallbackOutboundOptions{
		Outbounds:    []string{"primary", "backup", "slow-third"},
		URL:          probeURL,
		RecoverTimes: 2,
	}, primary, backup, blockingThird)

	// Initial probe marks primary unhealthy and selects backup; release once isn't triggered yet if we arm after initial!
	// Wait: blockingThird once.Do fired on initial URLTest — create dedicated second gate for recovery batch!
	close(releaseSlow)
	_, _ = fb.URLTest(context.Background())
	if got := fb.Selected(N.NetworkTCP).Tag(); got != "backup" {
		t.Fatalf("expected backup after initial probe, got %s", got)
	}

	slowEntered2 := make(chan struct{})
	releaseSlow2 := make(chan struct{})
	blockingThird.onProbe = func(ctx context.Context) error {
		close(slowEntered2)
		select {
		case <-releaseSlow2:
		case <-ctx.Done():
		}
		return errors.New("slow-third down")
	}

	// Primary comes back online; start 1st periodic recovery batch (recover_times=2).
	primary.setProbe(2*time.Millisecond, false)
	batchDone := make(chan struct{})
	go func() {
		defer close(batchDone)
		fb.group.CheckOutbounds(context.Background(), false)
	}()

	<-slowEntered2
	waitUntil(t, 1*time.Second, "primary history written mid-batch", func() bool {
		return history.LoadURLTestHistory("primary") != nil
	})

	// Simulate Clash dashboard calling PerformUpdateCheck() while batch is still waiting on slow-third!
	fb.PerformUpdateCheck()

	close(releaseSlow2)
	<-batchDone

	// Single probe MUST NOT be double-counted as 2/2!
	if got := fb.Selected(N.NetworkTCP).Tag(); got != "backup" {
		t.Fatalf("mid-batch PerformUpdateCheck double-counted recovery streak: got %s, want backup", got)
	}
}

func TestFallbackCyclicGroupDialReturnsErrorWithoutStackOverflow(t *testing.T) {
	_, probeURL, probeAddr := startProbeServer(t)
	backup := newMockFallbackOutbound("backup", probeAddr)
	ctx := context.Background()
	history := urltest.NewHistoryStorage()
	defer history.Close()
	mgr := newMockOutboundManager(backup)
	ctx = service.ContextWithPtr(ctx, history)
	ctx = service.ContextWith[adapter.OutboundManager](ctx, mgr)

	fbAOut, err := NewFallback(ctx, nil, log.NewNOPFactory().Logger(), "fb-a", option.FallbackOutboundOptions{
		Outbounds: []string{"fb-b", "backup"},
		URL:       probeURL,
	})
	if err != nil {
		t.Fatalf("NewFallback fb-a: %v", err)
	}
	fbBOut, err := NewFallback(ctx, nil, log.NewNOPFactory().Logger(), "fb-b", option.FallbackOutboundOptions{
		Outbounds: []string{"fb-a"},
		URL:       probeURL,
	})
	if err != nil {
		t.Fatalf("NewFallback fb-b: %v", err)
	}
	fbA := fbAOut.(*Fallback)
	fbB := fbBOut.(*Fallback)
	mgr.mu.Lock()
	mgr.outbounds["fb-a"] = fbA
	mgr.outbounds["fb-b"] = fbB
	mgr.order = append(mgr.order, fbA, fbB)
	mgr.mu.Unlock()

	if err := fbA.Start(adapter.StartStateStart, nil); err != nil {
		t.Fatalf("fbA.Start: %v", err)
	}
	defer fbA.group.Close()
	if err := fbB.Start(adapter.StartStateStart, nil); err != nil {
		t.Fatalf("fbB.Start: %v", err)
	}
	defer fbB.group.Close()

	// Dialing cyclic fb-a -> fb-b -> fb-a must break cycle cleanly and rescue onto backup!
	c, err := fbA.DialContext(context.Background(), N.NetworkTCP, M.ParseSocksaddr("example.com:443"))
	if err != nil {
		t.Fatalf("expected cyclic fb-a->fb-b to rescue cleanly onto backup, got %v", err)
	}
	_ = c.Close()
}
