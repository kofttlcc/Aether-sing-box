package group

import (
	"context"
	"errors"
	"io"
	"maps"
	"net"
	"net/netip"
	"os"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/outbound"
	"github.com/sagernet/sing-box/common/dialer"
	"github.com/sagernet/sing-box/common/interrupt"
	"github.com/sagernet/sing-box/common/urltest"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/batch"
	"github.com/sagernet/sing/common/buf"
	"github.com/sagernet/sing/common/bufio"
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/common/x/list"
	"github.com/sagernet/sing/service"
	"github.com/sagernet/sing/service/pause"
)

const (
	defaultFallbackFailTimes    uint8 = 2
	defaultFallbackRecoverTimes uint8 = 2
	defaultFallbackProbeTimeout       = 5 * time.Second
	fallbackVerifyTimeout             = 3 * time.Second
	fallbackMaxRescueAttempts         = 2
)

func RegisterFallback(registry *outbound.Registry) {
	outbound.Register[option.FallbackOutboundOptions](registry, C.TypeFallback, NewFallback)
}

var (
	_ adapter.OutboundGroup              = (*Fallback)(nil)
	_ adapter.DialerOutboundGroup        = (*Fallback)(nil)
	_ adapter.URLTestGroup               = (*Fallback)(nil)
	_ adapter.InterfaceUpdateListener    = (*Fallback)(nil)
	_ adapter.Referrer                   = (*Fallback)(nil)
	_ N.Dialer                           = (*Fallback)(nil)
	_ N.ParallelDialer                   = (*Fallback)(nil)
	_ dialer.ParallelNetworkDialer       = (*Fallback)(nil)
	_ dialer.PacketDialerWithDestination = (*Fallback)(nil)
)

type Fallback struct {
	outbound.Adapter
	ctx                          context.Context
	outbound                     adapter.OutboundManager
	logger                       log.ContextLogger
	tags                         []string
	link                         string
	interval                     time.Duration
	idleTimeout                  time.Duration
	maxDelay                     uint16
	failTimes                    uint8
	recoverTimes                 uint8
	interruptExternalConnections bool
	group                        *FallbackGroup
	checkAccess                  sync.Mutex
}

func NewFallback(ctx context.Context, router adapter.Router, logger log.ContextLogger, tag string, options option.FallbackOutboundOptions) (adapter.Outbound, error) {
	interruptExternal := true
	if options.InterruptExistConnections != nil {
		interruptExternal = *options.InterruptExistConnections
	}
	fb := &Fallback{
		Adapter:                      outbound.NewAdapter(C.TypeFallback, tag, []string{N.NetworkTCP, N.NetworkUDP}, options.Outbounds),
		ctx:                          ctx,
		outbound:                     service.FromContext[adapter.OutboundManager](ctx),
		logger:                       logger,
		tags:                         options.Outbounds,
		link:                         options.URL,
		interval:                     time.Duration(options.Interval),
		idleTimeout:                  time.Duration(options.IdleTimeout),
		maxDelay:                     options.MaxDelay,
		failTimes:                    options.FailTimes,
		recoverTimes:                 options.RecoverTimes,
		interruptExternalConnections: interruptExternal,
	}
	if len(fb.tags) == 0 {
		return nil, E.New("missing tags")
	}
	for i, memberTag := range fb.tags {
		if slices.Contains(fb.tags[:i], memberTag) {
			return nil, E.New("duplicate tag: ", memberTag)
		}
	}
	return fb, nil
}

func (s *Fallback) Start(stage adapter.StartStage, scope *adapter.Scope) error {
	switch stage {
	case adapter.StartStateStart:
		outbounds := make([]adapter.Outbound, 0, len(s.tags))
		for i, tag := range s.tags {
			detour, loaded := s.outbound.Outbound(tag)
			if !loaded {
				return E.New("outbound ", i, " not found: ", tag)
			}
			outbounds = append(outbounds, detour)
		}
		group, err := NewFallbackGroup(
			s.ctx,
			s.outbound,
			s.logger,
			outbounds,
			s.link,
			s.interval,
			s.idleTimeout,
			s.maxDelay,
			s.failTimes,
			s.recoverTimes,
			s.interruptExternalConnections,
		)
		if err != nil {
			return err
		}
		s.group = group
	case adapter.StartStateStarted:
		s.group.PostStart()
		scope.Add(s.group.Close)
	}
	return nil
}

func (s *Fallback) DialByGroup() bool {
	return true
}

func (s *Fallback) All() []string {
	return s.tags
}

func (s *Fallback) Selected(network string) adapter.Outbound {
	if s.group == nil {
		return nil
	}
	return s.group.selectedOrSelect(network)
}

func (s *Fallback) AttachConnection(closer io.Closer) func() {
	if s.group == nil {
		return func() {}
	}
	s.group.Touch()
	return s.group.interruptGroup.Add(closer, true)
}

func (s *Fallback) References() []string {
	group := s.group
	if group == nil {
		return nil
	}
	group.updateAccess.Lock()
	selectedTCP := group.selectedOutboundTCP
	selectedUDP := group.selectedOutboundUDP
	group.updateAccess.Unlock()
	var references []string
	if selectedTCP != nil {
		references = append(references, selectedTCP.Tag())
	}
	if selectedUDP != nil && selectedUDP != selectedTCP {
		references = append(references, selectedUDP.Tag())
	}
	return references
}

func (s *Fallback) SelectOutbound(tag string) bool {
	if s.group == nil {
		return false
	}
	return s.group.SelectOutbound(tag)
}

func (s *Fallback) IsPinned() bool {
	if s.group == nil {
		return false
	}
	return s.group.IsPinned()
}

func (s *Fallback) PinnedTag() string {
	if s.group == nil {
		return ""
	}
	return s.group.PinnedTag()
}

func (s *Fallback) URLTest(ctx context.Context) (map[string]uint16, error) {
	if s.group == nil {
		return make(map[string]uint16), nil
	}
	return s.group.URLTest(ctx)
}

func (s *Fallback) CheckOutbounds() {
	if s.group == nil {
		return
	}
	s.group.CheckOutbounds(s.group.closeCtx, true)
}

func (s *Fallback) PerformUpdateCheck() {
	if s.group == nil {
		return
	}
	s.group.performUpdateCheck()
}

func (s *Fallback) InterfaceUpdated(ctx context.Context) {
	group := s.group
	if group == nil {
		return
	}
	if group.pause != nil && (group.pause.IsDevicePaused() || group.pause.IsNetworkPaused()) {
		return
	}
	go func() {
		s.checkAccess.Lock()
		defer s.checkAccess.Unlock()
		if ctx.Err() != nil {
			group.scheduleRetryIfInitialIncomplete()
			return
		}
		group.CheckOutbounds(ctx, false)
	}()
}

type fallbackDialActiveKey struct{}

func unwrapGroupCandidate(candidate adapter.Outbound, network string) (adapter.Outbound, []adapter.Outbound) {
	var intermediates []adapter.Outbound
	visited := map[string]bool{candidate.Tag(): true}
	cur := candidate
	for range 16 {
		if dialerGroup, ok := cur.(adapter.DialerOutboundGroup); ok && dialerGroup.DialByGroup() {
			break
		}
		outGroup, ok := cur.(adapter.OutboundGroup)
		if !ok {
			break
		}
		next := outGroup.Selected(network)
		if next == nil || visited[next.Tag()] {
			break
		}
		visited[next.Tag()] = true
		intermediates = append(intermediates, cur)
		cur = next
	}
	return cur, intermediates
}

func wrapIntermediateConn(conn net.Conn, intermediates []adapter.Outbound, isExternal bool) net.Conn {
	for i := len(intermediates) - 1; i >= 0; i-- {
		switch g := intermediates[i].(type) {
		case *Selector:
			conn = g.interruptGroup.NewConn(conn, isExternal)
		case *URLTest:
			if g.group != nil {
				g.group.Touch()
				conn = g.group.interruptGroup.NewConn(conn, isExternal)
			}
		}
	}
	return conn
}

func wrapIntermediatePacketConn(conn net.PacketConn, intermediates []adapter.Outbound, isExternal bool) net.PacketConn {
	for i := len(intermediates) - 1; i >= 0; i-- {
		switch g := intermediates[i].(type) {
		case *Selector:
			conn = g.interruptGroup.NewPacketConn(conn, isExternal)
		case *URLTest:
			if g.group != nil {
				g.group.Touch()
				conn = g.group.interruptGroup.NewPacketConn(conn, isExternal)
			}
		}
	}
	return conn
}

func (s *Fallback) wrapDialedConn(conn net.Conn, target adapter.Outbound, intermediates []adapter.Outbound, pinned bool, isExternal bool) net.Conn {
	if !N.NeedHandshakeForWrite(conn) && !N.NeedHandshakeForRead(conn) {
		s.group.onDialSuccess(target.Tag())
		conn = wrapIntermediateConn(conn, intermediates, isExternal)
		return s.group.wrapMemberConn(conn, target.Tag(), isExternal)
	}
	var tracked net.Conn = newFallbackTrackedConn(conn, s.group, target, pinned)
	tracked = wrapIntermediateConn(tracked, intermediates, isExternal)
	return s.group.wrapMemberConn(tracked, target.Tag(), isExternal)
}

func (s *Fallback) dialWithRescue(ctx context.Context, network string, dialFn func(dialCtx context.Context, candidate adapter.Outbound) (net.Conn, error)) (net.Conn, error) {
	if s.group == nil {
		return nil, E.New("fallback group not started")
	}
	activeDials, _ := ctx.Value(fallbackDialActiveKey{}).(map[*Fallback]bool)
	if activeDials[s] {
		return nil, E.New("routing loop in fallback group: ", s.Tag())
	}
	nextActive := make(map[*Fallback]bool, len(activeDials)+1)
	maps.Copy(nextActive, activeDials)
	nextActive[s] = true
	ctx = context.WithValue(ctx, fallbackDialActiveKey{}, nextActive)

	s.group.Touch()
	netName := N.NetworkName(network)
	if netName != N.NetworkTCP && netName != N.NetworkUDP {
		return nil, E.Extend(N.ErrUnknownNetwork, network)
	}
	primary := s.group.selectedOrSelect(netName)
	if primary == nil {
		return nil, E.New("missing supported outbound")
	}
	isExternal := interrupt.IsExternalConnectionFromContext(ctx)
	pinned := s.group.IsPinned()

	primaryLeaf, primaryIntermediates := unwrapGroupCandidate(primary, netName)
	conn, err := dialFn(ctx, primaryLeaf)
	if err == nil {
		return s.wrapDialedConn(conn, primary, primaryIntermediates, pinned, isExternal), nil
	}
	s.logger.ErrorContext(ctx, err)
	if pinned || ctx.Err() != nil {
		return nil, err
	}

	s.group.onDialFailure(primary)
	candidates := s.group.rescueCandidates(netName, primary.Tag(), fallbackMaxRescueAttempts)
	for _, candidate := range candidates {
		if ctx.Err() != nil {
			break
		}
		rescueLeaf, rescueIntermediates := unwrapGroupCandidate(candidate, netName)
		rescueConn, rescueErr := dialFn(ctx, rescueLeaf)
		if rescueErr == nil {
			return s.wrapDialedConn(rescueConn, candidate, rescueIntermediates, false, isExternal), nil
		}
		s.logger.ErrorContext(ctx, rescueErr)
		if ctx.Err() == nil {
			s.group.onDialFailure(candidate)
		}
	}
	return nil, err
}

func (s *Fallback) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	return s.dialWithRescue(ctx, network, func(dialCtx context.Context, candidate adapter.Outbound) (net.Conn, error) {
		return candidate.DialContext(dialCtx, network, destination)
	})
}

func (s *Fallback) DialParallel(ctx context.Context, network string, destination M.Socksaddr, destinationAddresses []netip.Addr) (net.Conn, error) {
	return s.dialWithRescue(ctx, network, func(dialCtx context.Context, candidate adapter.Outbound) (net.Conn, error) {
		return N.DialSerial(dialCtx, candidate, network, destination, destinationAddresses)
	})
}

func (s *Fallback) DialParallelNetwork(ctx context.Context, network string, destination M.Socksaddr, destinationAddresses []netip.Addr, strategy *C.NetworkStrategy, interfaceType []C.InterfaceType, fallbackInterfaceType []C.InterfaceType, fallbackDelay time.Duration) (net.Conn, error) {
	return s.dialWithRescue(ctx, network, func(dialCtx context.Context, candidate adapter.Outbound) (net.Conn, error) {
		return dialer.DialSerialNetwork(dialCtx, candidate, network, destination, destinationAddresses, strategy, interfaceType, fallbackInterfaceType, fallbackDelay)
	})
}

func (s *Fallback) listenPacketWithRescue(ctx context.Context, listenFn func(listenCtx context.Context, candidate adapter.Outbound) (net.PacketConn, netip.Addr, error)) (net.PacketConn, netip.Addr, error) {
	if s.group == nil {
		return nil, netip.Addr{}, E.New("fallback group not started")
	}
	activeDials, _ := ctx.Value(fallbackDialActiveKey{}).(map[*Fallback]bool)
	if activeDials[s] {
		return nil, netip.Addr{}, E.New("routing loop in fallback group: ", s.Tag())
	}
	nextActive := make(map[*Fallback]bool, len(activeDials)+1)
	maps.Copy(nextActive, activeDials)
	nextActive[s] = true
	ctx = context.WithValue(ctx, fallbackDialActiveKey{}, nextActive)

	s.group.Touch()
	primary := s.group.selectedOrSelect(N.NetworkUDP)
	if primary == nil {
		return nil, netip.Addr{}, E.New("missing supported outbound")
	}
	isExternal := interrupt.IsExternalConnectionFromContext(ctx)
	pinned := s.group.IsPinned()

	primaryLeaf, primaryIntermediates := unwrapGroupCandidate(primary, N.NetworkUDP)
	conn, addr, err := listenFn(ctx, primaryLeaf)
	if err == nil {
		s.group.onDialSuccess(primary.Tag())
		conn = wrapIntermediatePacketConn(conn, primaryIntermediates, isExternal)
		return s.group.wrapMemberPacketConn(conn, primary.Tag(), isExternal), addr, nil
	}
	s.logger.ErrorContext(ctx, err)
	if pinned || ctx.Err() != nil {
		return nil, netip.Addr{}, err
	}

	s.group.onDialFailure(primary)
	candidates := s.group.rescueCandidates(N.NetworkUDP, primary.Tag(), fallbackMaxRescueAttempts)
	for _, candidate := range candidates {
		if ctx.Err() != nil {
			break
		}
		rescueLeaf, rescueIntermediates := unwrapGroupCandidate(candidate, N.NetworkUDP)
		rescueConn, rescueAddr, rescueErr := listenFn(ctx, rescueLeaf)
		if rescueErr == nil {
			s.group.onDialSuccess(candidate.Tag())
			rescueConn = wrapIntermediatePacketConn(rescueConn, rescueIntermediates, isExternal)
			return s.group.wrapMemberPacketConn(rescueConn, candidate.Tag(), isExternal), rescueAddr, nil
		}
		s.logger.ErrorContext(ctx, rescueErr)
		if ctx.Err() == nil {
			s.group.onDialFailure(candidate)
		}
	}
	return nil, netip.Addr{}, err
}

func (s *Fallback) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	conn, _, err := s.listenPacketWithRescue(ctx, func(listenCtx context.Context, candidate adapter.Outbound) (net.PacketConn, netip.Addr, error) {
		pc, listenErr := candidate.ListenPacket(listenCtx, destination)
		return pc, netip.Addr{}, listenErr
	})
	return conn, err
}

func (s *Fallback) ListenPacketWithDestination(ctx context.Context, destination M.Socksaddr) (net.PacketConn, netip.Addr, error) {
	return s.listenPacketWithRescue(ctx, func(listenCtx context.Context, candidate adapter.Outbound) (net.PacketConn, netip.Addr, error) {
		if packetDialer, ok := candidate.(dialer.PacketDialerWithDestination); ok {
			return packetDialer.ListenPacketWithDestination(listenCtx, destination)
		}
		pc, listenErr := candidate.ListenPacket(listenCtx, destination)
		return pc, netip.Addr{}, listenErr
	})
}

func (s *Fallback) ListenSerialNetworkPacket(ctx context.Context, destination M.Socksaddr, destinationAddresses []netip.Addr, strategy *C.NetworkStrategy, interfaceType []C.InterfaceType, fallbackInterfaceType []C.InterfaceType, fallbackDelay time.Duration) (net.PacketConn, netip.Addr, error) {
	return s.listenPacketWithRescue(ctx, func(listenCtx context.Context, candidate adapter.Outbound) (net.PacketConn, netip.Addr, error) {
		return dialer.ListenSerialNetworkPacket(listenCtx, candidate, destination, destinationAddresses, strategy, interfaceType, fallbackInterfaceType, fallbackDelay)
	})
}

type fallbackTrackedConn struct {
	N.ExtendedConn
	rawConn net.Conn
	group   *FallbackGroup
	target  adapter.Outbound
	pinned  bool
	closed  atomic.Bool
	settled atomic.Bool
}

var (
	_ N.ExtendedConn                  = (*fallbackTrackedConn)(nil)
	_ N.EarlyWriter                   = (*fallbackTrackedConn)(nil)
	_ N.EarlyReader                   = (*fallbackTrackedConn)(nil)
	_ adapter.HandshakeResultObserver = (*fallbackTrackedConn)(nil)
)

func newFallbackTrackedConn(conn net.Conn, group *FallbackGroup, target adapter.Outbound, pinned bool) *fallbackTrackedConn {
	return &fallbackTrackedConn{
		ExtendedConn: bufio.NewExtendedConn(conn),
		rawConn:      conn,
		group:        group,
		target:       target,
		pinned:       pinned,
	}
}

func (c *fallbackTrackedConn) Read(p []byte) (int, error) {
	n, err := c.ExtendedConn.Read(p)
	c.observeReadResult(n, err)
	return n, err
}

func (c *fallbackTrackedConn) ReadBuffer(buffer *buf.Buffer) error {
	beforeLen := buffer.Len()
	err := c.ExtendedConn.ReadBuffer(buffer)
	c.observeReadResult(buffer.Len()-beforeLen, err)
	return err
}

func (c *fallbackTrackedConn) Write(p []byte) (int, error) {
	n, err := c.ExtendedConn.Write(p)
	c.observeWriteResult(len(p) == 0, err)
	return n, err
}

func (c *fallbackTrackedConn) WriteBuffer(buffer *buf.Buffer) error {
	wasEmpty := buffer.IsEmpty()
	err := c.ExtendedConn.WriteBuffer(buffer)
	c.observeWriteResult(wasEmpty, err)
	return err
}

func (c *fallbackTrackedConn) observeReadResult(n int, err error) {
	if c.settled.Load() {
		return
	}
	if n > 0 {
		c.OnHandshakeSuccess()
		return
	}
	if err != nil && !errors.Is(err, io.EOF) && !E.IsClosedOrCanceled(err) && !E.IsTimeout(err) {
		c.OnHandshakeFailure(err)
	}
}

func (c *fallbackTrackedConn) observeWriteResult(emptyProbe bool, err error) {
	if err == nil || c.settled.Load() {
		return
	}
	if emptyProbe && (E.IsMulti(err, os.ErrInvalid, os.ErrDeadlineExceeded, context.DeadlineExceeded) || E.IsTimeout(err)) {
		return
	}
	if !E.IsClosedOrCanceled(err) {
		c.OnHandshakeFailure(err)
	}
}

func (c *fallbackTrackedConn) Close() error {
	c.closed.Store(true)
	return c.ExtendedConn.Close()
}

func (c *fallbackTrackedConn) NeedHandshakeForWrite() bool {
	return N.NeedHandshakeForWrite(c.rawConn)
}

func (c *fallbackTrackedConn) NeedHandshakeForRead() bool {
	return N.NeedHandshakeForRead(c.rawConn)
}

func (c *fallbackTrackedConn) FrontHeadroom() int {
	if h, ok := c.rawConn.(interface{ FrontHeadroom() int }); ok {
		return h.FrontHeadroom()
	}
	return 0
}

func (c *fallbackTrackedConn) RearHeadroom() int {
	if h, ok := c.rawConn.(interface{ RearHeadroom() int }); ok {
		return h.RearHeadroom()
	}
	return 0
}

func (c *fallbackTrackedConn) WriterMTU() int {
	if h, ok := c.rawConn.(interface{ WriterMTU() int }); ok {
		return h.WriterMTU()
	}
	return 0
}

func (c *fallbackTrackedConn) ReaderReplaceable() bool {
	return c.settled.Load()
}

func (c *fallbackTrackedConn) WriterReplaceable() bool {
	return c.settled.Load()
}

func (c *fallbackTrackedConn) Upstream() any {
	return c.rawConn
}

func (c *fallbackTrackedConn) OnHandshakeSuccess() {
	if c.closed.Load() || !c.settled.CompareAndSwap(false, true) {
		return
	}
	c.group.onDialSuccess(c.target.Tag())
}

func (c *fallbackTrackedConn) OnHandshakeFailure(err error) {
	if c.closed.Load() || c.pinned || c.group.closeCtx.Err() != nil {
		return
	}
	if !c.settled.CompareAndSwap(false, true) {
		return
	}
	c.group.onDialFailure(c.target)
}

type fallbackMemberState struct {
	tag                 string
	outbound            adapter.Outbound
	healthy             bool
	degraded            bool
	consecutiveSuccess  uint8
	lastDelay           uint16
	lastHistoryTime     time.Time
	demoteGen           uint64
	tcpInterruptGroup   *interrupt.Group
	udpInterruptGroup   *interrupt.Group
	consecutiveDialFail atomic.Uint32
	verifying           atomic.Bool
}

type fallbackProbeOutcome struct {
	probed    bool
	err       error
	delay     uint16
	timestamp time.Time
	startGen  uint64
}

type fallbackActiveGroupsKey struct{}

type FallbackGroup struct {
	ctx                          context.Context
	closeCtx                     context.Context
	closeCancel                  context.CancelFunc
	outbound                     adapter.OutboundManager
	pause                        pause.Manager
	pauseCallback                *list.Element[pause.Callback]
	logger                       log.Logger
	outbounds                    []adapter.Outbound
	states                       []*fallbackMemberState
	stateByTag                   map[string]*fallbackMemberState
	link                         string
	interval                     time.Duration
	idleTimeout                  time.Duration
	maxDelay                     uint16
	failTimes                    uint8
	recoverTimes                 uint8
	history                      *urltest.HistoryStorage
	initialProbeDone             bool
	pinnedTag                    string
	selectedOutboundTCP          adapter.Outbound
	selectedOutboundUDP          adapter.Outbound
	interruptGroup               *interrupt.Group
	interruptExternalConnections bool
	access                       sync.Mutex
	updateAccess                 sync.Mutex
	ticker                       *time.Ticker
	close                        chan struct{}
	closeOnce                    sync.Once
	started                      atomic.Bool
	lastActive                   common.TypedValue[time.Time]

	checkMu              sync.Mutex
	checkRunning         bool
	checkWaitCh          chan struct{}
	pendingRecheck       bool
	pendingForce         bool
	pendingBypassRecover bool
	lastBatchDelays      map[string]uint16
}

func NewFallbackGroup(
	ctx context.Context,
	outboundManager adapter.OutboundManager,
	logger log.Logger,
	outbounds []adapter.Outbound,
	link string,
	interval time.Duration,
	idleTimeout time.Duration,
	maxDelay uint16,
	failTimes uint8,
	recoverTimes uint8,
	interruptExternalConnections bool,
) (*FallbackGroup, error) {
	if interval == 0 {
		interval = C.DefaultURLTestInterval
	}
	if idleTimeout == 0 {
		idleTimeout = C.DefaultURLTestIdleTimeout
	}
	if interval > idleTimeout {
		return nil, E.New("interval must be less or equal than idle_timeout")
	}
	if failTimes == 0 {
		failTimes = defaultFallbackFailTimes
	}
	if recoverTimes == 0 {
		recoverTimes = defaultFallbackRecoverTimes
	}
	history := service.PtrFromContext[urltest.HistoryStorage](ctx)
	if history == nil {
		return nil, E.New("missing URL test history storage")
	}
	closeCtx, closeCancel := context.WithCancel(ctx)
	states := make([]*fallbackMemberState, len(outbounds))
	stateByTag := make(map[string]*fallbackMemberState, len(outbounds))
	for i, detour := range outbounds {
		st := &fallbackMemberState{
			tag:               detour.Tag(),
			outbound:          detour,
			healthy:           true,
			tcpInterruptGroup: interrupt.NewGroup(),
			udpInterruptGroup: interrupt.NewGroup(),
		}
		states[i] = st
		stateByTag[detour.Tag()] = st
	}
	g := &FallbackGroup{
		ctx:                          ctx,
		closeCtx:                     closeCtx,
		closeCancel:                  closeCancel,
		outbound:                     outboundManager,
		pause:                        service.FromContext[pause.Manager](ctx),
		logger:                       logger,
		outbounds:                    outbounds,
		states:                       states,
		stateByTag:                   stateByTag,
		link:                         link,
		interval:                     interval,
		idleTimeout:                  idleTimeout,
		maxDelay:                     maxDelay,
		failTimes:                    failTimes,
		recoverTimes:                 recoverTimes,
		history:                      history,
		interruptGroup:               interrupt.NewGroup(),
		interruptExternalConnections: interruptExternalConnections,
		close:                        make(chan struct{}),
	}
	g.selectedOutboundTCP, _ = g.selectLocked(N.NetworkTCP)
	g.selectedOutboundUDP, _ = g.selectLocked(N.NetworkUDP)
	return g, nil
}

func (g *FallbackGroup) PostStart() {
	g.access.Lock()
	select {
	case <-g.close:
		g.access.Unlock()
		return
	default:
	}
	g.started.Store(true)
	g.lastActive.Store(time.Now())
	g.access.Unlock()
	go func() {
		_, _ = g.urlTest(g.closeCtx, true, true)
	}()
}

func (g *FallbackGroup) Touch() {
	if !g.started.Load() {
		return
	}
	g.access.Lock()
	defer g.access.Unlock()
	select {
	case <-g.close:
		return
	default:
	}
	now := time.Now()
	prevActive := g.lastActive.Load()
	g.lastActive.Store(now)
	if g.ticker != nil {
		return
	}
	wakeImmediate := !prevActive.IsZero() && now.Sub(prevActive) >= g.interval
	ticker := time.NewTicker(g.interval)
	g.ticker = ticker
	if g.pause != nil {
		g.pauseCallback = pause.RegisterTicker(g.pause, ticker, g.interval, nil)
	}
	go g.loopCheck(ticker, g.close, wakeImmediate)
}

func (g *FallbackGroup) ensureDegradedTicker() {
	if !g.started.Load() || !g.shouldKeepProbingWhileIdle() {
		return
	}
	g.access.Lock()
	defer g.access.Unlock()
	select {
	case <-g.close:
		return
	default:
	}
	if g.ticker != nil {
		return
	}
	ticker := time.NewTicker(g.interval)
	g.ticker = ticker
	if g.pause != nil {
		g.pauseCallback = pause.RegisterTicker(g.pause, ticker, g.interval, nil)
	}
	go g.loopCheck(ticker, g.close, false)
}

func (g *FallbackGroup) Close() error {
	g.closeCancel()
	g.access.Lock()
	defer g.access.Unlock()
	g.closeOnce.Do(func() {
		close(g.close)
	})
	if g.ticker != nil {
		g.ticker.Stop()
		g.ticker = nil
	}
	if g.pause != nil && g.pauseCallback != nil {
		g.pause.UnregisterCallback(g.pauseCallback)
		g.pauseCallback = nil
	}
	return nil
}

func (g *FallbackGroup) IsPinned() bool {
	g.updateAccess.Lock()
	pinned := g.pinnedTag != ""
	g.updateAccess.Unlock()
	return pinned
}

func (g *FallbackGroup) PinnedTag() string {
	g.updateAccess.Lock()
	tag := g.pinnedTag
	g.updateAccess.Unlock()
	return tag
}

func (g *FallbackGroup) SelectOutbound(tag string) bool {
	g.updateAccess.Lock()
	if tag == "" {
		g.pinnedTag = ""
	} else {
		if _, ok := g.stateByTag[tag]; !ok {
			g.updateAccess.Unlock()
			return false
		}
		g.pinnedTag = tag
	}
	changed, toInterrupt := g.reselectLocked()
	keepProbing := g.shouldKeepProbingWhileIdleLocked()
	g.updateAccess.Unlock()
	g.notifyAndInterrupt(changed, toInterrupt)
	if keepProbing {
		g.ensureDegradedTicker()
	}
	return true
}

func (g *FallbackGroup) wrapMemberConn(conn net.Conn, tag string, isExternal bool) net.Conn {
	if st, ok := g.stateByTag[tag]; ok {
		return st.tcpInterruptGroup.NewConn(conn, isExternal)
	}
	return g.interruptGroup.NewConn(conn, isExternal)
}

func (g *FallbackGroup) wrapMemberPacketConn(conn net.PacketConn, tag string, isExternal bool) net.PacketConn {
	if st, ok := g.stateByTag[tag]; ok {
		return st.udpInterruptGroup.NewPacketConn(conn, isExternal)
	}
	return g.interruptGroup.NewPacketConn(conn, isExternal)
}

func (g *FallbackGroup) selectedOrSelect(network string) adapter.Outbound {
	g.updateAccess.Lock()
	var selected adapter.Outbound
	if network == N.NetworkUDP {
		selected = g.selectedOutboundUDP
	} else {
		selected = g.selectedOutboundTCP
	}
	if selected == nil && g.pinnedTag == "" {
		selected, _ = g.selectLocked(network)
	}
	g.updateAccess.Unlock()
	return selected
}

func (g *FallbackGroup) Select(network string) (adapter.Outbound, bool) {
	g.updateAccess.Lock()
	defer g.updateAccess.Unlock()
	return g.selectLocked(network)
}

func (g *FallbackGroup) isUsableLocked(state *fallbackMemberState) bool {
	if !state.healthy {
		return false
	}
	if g.maxDelay > 0 && state.lastDelay > g.maxDelay {
		return false
	}
	return true
}

func (g *FallbackGroup) selectLocked(network string) (adapter.Outbound, bool) {
	if g.pinnedTag != "" {
		if state, ok := g.stateByTag[g.pinnedTag]; ok && common.Contains(state.outbound.Network(), network) {
			return state.outbound, true
		}
		return nil, false
	}
	for _, state := range g.states {
		if !common.Contains(state.outbound.Network(), network) {
			continue
		}
		if !g.isUsableLocked(state) {
			continue
		}
		return state.outbound, true
	}
	for _, state := range g.states {
		if !common.Contains(state.outbound.Network(), network) {
			continue
		}
		return state.outbound, false
	}
	return nil, false
}

func (g *FallbackGroup) reselectLocked() (bool, []*interrupt.Group) {
	var changedTCP, changedUDP bool
	nextTCP, _ := g.selectLocked(N.NetworkTCP)
	if nextTCP != g.selectedOutboundTCP {
		if g.selectedOutboundTCP != nil {
			changedTCP = true
		}
		g.selectedOutboundTCP = nextTCP
	}
	nextUDP, _ := g.selectLocked(N.NetworkUDP)
	if nextUDP != g.selectedOutboundUDP {
		if g.selectedOutboundUDP != nil {
			changedUDP = true
		}
		g.selectedOutboundUDP = nextUDP
	}
	if !changedTCP && !changedUDP {
		return false, nil
	}
	toInterrupt := []*interrupt.Group{g.interruptGroup}
	for _, st := range g.states {
		if changedTCP && st.outbound != nextTCP {
			toInterrupt = append(toInterrupt, st.tcpInterruptGroup)
		}
		if changedUDP && st.outbound != nextUDP {
			toInterrupt = append(toInterrupt, st.udpInterruptGroup)
		}
	}
	return true, toInterrupt
}

func (g *FallbackGroup) shouldKeepProbingWhileIdle() bool {
	g.updateAccess.Lock()
	defer g.updateAccess.Unlock()
	return g.shouldKeepProbingWhileIdleLocked()
}

func (g *FallbackGroup) shouldKeepProbingWhileIdleLocked() bool {
	if g.pinnedTag != "" {
		return false
	}
	if !g.initialProbeDone {
		return true
	}
	var primaryTCP, primaryUDP *fallbackMemberState
	for _, state := range g.states {
		if primaryTCP == nil && common.Contains(state.outbound.Network(), N.NetworkTCP) {
			primaryTCP = state
		}
		if primaryUDP == nil && common.Contains(state.outbound.Network(), N.NetworkUDP) {
			primaryUDP = state
		}
		if primaryTCP != nil && primaryUDP != nil {
			break
		}
	}
	if primaryTCP != nil && (!g.isUsableLocked(primaryTCP) || g.selectedOutboundTCP != primaryTCP.outbound) {
		return true
	}
	if primaryUDP != nil && (!g.isUsableLocked(primaryUDP) || g.selectedOutboundUDP != primaryUDP.outbound) {
		return true
	}
	return false
}

func (g *FallbackGroup) notifyAndInterrupt(changed bool, groups []*interrupt.Group) {
	if g.history != nil {
		g.history.NotifyUpdated()
	}
	if changed {
		for _, ig := range groups {
			ig.Interrupt(g.interruptExternalConnections)
		}
	}
}

func (g *FallbackGroup) onDialSuccess(tag string) {
	if state, ok := g.stateByTag[tag]; ok {
		state.consecutiveDialFail.Store(0)
	}
}

func (g *FallbackGroup) onDialFailure(target adapter.Outbound) {
	state, ok := g.stateByTag[target.Tag()]
	if !ok {
		return
	}
	fails := state.consecutiveDialFail.Add(1)
	if fails < uint32(g.failTimes) {
		return
	}
	if !state.verifying.CompareAndSwap(false, true) {
		return
	}
	go g.verifyAndFailover(state)
}

func (g *FallbackGroup) rescueCandidates(network string, failedTag string, maxCount int) []adapter.Outbound {
	g.updateAccess.Lock()
	defer g.updateAccess.Unlock()

	candidates := make([]adapter.Outbound, 0, maxCount)
	seen := make(map[string]bool, maxCount+1)
	seen[failedTag] = true

	failedIndex := -1
	for i, state := range g.states {
		if state.tag == failedTag {
			failedIndex = i
		}
	}

	// Pass 1: healthy backups in strict priority order 0..N-1.
	for _, state := range g.states {
		if len(candidates) >= maxCount {
			return candidates
		}
		if seen[state.tag] || !common.Contains(state.outbound.Network(), network) {
			continue
		}
		if !g.isUsableLocked(state) {
			continue
		}
		candidates = append(candidates, state.outbound)
		seen[state.tag] = true
	}

	// Pass 2: subsequent members after failedIndex, then wrap around, if fewer than maxCount.
	n := len(g.states)
	if n == 0 {
		return candidates
	}
	start := failedIndex + 1
	if start < 0 {
		start = 0
	}
	for offset := 0; offset < n && len(candidates) < maxCount; offset++ {
		state := g.states[(start+offset)%n]
		if seen[state.tag] || !common.Contains(state.outbound.Network(), network) {
			continue
		}
		candidates = append(candidates, state.outbound)
		seen[state.tag] = true
	}
	return candidates
}

func (g *FallbackGroup) verifyAndFailover(state *fallbackMemberState) {
	defer state.verifying.Store(false)
	if g.closeCtx.Err() != nil {
		return
	}
	verifyCtx, cancel := context.WithTimeout(g.closeCtx, fallbackVerifyTimeout)
	defer cancel()

	delay, err := g.probeSingle(verifyCtx, state.outbound)
	if g.closeCtx.Err() != nil {
		return
	}

	now := time.Now()
	realTag := RealTag(state.outbound, N.NetworkTCP)
	if realTag == "" {
		realTag = state.tag
	}
	probeOK := err == nil && (g.maxDelay == 0 || delay <= g.maxDelay)
	if err != nil {
		g.logger.Debug("fallback verify ", state.tag, " unavailable: ", err)
		g.history.DeleteURLTestHistory(realTag)
	} else {
		g.logger.Debug("fallback verify ", state.tag, " available: ", delay, "ms")
		g.history.StoreURLTestHistory(realTag, &adapter.URLTestHistory{
			Time:  now,
			Delay: delay,
		})
	}

	g.updateAccess.Lock()
	state.consecutiveDialFail.Store(0)
	if probeOK {
		state.lastDelay = delay
		state.lastHistoryTime = now
		g.updateAccess.Unlock()
		return
	}
	state.demoteGen++
	if err == nil {
		state.lastDelay = delay
		state.lastHistoryTime = now
	} else {
		state.lastDelay = 0
		state.lastHistoryTime = time.Time{}
	}
	state.healthy = false
	state.degraded = true
	state.consecutiveSuccess = 0
	changed, toInterrupt := g.reselectLocked()
	keepProbing := g.shouldKeepProbingWhileIdleLocked()
	g.updateAccess.Unlock()

	if changed {
		g.notifyAndInterrupt(true, toInterrupt)
	}
	if keepProbing {
		g.ensureDegradedTicker()
	}
}

func (g *FallbackGroup) probeSingle(ctx context.Context, detour adapter.Outbound) (uint16, error) {
	testChan := make(chan urlTestResult, 1)
	go func() {
		delay, testErr := urltest.URLTest(ctx, g.link, detour)
		testChan <- urlTestResult{delay, testErr}
	}()
	select {
	case res := <-testChan:
		return res.delay, res.err
	case <-ctx.Done():
		return 0, ctx.Err()
	}
}

func (g *FallbackGroup) loopCheck(ticker *time.Ticker, closeChan <-chan struct{}, wakeImmediate bool) {
	probedSinceWake := false
	if wakeImmediate {
		_, _ = g.urlTestInternal(g.closeCtx, true, false, false)
		probedSinceWake = true
	}
	for {
		select {
		case <-closeChan:
			return
		case <-ticker.C:
		}
		if probedSinceWake && time.Since(g.lastActive.Load()) >= g.idleTimeout && !g.shouldKeepProbingWhileIdle() {
			g.access.Lock()
			if g.ticker == ticker {
				g.ticker.Stop()
				g.ticker = nil
				if g.pause != nil && g.pauseCallback != nil {
					g.pause.UnregisterCallback(g.pauseCallback)
					g.pauseCallback = nil
				}
			}
			g.access.Unlock()
			return
		}
		_, _ = g.urlTestInternal(g.closeCtx, true, false, false)
		probedSinceWake = true
	}
}

func (g *FallbackGroup) scheduleRetryIfInitialIncomplete() {
	if !g.started.Load() || g.closeCtx.Err() != nil {
		return
	}
	g.updateAccess.Lock()
	done := g.initialProbeDone
	g.updateAccess.Unlock()
	if done {
		return
	}
	go func() {
		_, _ = g.urlTestInternal(g.closeCtx, true, true, false)
	}()
}

func (g *FallbackGroup) CheckOutbounds(ctx context.Context, force bool) {
	_, _ = g.urlTestInternal(ctx, true, force, false)
}

func (g *FallbackGroup) URLTest(ctx context.Context) (map[string]uint16, error) {
	return g.urlTestInternal(ctx, true, true, true)
}

func (g *FallbackGroup) urlTest(ctx context.Context, force bool, bypassRecoverStreak bool) (map[string]uint16, error) {
	return g.urlTestInternal(ctx, force, bypassRecoverStreak, bypassRecoverStreak)
}

func (g *FallbackGroup) urlTestInternal(ctx context.Context, force bool, bypassRecoverStreak bool, waitIfBusy bool) (map[string]uint16, error) {
	if g == nil {
		return make(map[string]uint16), nil
	}
	if ctx == nil {
		ctx = g.closeCtx
	}
	if activeMap, ok := ctx.Value(fallbackActiveGroupsKey{}).(map[*FallbackGroup]bool); ok && activeMap[g] {
		return make(map[string]uint16), nil
	}
	if g.closeCtx.Err() != nil {
		return make(map[string]uint16), g.closeCtx.Err()
	}
	if ctx.Err() != nil {
		g.scheduleRetryIfInitialIncomplete()
		if waitIfBusy {
			return make(map[string]uint16), ctx.Err()
		}
		return make(map[string]uint16), nil
	}

	g.checkMu.Lock()
	if g.checkRunning {
		g.pendingRecheck = true
		if force {
			g.pendingForce = true
		}
		if bypassRecoverStreak {
			g.pendingBypassRecover = true
		}
		waitCh := g.checkWaitCh
		g.checkMu.Unlock()
		if !waitIfBusy || waitCh == nil {
			return make(map[string]uint16), nil
		}
		select {
		case <-waitCh:
			g.checkMu.Lock()
			res := maps.Clone(g.lastBatchDelays)
			g.checkMu.Unlock()
			if res == nil {
				res = make(map[string]uint16)
			}
			return res, nil
		case <-ctx.Done():
			return make(map[string]uint16), ctx.Err()
		case <-g.closeCtx.Done():
			return make(map[string]uint16), g.closeCtx.Err()
		}
	}
	g.checkRunning = true
	g.checkWaitCh = make(chan struct{})
	g.checkMu.Unlock()

	res := g.runCheckLoop(ctx, force, bypassRecoverStreak)
	if waitIfBusy && ctx.Err() != nil {
		return res, ctx.Err()
	}
	return res, nil
}

func (g *FallbackGroup) runCheckLoop(ctx context.Context, force bool, bypassRecoverStreak bool) map[string]uint16 {
	var latest map[string]uint16
	for {
		res, completed := g.executeSingleProbeBatch(ctx, force, bypassRecoverStreak)
		if completed {
			latest = res
		}
		g.checkMu.Lock()
		if completed {
			g.lastBatchDelays = maps.Clone(res)
		}
		g.updateAccess.Lock()
		needInitialRetry := !completed && !g.initialProbeDone && g.closeCtx.Err() == nil
		g.updateAccess.Unlock()
		if needInitialRetry {
			g.pendingRecheck = true
			g.pendingForce = true
			g.pendingBypassRecover = true
		}
		if !g.pendingRecheck || g.closeCtx.Err() != nil {
			g.pendingRecheck = false
			g.pendingForce = false
			g.pendingBypassRecover = false
			g.checkRunning = false
			waitCh := g.checkWaitCh
			g.checkWaitCh = nil
			if latest == nil && g.lastBatchDelays != nil {
				latest = maps.Clone(g.lastBatchDelays)
			}
			g.checkMu.Unlock()
			if waitCh != nil {
				close(waitCh)
			}
			if latest == nil {
				return make(map[string]uint16)
			}
			return latest
		}
		force = g.pendingForce
		bypassRecoverStreak = g.pendingBypassRecover
		g.pendingRecheck = false
		g.pendingForce = false
		g.pendingBypassRecover = false
		if ctx != g.closeCtx && ctx.Err() != nil {
			nextForce := force
			nextBypass := bypassRecoverStreak
			if latest == nil && g.lastBatchDelays != nil {
				latest = maps.Clone(g.lastBatchDelays)
			}
			g.checkMu.Unlock()
			go g.runCheckLoop(g.closeCtx, nextForce, nextBypass)
			if latest == nil {
				return make(map[string]uint16)
			}
			return latest
		}
		ctx = g.closeCtx
		g.checkMu.Unlock()
	}
}

func realGroupTag(detour adapter.Outbound) string {
	if tag := RealTag(detour, N.NetworkTCP); tag != "" {
		return tag
	}
	return RealTag(detour, N.NetworkUDP)
}

func (g *FallbackGroup) executeSingleProbeBatch(ctx context.Context, force bool, bypassRecoverStreak bool) (map[string]uint16, bool) {
	if ctx.Err() != nil || g.closeCtx.Err() != nil {
		return make(map[string]uint16), false
	}
	parentActive, _ := ctx.Value(fallbackActiveGroupsKey{}).(map[*FallbackGroup]bool)
	nextActive := make(map[*FallbackGroup]bool, len(parentActive)+1)
	maps.Copy(nextActive, parentActive)
	nextActive[g] = true

	batchCtx, batchCancel := context.WithCancel(context.WithValue(g.closeCtx, fallbackActiveGroupsKey{}, nextActive))
	var stopCaller func() bool
	if ctx != g.closeCtx {
		stopCaller = context.AfterFunc(ctx, batchCancel)
	}
	defer func() {
		if stopCaller != nil {
			stopCaller()
		}
		batchCancel()
	}()

	outcomes := make([]fallbackProbeOutcome, len(g.states))
	startGens := make([]uint64, len(g.states))
	g.updateAccess.Lock()
	for i, st := range g.states {
		startGens[i] = st.demoteGen
	}
	g.updateAccess.Unlock()

	result := make(map[string]uint16)
	var resultAccess sync.Mutex

	b, _ := batch.New(batchCtx, batch.WithConcurrencyNum[any](10))
	for i, state := range g.states {
		idx := i
		detour := state.outbound
		tag := state.tag
		gen := startGens[i]
		b.Go(tag, func() (any, error) {
			switch nested := detour.(type) {
			case *URLTest:
				if nested.group != nil {
					nestedResult, _ := nested.group.urlTest(batchCtx, force)
					resultAccess.Lock()
					maps.Copy(result, nestedResult)
					resultAccess.Unlock()
				}
				if batchCtx.Err() != nil {
					return nil, nil
				}
				if h := g.history.LoadURLTestHistory(realGroupTag(nested)); h != nil {
					outcomes[idx] = fallbackProbeOutcome{probed: true, delay: h.Delay, timestamp: h.Time, startGen: gen}
					resultAccess.Lock()
					result[tag] = h.Delay
					resultAccess.Unlock()
				} else {
					outcomes[idx] = fallbackProbeOutcome{probed: true, err: E.New("nested urltest unavailable"), startGen: gen}
				}
			case *Fallback:
				if nested.group != nil {
					nestedResult, _ := nested.group.urlTest(batchCtx, force, bypassRecoverStreak)
					resultAccess.Lock()
					maps.Copy(result, nestedResult)
					resultAccess.Unlock()
				}
				if batchCtx.Err() != nil {
					return nil, nil
				}
				if h := g.history.LoadURLTestHistory(realGroupTag(nested)); h != nil {
					outcomes[idx] = fallbackProbeOutcome{probed: true, delay: h.Delay, timestamp: h.Time, startGen: gen}
					resultAccess.Lock()
					result[tag] = h.Delay
					resultAccess.Unlock()
				} else {
					outcomes[idx] = fallbackProbeOutcome{probed: true, err: E.New("nested fallback unavailable"), startGen: gen}
				}
			case adapter.OutboundGroup:
				if g.outbound != nil {
					members := common.FilterNotNil(common.Map(nested.All(), func(it string) adapter.Outbound {
						member, _ := g.outbound.Outbound(it)
						return member
					}))
					nestedResult := URLTestOutbounds(batchCtx, g.outbound, g.history, g.logger, members, g.link, g.interval, force)
					resultAccess.Lock()
					maps.Copy(result, nestedResult)
					resultAccess.Unlock()
				}
				if batchCtx.Err() != nil {
					return nil, nil
				}
				if h := g.history.LoadURLTestHistory(realGroupTag(nested)); h != nil {
					outcomes[idx] = fallbackProbeOutcome{probed: true, delay: h.Delay, timestamp: h.Time, startGen: gen}
					resultAccess.Lock()
					result[tag] = h.Delay
					resultAccess.Unlock()
				} else {
					outcomes[idx] = fallbackProbeOutcome{probed: true, err: E.New("nested group unavailable"), startGen: gen}
				}
			default:
				testCtx, cancel := context.WithTimeout(batchCtx, defaultFallbackProbeTimeout)
				defer cancel()
				delay, testErr := g.probeSingle(testCtx, detour)
				if testErr != nil {
					if batchCtx.Err() != nil {
						return nil, nil
					}
					g.logger.Debug("outbound ", tag, " unavailable: ", testErr)
					g.history.DeleteURLTestHistory(tag)
					outcomes[idx] = fallbackProbeOutcome{probed: true, err: testErr, startGen: gen}
				} else {
					now := time.Now()
					g.logger.Debug("outbound ", tag, " available: ", delay, "ms")
					g.history.StoreURLTestHistory(tag, &adapter.URLTestHistory{
						Time:  now,
						Delay: delay,
					})
					outcomes[idx] = fallbackProbeOutcome{probed: true, delay: delay, timestamp: now, startGen: gen}
					resultAccess.Lock()
					result[tag] = delay
					resultAccess.Unlock()
				}
			}
			return nil, nil
		})
	}
	b.Wait()

	if ctx.Err() != nil || g.closeCtx.Err() != nil {
		return result, false
	}
	g.evaluateProbeResults(outcomes, bypassRecoverStreak)
	return result, true
}

func (g *FallbackGroup) evaluateProbeResults(outcomes []fallbackProbeOutcome, bypassRecoverStreak bool) {
	g.updateAccess.Lock()
	isInitial := !g.initialProbeDone
	var anyHealthyTCPBefore, anyHealthyUDPBefore bool
	for _, st := range g.states {
		if !g.isUsableLocked(st) {
			continue
		}
		if common.Contains(st.outbound.Network(), N.NetworkTCP) {
			anyHealthyTCPBefore = true
		}
		if common.Contains(st.outbound.Network(), N.NetworkUDP) {
			anyHealthyUDPBefore = true
		}
	}
	var promotedTCP, promotedUDP bool

	for i, state := range g.states {
		outcome := outcomes[i]
		if !outcome.probed || outcome.startGen != state.demoteGen {
			continue
		}
		probeOK := outcome.err == nil && (g.maxDelay == 0 || outcome.delay <= g.maxDelay)
		if probeOK {
			alreadyCounted := !outcome.timestamp.IsZero() && outcome.timestamp.Equal(state.lastHistoryTime)
			state.lastDelay = outcome.delay
			state.lastHistoryTime = outcome.timestamp
			state.consecutiveDialFail.Store(0)
			if state.healthy {
				state.degraded = false
				state.consecutiveSuccess = g.recoverTimes
				continue
			}
			supportsTCP := common.Contains(state.outbound.Network(), N.NetworkTCP)
			supportsUDP := common.Contains(state.outbound.Network(), N.NetworkUDP)
			safetyNetImmediate := (!anyHealthyTCPBefore && !promotedTCP && supportsTCP) ||
				(!anyHealthyUDPBefore && !promotedUDP && supportsUDP)
			if bypassRecoverStreak || isInitial || safetyNetImmediate {
				state.healthy = true
				state.degraded = false
				state.consecutiveSuccess = g.recoverTimes
				if supportsTCP {
					promotedTCP = true
				}
				if supportsUDP {
					promotedUDP = true
				}
			} else if !alreadyCounted {
				state.consecutiveSuccess++
				if state.consecutiveSuccess >= g.recoverTimes {
					state.healthy = true
					state.degraded = false
				}
			}
		} else {
			if outcome.err == nil {
				state.lastDelay = outcome.delay
				state.lastHistoryTime = outcome.timestamp
			} else {
				state.lastDelay = 0
				state.lastHistoryTime = time.Time{}
			}
			state.healthy = false
			state.degraded = true
			state.consecutiveSuccess = 0
		}
	}
	g.initialProbeDone = true
	changed, toInterrupt := g.reselectLocked()
	keepProbing := g.shouldKeepProbingWhileIdleLocked()
	g.updateAccess.Unlock()

	g.notifyAndInterrupt(changed, toInterrupt)
	if keepProbing {
		g.ensureDegradedTicker()
	}
}

func (g *FallbackGroup) performUpdateCheck() {
	g.updateAccess.Lock()
	var anyHealthyTCPBefore, anyHealthyUDPBefore bool
	for _, st := range g.states {
		if !g.isUsableLocked(st) {
			continue
		}
		if common.Contains(st.outbound.Network(), N.NetworkTCP) {
			anyHealthyTCPBefore = true
		}
		if common.Contains(st.outbound.Network(), N.NetworkUDP) {
			anyHealthyUDPBefore = true
		}
	}
	var promotedTCP, promotedUDP bool

	for _, state := range g.states {
		realTag := RealTag(state.outbound, N.NetworkTCP)
		if realTag == "" {
			realTag = state.tag
		}
		h := g.history.LoadURLTestHistory(realTag)
		if h == nil {
			if !state.lastHistoryTime.IsZero() {
				state.lastDelay = 0
				state.lastHistoryTime = time.Time{}
				state.healthy = false
				state.degraded = true
				state.consecutiveSuccess = 0
			}
			continue
		}
		if h.Time.Equal(state.lastHistoryTime) {
			continue
		}
		state.lastDelay = h.Delay
		state.lastHistoryTime = h.Time
		if g.maxDelay > 0 && h.Delay > g.maxDelay {
			state.healthy = false
			state.degraded = true
			state.consecutiveSuccess = 0
			continue
		}
		if state.healthy {
			state.degraded = false
			state.consecutiveSuccess = g.recoverTimes
			continue
		}
		supportsTCP := common.Contains(state.outbound.Network(), N.NetworkTCP)
		supportsUDP := common.Contains(state.outbound.Network(), N.NetworkUDP)
		safetyNetImmediate := (!anyHealthyTCPBefore && !promotedTCP && supportsTCP) ||
			(!anyHealthyUDPBefore && !promotedUDP && supportsUDP)
		if safetyNetImmediate {
			state.healthy = true
			state.degraded = false
			state.consecutiveSuccess = g.recoverTimes
			if supportsTCP {
				promotedTCP = true
			}
			if supportsUDP {
				promotedUDP = true
			}
			continue
		}
		state.consecutiveSuccess++
		if state.consecutiveSuccess >= g.recoverTimes {
			state.healthy = true
			state.degraded = false
		}
	}
	changed, toInterrupt := g.reselectLocked()
	keepProbing := g.shouldKeepProbingWhileIdleLocked()
	g.updateAccess.Unlock()

	if changed {
		g.notifyAndInterrupt(true, toInterrupt)
	}
	if keepProbing {
		g.ensureDegradedTicker()
	}
}
