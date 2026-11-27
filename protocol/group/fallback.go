package group

import (
	"context"
	"io"
	"maps"
	"net"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/outbound"
	"github.com/sagernet/sing-box/common/interrupt"
	"github.com/sagernet/sing-box/common/urltest"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/batch"
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
	fallbackVerifyTimeout             = 3 * time.Second
	fallbackMaxRescueAttempts         = 2
)

func RegisterFallback(registry *outbound.Registry) {
	outbound.Register[option.FallbackOutboundOptions](registry, C.TypeFallback, NewFallback)
}

var (
	_ adapter.OutboundGroup           = (*Fallback)(nil)
	_ adapter.URLTestGroup            = (*Fallback)(nil)
	_ adapter.InterfaceUpdateListener = (*Fallback)(nil)
	_ adapter.Referrer                = (*Fallback)(nil)
	_ N.Dialer                        = (*Fallback)(nil)
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
	s.group.CheckOutbounds(s.ctx, true)
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
			return
		}
		group.CheckOutbounds(ctx, false)
	}()
}

func (s *Fallback) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
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

	conn, err := primary.DialContext(ctx, network, destination)
	if err == nil {
		s.group.onDialSuccess(primary.Tag())
		return s.group.interruptGroup.NewConn(conn, isExternal), nil
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
		rescueConn, rescueErr := candidate.DialContext(ctx, network, destination)
		if rescueErr == nil {
			s.group.onDialSuccess(candidate.Tag())
			return s.group.interruptGroup.NewConn(rescueConn, isExternal), nil
		}
		s.logger.ErrorContext(ctx, rescueErr)
		if ctx.Err() == nil {
			s.group.onDialFailure(candidate)
		}
	}
	return nil, err
}

func (s *Fallback) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	s.group.Touch()
	primary := s.group.selectedOrSelect(N.NetworkUDP)
	if primary == nil {
		return nil, E.New("missing supported outbound")
	}
	isExternal := interrupt.IsExternalConnectionFromContext(ctx)
	pinned := s.group.IsPinned()

	conn, err := primary.ListenPacket(ctx, destination)
	if err == nil {
		s.group.onDialSuccess(primary.Tag())
		return s.group.interruptGroup.NewPacketConn(conn, isExternal), nil
	}
	s.logger.ErrorContext(ctx, err)
	if pinned || ctx.Err() != nil {
		return nil, err
	}

	s.group.onDialFailure(primary)
	candidates := s.group.rescueCandidates(N.NetworkUDP, primary.Tag(), fallbackMaxRescueAttempts)
	for _, candidate := range candidates {
		if ctx.Err() != nil {
			break
		}
		rescueConn, rescueErr := candidate.ListenPacket(ctx, destination)
		if rescueErr == nil {
			s.group.onDialSuccess(candidate.Tag())
			return s.group.interruptGroup.NewPacketConn(rescueConn, isExternal), nil
		}
		s.logger.ErrorContext(ctx, rescueErr)
		if ctx.Err() == nil {
			s.group.onDialFailure(candidate)
		}
	}
	return nil, err
}

type fallbackMemberState struct {
	tag                 string
	outbound            adapter.Outbound
	healthy             bool
	degraded            bool
	consecutiveSuccess  uint8
	lastHistoryTime     time.Time
	consecutiveDialFail atomic.Uint32
	verifying           atomic.Bool
}

type fallbackProbeOutcome struct {
	probed    bool
	err       error
	delay     uint16
	timestamp time.Time
}

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
	checking                     atomic.Bool
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
			tag:      detour.Tag(),
			outbound: detour,
			healthy:  true,
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
	defer g.access.Unlock()
	select {
	case <-g.close:
		return
	default:
	}
	g.started.Store(true)
	g.lastActive.Store(time.Now())
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
	if g.ticker != nil {
		g.lastActive.Store(time.Now())
		return
	}
	ticker := time.NewTicker(g.interval)
	g.ticker = ticker
	if g.pause != nil {
		g.pauseCallback = pause.RegisterTicker(g.pause, ticker, g.interval, nil)
	}
	go g.loopCheck(ticker, g.close)
}

func (g *FallbackGroup) Close() error {
	g.access.Lock()
	defer g.access.Unlock()
	g.closeCancel()
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
	var notify bool
	if tag == "" {
		notify = g.pinnedTag != ""
		g.pinnedTag = ""
	} else {
		if _, ok := g.stateByTag[tag]; !ok {
			g.updateAccess.Unlock()
			return false
		}
		notify = g.pinnedTag != tag
		g.pinnedTag = tag
	}
	changed := g.reselectLocked()
	g.updateAccess.Unlock()
	if changed || notify {
		g.notifyAndInterrupt(changed)
	}
	return true
}

func (g *FallbackGroup) selectedOrSelect(network string) adapter.Outbound {
	g.updateAccess.Lock()
	var selected adapter.Outbound
	if network == N.NetworkUDP {
		selected = g.selectedOutboundUDP
	} else {
		selected = g.selectedOutboundTCP
	}
	if selected == nil {
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

func (g *FallbackGroup) selectLocked(network string) (adapter.Outbound, bool) {
	if g.pinnedTag != "" {
		if state, ok := g.stateByTag[g.pinnedTag]; ok && common.Contains(state.outbound.Network(), network) {
			return state.outbound, true
		}
	}
	for _, state := range g.states {
		if !common.Contains(state.outbound.Network(), network) {
			continue
		}
		if !state.healthy {
			continue
		}
		if g.maxDelay > 0 {
			if history := g.history.LoadURLTestHistory(RealTag(state.outbound, network)); history != nil && history.Delay > g.maxDelay {
				continue
			}
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

func (g *FallbackGroup) reselectLocked() bool {
	var changed bool
	if nextTCP, _ := g.selectLocked(N.NetworkTCP); nextTCP != nil && nextTCP != g.selectedOutboundTCP {
		if g.selectedOutboundTCP != nil {
			changed = true
		}
		g.selectedOutboundTCP = nextTCP
	}
	if nextUDP, _ := g.selectLocked(N.NetworkUDP); nextUDP != nil && nextUDP != g.selectedOutboundUDP {
		if g.selectedOutboundUDP != nil {
			changed = true
		}
		g.selectedOutboundUDP = nextUDP
	}
	return changed
}

func (g *FallbackGroup) notifyAndInterrupt(changed bool) {
	if g.history != nil {
		g.history.NotifyUpdated()
	}
	if changed && g.interruptExternalConnections {
		g.interruptGroup.Interrupt(true)
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
		if !state.healthy {
			continue
		}
		if g.maxDelay > 0 {
			if history := g.history.LoadURLTestHistory(RealTag(state.outbound, network)); history != nil && history.Delay > g.maxDelay {
				continue
			}
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
		state.lastHistoryTime = now
		g.updateAccess.Unlock()
		return
	}
	if err == nil {
		state.lastHistoryTime = now
	} else {
		state.lastHistoryTime = time.Time{}
	}
	state.healthy = false
	state.degraded = true
	state.consecutiveSuccess = 0
	changed := g.reselectLocked()
	g.updateAccess.Unlock()

	if changed {
		g.notifyAndInterrupt(true)
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

func (g *FallbackGroup) loopCheck(ticker *time.Ticker, closeChan <-chan struct{}) {
	if time.Since(g.lastActive.Load()) > g.interval {
		g.lastActive.Store(time.Now())
		_, _ = g.urlTest(g.closeCtx, true, false)
	}
	for {
		select {
		case <-closeChan:
			return
		case <-ticker.C:
		}
		if time.Since(g.lastActive.Load()) > g.idleTimeout {
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
		_, _ = g.urlTest(g.closeCtx, true, false)
	}
}

func (g *FallbackGroup) CheckOutbounds(ctx context.Context, force bool) {
	_, _ = g.urlTest(ctx, true, force)
}

func (g *FallbackGroup) URLTest(ctx context.Context) (map[string]uint16, error) {
	return g.urlTest(ctx, true, true)
}

func (g *FallbackGroup) urlTest(ctx context.Context, force bool, bypassRecoverStreak bool) (map[string]uint16, error) {
	if g.checking.Swap(true) {
		return make(map[string]uint16), nil
	}
	defer g.checking.Store(false)

	outcomes := make([]fallbackProbeOutcome, len(g.states))
	result := make(map[string]uint16)
	var resultAccess sync.Mutex

	b, _ := batch.New(ctx, batch.WithConcurrencyNum[any](10))
	for i, state := range g.states {
		idx := i
		detour := state.outbound
		tag := state.tag
		b.Go(tag, func() (any, error) {
			switch nested := detour.(type) {
			case *URLTest:
				if nested.group != nil {
					nestedResult, _ := nested.group.urlTest(ctx, force)
					resultAccess.Lock()
					maps.Copy(result, nestedResult)
					resultAccess.Unlock()
				}
				if ctx.Err() != nil {
					return nil, nil
				}
				if h := g.history.LoadURLTestHistory(RealTag(nested, N.NetworkTCP)); h != nil {
					outcomes[idx] = fallbackProbeOutcome{probed: true, delay: h.Delay, timestamp: h.Time}
					resultAccess.Lock()
					result[tag] = h.Delay
					resultAccess.Unlock()
				} else {
					outcomes[idx] = fallbackProbeOutcome{probed: true, err: E.New("nested urltest unavailable")}
				}
			case *Fallback:
				if nested.group != nil {
					nestedResult, _ := nested.group.urlTest(ctx, force, bypassRecoverStreak)
					resultAccess.Lock()
					maps.Copy(result, nestedResult)
					resultAccess.Unlock()
				}
				if ctx.Err() != nil {
					return nil, nil
				}
				if h := g.history.LoadURLTestHistory(RealTag(nested, N.NetworkTCP)); h != nil {
					outcomes[idx] = fallbackProbeOutcome{probed: true, delay: h.Delay, timestamp: h.Time}
					resultAccess.Lock()
					result[tag] = h.Delay
					resultAccess.Unlock()
				} else {
					outcomes[idx] = fallbackProbeOutcome{probed: true, err: E.New("nested fallback unavailable")}
				}
			case adapter.OutboundGroup:
				if g.outbound != nil {
					members := common.FilterNotNil(common.Map(nested.All(), func(it string) adapter.Outbound {
						member, _ := g.outbound.Outbound(it)
						return member
					}))
					nestedResult := URLTestOutbounds(ctx, g.outbound, g.history, g.logger, members, g.link, g.interval, force)
					resultAccess.Lock()
					maps.Copy(result, nestedResult)
					resultAccess.Unlock()
				}
				if ctx.Err() != nil {
					return nil, nil
				}
				if h := g.history.LoadURLTestHistory(RealTag(nested, N.NetworkTCP)); h != nil {
					outcomes[idx] = fallbackProbeOutcome{probed: true, delay: h.Delay, timestamp: h.Time}
					resultAccess.Lock()
					result[tag] = h.Delay
					resultAccess.Unlock()
				} else {
					outcomes[idx] = fallbackProbeOutcome{probed: true, err: E.New("nested group unavailable")}
				}
			default:
				testCtx, cancel := context.WithTimeout(ctx, C.TCPTimeout)
				defer cancel()
				delay, testErr := g.probeSingle(testCtx, detour)
				if testErr != nil {
					if ctx.Err() != nil {
						return nil, nil
					}
					g.logger.Debug("outbound ", tag, " unavailable: ", testErr)
					g.history.DeleteURLTestHistory(tag)
					outcomes[idx] = fallbackProbeOutcome{probed: true, err: testErr}
				} else {
					now := time.Now()
					g.logger.Debug("outbound ", tag, " available: ", delay, "ms")
					g.history.StoreURLTestHistory(tag, &adapter.URLTestHistory{
						Time:  now,
						Delay: delay,
					})
					outcomes[idx] = fallbackProbeOutcome{probed: true, delay: delay, timestamp: now}
					resultAccess.Lock()
					result[tag] = delay
					resultAccess.Unlock()
				}
			}
			return nil, nil
		})
	}
	b.Wait()

	g.evaluateProbeResults(outcomes, bypassRecoverStreak)
	return result, nil
}

func (g *FallbackGroup) evaluateProbeResults(outcomes []fallbackProbeOutcome, bypassRecoverStreak bool) {
	g.updateAccess.Lock()
	isInitial := !g.initialProbeDone
	for i, state := range g.states {
		outcome := outcomes[i]
		if !outcome.probed {
			continue
		}
		probeOK := outcome.err == nil && (g.maxDelay == 0 || outcome.delay <= g.maxDelay)
		if probeOK {
			state.lastHistoryTime = outcome.timestamp
			state.consecutiveDialFail.Store(0)
			if state.healthy {
				state.degraded = false
				state.consecutiveSuccess = g.recoverTimes
			} else if bypassRecoverStreak || isInitial {
				state.healthy = true
				state.degraded = false
				state.consecutiveSuccess = g.recoverTimes
			} else {
				state.consecutiveSuccess++
				if state.consecutiveSuccess >= g.recoverTimes {
					state.healthy = true
					state.degraded = false
				}
			}
		} else {
			if outcome.err == nil {
				state.lastHistoryTime = outcome.timestamp
			} else {
				state.lastHistoryTime = time.Time{}
			}
			state.healthy = false
			state.degraded = true
			state.consecutiveSuccess = 0
		}
	}
	g.initialProbeDone = true
	changed := g.reselectLocked()
	g.updateAccess.Unlock()

	if changed {
		g.notifyAndInterrupt(true)
	}
}

func (g *FallbackGroup) performUpdateCheck() {
	g.updateAccess.Lock()
	for _, state := range g.states {
		realTag := RealTag(state.outbound, N.NetworkTCP)
		if realTag == "" {
			realTag = state.tag
		}
		h := g.history.LoadURLTestHistory(realTag)
		if h == nil {
			if !state.lastHistoryTime.IsZero() {
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
		state.lastHistoryTime = h.Time
		if g.maxDelay > 0 && h.Delay > g.maxDelay {
			state.healthy = false
			state.degraded = true
			state.consecutiveSuccess = 0
		} else {
			state.healthy = true
			state.degraded = false
			state.consecutiveSuccess = g.recoverTimes
			state.consecutiveDialFail.Store(0)
		}
	}
	changed := g.reselectLocked()
	g.updateAccess.Unlock()

	if changed {
		g.notifyAndInterrupt(true)
	}
}
