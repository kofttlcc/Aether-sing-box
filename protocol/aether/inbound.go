package aether

import (
	"context"
	"net"
	"sync"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/inbound"
	"github.com/sagernet/sing-box/common/listener"
	"github.com/sagernet/sing-box/common/mux"
	"github.com/sagernet/sing-box/common/uot"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	singmux "github.com/sagernet/sing-mux"
	"github.com/sagernet/sing/common"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/common/ntp"
	sing_uot "github.com/sagernet/sing/common/uot"
)

// RegisterInbound registers the Aether v2 inbound adapter in sing-box's registry.
func RegisterInbound(registry *inbound.Registry) {
	inbound.Register[option.AetherInboundOptions](registry, C.TypeAether, NewInbound)
}

var _ adapter.TCPInjectableInbound = (*Inbound)(nil)

// Inbound implements the Aether v2 server inbound adapter.
type Inbound struct {
	inbound.Adapter
	ctx               context.Context
	cancel            context.CancelFunc
	router            adapter.ConnectionRouterEx
	uotRouter         adapter.ConnectionRouterEx
	muxRouter         adapter.ConnectionRouterEx
	muxEnabled        bool
	logger            logger.ContextLogger
	listener          *listener.Listener
	authenticator     *ServerAuthenticator
	replayFilter      *SlidingBloomFilter
	handshakeTimeout  time.Duration
	heartbeatInterval time.Duration
	disableShaping    bool
	timeFunc          func() time.Time
	drainGuard        *DrainGuard
	closeOnce         sync.Once
}

// NewInbound constructs and validates an Aether v2 inbound from options.
func NewInbound(ctx context.Context, router adapter.Router, logger log.ContextLogger, tag string, options option.AetherInboundOptions) (adapter.Inbound, error) {
	authenticator, err := NewServerAuthenticatorFromOptions(options)
	if err != nil {
		return nil, err
	}

	timeWindow := options.TimeWindow.Build()
	replayFilter := NewSlidingBloomFilterFromContext(ctx, timeWindow)

	handshakeTimeout := options.HandshakeTimeout.Build()
	if handshakeTimeout <= 0 {
		handshakeTimeout = DefaultHandshakeTimeout
	}

	heartbeatInterval := options.HeartbeatInterval.Build()
	if heartbeatInterval == 0 {
		heartbeatInterval = DefaultHeartbeatInterval
	}

	uotRouter := uot.NewRouter(router, logger)
	muxOptions := common.PtrValueOrDefault(options.Multiplex)
	muxEnabled := muxOptions.Enabled
	var muxRouter adapter.ConnectionRouterEx
	if muxEnabled {
		muxRouter, err = mux.NewRouterWithOptions(uotRouter, logger, muxOptions)
		if err != nil {
			return nil, err
		}
	}

	inCtx, cancel := context.WithCancel(ctx)
	in := &Inbound{
		Adapter:           inbound.NewAdapter(C.TypeAether, tag),
		ctx:               inCtx,
		cancel:            cancel,
		router:            router,
		uotRouter:         uotRouter,
		muxRouter:         muxRouter,
		muxEnabled:        muxEnabled,
		logger:            logger,
		authenticator:     authenticator,
		replayFilter:      replayFilter,
		handshakeTimeout:  handshakeTimeout,
		heartbeatInterval: heartbeatInterval,
		disableShaping:    options.DisableShaping,
		timeFunc:          ResolveTimeFunc(ctx),
		drainGuard: NewDrainGuard(DrainGuardOptions{
			Logger: logger,
		}),
	}
	in.listener = listener.New(listener.Options{
		Context:           ctx,
		Logger:            logger,
		Network:           []string{N.NetworkTCP},
		Listen:            options.ListenOptions,
		ConnectionHandler: in,
	})
	return in, nil
}

// Start starts the TCP listener during StartStateStart and binds Close to the lifecycle scope.
func (in *Inbound) Start(stage adapter.StartStage, scope *adapter.Scope) error {
	if stage != adapter.StartStateStart {
		return nil
	}
	err := in.listener.Start()
	if err != nil {
		return err
	}
	if scope != nil {
		scope.Add(in.Close)
	}
	return nil
}

// Close cancels in-flight handshakes/drains and closes the listener cleanly.
func (in *Inbound) Close() error {
	var err error
	in.closeOnce.Do(func() {
		if in.cancel != nil {
			in.cancel()
		}
		if in.listener != nil {
			err = in.listener.Close()
		}
	})
	return err
}

// NewConnectionEx supports direct N.TCPConnectionHandlerEx injection (detour/testing).
func (in *Inbound) NewConnectionEx(ctx context.Context, conn net.Conn, source M.Socksaddr, destination M.Socksaddr, onClose N.CloseHandlerFunc) {
	var metadata adapter.InboundContext
	metadata.Source = source
	metadata.Destination = destination
	if in.listener != nil {
		//nolint:staticcheck
		metadata.InboundDetour = in.listener.ListenOptions().Detour
	}
	in.NewConnection(ctx, conn, metadata, onClose)
}

// NewConnection authenticates and routes an incoming Aether v2 connection.
func (in *Inbound) NewConnection(ctx context.Context, conn net.Conn, metadata adapter.InboundContext, onClose N.CloseHandlerFunc) {
	sourceIP := normalizeSourceIP(conn, metadata)

	waitCtx, waitCancel := context.WithTimeout(in.ctx, in.handshakeTimeout)
	releaseHandshake, acquired := in.drainGuard.AcquireHandshake(waitCtx)
	waitCancel()
	if !acquired {
		cause := waitCtx.Err()
		if cause == nil {
			cause = context.DeadlineExceeded
		}
		in.drainGuard.CloseTimeout(ctx, conn, sourceIP, ReasonTimeout, cause, onClose)
		return
	}

	stopCloseOnShutdown := context.AfterFunc(in.ctx, func() {
		_ = conn.Close()
	})
	timeFunc := in.resolveTimeFunc(ctx)

	_ = conn.SetReadDeadline(time.Now().Add(in.handshakeTimeout))
	res, err := AcceptServerConn(in.ctx, conn, ServerConnOptions{
		Authenticator:     in.authenticator,
		ReplayFilter:      in.replayFilter,
		HeartbeatInterval: in.heartbeatInterval,
		DisableShaping:    in.disableShaping,
		TimeFunc:          timeFunc,
	})
	stopCloseOnShutdown()

	// Release handshakeSem strictly BEFORE entering StealthDrain so drain floods
	// cannot exhaust handshake capacity for legitimate connections (T2-F19-06).
	releaseHandshake()

	if err != nil {
		reason, shouldDrain := ClassifyHandshakeFailure(err)
		if shouldDrain {
			in.drainGuard.StealthDrain(in.ctx, conn, sourceIP, reason, err, onClose)
		} else {
			in.drainGuard.CloseTimeout(ctx, conn, sourceIP, reason, err, onClose)
		}
		return
	}

	// Clear the temporary HandshakeTimeout read deadline before passing to router.
	_ = res.Conn.SetReadDeadline(time.Time{})

	metadata.Inbound = in.Tag()
	metadata.InboundType = in.Type()
	metadata.User = res.UserName
	metadata.Destination = res.TargetAddr.Unwrap()

	in.routeAccepted(ctx, res, metadata, onClose)
}

func (in *Inbound) routeAccepted(
	ctx context.Context,
	res *ServerAcceptResult,
	metadata adapter.InboundContext,
	onClose N.CloseHandlerFunc,
) {
	switch res.Command {
	case CommandMux:
		if !in.muxEnabled || in.muxRouter == nil {
			muxErr := E.New("aether: multiplex is not enabled on inbound")
			in.logUser(ctx, metadata.User, "rejecting mux connection from ", metadata.Source, ": ", muxErr)
			_ = res.Conn.Close()
			if onClose != nil {
				onClose(muxErr)
			}
			return
		}
		if !metadata.Destination.IsValid() {
			metadata.Destination = singmux.Destination
		}
		// Flush the coalesced ServerResponsePrefix + initial control/chaff frame
		// immediately for mux tunnels so smux/yamux clients do not stall waiting on
		// ServerResponsePrefix before sending StreamRequest in Write #2 (emits
		// FramePing when heartbeat > 0 or shaped 0B FrameData when <= 0).
		if err := res.Conn.sendPendingServerRespControl(); err != nil {
			_ = res.Conn.Close()
			if onClose != nil {
				onClose(err)
			}
			return
		}
		in.logUser(ctx, metadata.User, "inbound multiplex connection")
		in.muxRouter.RouteConnectionEx(ctx, res.Conn, metadata, onClose)

	case CommandUoT:
		if !metadata.Destination.IsValid() {
			metadata.Destination = sing_uot.RequestDestination(sing_uot.Version)
		}
		in.logUser(ctx, metadata.User, "inbound UoT connection to ", metadata.Destination)
		in.uotRouter.RouteConnectionEx(ctx, res.Conn, metadata, onClose)

	case CommandUDP:
		pktConn := NewServerPacketConn(res.Conn)
		in.logUser(ctx, metadata.User, "inbound packet connection to ", metadata.Destination)
		in.router.RoutePacketConnectionEx(ctx, pktConn, metadata, onClose)

	case CommandTCP:
		in.logUser(ctx, metadata.User, "inbound connection to ", metadata.Destination)
		in.router.RouteConnectionEx(ctx, res.Conn, metadata, onClose)

	default:
		cmdErr := E.New("aether: unsupported command ", res.Command)
		in.logger.WarnContext(ctx, cmdErr)
		_ = res.Conn.Close()
		if onClose != nil {
			onClose(cmdErr)
		}
	}
}

func (in *Inbound) resolveTimeFunc(ctx context.Context) func() time.Time {
	if ctx != nil {
		if fn := ntp.TimeFuncFromContext(ctx); fn != nil {
			return fn
		}
	}
	if in.timeFunc != nil {
		return in.timeFunc
	}
	return time.Now
}

func (in *Inbound) logUser(ctx context.Context, user string, args ...any) {
	if in.logger == nil {
		return
	}
	if user != "" {
		prefixed := make([]any, 0, 3+len(args))
		prefixed = append(prefixed, "[", user, "] ")
		prefixed = append(prefixed, args...)
		in.logger.InfoContext(ctx, prefixed...)
		return
	}
	in.logger.InfoContext(ctx, args...)
}
