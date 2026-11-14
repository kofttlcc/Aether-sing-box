package aether

import (
	"context"
	"net"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/inbound"
	"github.com/sagernet/sing-box/common/listener"
	"github.com/sagernet/sing-box/common/mux"
	"github.com/sagernet/sing-box/common/uot"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

func RegisterInbound(registry *inbound.Registry) {
	inbound.Register[option.AetherInboundOptions](registry, C.TypeAether, NewInbound)
}

var _ adapter.TCPInjectableInbound = (*Inbound)(nil)

type Inbound struct {
	inbound.Adapter
	router               adapter.ConnectionRouterEx
	logger               logger.ContextLogger
	listener             *listener.Listener
	psk                  [32]byte
	replayFilter         *ReplayFilter
	heartbeatIntervalSec int
}

func NewInbound(ctx context.Context, router adapter.Router, logger log.ContextLogger, tag string, options option.AetherInboundOptions) (adapter.Inbound, error) {
	secret, err := option.ResolveSecret(options.Password, options.Key)
	if err != nil {
		return nil, err
	}
	for _, user := range options.Users {
		userSecret, userErr := option.ResolveSecret(user.Password, user.Key)
		if userErr != nil {
			return nil, userErr
		}
		if secret == "" && userSecret != "" {
			secret = userSecret
		}
	}
	psk := KeyFromPassword(secret)
	timeLimit := options.TimeWindow.Build().Milliseconds()
	if timeLimit <= 0 {
		timeLimit = MaxTimeDiffMs
	}
	heartbeatIntervalSec := int(options.HeartbeatInterval.Build() / time.Second)

	baseRouter := uot.NewRouter(router, logger)
	muxRouter, err := mux.NewRouterWithOptions(baseRouter, logger, common.PtrValueOrDefault(options.Multiplex))
	if err != nil {
		return nil, err
	}

	in := &Inbound{
		Adapter:              inbound.NewAdapter(C.TypeAether, tag),
		router:               muxRouter,
		logger:               logger,
		psk:                  psk,
		replayFilter:         NewReplayFilter(10000, timeLimit),
		heartbeatIntervalSec: heartbeatIntervalSec,
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

func (in *Inbound) Start(stage adapter.StartStage, scope *adapter.Scope) error {
	if stage != adapter.StartStateStart {
		return nil
	}
	err := in.listener.Start()
	if err != nil {
		return err
	}
	scope.Add(in.listener.Close)
	return nil
}

func (in *Inbound) Close() error {
	return common.Close(common.PtrOrNil(in.listener))
}

func (in *Inbound) NewConnection(ctx context.Context, conn net.Conn, metadata adapter.InboundContext, onClose N.CloseHandlerFunc) {
	aetherConn, header, err := NewServerConn(conn, in.psk, in.replayFilter, in.heartbeatIntervalSec)
	if err != nil {
		N.CloseOnHandshakeFailure(conn, onClose, err)
		return
	}

	metadata.Inbound = in.Tag()
	metadata.InboundType = in.Type()
	metadata.Destination = M.ParseSocksaddr(header.Address)

	in.logger.InfoContext(ctx, "inbound connection to ", metadata.Destination)
	in.router.RouteConnectionEx(ctx, aetherConn, metadata, onClose)
}

func (in *Inbound) NewConnectionEx(ctx context.Context, conn net.Conn, source M.Socksaddr, destination M.Socksaddr, onClose N.CloseHandlerFunc) {
	_, metadata := adapter.ExtendContext(ctx)
	if source.IsValid() {
		metadata.Source = source
	}
	if destination.IsValid() {
		metadata.Destination = destination
	}
	in.NewConnection(ctx, conn, *metadata, onClose)
}
