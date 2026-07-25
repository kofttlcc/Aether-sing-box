package aether

import (
	"context"
	"net"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/inbound"
	"github.com/sagernet/sing-box/common/listener"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

func RegisterInbound(registry *inbound.Registry) {
	inbound.Register[option.AetherInboundOptions](registry, C.TypeAether, NewInbound)
}

type Inbound struct {
	inbound.Adapter
	router       adapter.ConnectionRouter
	logger       logger.ContextLogger
	listener     *listener.Listener
	psk          [32]byte
	replayFilter *ReplayFilter
}

func NewInbound(ctx context.Context, router adapter.Router, logger log.ContextLogger, tag string, options option.AetherInboundOptions) (adapter.Inbound, error) {
	psk := KeyFromPassword(options.Password)
	timeLimit := options.TimeLimitMs
	if timeLimit <= 0 {
		timeLimit = MaxTimeDiffMs
	}

	in := &Inbound{
		Adapter:      inbound.NewAdapter(C.TypeAether, tag),
		router:       router,
		logger:       logger,
		psk:          psk,
		replayFilter: NewReplayFilter(10000, timeLimit),
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

func (in *Inbound) Start(stage adapter.StartStage) error {
	if stage != adapter.StartStateStart {
		return nil
	}
	return in.listener.Start()
}

func (in *Inbound) Close() error {
	return in.listener.Close()
}

func (in *Inbound) NewConnectionEx(ctx context.Context, conn net.Conn, source M.Socksaddr, destination M.Socksaddr, onClose N.CloseHandlerFunc) {
	aetherConn, header, err := NewServerConn(conn, in.psk, in.replayFilter)
	if err != nil {
		return
	}

	_, metadata := adapter.ExtendContext(ctx)
	metadata.Inbound = in.Tag()
	metadata.InboundType = in.Type()
	if source.IsValid() {
		metadata.Source = source
	}
	metadata.Destination = M.ParseSocksaddr(header.Address)

	in.router.RouteConnectionEx(ctx, aetherConn, *metadata, onClose)
}
