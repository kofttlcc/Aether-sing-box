package aether

import (
	"context"
	"net"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/outbound"
	"github.com/sagernet/sing-box/common/dialer"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

func RegisterOutbound(registry *outbound.Registry) {
	outbound.Register[option.AetherOutboundOptions](registry, C.TypeAether, NewOutbound)
}

type Outbound struct {
	outbound.Adapter
	logger     logger.ContextLogger
	dialer     N.Dialer
	serverAddr M.Socksaddr
	psk        [32]byte
}

func NewOutbound(ctx context.Context, router adapter.Router, logger log.ContextLogger, tag string, options option.AetherOutboundOptions) (adapter.Outbound, error) {
	outboundDialer, err := dialer.New(ctx, options.DialerOptions, options.ServerIsDomain())
	if err != nil {
		return nil, err
	}

	out := &Outbound{
		Adapter:    outbound.NewAdapterWithDialerOptions(C.TypeAether, tag, options.Network.Build(), options.DialerOptions),
		logger:     logger,
		dialer:     outboundDialer,
		serverAddr: options.ServerOptions.Build(),
		psk:        KeyFromPassword(options.Password),
	}
	return out, nil
}

func (out *Outbound) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	ctx, metadata := adapter.ExtendContext(ctx)
	metadata.Outbound = out.Tag()
	metadata.Destination = destination

	out.logger.InfoContext(ctx, "outbound connection to ", destination)

	rawConn, err := out.dialer.DialContext(ctx, N.NetworkTCP, out.serverAddr)
	if err != nil {
		return nil, err
	}

	target := destination.String()
	aetherConn, err := NewClientConn(rawConn, out.psk, target, nil)
	if err != nil {
		_ = rawConn.Close()
		return nil, err
	}

	return aetherConn, nil
}
