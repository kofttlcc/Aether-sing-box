package aether

import (
	"context"
	"net"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/outbound"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	M "github.com/sagernet/sing/common/metadata"
)

func RegisterOutbound(registry *outbound.Registry) {
	outbound.Register[option.AetherOutboundOptions](registry, C.TypeAether, NewOutbound)
}

type Outbound struct {
	outbound.Adapter
	serverAddr M.Socksaddr
	psk        [32]byte
}

func NewOutbound(ctx context.Context, router adapter.Router, logger log.ContextLogger, tag string, options option.AetherOutboundOptions) (adapter.Outbound, error) {
	out := &Outbound{
		Adapter:    outbound.NewAdapterWithDialerOptions(C.TypeAether, tag, options.DialerOptions),
		serverAddr: options.ServerOptions.Build(),
		psk:        KeyFromPassword(options.Password),
	}
	return out, nil
}

func (out *Outbound) DialContext(ctx context.Context, metadata M.Metadata) (net.Conn, error) {
	rawConn, err := out.Dialer().DialContext(ctx, "tcp", out.serverAddr)
	if err != nil {
		return nil, err
	}

	target := metadata.Destination.String()
	aetherConn, err := NewClientConn(rawConn, out.psk, target, nil)
	if err != nil {
		_ = rawConn.Close()
		return nil, err
	}

	return aetherConn, nil
}
