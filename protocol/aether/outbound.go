package aether

import (
	"context"
	"net"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/outbound"
	"github.com/sagernet/sing-box/common/dialer"
	"github.com/sagernet/sing-box/common/mux"
	"github.com/sagernet/sing-box/common/uot"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

func RegisterOutbound(registry *outbound.Registry) {
	outbound.Register[option.AetherOutboundOptions](registry, C.TypeAether, NewOutbound)
}

type Outbound struct {
	outbound.Adapter
	logger               logger.ContextLogger
	dialer               N.Dialer
	serverAddr           M.Socksaddr
	psk                  [32]byte
	heartbeatIntervalSec int
	uotClient            *uot.Client
	multiplexDialer      *mux.Client
}

type aetherDialer Outbound

func (d *aetherDialer) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	return (*Outbound)(d).dial(ctx, network, destination)
}

func (d *aetherDialer) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	return nil, E.New("packet connection unsupported on raw Aether dialer")
}

func NewOutbound(ctx context.Context, router adapter.Router, logger log.ContextLogger, tag string, options option.AetherOutboundOptions) (adapter.Outbound, error) {
	outboundDialer, err := dialer.New(ctx, options.DialerOptions, options.ServerIsDomain())
	if err != nil {
		return nil, err
	}

	out := &Outbound{
		Adapter:              outbound.NewAdapterWithDialerOptions(C.TypeAether, tag, options.Network.Build(), options.DialerOptions),
		logger:               logger,
		dialer:               outboundDialer,
		serverAddr:           options.ServerOptions.Build(),
		psk:                  KeyFromPassword(options.Password),
		heartbeatIntervalSec: options.HeartbeatIntervalSec,
	}

	uotOptions := common.PtrValueOrDefault(options.UDPOverTCP)
	if !uotOptions.Enabled {
		out.multiplexDialer, err = mux.NewClientWithOptions((*aetherDialer)(out), logger, common.PtrValueOrDefault(options.Multiplex))
		if err != nil {
			return nil, err
		}
	}

	if uotOptions.Enabled {
		out.uotClient = &uot.Client{
			Dialer:  (*aetherDialer)(out),
			Version: uotOptions.Version,
		}
	}

	return out, nil
}

func (out *Outbound) dial(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	rawConn, err := out.dialer.DialContext(ctx, N.NetworkTCP, out.serverAddr)
	if err != nil {
		return nil, err
	}

	target := destination.String()
	aetherConn, err := NewClientConn(rawConn, out.psk, target, nil, out.heartbeatIntervalSec)
	if err != nil {
		return nil, err
	}

	return aetherConn, nil
}

func (out *Outbound) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	ctx, metadata := adapter.ExtendContext(ctx)
	metadata.Outbound = out.Tag()
	metadata.Destination = destination

	if out.multiplexDialer == nil {
		switch N.NetworkName(network) {
		case N.NetworkTCP:
			out.logger.InfoContext(ctx, "outbound connection to ", destination)
		case N.NetworkUDP:
			if out.uotClient != nil {
				out.logger.InfoContext(ctx, "outbound UoT connect packet connection to ", destination)
				return out.uotClient.DialContext(ctx, network, destination)
			} else {
				out.logger.InfoContext(ctx, "outbound packet connection to ", destination)
			}
		}
		return out.dial(ctx, network, destination)
	} else {
		switch N.NetworkName(network) {
		case N.NetworkTCP:
			out.logger.InfoContext(ctx, "outbound multiplex connection to ", destination)
		case N.NetworkUDP:
			if out.uotClient != nil {
				out.logger.InfoContext(ctx, "outbound UoT connect packet connection to ", destination)
				return out.uotClient.DialContext(ctx, network, destination)
			} else {
				out.logger.InfoContext(ctx, "outbound multiplex packet connection to ", destination)
			}
		}
		return out.multiplexDialer.DialContext(ctx, network, destination)
	}
}

func (out *Outbound) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	ctx, metadata := adapter.ExtendContext(ctx)
	metadata.Outbound = out.Tag()
	metadata.Destination = destination

	if out.uotClient != nil {
		out.logger.InfoContext(ctx, "outbound UoT packet connection to ", destination)
		return out.uotClient.ListenPacket(ctx, destination)
	}
	return nil, E.New("Aether protocol requires udp_over_tcp enabled to proxy UDP packets")
}
