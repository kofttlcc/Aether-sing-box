package aether

import (
	"context"
	"net"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/outbound"
	"github.com/sagernet/sing-box/common/dialer"
	"github.com/sagernet/sing-box/common/mux"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/common/uot"
)

func RegisterOutbound(registry *outbound.Registry) {
	outbound.Register[option.AetherOutboundOptions](registry, C.TypeAether, NewOutbound)
}

var (
	_ adapter.Outbound                = (*Outbound)(nil)
	_ adapter.Lifecycle               = (*Outbound)(nil)
	_ adapter.OutboundWithMultiplex   = (*Outbound)(nil)
	_ adapter.InterfaceUpdateListener = (*Outbound)(nil)
	_ adapter.IdleConnectionKeeper    = (*Outbound)(nil)
)

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
	secret, err := option.ResolveSecret(options.Password, options.Key)
	if err != nil {
		return nil, err
	}
	switch options.Cipher {
	case "", "auto", "aes-256-gcm", "chacha20-poly1305":
	default:
		return nil, E.New("unsupported aether cipher: ", options.Cipher)
	}
	outboundDialer, err := dialer.New(ctx, options.DialerOptions, options.ServerIsDomain())
	if err != nil {
		return nil, err
	}

	out := &Outbound{
		Adapter:              outbound.NewAdapterWithDialerOptions(C.TypeAether, tag, options.Network.Build(), options.DialerOptions),
		logger:               logger,
		dialer:               outboundDialer,
		serverAddr:           options.ServerOptions.Build(),
		psk:                  KeyFromPassword(secret),
		heartbeatIntervalSec: int(options.HeartbeatInterval.Build() / time.Second),
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

func (out *Outbound) Start(stage adapter.StartStage, scope *adapter.Scope) error {
	if stage != adapter.StartStateInitialize {
		return nil
	}
	if out.multiplexDialer != nil {
		scope.Add(out.multiplexDialer.Close)
	}
	return nil
}

func (out *Outbound) MultiplexEnabled() bool {
	return out.multiplexDialer != nil
}

func (out *Outbound) InterfaceUpdated(ctx context.Context) {
	if out.multiplexDialer != nil {
		out.multiplexDialer.Reset()
	}
}

func (out *Outbound) SetKeepIdleConnections(keep bool) {
	if out.multiplexDialer != nil {
		out.multiplexDialer.SetKeepIdleConnections(keep)
	}
}

func (out *Outbound) CloseIdleConnections() {
	if out.multiplexDialer != nil {
		out.multiplexDialer.CloseIdleConnections()
	}
}

func (out *Outbound) Close() error {
	return common.Close(common.PtrOrNil(out.multiplexDialer))
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
