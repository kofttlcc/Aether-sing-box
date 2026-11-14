package aether

import (
	"context"
	"crypto/ecdh"
	"net"
	"os"
	"sync"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/outbound"
	"github.com/sagernet/sing-box/common/dialer"
	"github.com/sagernet/sing-box/common/mux"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/buf"
	"github.com/sagernet/sing/common/bufio"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/common/ntp"
	"github.com/sagernet/sing/common/uot"
)

// RegisterOutbound registers the Aether v2 outbound adapter in sing-box's registry.
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

// Outbound implements the Aether v2 client outbound adapter.
type Outbound struct {
	outbound.Adapter
	logger            logger.ContextLogger
	dialer            N.Dialer
	serverAddr        M.Socksaddr
	credentials       ClientCredentials
	serverStaticPub   *ecdh.PublicKey
	cipherSuite       uint8
	heartbeatInterval time.Duration
	disableShaping    bool
	timeFunc          func() time.Time
	uotClient         *uot.Client
	multiplexDialer   *mux.Client
}

type aetherMuxDialer Outbound

func (d *aetherMuxDialer) DialContext(ctx context.Context, _ string, destination M.Socksaddr) (net.Conn, error) {
	conn, err := (*Outbound)(d).dialCommand(ctx, CommandMux, destination)
	if err != nil {
		return nil, err
	}
	return newMuxEarlyConn(conn), nil
}

func (d *aetherMuxDialer) ListenPacket(_ context.Context, _ M.Socksaddr) (net.PacketConn, error) {
	return nil, os.ErrInvalid
}

// muxEarlyConn defers Read until the first Write flushes ClientInitialBurst (with
// sing-mux Request + initial mux frame) so background recv loops such as yamux.Client
// cannot flush an empty 0-RTT burst and deadlock handshakeReadMu against Write.
type muxEarlyConn struct {
	*Conn
	writeOnce sync.Once
	writeGate chan struct{}
}

func newMuxEarlyConn(conn *Conn) *muxEarlyConn {
	return &muxEarlyConn{
		Conn:      conn,
		writeGate: make(chan struct{}),
	}
}

func (c *muxEarlyConn) releaseRead() {
	c.writeOnce.Do(func() {
		close(c.writeGate)
	})
}

func (c *muxEarlyConn) Read(p []byte) (int, error) {
	<-c.writeGate
	return c.Conn.Read(p)
}

func (c *muxEarlyConn) ReadBuffer(buffer *buf.Buffer) error {
	<-c.writeGate
	return c.Conn.ReadBuffer(buffer)
}

func (c *muxEarlyConn) Write(p []byte) (int, error) {
	defer c.releaseRead()
	return c.Conn.Write(p)
}

func (c *muxEarlyConn) WriteBuffer(buffer *buf.Buffer) error {
	defer c.releaseRead()
	return c.Conn.WriteBuffer(buffer)
}

func (c *muxEarlyConn) CloseWrite() error {
	defer c.releaseRead()
	return c.Conn.CloseWrite()
}

func (c *muxEarlyConn) Close() error {
	c.releaseRead()
	return c.Conn.Close()
}

func (c *muxEarlyConn) Upstream() any {
	return c.Conn
}

type aetherUoTDialer Outbound

func (d *aetherUoTDialer) DialContext(ctx context.Context, _ string, destination M.Socksaddr) (net.Conn, error) {
	return (*Outbound)(d).dialCommand(ctx, CommandUoT, destination)
}

func (d *aetherUoTDialer) ListenPacket(_ context.Context, _ M.Socksaddr) (net.PacketConn, error) {
	return nil, os.ErrInvalid
}

// NewOutbound constructs and validates an Aether v2 outbound from options.
func NewOutbound(ctx context.Context, _ adapter.Router, logger log.ContextLogger, tag string, options option.AetherOutboundOptions) (adapter.Outbound, error) {
	if options.Server == "" {
		return nil, E.New("missing aether server address")
	}
	if options.ServerPort == 0 {
		return nil, E.New("missing aether server port")
	}

	secret, err := option.ResolveSecret(options.Password, options.Key)
	if err != nil {
		return nil, err
	}
	creds, err := ParseOutboundCredentials(secret)
	if err != nil {
		return nil, err
	}

	var serverStaticPub *ecdh.PublicKey
	if options.ServerPublicKey != "" {
		serverStaticPub, err = ParseX25519PublicKey(options.ServerPublicKey)
		if err != nil {
			return nil, err
		}
	}

	cipherSuite, err := SelectCipherSuite(options.Cipher)
	if err != nil {
		return nil, err
	}

	heartbeatInterval := options.HeartbeatInterval.Build()
	if heartbeatInterval == 0 {
		heartbeatInterval = DefaultHeartbeatInterval
	}

	outboundDialer, err := dialer.New(ctx, options.DialerOptions, options.ServerIsDomain())
	if err != nil {
		return nil, err
	}

	out := &Outbound{
		Adapter:           outbound.NewAdapterWithDialerOptions(C.TypeAether, tag, options.Network.Build(), options.DialerOptions),
		logger:            logger,
		dialer:            outboundDialer,
		serverAddr:        options.ServerOptions.Build(),
		credentials:       creds,
		serverStaticPub:   serverStaticPub,
		cipherSuite:       cipherSuite,
		heartbeatInterval: heartbeatInterval,
		disableShaping:    options.DisableShaping,
		timeFunc:          ResolveTimeFunc(ctx),
	}

	// R-5: initialize UoT and Multiplex independently so configuring both does
	// not drop uotClient; transport priority is applied on dial.
	uotOptions := common.PtrValueOrDefault(options.UDPOverTCP)
	if uotOptions.Enabled {
		out.uotClient = &uot.Client{
			Dialer:  (*aetherUoTDialer)(out),
			Version: uotOptions.Version,
		}
	}

	out.multiplexDialer, err = mux.NewClientWithOptions((*aetherMuxDialer)(out), logger, common.PtrValueOrDefault(options.Multiplex))
	if err != nil {
		return nil, err
	}

	return out, nil
}

// Start registers multiplex client cleanup on StartStateInitialize.
func (out *Outbound) Start(stage adapter.StartStage, scope *adapter.Scope) error {
	if stage != adapter.StartStateInitialize {
		return nil
	}
	if out.multiplexDialer != nil && scope != nil {
		scope.Add(out.multiplexDialer.Close)
	}
	return nil
}

// Close closes the multiplex client if active.
func (out *Outbound) Close() error {
	if out.multiplexDialer != nil {
		return out.multiplexDialer.Close()
	}
	return nil
}

// MultiplexEnabled reports whether multiplex tunneling is enabled on this outbound.
func (out *Outbound) MultiplexEnabled() bool {
	return out.multiplexDialer != nil
}

// InterfaceUpdated resets multiplex sessions across network interface changes.
func (out *Outbound) InterfaceUpdated(_ context.Context) {
	if out.multiplexDialer != nil {
		out.multiplexDialer.Reset()
	}
}

// SetKeepIdleConnections forwards idle session retention to multiplex.
func (out *Outbound) SetKeepIdleConnections(keep bool) {
	if out.multiplexDialer != nil {
		out.multiplexDialer.SetKeepIdleConnections(keep)
	}
}

// CloseIdleConnections closes any idle multiplex sessions.
func (out *Outbound) CloseIdleConnections() {
	if out.multiplexDialer != nil {
		out.multiplexDialer.CloseIdleConnections()
	}
}

func (out *Outbound) supportsNetwork(network string) bool {
	return common.Contains(out.Network(), network)
}

// DialContext establishes a stream (TCP) or bound packet (UDP) connection via Aether v2.
func (out *Outbound) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	netName := N.NetworkName(network)
	if netName != N.NetworkTCP && netName != N.NetworkUDP {
		return nil, E.Extend(N.ErrUnknownNetwork, network)
	}
	if !out.supportsNetwork(netName) {
		return nil, E.Extend(N.ErrUnknownNetwork, network)
	}

	ctx, metadata := adapter.ExtendContext(ctx)
	metadata.Outbound = out.Tag()
	metadata.Destination = destination

	if out.multiplexDialer != nil {
		switch netName {
		case N.NetworkTCP:
			out.logger.InfoContext(ctx, "outbound multiplex connection to ", destination)
		case N.NetworkUDP:
			out.logger.InfoContext(ctx, "outbound multiplex packet connection to ", destination)
		}
		return out.multiplexDialer.DialContext(ctx, network, destination)
	}

	if netName == N.NetworkUDP {
		if out.uotClient != nil {
			out.logger.InfoContext(ctx, "outbound UoT connect packet connection to ", destination)
			return out.uotClient.DialContext(ctx, network, destination)
		}
		out.logger.InfoContext(ctx, "outbound packet connection to ", destination)
		aetherConn, err := out.dialCommand(ctx, CommandUDP, destination)
		if err != nil {
			return nil, err
		}
		return bufio.NewBindPacketConn(NewClientPacketConn(aetherConn), destination), nil
	}

	out.logger.InfoContext(ctx, "outbound connection to ", destination)
	return out.dialCommand(ctx, CommandTCP, destination)
}

// ListenPacket establishes a packet connection via Aether v2 according to Mux > UoT > Native priority.
func (out *Outbound) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	if !out.supportsNetwork(N.NetworkUDP) {
		return nil, E.Extend(N.ErrUnknownNetwork, N.NetworkUDP)
	}

	ctx, metadata := adapter.ExtendContext(ctx)
	metadata.Outbound = out.Tag()
	metadata.Destination = destination

	if out.multiplexDialer != nil {
		out.logger.InfoContext(ctx, "outbound multiplex packet connection to ", destination)
		return out.multiplexDialer.ListenPacket(ctx, destination)
	}
	if out.uotClient != nil {
		out.logger.InfoContext(ctx, "outbound UoT packet connection to ", destination)
		return out.uotClient.ListenPacket(ctx, destination)
	}
	out.logger.InfoContext(ctx, "outbound packet connection to ", destination)
	aetherConn, err := out.dialCommand(ctx, CommandUDP, destination)
	if err != nil {
		return nil, err
	}
	return NewClientPacketConn(aetherConn), nil
}

func (out *Outbound) dialCommand(ctx context.Context, command uint8, destination M.Socksaddr) (*Conn, error) {
	rawConn, err := out.dialer.DialContext(ctx, N.NetworkTCP, out.serverAddr)
	if err != nil {
		return nil, err
	}

	timeFunc := out.timeFunc
	if ctxTimeFunc := ntp.TimeFuncFromContext(ctx); ctxTimeFunc != nil {
		timeFunc = ctxTimeFunc
	}

	conn, err := DialEarlyConnContext(ctx, rawConn, ClientConnOptions{
		Credentials:       out.credentials,
		ServerStaticPub:   out.serverStaticPub,
		Command:           command,
		CipherSuite:       out.cipherSuite,
		TargetAddr:        destination,
		HeartbeatInterval: out.heartbeatInterval,
		DisableShaping:    out.disableShaping,
		TimeFunc:          timeFunc,
	})
	if err != nil {
		_ = rawConn.Close()
		return nil, err
	}
	return conn, nil
}
