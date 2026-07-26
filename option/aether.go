package option

type AetherInboundOptions struct {
	ListenOptions
	Password             string                  `json:"password"`
	TimeLimitMs          int64                   `json:"time_limit_ms,omitempty"`
	HeartbeatIntervalSec int                     `json:"heartbeat_interval_sec,omitempty"`
	Multiplex            *InboundMultiplexOptions `json:"multiplex,omitempty"`
}

type AetherOutboundOptions struct {
	DialerOptions
	ServerOptions
	Network              NetworkList              `json:"network,omitempty"`
	Password             string                   `json:"password"`
	HeartbeatIntervalSec int                      `json:"heartbeat_interval_sec,omitempty"`
	Multiplex            *OutboundMultiplexOptions `json:"multiplex,omitempty"`
}
