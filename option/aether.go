package option

type AetherInboundOptions struct {
	ListenOptions
	Password    string `json:"password"`
	TimeLimitMs int64  `json:"time_limit_ms,omitempty"`
}

type AetherOutboundOptions struct {
	DialerOptions
	ServerOptions
	Password string `json:"password"`
}
