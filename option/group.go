package option

import "github.com/sagernet/sing/common/json/badoption"

type SelectorOutboundOptions struct {
	Outbounds                 []string `json:"outbounds" reference:"outbound"`
	Default                   string   `json:"default,omitempty" reference:"outbound"`
	InterruptExistConnections bool     `json:"interrupt_exist_connections,omitempty"`
}

type URLTestOutboundOptions struct {
	Outbounds                 []string           `json:"outbounds" reference:"outbound"`
	URL                       string             `json:"url,omitempty"`
	Interval                  badoption.Duration `json:"interval,omitempty"`
	Tolerance                 uint16             `json:"tolerance,omitempty"`
	IdleTimeout               badoption.Duration `json:"idle_timeout,omitempty"`
	InterruptExistConnections bool               `json:"interrupt_exist_connections,omitempty"`
}

type FallbackOutboundOptions struct {
	Outbounds                 []string           `json:"outbounds" reference:"outbound"`
	URL                       string             `json:"url,omitempty"`
	Interval                  badoption.Duration `json:"interval,omitempty"`
	IdleTimeout               badoption.Duration `json:"idle_timeout,omitempty"`
	MaxDelay                  uint16             `json:"max_delay,omitempty"`
	FailTimes                 uint8              `json:"fail_times,omitempty"`
	RecoverTimes              uint8              `json:"recover_times,omitempty"`
	InterruptExistConnections *bool              `json:"interrupt_exist_connections,omitempty"`
}
