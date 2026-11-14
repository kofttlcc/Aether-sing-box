package option

import (
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/json/badoption"
)

type AetherUser struct {
	Name     string `json:"name,omitempty"`
	Password string `json:"password,omitempty"`
	Key      string `json:"key,omitempty"` // Alias for Password if Password == ""
}

type AetherInboundOptions struct {
	ListenOptions
	Password          string                   `json:"password,omitempty"`
	Key               string                   `json:"key,omitempty"` // Alias for Password if Password == ""
	Users             []AetherUser             `json:"users,omitempty"`
	ServerPrivateKey  string                   `json:"private_key,omitempty"`
	TimeWindow        badoption.Duration       `json:"time_window,omitempty"`        // Default 30s
	HandshakeTimeout  badoption.Duration       `json:"handshake_timeout,omitempty"`  // Default 6s
	HeartbeatInterval badoption.Duration       `json:"heartbeat_interval,omitempty"` // Default 30s
	DisableShaping    bool                     `json:"disable_shaping,omitempty"`
	Multiplex         *InboundMultiplexOptions `json:"multiplex,omitempty"`
}

type AetherOutboundOptions struct {
	DialerOptions
	ServerOptions
	Network           NetworkList               `json:"network,omitempty"`
	Password          string                    `json:"password,omitempty"`
	Key               string                    `json:"key,omitempty"` // Alias for Password if Password == ""
	Cipher            string                    `json:"cipher,omitempty" enum:"auto,aes-256-gcm,chacha20-poly1305"`
	ServerPublicKey   string                    `json:"public_key,omitempty"`
	HeartbeatInterval badoption.Duration        `json:"heartbeat_interval,omitempty"` // Default 30s
	DisableShaping    bool                      `json:"disable_shaping,omitempty"`
	Multiplex         *OutboundMultiplexOptions `json:"multiplex,omitempty"`
	UDPOverTCP        *UDPOverTCPOptions        `json:"udp_over_tcp,omitempty"`
}

func ResolveSecret(password, key string) (string, error) {
	if password != "" && key != "" && password != key {
		return "", E.New("conflicting password and key")
	}
	if password != "" {
		return password, nil
	}
	return key, nil
}
