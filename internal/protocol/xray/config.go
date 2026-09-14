package xray

import (
	"encoding/json"
	"errors"
	"fmt"
)

type XrayConfig struct {
	Log       LogConfig        `json:"log"`
	Inbounds  []InboundConfig  `json:"inbounds"`
	Outbounds []OutboundConfig `json:"outbounds"`
}

type LogConfig struct {
	LogLevel string `json:"loglevel"`
}

type InboundConfig struct {
	Port           int             `json:"port"`
	Protocol       string          `json:"protocol"`
	Settings       InboundSettings `json:"settings"`
	StreamSettings StreamSettings  `json:"streamSettings"`
	Sniffing       *SniffingConfig `json:"sniffing,omitempty"`
}

type InboundSettings struct {
	Clients    []VlessClient `json:"clients"`
	Decryption string        `json:"decryption"`
}

type VlessClient struct {
	ID    string `json:"id"`
	Flow  string `json:"flow"`
	Email string `json:"email,omitempty"`
}

type StreamSettings struct {
	Network         string          `json:"network"`
	Security        string          `json:"security"`
	RealitySettings RealitySettings `json:"realitySettings"`
}

type RealitySettings struct {
	Show        bool     `json:"show"`
	Dest        string   `json:"dest"`
	Xver        int      `json:"xver"`
	ServerNames []string `json:"serverNames"`
	PrivateKey  string   `json:"privateKey"`
	ShortIds    []string `json:"shortIds"`
}

type SniffingConfig struct {
	Enabled      bool     `json:"enabled"`
	DestOverride []string `json:"destOverride"`
}

type OutboundConfig struct {
	Protocol string `json:"protocol"`
	Tag      string `json:"tag"`
}

// GenerateServerConfig creates an Xray server configuration JSON
func GenerateServerConfig(port int, privKey, sni string, shortIDs []string, clients []VlessClient) ([]byte, error) {
	if sni == "" {
		sni = "dl.google.com"
	}
	dest := fmt.Sprintf("%s:443", sni)

	cfg := XrayConfig{
		Log: LogConfig{
			LogLevel: "warning",
		},
		Inbounds: []InboundConfig{
			{
				Port:     port,
				Protocol: "vless",
				Settings: InboundSettings{
					Clients:    clients,
					Decryption: "none",
				},
				StreamSettings: StreamSettings{
					Network:  "tcp",
					Security: "reality",
					RealitySettings: RealitySettings{
						Show:        false,
						Dest:        dest,
						Xver:        0,
						ServerNames: []string{sni},
						PrivateKey:  privKey,
						ShortIds:    shortIDs,
					},
				},
				Sniffing: &SniffingConfig{
					Enabled:      true,
					DestOverride: []string{"http", "tls", "quic"},
				},
			},
		},
		Outbounds: []OutboundConfig{
			{
				Protocol: "freedom",
				Tag:      "direct",
			},
			{
				Protocol: "blackhole",
				Tag:      "block",
			},
		},
	}

	return json.MarshalIndent(cfg, "", "  ")
}

// ValidateServerConfig performs strict pre-write schema and semantic validation
// to prevent corrupted or malicious configurations from being applied.
func ValidateServerConfig(data []byte) error {
	if len(data) == 0 {
		return errors.New("xray config is empty")
	}

	var cfg XrayConfig
	if err := json.Unmarshal(data, &cfg); err != nil {
		return fmt.Errorf("invalid json syntax: %w", err)
	}

	if len(cfg.Inbounds) == 0 {
		return errors.New("xray config must contain at least one inbound")
	}
	if len(cfg.Outbounds) == 0 {
		return errors.New("xray config must contain at least one outbound")
	}

	inbound := cfg.Inbounds[0]
	if inbound.Port < 1 || inbound.Port > 65535 {
		return fmt.Errorf("invalid inbound port: %d", inbound.Port)
	}

	if inbound.Protocol != "vless" {
		return fmt.Errorf("expected vless protocol, got %s", inbound.Protocol)
	}

	if inbound.StreamSettings.RealitySettings.PrivateKey == "" {
		return errors.New("reality private key cannot be empty")
	}

	return nil
}
