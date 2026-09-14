package amneziawg

import (
	"bytes"
	"errors"
	"fmt"
	"strings"
	"text/template"
)

type ClientConfigParams struct {
	ClientPrivateKey string
	ClientAddress    string
	DNS              string

	// Obfuscation parameters
	Jc   int
	Jmin int
	Jmax int
	S1   int
	S2   int
	H1   uint32
	H2   uint32
	H3   uint32
	H4   uint32

	// Server peer
	ServerPublicKey string
	PresharedKey    string
	Endpoint        string // host:port
	AllowedIPs      string
}

const clientConfTemplate = `[Interface]
PrivateKey = {{.ClientPrivateKey}}
Address = {{.ClientAddress}}
DNS = {{.DNS}}
Jc = {{.Jc}}
Jmin = {{.Jmin}}
Jmax = {{.Jmax}}
S1 = {{.S1}}
S2 = {{.S2}}
H1 = {{.H1}}
H2 = {{.H2}}
H3 = {{.H3}}
H4 = {{.H4}}

[Peer]
PublicKey = {{.ServerPublicKey}}
{{- if .PresharedKey}}
PresharedKey = {{.PresharedKey}}
{{- end}}
Endpoint = {{.Endpoint}}
AllowedIPs = {{.AllowedIPs}}
PersistentKeepalive = 25
`

type ServerPeerConfig struct {
	PublicKey    string
	PresharedKey string
	AllowedIPs   string // e.g. "10.8.0.2/32"
}

type ServerConfigParams struct {
	ServerPrivateKey string
	ListenPort       int
	Address          string // e.g. "10.8.0.1/24"

	Jc   int
	Jmin int
	Jmax int
	S1   int
	S2   int
	H1   uint32
	H2   uint32
	H3   uint32
	H4   uint32

	Peers []ServerPeerConfig
}

const serverConfTemplate = `[Interface]
PrivateKey = {{.ServerPrivateKey}}
Address = {{.Address}}
ListenPort = {{.ListenPort}}
Jc = {{.Jc}}
Jmin = {{.Jmin}}
Jmax = {{.Jmax}}
S1 = {{.S1}}
S2 = {{.S2}}
H1 = {{.H1}}
H2 = {{.H2}}
H3 = {{.H3}}
H4 = {{.H4}}

{{range .Peers}}
[Peer]
PublicKey = {{.PublicKey}}
{{- if .PresharedKey}}
PresharedKey = {{.PresharedKey}}
{{- end}}
AllowedIPs = {{.AllowedIPs}}
{{end}}
`

// GenerateClientConfig generates a ready-to-use .conf file for AmneziaVPN / WireGuard
func GenerateClientConfig(p ClientConfigParams) (string, error) {
	if p.DNS == "" {
		p.DNS = "1.1.1.1, 8.8.8.8"
	}
	if p.AllowedIPs == "" {
		p.AllowedIPs = "0.0.0.0/0, ::/0"
	}

	tmpl, err := template.New("clientConf").Parse(clientConfTemplate)
	if err != nil {
		return "", fmt.Errorf("failed to parse template: %w", err)
	}

	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, p); err != nil {
		return "", fmt.Errorf("failed to render client config: %w", err)
	}

	return buf.String(), nil
}

// GenerateServerConfig generates the server-side awg0.conf
func GenerateServerConfig(p ServerConfigParams) (string, error) {
	if p.ServerPrivateKey == "" {
		return "", errors.New("server private key cannot be empty")
	}
	if p.ListenPort < 1 || p.ListenPort > 65535 {
		return "", fmt.Errorf("invalid listen port: %d", p.ListenPort)
	}

	tmpl, err := template.New("serverConf").Parse(serverConfTemplate)
	if err != nil {
		return "", fmt.Errorf("failed to parse template: %w", err)
	}

	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, p); err != nil {
		return "", fmt.Errorf("failed to render server config: %w", err)
	}

	return buf.String(), nil
}

// ValidateServerConfig performs structural validation on generated awg0.conf
func ValidateServerConfig(conf string) error {
	if len(strings.TrimSpace(conf)) == 0 {
		return errors.New("awg config is empty")
	}
	if !strings.Contains(conf, "[Interface]") {
		return errors.New("missing [Interface] section")
	}
	if !strings.Contains(conf, "PrivateKey = ") {
		return errors.New("missing PrivateKey parameter")
	}
	if !strings.Contains(conf, "ListenPort = ") {
		return errors.New("missing ListenPort parameter")
	}
	return nil
}
