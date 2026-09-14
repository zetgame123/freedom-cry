package hysteria

import (
	"bytes"
	"fmt"
	"net/url"
	"text/template"
)

type HysteriaServerParams struct {
	ListenPort      int      `yaml:"listen_port"`      // e.g. 8443
	CertFile        string   `yaml:"cert_file"`        // /etc/freedom-cry/hysteria.crt
	KeyFile         string   `yaml:"key_file"`         // /etc/freedom-cry/hysteria.key
	MasqueradeURL   string   `yaml:"masquerade_url"`   // e.g. https://bing.com
	ClientPasswords []string `yaml:"client_passwords"` // Active client password hashes/tokens
}

const hysteriaServerTmpl = `listen: :{{.ListenPort}}

tls:
  cert: {{.CertFile}}
  key: {{.KeyFile}}

auth:
  type: password
  password: {{index .ClientPasswords 0}}

masquerade:
  type: proxy
  proxy:
    url: {{.MasqueradeURL}}
    rewriteHost: true

outbounds:
  - name: default
    type: direct

quic:
  initStreamReceiveWindow: 8388608
  maxStreamReceiveWindow: 8388608
  initConnReceiveWindow: 20971520
  maxConnReceiveWindow: 20971520
  maxIdleTimeout: 30s
  keepAlivePeriod: 10s
`

// GenerateHysteriaServerConfig outputs a YAML configuration for hysteria2 server daemon
func GenerateHysteriaServerConfig(params HysteriaServerParams) (string, error) {
	if len(params.ClientPasswords) == 0 {
		params.ClientPasswords = []string{"freedom-cry-quic-auth-token"}
	}
	if params.MasqueradeURL == "" {
		params.MasqueradeURL = "https://bing.com"
	}
	if params.CertFile == "" {
		params.CertFile = "/etc/freedom-cry/hysteria.crt"
	}
	if params.KeyFile == "" {
		params.KeyFile = "/etc/freedom-cry/hysteria.key"
	}

	tmpl, err := template.New("hysteria").Parse(hysteriaServerTmpl)
	if err != nil {
		return "", err
	}

	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, params); err != nil {
		return "", err
	}

	return buf.String(), nil
}

type HysteriaClientParams struct {
	Host        string
	Port        int
	Password    string
	SNI         string
	Insecure    bool
	CountryCode string
	NodeName    string
}

// BuildHysteria2Link generates standard hysteria2:// URI
func BuildHysteria2Link(params HysteriaClientParams) string {
	insecureStr := "0"
	if params.Insecure {
		insecureStr = "1"
	}

	q := url.Values{}
	q.Set("sni", params.SNI)
	q.Set("insecure", insecureStr)

	tag := fmt.Sprintf("FreedomCry-%s-%s", params.CountryCode, params.NodeName)
	return fmt.Sprintf("hysteria2://%s@%s:%d/?%s#%s",
		url.QueryEscape(params.Password),
		params.Host,
		params.Port,
		q.Encode(),
		url.QueryEscape(tag),
	)
}
