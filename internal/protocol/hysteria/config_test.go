package hysteria

import (
	"strings"
	"testing"
)

func TestHysteriaConfigAndLink(t *testing.T) {
	serverConf, err := GenerateHysteriaServerConfig(HysteriaServerParams{
		ListenPort:      8443,
		MasqueradeURL:   "https://bing.com",
		ClientPasswords: []string{"testpass123"},
	})
	if err != nil {
		t.Fatalf("GenerateHysteriaServerConfig failed: %v", err)
	}

	if !strings.Contains(serverConf, "listen: :8443") || !strings.Contains(serverConf, "password: testpass123") {
		t.Errorf("server config missing expected parameters")
	}

	link := BuildHysteria2Link(HysteriaClientParams{
		Host:        "nl1.freedomcry.net",
		Port:        8443,
		Password:    "secretpass",
		SNI:         "gateway.icloud.com",
		Insecure:    false,
		CountryCode: "NL",
		NodeName:    "Amsterdam",
	})

	if !strings.HasPrefix(link, "hysteria2://secretpass@nl1.freedomcry.net:8443/?") {
		t.Errorf("invalid hysteria link prefix: %s", link)
	}
	if !strings.Contains(link, "sni=gateway.icloud.com") {
		t.Errorf("link missing SNI parameter: %s", link)
	}
}
