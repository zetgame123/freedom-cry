package routing

import (
	"testing"
)

func TestDetermineRouting(t *testing.T) {
	tests := []struct {
		target   string
		expected RouteAction
	}{
		// Private LAN IPs
		{"127.0.0.1", ActionDirect},
		{"192.168.1.1", ActionDirect},
		{"10.200.0.5", ActionDirect},
		{"172.20.0.1", ActionDirect},
		{"::1", ActionDirect},

		// Russian domestic services & TLDs
		{"gosuslugi.ru", ActionDirect},
		{"api.gosuslugi.ru", ActionDirect},
		{"sberbank.ru", ActionDirect},
		{"online.sberbank.ru:443", ActionDirect},
		{"yandex.ru", ActionDirect},
		{"vk.com", ActionDirect},
		{"customs.gov.ru", ActionDirect},
		{"example.рф", ActionDirect},
		{"test.xn--p1ai", ActionDirect},

		// Censored services (even if on .ru like theins.ru)
		{"theins.ru", ActionTunnel},
		{"instagram.com", ActionTunnel},
		{"graph.instagram.com:443", ActionTunnel},
		{"x.com", ActionTunnel},
		{"twitter.com", ActionTunnel},
		{"chatgpt.com", ActionTunnel},
		{"openai.com", ActionTunnel},
		{"rutracker.org", ActionTunnel},
		{"meduza.io", ActionTunnel},

		// General foreign traffic
		{"google.com", ActionTunnel},
		{"cloudflare.com", ActionTunnel},
		{"github.com", ActionTunnel},
		{"8.8.8.8", ActionTunnel},
	}

	for _, tc := range tests {
		got := DetermineRouting(tc.target)
		if got != tc.expected {
			t.Errorf("DetermineRouting(%q) = %s; want %s", tc.target, got, tc.expected)
		}
	}
}

func TestGenerateSingBoxRouteRules(t *testing.T) {
	rules := GenerateSingBoxRouteRules()
	if len(rules) == 0 {
		t.Fatal("expected non-empty sing-box rules")
	}

	lastRule := rules[len(rules)-1]
	if lastRule["outbound"] != "proxy" {
		t.Errorf("expected default rule outbound to be 'proxy', got %v", lastRule["outbound"])
	}

	// Verify censoredDomains appears BEFORE russianTLDs
	censoredIdx := -1
	russianIdx := -1
	for i, r := range rules {
		if suffixes, ok := r["domain_suffix"].([]string); ok && len(suffixes) > 0 {
			if suffixes[0] == "instagram.com" {
				censoredIdx = i
			}
			if suffixes[0] == ".ru" {
				russianIdx = i
			}
		}
	}
	if censoredIdx == -1 || russianIdx == -1 {
		t.Fatalf("missing expected rules in singbox route rules: censoredIdx=%d, russianIdx=%d", censoredIdx, russianIdx)
	}
	if censoredIdx >= russianIdx {
		t.Errorf("CRITICAL ROUTING LEAK: censored domains rule (idx %d) must precede russian TLDs rule (idx %d)", censoredIdx, russianIdx)
	}
}

