package api

import (
	"testing"

	"freedom-cry/internal/config"
)

func TestIsAllowedOrigin(t *testing.T) {
	cfgProd := &config.Config{
		Server: config.ServerConfig{Mode: "release"},
		App:    config.AppConfig{BaseURL: "https://vpn.freedomcry.net"},
	}

	tests := []struct {
		origin  string
		allowed bool
	}{
		{"https://vpn.freedomcry.net", true},
		{"https://vpn.freedomcry.net/", false},
		{"https://vpn.freedomcry.net.attacker.com", false},
		{"https://vpn.freedomcry.net-evil.org", false},
		{"http://evil.com", false},
		{"http://localhost", false},
		{"http://127.0.0.1", false},
		{"", false},
	}

	for _, tc := range tests {
		got := isAllowedOrigin(tc.origin, cfgProd)
		if got != tc.allowed {
			t.Errorf("origin %q in release mode: expected %v, got %v", tc.origin, tc.allowed, got)
		}
	}

	// In debug mode, localhost is allowed
	cfgDev := &config.Config{
		Server: config.ServerConfig{Mode: "debug"},
		App:    config.AppConfig{BaseURL: "http://localhost:8080"},
	}

	devTests := []struct {
		origin  string
		allowed bool
	}{
		{"http://localhost:8080", true},
		{"http://localhost:3000", true},
		{"http://127.0.0.1:5173", true},
		{"https://evil.com", false},
		{"http://localhost.attacker.com", false},
	}

	for _, tc := range devTests {
		got := isAllowedOrigin(tc.origin, cfgDev)
		if got != tc.allowed {
			t.Errorf("origin %q in dev mode: expected %v, got %v", tc.origin, tc.allowed, got)
		}
	}
}
