package middleware

import (
	"testing"
)

func TestMaskSensitivePath(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"/health", "/health"},
		{"/api/v1/auth/login", "/api/v1/auth/login"},
		{"/sub/4f2a7b8c9d0e1f2a3b4c5d6e7f8a9b0c", "/sub/[REDACTED]"},
		{"/sub/4f2a7b8c9d0e1f2a3b4c5d6e7f8a9b0c/vless", "/sub/[REDACTED]/vless"},
		{"/sub/4f2a7b8c9d0e1f2a3b4c5d6e7f8a9b0c/awg/nl1", "/sub/[REDACTED]/awg/nl1"},
		{"/sub/4f2a7b8c9d0e1f2a3b4c5d6e7f8a9b0c/info", "/sub/[REDACTED]/info"},
	}

	for _, tt := range tests {
		got := maskSensitivePath(tt.input)
		if got != tt.expected {
			t.Errorf("maskSensitivePath(%q) = %q, want %q", tt.input, got, tt.expected)
		}
	}
}

func TestMaskQuery(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"", ""},
		{"page=1&limit=10", "page=1&limit=10"},
		{"token=secret123456", "token=[REDACTED]"},
		{"key=mykey&user=john", "key=[REDACTED]&user=john"},
	}

	for _, tt := range tests {
		got := maskQuery(tt.input)
		if got != tt.expected {
			t.Errorf("maskQuery(%q) = %q, want %q", tt.input, got, tt.expected)
		}
	}
}
