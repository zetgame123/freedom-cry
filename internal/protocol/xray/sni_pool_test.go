package xray

import (
	"testing"
)

func TestSelectHealthySNI(t *testing.T) {
	// Fallback test when pool has invalid domains
	fallback := "dl.google.com"
	selected := SelectHealthySNI("invalid-domain-1234567.local, another-bogus-one.fake", fallback)
	if selected != fallback {
		t.Errorf("expected fallback %s, got %s", fallback, selected)
	}

	// Test with valid pool
	healthy := SelectHealthySNI("www.microsoft.com,gateway.icloud.com", fallback)
	if healthy == "" {
		t.Errorf("expected non-empty healthy SNI")
	}
}
