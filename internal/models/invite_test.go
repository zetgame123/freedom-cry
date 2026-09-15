package models

import (
	"strings"
	"testing"
)

func TestGenerateInviteCode_Full128BitEntropy(t *testing.T) {
	code, err := GenerateInviteCode("FC")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	parts := strings.Split(code, "-")
	// Prefix "FC" + 8 chunks of 4 hex chars = 9 parts
	if len(parts) != 9 {
		t.Fatalf("expected 9 parts in invite code, got %d (code: %s)", len(parts), code)
	}

	if parts[0] != "FC" {
		t.Fatalf("expected prefix FC, got %s", parts[0])
	}

	hexPayload := strings.Join(parts[1:], "")
	if len(hexPayload) != 32 {
		t.Fatalf("expected 32 hex characters (128 bits), got %d (payload: %s)", len(hexPayload), hexPayload)
	}

	for _, p := range parts[1:] {
		if len(p) != 4 {
			t.Fatalf("expected chunk length 4, got %d (%s)", len(p), p)
		}
	}

	// Verify uniqueness across 1000 generated codes
	seen := make(map[string]bool)
	for i := 0; i < 1000; i++ {
		c, err := GenerateInviteCode("")
		if err != nil {
			t.Fatalf("failed at iteration %d: %v", i, err)
		}
		if seen[c] {
			t.Fatalf("collision detected on iteration %d for code %s", i, c)
		}
		seen[c] = true
	}
}
