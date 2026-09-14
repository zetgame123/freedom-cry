package xray

import (
	"strings"
	"testing"
)

func TestGenerateRealityKeyPair(t *testing.T) {
	kp, err := GenerateRealityKeyPair()
	if err != nil {
		t.Fatalf("GenerateRealityKeyPair error: %v", err)
	}

	if len(kp.PrivateKey) == 0 {
		t.Fatal("empty private key")
	}
	if len(kp.PublicKey) == 0 {
		t.Fatal("empty public key")
	}
	if len(kp.ShortID) != 16 {
		t.Fatalf("expected 16 hex chars short id, got %s (len: %d)", kp.ShortID, len(kp.ShortID))
	}
}

func TestBuildVlessLink(t *testing.T) {
	uuidStr := "11111111-2222-3333-4444-555555555555"
	link := BuildVlessLink(uuidStr, "node.example.com", 443, "pubKey123", "dl.google.com", "deadbeef12345678", "NL-Fast")

	if !strings.HasPrefix(link, "vless://") {
		t.Fatalf("link does not start with vless://: %s", link)
	}
	if !strings.Contains(link, "security=reality") {
		t.Fatalf("link missing security=reality: %s", link)
	}
	if !strings.Contains(link, "flow=xtls-rprx-vision") {
		t.Fatalf("link missing flow: %s", link)
	}
	if !strings.Contains(link, "FreedomCry-NL-Fast") {
		t.Fatalf("link missing fragment: %s", link)
	}
}
