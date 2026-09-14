package amneziawg

import (
	"strings"
	"testing"
)

func TestGenerateAWGKeyPair(t *testing.T) {
	kp, err := GenerateAWGKeyPair()
	if err != nil {
		t.Fatalf("GenerateAWGKeyPair error: %v", err)
	}

	if len(kp.PrivateKey) == 0 || len(kp.PublicKey) == 0 || len(kp.PresharedKey) == 0 {
		t.Fatal("empty keys in AWG key pair")
	}
}

func TestGenerateClientConfig(t *testing.T) {
	params := ClientConfigParams{
		ClientPrivateKey: "cPrivKey123=",
		ClientAddress:    "10.8.0.2/32",
		DNS:              "1.1.1.1",
		Jc:               4,
		Jmin:             50,
		Jmax:             1000,
		S1:               64,
		S2:               64,
		H1:               1234567,
		H2:               2345678,
		H3:               3456789,
		H4:               4567890,
		ServerPublicKey:  "sPubKey123=",
		PresharedKey:     "psk123=",
		Endpoint:         "vpn.example.com:51820",
		AllowedIPs:       "0.0.0.0/0",
	}

	conf, err := GenerateClientConfig(params)
	if err != nil {
		t.Fatalf("GenerateClientConfig error: %v", err)
	}

	expectedParts := []string{
		"[Interface]",
		"PrivateKey = cPrivKey123=",
		"Address = 10.8.0.2/32",
		"Jc = 4",
		"H1 = 1234567",
		"[Peer]",
		"PublicKey = sPubKey123=",
		"PresharedKey = psk123=",
		"Endpoint = vpn.example.com:51820",
	}

	for _, p := range expectedParts {
		if !strings.Contains(conf, p) {
			t.Errorf("expected config to contain '%s', got:\n%s", p, conf)
		}
	}
}
