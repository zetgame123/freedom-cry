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

func TestClientConfigDualStackAndDecryptedKey(t *testing.T) {
	token := "4f2a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a"
	kp, err := GenerateAWGKeyPair()
	if err != nil {
		t.Fatalf("failed to generate key pair: %v", err)
	}

	encPrivKey, err := EncryptClientPrivateKey(token, kp.PrivateKey)
	if err != nil {
		t.Fatalf("failed to encrypt private key: %v", err)
	}

	decryptedPrivKey, err := DecryptClientPrivateKey(token, encPrivKey)
	if err != nil {
		t.Fatalf("failed to decrypt private key: %v", err)
	}

	if decryptedPrivKey != kp.PrivateKey {
		t.Fatalf("expected decrypted key %s, got %s", kp.PrivateKey, decryptedPrivKey)
	}

	params := ClientConfigParams{
		ClientPrivateKey: decryptedPrivKey,
		ClientAddress:    "10.8.0.2/32, fd00:8::2/128",
		DNS:              "1.1.1.1, 8.8.8.8",
		Jc:               4,
		Jmin:             50,
		Jmax:             1000,
		S1:               64,
		S2:               64,
		H1:               1234567,
		H2:               2345678,
		H3:               3456789,
		H4:               4567890,
		ServerPublicKey:  kp.PublicKey,
		PresharedKey:     kp.PresharedKey,
		Endpoint:         "vpn.example.com:51820",
		AllowedIPs:       "0.0.0.0/0, ::/0",
	}

	conf, err := GenerateClientConfig(params)
	if err != nil {
		t.Fatalf("GenerateClientConfig error: %v", err)
	}

	// Verify no placeholder exists and real private key is present
	if strings.Contains(conf, "<INSERT_YOUR_LOCAL_CLIENT_PRIVATE_KEY_HERE>") {
		t.Errorf("conf must not contain placeholder")
	}
	if !strings.Contains(conf, "PrivateKey = "+kp.PrivateKey) {
		t.Errorf("conf missing valid PrivateKey")
	}
	if !strings.Contains(conf, "Address = 10.8.0.2/32, fd00:8::2/128") {
		t.Errorf("conf missing dual-stack address")
	}
	if !strings.Contains(conf, "AllowedIPs = 0.0.0.0/0, ::/0") {
		t.Errorf("conf missing dual-stack AllowedIPs")
	}
}
