package amneziawg

import (
	"testing"
)

func TestClientPrivateKeyEncryptDecrypt(t *testing.T) {
	token := "4f2a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a"
	plainPrivKey := "yAnz5TF+lXXJ7iZq8e9zT4Q8K5u4jY+H6mN8pQ1rTs="

	encrypted, err := EncryptClientPrivateKey(token, plainPrivKey)
	if err != nil {
		t.Fatalf("encryption failed: %v", err)
	}

	if encrypted == plainPrivKey {
		t.Fatalf("ciphertext must not match plaintext")
	}

	decrypted, err := DecryptClientPrivateKey(token, encrypted)
	if err != nil {
		t.Fatalf("decryption failed: %v", err)
	}

	if decrypted != plainPrivKey {
		t.Fatalf("expected decrypted key %q, got %q", plainPrivKey, decrypted)
	}

	// Test wrong token fails authentication
	wrongToken := "0000000000000000000000000000000000000000000000000000000000000000"
	_, err = DecryptClientPrivateKey(wrongToken, encrypted)
	if err == nil {
		t.Fatalf("expected error when decrypting with wrong token, got nil")
	}

	// Test tampered ciphertext
	tampered := encrypted[:len(encrypted)-4] + "AAAA"
	_, err = DecryptClientPrivateKey(token, tampered)
	if err == nil {
		t.Fatalf("expected error when decrypting tampered ciphertext, got nil")
	}
}
