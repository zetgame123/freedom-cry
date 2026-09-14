package amneziawg

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"io"

	"golang.org/x/crypto/hkdf"
)

const (
	privKeyTokenSalt = "freedom-cry-awg-token-salt-v1"
	privKeyHKDFInfo  = "freedom-cry-client-privkey-encryption"
)

// EncryptClientPrivateKey encrypts the WireGuard client private key using AES-256-GCM
// with a key derived from the user's secret subscription token via HKDF-SHA256.
// This guarantees Zero-Knowledge at rest in the database: if PostgreSQL is compromised,
// an attacker cannot obtain any client private keys without the corresponding subscription tokens.
func EncryptClientPrivateKey(token string, plainPrivKey string) (string, error) {
	if token == "" || plainPrivKey == "" {
		return "", errors.New("token and private key must not be empty")
	}

	hkdfReader := hkdf.New(sha256.New, []byte(token), []byte(privKeyTokenSalt), []byte(privKeyHKDFInfo))
	aesKey := make([]byte, 32)
	if _, err := io.ReadFull(hkdfReader, aesKey); err != nil {
		return "", fmt.Errorf("failed to derive encryption key: %w", err)
	}

	block, err := aes.NewCipher(aesKey)
	if err != nil {
		return "", fmt.Errorf("failed to create cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("failed to create GCM: %w", err)
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", fmt.Errorf("failed to generate nonce: %w", err)
	}

	ciphertext := gcm.Seal(nonce, nonce, []byte(plainPrivKey), nil)
	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

// DecryptClientPrivateKey decrypts the WireGuard client private key using AES-256-GCM
// with the key derived from the user's secret subscription token.
func DecryptClientPrivateKey(token string, encPrivKeyBase64 string) (string, error) {
	if token == "" || encPrivKeyBase64 == "" {
		return "", errors.New("token and encrypted private key must not be empty")
	}

	data, err := base64.StdEncoding.DecodeString(encPrivKeyBase64)
	if err != nil {
		return "", fmt.Errorf("failed to decode base64: %w", err)
	}

	hkdfReader := hkdf.New(sha256.New, []byte(token), []byte(privKeyTokenSalt), []byte(privKeyHKDFInfo))
	aesKey := make([]byte, 32)
	if _, err := io.ReadFull(hkdfReader, aesKey); err != nil {
		return "", fmt.Errorf("failed to derive decryption key: %w", err)
	}

	block, err := aes.NewCipher(aesKey)
	if err != nil {
		return "", fmt.Errorf("failed to create cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("failed to create GCM: %w", err)
	}

	nonceSize := gcm.NonceSize()
	if len(data) < nonceSize {
		return "", errors.New("ciphertext too short")
	}

	nonce, ciphertext := data[:nonceSize], data[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return "", fmt.Errorf("failed to decrypt client private key: %w", err)
	}

	return string(plaintext), nil
}
