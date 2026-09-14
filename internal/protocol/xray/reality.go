package xray

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net/url"

	"golang.org/x/crypto/curve25519"
)

type RealityKeyPair struct {
	PrivateKey string `json:"private_key"`
	PublicKey  string `json:"public_key"`
	ShortID    string `json:"short_id"`
}

// GenerateRealityKeyPair generates an X25519 keypair for VLESS Reality
func GenerateRealityKeyPair() (*RealityKeyPair, error) {
	var priv [32]byte
	if _, err := rand.Read(priv[:]); err != nil {
		return nil, fmt.Errorf("failed to generate random bytes: %w", err)
	}

	// Clamp private key according to Curve25519 specification
	priv[0] &= 248
	priv[31] &= 127
	priv[31] |= 64

	pub, err := curve25519.X25519(priv[:], curve25519.Basepoint)
	if err != nil {
		return nil, fmt.Errorf("failed to derive public key: %w", err)
	}

	// Short ID: 8 random bytes -> 16 hex characters
	shortIDBytes := make([]byte, 8)
	if _, err := rand.Read(shortIDBytes); err != nil {
		return nil, fmt.Errorf("failed to generate short id: %w", err)
	}

	return &RealityKeyPair{
		PrivateKey: base64.RawURLEncoding.EncodeToString(priv[:]),
		PublicKey:  base64.RawURLEncoding.EncodeToString(pub),
		ShortID:    hex.EncodeToString(shortIDBytes),
	}, nil
}

// BuildVlessLink constructs a standard VLESS + Reality client URI
func BuildVlessLink(uuidStr, host string, port int, pubKey, sni, shortID, nodeName string) string {
	query := url.Values{}
	query.Set("type", "tcp")
	query.Set("security", "reality")
	query.Set("pbk", pubKey)
	query.Set("fp", "chrome")
	query.Set("sni", sni)
	query.Set("sid", shortID)
	query.Set("spx", "/")
	query.Set("flow", "xtls-rprx-vision")
	query.Set("encryption", "none")

	fragment := url.PathEscape("FreedomCry-" + nodeName)

	return fmt.Sprintf("vless://%s@%s:%d?%s#%s", uuidStr, host, port, query.Encode(), fragment)
}
