package amneziawg

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"fmt"

	"golang.org/x/crypto/curve25519"
)

type AWGKeyPair struct {
	PrivateKey   string `json:"private_key"`
	PublicKey    string `json:"public_key"`
	PresharedKey string `json:"preshared_key"`
}

type AWGObfuscationParams struct {
	Jc   int    `json:"jc"`
	Jmin int    `json:"jmin"`
	Jmax int    `json:"jmax"`
	S1   int    `json:"s1"`
	S2   int    `json:"s2"`
	H1   uint32 `json:"h1"`
	H2   uint32 `json:"h2"`
	H3   uint32 `json:"h3"`
	H4   uint32 `json:"h4"`
}

// GenerateAWGKeyPair generates WireGuard Curve25519 keypair and preshared key
func GenerateAWGKeyPair() (*AWGKeyPair, error) {
	var priv [32]byte
	if _, err := rand.Read(priv[:]); err != nil {
		return nil, fmt.Errorf("failed to generate random bytes: %w", err)
	}

	// Clamp according to WireGuard spec
	priv[0] &= 248
	priv[31] = (priv[31] & 127) | 64

	pub, err := curve25519.X25519(priv[:], curve25519.Basepoint)
	if err != nil {
		return nil, fmt.Errorf("failed to derive public key: %w", err)
	}

	var psk [32]byte
	if _, err := rand.Read(psk[:]); err != nil {
		return nil, fmt.Errorf("failed to generate psk: %w", err)
	}

	return &AWGKeyPair{
		PrivateKey:   base64.StdEncoding.EncodeToString(priv[:]),
		PublicKey:    base64.StdEncoding.EncodeToString(pub),
		PresharedKey: base64.StdEncoding.EncodeToString(psk[:]),
	}, nil
}

// GenerateDefaultObfuscationParams generates random obfuscation parameters for AmneziaWG
func GenerateDefaultObfuscationParams() (*AWGObfuscationParams, error) {
	var buf [16]byte
	if _, err := rand.Read(buf[:]); err != nil {
		return nil, err
	}

	// Ensure headers are non-zero and > 1000000
	h1 := binary.BigEndian.Uint32(buf[0:4]) | 0x100000
	h2 := binary.BigEndian.Uint32(buf[4:8]) | 0x200000
	h3 := binary.BigEndian.Uint32(buf[8:12]) | 0x300000
	h4 := binary.BigEndian.Uint32(buf[12:16]) | 0x400000

	return &AWGObfuscationParams{
		Jc:   4,
		Jmin: 50,
		Jmax: 1000,
		S1:   64,
		S2:   64,
		H1:   h1,
		H2:   h2,
		H3:   h3,
		H4:   h4,
	}, nil
}
