package service

import (
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"sync"
	"time"

	"freedom-cry/internal/models"
	"freedom-cry/internal/protocol/blind"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

type BlindTokenService struct {
	db      *gorm.DB
	keyPair *blind.BlindKeyPair
	mu      sync.RWMutex
}

func NewBlindTokenService(db *gorm.DB) (*BlindTokenService, error) {
	kp, err := blind.GenerateBlindKeyPair()
	if err != nil {
		return nil, fmt.Errorf("failed to initialize blind signing keys: %w", err)
	}

	return &BlindTokenService{
		db:      db,
		keyPair: kp,
	}, nil
}

// GetPublicKeyPEM returns the Master public key in PEM format so nodes and clients can verify signatures
func (s *BlindTokenService) GetPublicKeyPEM() (string, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	pubASN1, err := x509.MarshalPKIXPublicKey(s.keyPair.PublicKey)
	if err != nil {
		return "", err
	}

	block := &pem.Block{
		Type:  "RSA PUBLIC KEY",
		Bytes: pubASN1,
	}

	return string(pem.EncodeToMemory(block)), nil
}

// GetPublicKey returns the raw RSA public key
func (s *BlindTokenService) GetPublicKey() *rsa.PublicKey {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.keyPair.PublicKey
}

// SignBlindedToken verifies user has an active subscription, then signs the blinded message with Master's private key.
// Master NEVER sees the plaintext token seed.
func (s *BlindTokenService) SignBlindedToken(userID uuid.UUID, blindedMessageHex string) (string, error) {
	// 1. Verify user subscription status
	var sub models.Subscription
	err := s.db.Where("user_id = ? AND status = ? AND expires_at > ?", userID, models.SubActive, time.Now()).First(&sub).Error
	if err != nil {
		return "", errors.New("active subscription required for blind token issuance")
	}

	// 2. Parse blinded message big.Int
	blindedBytes, err := hex.DecodeString(blindedMessageHex)
	if err != nil {
		return "", fmt.Errorf("invalid hex encoding: %w", err)
	}
	blindedMsg := new(big.Int).SetBytes(blindedBytes)

	// 3. Sign blinded message
	s.mu.RLock()
	sigPrime, err := blind.SignBlindedMessage(s.keyPair.PrivateKey, blindedMsg)
	s.mu.RUnlock()
	if err != nil {
		return "", fmt.Errorf("blind signing failed: %w", err)
	}

	return hex.EncodeToString(sigPrime.Bytes()), nil
}

type RedemptionResult struct {
	SessionToken string    `json:"session_token"`
	VlessUUID    string    `json:"vless_uuid"`
	ExpiresAt    time.Time `json:"expires_at"`
}

// RedeemToken verifies an unblinded Privacy Pass signature (m, s) and checks the nullifier registry.
// This endpoint is completely anonymous and unlinkable: Master does NOT know which account requested it.
func (s *BlindTokenService) RedeemToken(tokenSeedHex string, signatureHex string) (*RedemptionResult, error) {
	tokenSeed, err := hex.DecodeString(tokenSeedHex)
	if err != nil || len(tokenSeed) == 0 {
		return nil, errors.New("invalid token seed hex")
	}

	sigBytes, err := hex.DecodeString(signatureHex)
	if err != nil || len(sigBytes) == 0 {
		return nil, errors.New("invalid signature hex")
	}
	signature := new(big.Int).SetBytes(sigBytes)

	// 1. Verify cryptographic blind signature against Master public key
	s.mu.RLock()
	valid := blind.VerifyRedeemedToken(s.keyPair.PublicKey, tokenSeed, signature)
	s.mu.RUnlock()
	if !valid {
		return nil, errors.New("invalid or forged blind signature")
	}

	// 2. Nullifier check (Double-Spend Prevention)
	h := sha256.Sum256(tokenSeed)
	tokenHash := hex.EncodeToString(h[:])

	now := time.Now()
	expiresAt := now.Add(24 * time.Hour)

	err = s.db.Transaction(func(tx *gorm.DB) error {
		var existing models.RedeemedBlindToken
		if err := tx.Where("token_hash = ?", tokenHash).First(&existing).Error; err == nil {
			return errors.New("token has already been redeemed (double-spend rejected)")
		}

		record := models.RedeemedBlindToken{
			TokenHash:  tokenHash,
			RedeemedAt: now,
			ExpiresAt:  expiresAt,
		}
		return tx.Create(&record).Error
	})

	if err != nil {
		return nil, err
	}

	// 3. Issue anonymous ephemeral VLESS UUID and access credentials
	ephemeralVlessUUID := uuid.New().String()
	sessionToken := uuid.New().String()

	return &RedemptionResult{
		SessionToken: sessionToken,
		VlessUUID:    ephemeralVlessUUID,
		ExpiresAt:    expiresAt,
	}, nil
}
