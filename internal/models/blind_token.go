package models

import (
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

// RedeemedBlindToken serves as a cryptographic nullifier registry to prevent double-spending
// of unblinded Privacy Pass tokens. Contains NO link to user accounts or identity.
type RedeemedBlindToken struct {
	ID         uuid.UUID `gorm:"type:uuid;primary_key;default:gen_random_uuid()" json:"id"`
	TokenHash  string    `gorm:"type:varchar(64);uniqueIndex;not null" json:"token_hash"` // SHA-256 hex of token seed
	RedeemedAt time.Time `gorm:"index" json:"redeemed_at"`
	ExpiresAt  time.Time `gorm:"index" json:"expires_at"`
}

func (t *RedeemedBlindToken) BeforeCreate(tx *gorm.DB) error {
	if t.ID == uuid.Nil {
		t.ID = uuid.New()
	}
	if t.RedeemedAt.IsZero() {
		t.RedeemedAt = time.Now()
	}
	return nil
}
