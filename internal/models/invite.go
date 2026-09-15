package models

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

type InviteCode struct {
	ID          uuid.UUID      `gorm:"type:uuid;primary_key;default:gen_random_uuid()" json:"id"`
	Code        string         `gorm:"type:varchar(64);uniqueIndex;not null" json:"code"`
	Description string         `gorm:"type:varchar(255)" json:"description"`
	MaxUses     int            `gorm:"default:1" json:"max_uses"` // 0 = unlimited
	UsesCount   int            `gorm:"default:0" json:"uses_count"`
	IsActive    bool           `gorm:"default:true" json:"is_active"`
	PlanID      *uuid.UUID     `gorm:"type:uuid" json:"plan_id"`
	Plan        *Plan          `json:"plan,omitempty"`
	CreatedAt   time.Time      `json:"created_at"`
	UpdatedAt   time.Time      `json:"updated_at"`
	DeletedAt   gorm.DeletedAt `gorm:"index" json:"-"`
}

// GenerateInviteCode creates a cryptographically random invite code (e.g. FC-8F2B-91A4)
func GenerateInviteCode(prefix string) (string, error) {
	bytes := make([]byte, 4)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	h := strings.ToUpper(hex.EncodeToString(bytes))
	if prefix == "" {
		prefix = "FC"
	}
	return fmt.Sprintf("%s-%s-%s", prefix, h[:4], h[4:]), nil
}
