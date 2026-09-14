package models

import (
	"crypto/rand"
	"fmt"
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

type UserRole string

const (
	RoleUser  UserRole = "user"
	RoleAdmin UserRole = "admin"
)

type User struct {
	ID            uuid.UUID      `gorm:"type:uuid;primary_key;default:gen_random_uuid()" json:"id"`
	AccountNumber string         `gorm:"type:varchar(32);uniqueIndex;not null" json:"account_number"` // Mullvad-style: 1234-5678-9012-3456
	Email         string         `gorm:"index" json:"email,omitempty"`
	PasswordHash  string         `json:"-"`
	TelegramID    *int64         `gorm:"uniqueIndex" json:"telegram_id,omitempty"`
	Balance       float64        `gorm:"type:decimal(12,2);default:0.00" json:"balance"`
	Role          UserRole       `gorm:"type:varchar(20);default:'user'" json:"role"`
	IsActive      bool           `gorm:"default:true" json:"is_active"`
	CreatedAt     time.Time      `json:"created_at"`
	UpdatedAt     time.Time      `json:"updated_at"`
	DeletedAt     gorm.DeletedAt `gorm:"index" json:"-"`

	Subscriptions []Subscription `gorm:"foreignKey:UserID" json:"subscriptions,omitempty"`
}

// GenerateAccountNumber creates a cryptographically secure 16-digit account number (Mullvad style)
func GenerateAccountNumber() (string, error) {
	var digits [16]byte
	for i := 0; i < 16; i++ {
		b := make([]byte, 1)
		for {
			if _, err := rand.Read(b); err != nil {
				return "", err
			}
			val := b[0] & 0x0F
			if val < 10 {
				digits[i] = '0' + val
				break
			}
		}
	}
	return fmt.Sprintf("%s-%s-%s-%s",
		string(digits[0:4]),
		string(digits[4:8]),
		string(digits[8:12]),
		string(digits[12:16]),
	), nil
}

func (u *User) BeforeCreate(tx *gorm.DB) error {
	if u.ID == uuid.Nil {
		u.ID = uuid.New()
	}
	if u.AccountNumber == "" {
		acc, err := GenerateAccountNumber()
		if err != nil {
			return err
		}
		u.AccountNumber = acc
	}
	return nil
}
