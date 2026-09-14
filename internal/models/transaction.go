package models

import (
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

type TxStatus string

const (
	TxPending   TxStatus = "pending"
	TxCompleted TxStatus = "completed"
	TxFailed    TxStatus = "failed"
	TxCancelled TxStatus = "cancelled"
)

type Transaction struct {
	ID           uuid.UUID      `gorm:"type:uuid;primary_key;default:gen_random_uuid()" json:"id"`
	UserID       uuid.UUID      `gorm:"type:uuid;not null;index" json:"user_id"`
	Amount       float64        `gorm:"type:decimal(12,2);not null" json:"amount"`
	Currency     string         `gorm:"type:varchar(10);default:'RUB'" json:"currency"`
	Description  string         `json:"description"`
	Provider     string         `gorm:"type:varchar(50);not null" json:"provider"` // "stars", "crypto", "yookassa", "manual"
	ProviderTxID string         `gorm:"type:varchar(100)" json:"provider_tx_id,omitempty"`
	Status       TxStatus       `gorm:"type:varchar(20);default:'pending'" json:"status"`
	CreatedAt    time.Time      `json:"created_at"`
	UpdatedAt    time.Time      `json:"updated_at"`
	DeletedAt    gorm.DeletedAt `gorm:"index" json:"-"`

	User User `gorm:"foreignKey:UserID" json:"user,omitempty"`
}

func (t *Transaction) BeforeCreate(tx *gorm.DB) error {
	if t.ID == uuid.Nil {
		t.ID = uuid.New()
	}
	return nil
}
