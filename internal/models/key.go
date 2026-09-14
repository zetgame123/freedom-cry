package models

import (
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

type ProtocolType string

const (
	ProtocolVless     ProtocolType = "vless"
	ProtocolAmneziaWG ProtocolType = "amneziawg"
)

type ClientKey struct {
	ID             uuid.UUID    `gorm:"type:uuid;primary_key;default:gen_random_uuid()" json:"id"`
	SubscriptionID uuid.UUID    `gorm:"type:uuid;not null;index" json:"subscription_id"`
	NodeID         uuid.UUID    `gorm:"type:uuid;not null;index;uniqueIndex:idx_node_awg_addr,priority:1" json:"node_id"`
	Protocol       ProtocolType `gorm:"type:varchar(20);not null" json:"protocol"`

	// --- VLESS details ---
	VlessUUID string `gorm:"type:varchar(64)" json:"vless_uuid,omitempty"`

	// --- AmneziaWG details ---
	// NOTE: Client private key is stored ONLY encrypted with HKDF(sub.Token).
	// Master PostgreSQL at rest NEVER contains the plaintext private key (Zero-Knowledge at rest).
	AwgAddress         string `gorm:"type:varchar(100);uniqueIndex:idx_node_awg_addr,priority:2" json:"awg_address,omitempty"` // e.g. 10.8.0.2/32, fd00:8::2/128
	AwgPublicKey       string `gorm:"type:varchar(100)" json:"awg_public_key,omitempty"`                                       // client's public key (stored on server)
	AwgPrivateKeyEnc   string `gorm:"type:text" json:"-"`                                                                     // AES-256-GCM encrypted using sub.Token
	AwgPresharedKey    string `gorm:"type:varchar(100)" json:"-"`

	CreatedAt time.Time      `json:"created_at"`
	UpdatedAt time.Time      `json:"updated_at"`
	DeletedAt gorm.DeletedAt `gorm:"index" json:"-"`

	Node ServerNode `gorm:"foreignKey:NodeID" json:"node,omitempty"`
}

func (k *ClientKey) BeforeCreate(tx *gorm.DB) error {
	if k.ID == uuid.Nil {
		k.ID = uuid.New()
	}
	return nil
}
