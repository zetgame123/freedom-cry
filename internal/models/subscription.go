package models

import (
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

type SubStatus string

const (
	SubActive    SubStatus = "active"
	SubExpired   SubStatus = "expired"
	SubSuspended SubStatus = "suspended"
)

type Subscription struct {
	ID               uuid.UUID      `gorm:"type:uuid;primary_key;default:gen_random_uuid()" json:"id"`
	UserID           uuid.UUID      `gorm:"type:uuid;not null;index" json:"user_id"`
	PlanID           uuid.UUID      `gorm:"type:uuid;not null;index" json:"plan_id"`
	Token            string         `gorm:"type:varchar(64);uniqueIndex;not null" json:"token"` // Secret token for subscription URL
	Status           SubStatus      `gorm:"type:varchar(20);default:'active'" json:"status"`
	TrafficLimitBytes int64         `gorm:"default:0" json:"traffic_limit_bytes"` // 0 = unlimited
	TrafficUsedBytes  int64         `gorm:"default:0" json:"traffic_used_bytes"`
	ExpiresAt        time.Time      `json:"expires_at"`
	CreatedAt        time.Time      `json:"created_at"`
	UpdatedAt        time.Time      `json:"updated_at"`
	DeletedAt        gorm.DeletedAt `gorm:"index" json:"-"`

	User       User        `gorm:"foreignKey:UserID" json:"user,omitempty"`
	Plan       Plan        `gorm:"foreignKey:PlanID" json:"plan,omitempty"`
	ClientKeys []ClientKey `gorm:"foreignKey:SubscriptionID" json:"client_keys,omitempty"`
}

func (s *Subscription) BeforeCreate(tx *gorm.DB) error {
	if s.ID == uuid.Nil {
		s.ID = uuid.New()
	}
	return nil
}

func (s *Subscription) IsValid() bool {
	return s.Status == SubActive && time.Now().Before(s.ExpiresAt) && (s.TrafficLimitBytes == 0 || s.TrafficUsedBytes < s.TrafficLimitBytes)
}
