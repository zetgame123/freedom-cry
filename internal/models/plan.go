package models

import (
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

type Plan struct {
	ID               uuid.UUID      `gorm:"type:uuid;primary_key;default:gen_random_uuid()" json:"id"`
	Name             string         `gorm:"not null" json:"name"`
	Description      string         `json:"description"`
	Price            float64        `gorm:"type:decimal(10,2);not null" json:"price"`
	DurationDays     int            `gorm:"not null" json:"duration_days"`
	TrafficLimitGB   int64          `gorm:"not null;default:0" json:"traffic_limit_gb"` // 0 = unlimited
	SpeedLimitMbps   int            `gorm:"default:0" json:"speed_limit_mbps"`          // 0 = unlimited
	AllowedProtocols string         `gorm:"default:'vless,awg'" json:"allowed_protocols"`
	IsActive         bool           `gorm:"default:true" json:"is_active"`
	CreatedAt        time.Time      `json:"created_at"`
	UpdatedAt        time.Time      `json:"updated_at"`
	DeletedAt        gorm.DeletedAt `gorm:"index" json:"-"`
}

func (p *Plan) BeforeCreate(tx *gorm.DB) error {
	if p.ID == uuid.Nil {
		p.ID = uuid.New()
	}
	return nil
}
