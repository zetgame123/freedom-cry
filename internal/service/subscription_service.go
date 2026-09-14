package service

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"freedom-cry/internal/config"
	"freedom-cry/internal/models"
	"freedom-cry/internal/protocol/amneziawg"

	"github.com/google/uuid"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

type SubscriptionService struct {
	db  *gorm.DB
	cfg *config.Config
}

func NewSubscriptionService(db *gorm.DB, cfg *config.Config) *SubscriptionService {
	return &SubscriptionService{db: db, cfg: cfg}
}

func (s *SubscriptionService) CreateSubscription(userID, planID uuid.UUID) (*models.Subscription, error) {
	var user models.User
	if err := s.db.First(&user, "id = ?", userID).Error; err != nil {
		return nil, errors.New("user not found")
	}

	var plan models.Plan
	if err := s.db.First(&plan, "id = ?", planID).Error; err != nil {
		return nil, errors.New("plan not found")
	}

	// Generate cryptographically secure 256-bit (64-char hex) subscription token
	tokenBytes := make([]byte, 32)
	if _, err := rand.Read(tokenBytes); err != nil {
		return nil, err
	}
	subToken := hex.EncodeToString(tokenBytes)

	trafficBytes := plan.TrafficLimitGB * 1024 * 1024 * 1024
	expiresAt := time.Now().AddDate(0, 0, plan.DurationDays)

	sub := models.Subscription{
		UserID:            userID,
		PlanID:            planID,
		Token:             subToken,
		Status:            models.SubActive,
		TrafficLimitBytes: trafficBytes,
		TrafficUsedBytes:  0,
		ExpiresAt:         expiresAt,
	}

	err := s.db.Transaction(func(tx *gorm.DB) error {
		if err := tx.Create(&sub).Error; err != nil {
			return err
		}

		// Provision client keys for each active node
		var nodes []models.ServerNode
		if err := tx.Where("is_online = ? AND is_revoked = ?", true, false).Find(&nodes).Error; err != nil {
			return err
		}

		for _, node := range nodes {
			// VLESS UUID
			vlessUUID := uuid.New().String()

			// Generate initial AWG client keypair
			// NOTE: Only the Public Key is retained on Master.
			// Private key is never persisted in PostgreSQL!
			awgKP, err := amneziawg.GenerateAWGKeyPair()
			if err != nil {
				return err
			}

			// Atomic concurrency-safe IP allocation with row-level locking:
			var lockedNode models.ServerNode
			if err := tx.Clauses(clause.Locking{Strength: "UPDATE"}).First(&lockedNode, "id = ?", node.ID).Error; err != nil {
				return err
			}

			lockedNode.LastAllocatedIP++
			clientOctet := (lockedNode.LastAllocatedIP % 250) + 2
			subnetOctet := (lockedNode.LastAllocatedIP / 250) % 255
			clientIP := fmt.Sprintf("10.8.%d.%d/32", subnetOctet, clientOctet)

			if err := tx.Model(&models.ServerNode{}).Where("id = ?", lockedNode.ID).Update("last_allocated_ip", lockedNode.LastAllocatedIP).Error; err != nil {
				return err
			}

			clientKey := models.ClientKey{
				SubscriptionID:  sub.ID,
				NodeID:          node.ID,
				Protocol:        models.ProtocolVless,
				VlessUUID:       vlessUUID,
				AwgAddress:      clientIP,
				AwgPublicKey:    awgKP.PublicKey,
				AwgPresharedKey: awgKP.PresharedKey,
			}

			if err := tx.Create(&clientKey).Error; err != nil {
				return err
			}
		}

		return nil
	})

	if err != nil {
		return nil, err
	}

	// Preload relations
	s.db.Preload("Plan").Preload("ClientKeys.Node").First(&sub, "id = ?", sub.ID)
	return &sub, nil
}

func (s *SubscriptionService) GetByToken(token string) (*models.Subscription, error) {
	if len(token) < 16 {
		return nil, errors.New("invalid token format")
	}

	var sub models.Subscription
	err := s.db.
		Preload("Plan").
		Preload("User").
		Preload("ClientKeys.Node").
		First(&sub, "token = ?", token).Error
	if err != nil {
		return nil, errors.New("subscription not found")
	}
	return &sub, nil
}

func (s *SubscriptionService) GetUserSubscriptions(userID uuid.UUID) ([]models.Subscription, error) {
	var subs []models.Subscription
	err := s.db.
		Preload("Plan").
		Preload("ClientKeys.Node").
		Where("user_id = ?", userID).
		Order("created_at desc").
		Find(&subs).Error
	return subs, err
}
