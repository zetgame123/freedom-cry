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

	// Generate random 32-char subscription token
	tokenBytes := make([]byte, 16)
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
		if err := tx.Where("is_online = ?", true).Find(&nodes).Error; err != nil {
			return err
		}

		for _, node := range nodes {
			// VLESS UUID
			vlessUUID := uuid.New().String()

			// AWG keypair
			awgKP, err := amneziawg.GenerateAWGKeyPair()
			if err != nil {
				return err
			}

			// Allocate IP: count existing keys for this node + 2 (10.8.0.2 .. 10.8.0.254)
			var keyCount int64
			tx.Model(&models.ClientKey{}).Where("node_id = ?", node.ID).Count(&keyCount)
			clientOctet := (keyCount % 250) + 2
			subnetOctet := (keyCount / 250)
			clientIP := fmt.Sprintf("10.8.%d.%d/32", subnetOctet, clientOctet)

			clientKey := models.ClientKey{
				SubscriptionID:  sub.ID,
				NodeID:          node.ID,
				Protocol:        models.ProtocolVless,
				VlessUUID:       vlessUUID,
				AwgAddress:      clientIP,
				AwgPrivateKey:   awgKP.PrivateKey,
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
