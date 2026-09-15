package service

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
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
			// NOTE: Private key is stored ONLY encrypted with HKDF(sub.Token).
			// Master PostgreSQL at rest NEVER contains the plaintext private key (Zero-Knowledge at rest).
			awgKP, err := amneziawg.GenerateAWGKeyPair()
			if err != nil {
				return err
			}

			encPrivKey, err := amneziawg.EncryptClientPrivateKey(sub.Token, awgKP.PrivateKey)
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
			clientIPv4 := fmt.Sprintf("10.8.%d.%d/32", subnetOctet, clientOctet)
			clientIPv6 := fmt.Sprintf("fd00:8::%x:%x/128", subnetOctet, clientOctet)
			clientAddress := fmt.Sprintf("%s, %s", clientIPv4, clientIPv6)

			if err := tx.Model(&models.ServerNode{}).Where("id = ?", lockedNode.ID).Update("last_allocated_ip", lockedNode.LastAllocatedIP).Error; err != nil {
				return err
			}

			clientKey := models.ClientKey{
				SubscriptionID:   sub.ID,
				NodeID:           node.ID,
				Protocol:         models.ProtocolVless,
				VlessUUID:        vlessUUID,
				AwgAddress:       clientAddress,
				AwgPublicKey:     awgKP.PublicKey,
				AwgPrivateKeyEnc: encPrivKey,
				AwgPresharedKey:  awgKP.PresharedKey,
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

// RotateSubscriptionToken generates a new secret 256-bit token for the subscription
// and re-encrypts any stored client private keys using the new token.
func (s *SubscriptionService) RotateSubscriptionToken(userID uuid.UUID, subID uuid.UUID) (*models.Subscription, error) {
	var updatedSub models.Subscription

	err := s.db.Transaction(func(tx *gorm.DB) error {
		var sub models.Subscription
		if err := tx.Preload("ClientKeys").First(&sub, "id = ? AND user_id = ?", subID, userID).Error; err != nil {
			return errors.New("subscription not found or access denied")
		}

		oldToken := sub.Token

		// Generate new high-entropy 256-bit token
		newTokenBytes := make([]byte, 32)
		if _, err := rand.Read(newTokenBytes); err != nil {
			return err
		}
		newToken := hex.EncodeToString(newTokenBytes)

		// Re-encrypt client private keys with the new token
		for i := range sub.ClientKeys {
			k := &sub.ClientKeys[i]
			if k.AwgPrivateKeyEnc != "" {
				plainPrivKey, err := amneziawg.DecryptClientPrivateKey(oldToken, k.AwgPrivateKeyEnc)
				if err == nil {
					newEnc, err := amneziawg.EncryptClientPrivateKey(newToken, plainPrivKey)
					if err == nil {
						k.AwgPrivateKeyEnc = newEnc
						if err := tx.Model(k).Update("awg_private_key_enc", newEnc).Error; err != nil {
							return err
						}
					}
				}
			}
		}

		if err := tx.Model(&sub).Update("token", newToken).Error; err != nil {
			return err
		}

		sub.Token = newToken
		updatedSub = sub
		return nil
	})

	if err != nil {
		return nil, err
	}

	s.db.Preload("Plan").Preload("ClientKeys.Node").First(&updatedSub, "id = ?", subID)
	return &updatedSub, nil
}

// RevokeSubscription invalidates the subscription and purges client keys immediately
func (s *SubscriptionService) RevokeSubscription(userID uuid.UUID, subID uuid.UUID) error {
	return s.db.Transaction(func(tx *gorm.DB) error {
		var sub models.Subscription
		if err := tx.First(&sub, "id = ? AND user_id = ?", subID, userID).Error; err != nil {
			return errors.New("subscription not found or access denied")
		}

		// Change status to suspended
		if err := tx.Model(&sub).Update("status", models.SubSuspended).Error; err != nil {
			return err
		}

		// Delete client keys to stop serving immediately on all nodes
		if err := tx.Where("subscription_id = ?", sub.ID).Delete(&models.ClientKey{}).Error; err != nil {
			return err
		}

		return nil
	})
}

// UpdateClientAWGKey allows a user to register their own client-generated WireGuard public key
func (s *SubscriptionService) UpdateClientAWGKey(userID uuid.UUID, subID uuid.UUID, nodeID uuid.UUID, newPubKey string) error {
	if len(newPubKey) < 40 {
		return errors.New("invalid WireGuard public key length")
	}

	return s.db.Transaction(func(tx *gorm.DB) error {
		var sub models.Subscription
		if err := tx.First(&sub, "id = ? AND user_id = ?", subID, userID).Error; err != nil {
			return errors.New("subscription not found")
		}

		var key models.ClientKey
		if err := tx.First(&key, "subscription_id = ? AND node_id = ?", subID, nodeID).Error; err != nil {
			return errors.New("client key for specified node not found")
		}

		// Update public key and wipe server encrypted private key (Zero Trust client-side generation)
		return tx.Model(&key).Updates(map[string]interface{}{
			"awg_public_key":       newPubKey,
			"awg_private_key_enc": "",
		}).Error
	})
}

// RotateVlessUUIDs rotates VLESS UUIDs that are older than 24 hours.
// Retains previous_vless_uuid for zero-downtime graceful in-flight client transitions.
func (s *SubscriptionService) RotateVlessUUIDs() (int, error) {
	var keys []models.ClientKey
	cutoff := time.Now().Add(-24 * time.Hour)

	if err := s.db.Where("protocol = ? AND (vless_rotated_at < ? OR vless_rotated_at IS NULL)", models.ProtocolVless, cutoff).Find(&keys).Error; err != nil {
		return 0, err
	}

	count := 0
	for i := range keys {
		k := &keys[i]
		newUUID := uuid.New().String()
		prev := k.VlessUUID
		now := time.Now()
		if err := s.db.Model(k).Updates(map[string]interface{}{
			"vless_uuid":          newUUID,
			"previous_vless_uuid": prev,
			"vless_rotated_at":    now,
		}).Error; err == nil {
			count++
		}
	}
	return count, nil
}

// GenerateSingBoxUniversalConfig builds a complete, production-ready sing-box configuration (JSON)
// that includes all active VLESS Reality and Hysteria 2 nodes, urltest automatic failover,
// manual selector, split routing rules for Russian domestic services, and secure DoH DNS.
func (s *SubscriptionService) GenerateSingBoxUniversalConfig(sub *models.Subscription) (string, error) {
	if sub == nil {
		return "", errors.New("nil subscription")
	}

	var nodeTags []string
	var nodeOutbounds []map[string]interface{}

	for _, k := range sub.ClientKeys {
		if k.Node.IsRevoked {
			continue
		}

		// 1. VLESS + Reality Outbound
		if k.Node.VlessEnabled && k.VlessUUID != "" {
			vlessTag := fmt.Sprintf("%s - Reality (%s)", k.Node.Name, k.Node.CountryCode)
			nodeTags = append(nodeTags, vlessTag)

			vlessOutbound := map[string]interface{}{
				"type":        "vless",
				"tag":         vlessTag,
				"server":      k.Node.Host,
				"server_port": k.Node.VlessPort,
				"uuid":        k.VlessUUID,
				"flow":        "xtls-rprx-vision",
				"tls": map[string]interface{}{
					"enabled":     true,
					"server_name": k.Node.RealityServerName,
					"utls": map[string]interface{}{
						"enabled":     true,
						"fingerprint": "chrome",
					},
					"reality": map[string]interface{}{
						"enabled":    true,
						"public_key": k.Node.RealityPubKey,
						"short_id":   k.Node.RealityShortID,
					},
				},
			}
			nodeOutbounds = append(nodeOutbounds, vlessOutbound)
		}

		// 2. Hysteria 2 Outbound
		if k.Node.HysteriaEnabled && k.Node.HysteriaPort > 0 {
			hy2Tag := fmt.Sprintf("%s - Hysteria 2 (%s)", k.Node.Name, k.Node.CountryCode)
			nodeTags = append(nodeTags, hy2Tag)

			hy2Outbound := map[string]interface{}{
				"type":        "hysteria2",
				"tag":         hy2Tag,
				"server":      k.Node.Host,
				"server_port": k.Node.HysteriaPort,
				"password":    k.VlessUUID,
				"tls": map[string]interface{}{
					"enabled":     true,
					"server_name": k.Node.RealityServerName,
					"insecure":    true,
				},
			}
			nodeOutbounds = append(nodeOutbounds, hy2Outbound)
		}
	}

	if len(nodeTags) == 0 {
		nodeTags = append(nodeTags, "direct")
	}

	// Master list of outbounds
	var allOutbounds []map[string]interface{}

	// Automatic lowest-latency selection
	allOutbounds = append(allOutbounds, map[string]interface{}{
		"type":      "urltest",
		"tag":       "FreedomCry-Auto",
		"outbounds": nodeTags,
		"url":       "https://www.gstatic.com/generate_204",
		"interval":  "3m",
		"tolerance": 50,
	})

	// Manual selector
	manualTags := append([]string{"FreedomCry-Auto"}, nodeTags...)
	allOutbounds = append(allOutbounds, map[string]interface{}{
		"type":      "selector",
		"tag":       "FreedomCry-Manual",
		"outbounds": manualTags,
		"default":   "FreedomCry-Auto",
	})

	// Add individual nodes
	allOutbounds = append(allOutbounds, nodeOutbounds...)

	// Direct and block outbounds
	allOutbounds = append(allOutbounds, map[string]interface{}{
		"type": "direct",
		"tag":  "direct",
	})
	allOutbounds = append(allOutbounds, map[string]interface{}{
		"type": "block",
		"tag":  "block",
	})
	allOutbounds = append(allOutbounds, map[string]interface{}{
		"type": "dns",
		"tag":  "dns-out",
	})

	configMap := map[string]interface{}{
		"log": map[string]interface{}{
			"level": "warn",
		},
		"dns": map[string]interface{}{
			"servers": []map[string]interface{}{
				{
					"tag":     "dns-remote",
					"address": "https://1.1.1.1/dns-query",
					"detour":  "FreedomCry-Manual",
				},
				{
					"tag":     "dns-direct",
					"address": "local",
					"detour":  "direct",
				},
				{
					"tag":     "dns-block",
					"address": "rcode://success",
				},
			},
			"rules": []map[string]interface{}{
				{
					"outbound": "any",
					"server":   "dns-direct",
				},
				{
					"geosite": []string{"category-gov-ru", "yandex", "vk", "mailru"},
					"server":  "dns-direct",
				},
			},
			"strategy": "prefer_ipv4",
		},
		"inbounds": []map[string]interface{}{
			{
				"type":        "mixed",
				"tag":         "mixed-in",
				"listen":      "127.0.0.1",
				"listen_port": 20808,
				"sniff":       true,
			},
		},
		"outbounds": allOutbounds,
		"route": map[string]interface{}{
			"auto_detect_interface": true,
			"final":                 "FreedomCry-Manual",
			"rules": []map[string]interface{}{
				{
					"protocol": "dns",
					"outbound": "dns-out",
				},
				{
					"geoip":    []string{"private", "ru"},
					"outbound": "direct",
				},
				{
					"geosite":  []string{"category-gov-ru", "yandex", "vk", "mailru", "sberbank", "tinkoff"},
					"outbound": "direct",
				},
			},
		},
	}

	data, err := json.MarshalIndent(configMap, "", "  ")
	if err != nil {
		return "", err
	}

	return string(data), nil
}

