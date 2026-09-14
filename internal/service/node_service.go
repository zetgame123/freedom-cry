package service

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"time"

	"freedom-cry/internal/models"
	"freedom-cry/internal/protocol/amneziawg"
	"freedom-cry/internal/protocol/xray"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

type NodeService struct {
	db *gorm.DB
}

func NewNodeService(db *gorm.DB) *NodeService {
	return &NodeService{db: db}
}

type CreateNodeDTO struct {
	Name              string `json:"name" binding:"required"`
	Country           string `json:"country" binding:"required"`
	CountryCode       string `json:"country_code" binding:"required"`
	Host              string `json:"host" binding:"required"`
	VlessPort         int    `json:"vless_port"`
	AwgPort           int    `json:"awg_port"`
	RealityServerName string `json:"reality_server_name"`
	PublicKey         string `json:"public_key"` // Optional Ed25519 node identity public key
}

// CreateNode registers a new node and generates a unique, cryptographically strong enrollment token.
// Server private keys are NEVER generated or stored on Master.
func (s *NodeService) CreateNode(dto CreateNodeDTO) (*models.ServerNode, string, error) {
	// Generate unique enrollment token
	tokenBytes := make([]byte, 32)
	if _, err := rand.Read(tokenBytes); err != nil {
		return nil, "", err
	}
	enrollmentToken := hex.EncodeToString(tokenBytes)
	tokenHash := sha256.Sum256([]byte(enrollmentToken))

	vlessPort := dto.VlessPort
	if vlessPort <= 0 {
		vlessPort = 443
	}

	awgPort := dto.AwgPort
	if awgPort <= 0 {
		awgPort = 51820
	}

	sni := dto.RealityServerName
	if sni == "" {
		sni = "dl.google.com"
	}

	// Generate initial placeholder public keys if not yet supplied by node
	realityKeys, _ := xray.GenerateRealityKeyPair()
	awgKeys, _ := amneziawg.GenerateAWGKeyPair()
	awgParams, _ := amneziawg.GenerateDefaultObfuscationParams()

	node := models.ServerNode{
		Name:              dto.Name,
		Country:           dto.Country,
		CountryCode:       dto.CountryCode,
		Host:              dto.Host,
		IsOnline:          true,
		IsRevoked:         false,
		AuthTokenHash:     hex.EncodeToString(tokenHash[:]),
		PublicKey:         dto.PublicKey,
		LastAllocatedIP:   1,
		VlessEnabled:      true,
		VlessPort:         vlessPort,
		RealityPubKey:     realityKeys.PublicKey,
		RealityShortID:    realityKeys.ShortID,
		RealityServerName: sni,

		AwgEnabled:      true,
		AwgPort:         awgPort,
		AwgServerSubnet: "10.8.0.0/24",
		AwgPubKey:       awgKeys.PublicKey,
		AwgJc:           awgParams.Jc,
		AwgJmin:         awgParams.Jmin,
		AwgJmax:         awgParams.Jmax,
		AwgS1:           awgParams.S1,
		AwgS2:           awgParams.S2,
		AwgH1:           awgParams.H1,
		AwgH2:           awgParams.H2,
		AwgH3:           awgParams.H3,
		AwgH4:           awgParams.H4,
	}

	if err := s.db.Create(&node).Error; err != nil {
		return nil, "", err
	}

	return &node, enrollmentToken, nil
}

func (s *NodeService) GetAll() ([]models.ServerNode, error) {
	var nodes []models.ServerNode
	if err := s.db.Where("is_revoked = ?", false).Find(&nodes).Error; err != nil {
		return nil, err
	}
	return nodes, nil
}

func (s *NodeService) GetActiveNodes() ([]models.ServerNode, error) {
	var nodes []models.ServerNode
	if err := s.db.Where("is_online = ? AND is_revoked = ?", true, false).Find(&nodes).Error; err != nil {
		return nil, err
	}
	return nodes, nil
}

func (s *NodeService) GetByID(id uuid.UUID) (*models.ServerNode, error) {
	var node models.ServerNode
	if err := s.db.First(&node, "id = ?", id).Error; err != nil {
		return nil, err
	}
	return &node, nil
}

func (s *NodeService) RecordHeartbeat(nodeID uuid.UUID, loadPercent int) error {
	now := time.Now()
	res := s.db.Model(&models.ServerNode{}).Where("id = ? AND is_revoked = ?", nodeID, false).Updates(map[string]interface{}{
		"load_percent": loadPercent,
		"is_online":    true,
		"last_seen_at": &now,
	})
	if res.Error != nil {
		return res.Error
	}
	if res.RowsAffected == 0 {
		return errors.New("node not found or revoked")
	}
	return nil
}

func (s *NodeService) RegisterNodeKeys(nodeID uuid.UUID, realityPubKey, realityShortID, awgPubKey, nodeIdentityPubKey string) error {
	updates := map[string]interface{}{}
	if realityPubKey != "" {
		updates["reality_pub_key"] = realityPubKey
	}
	if realityShortID != "" {
		updates["reality_short_id"] = realityShortID
	}
	if awgPubKey != "" {
		updates["awg_pub_key"] = awgPubKey
	}
	if nodeIdentityPubKey != "" {
		updates["public_key"] = nodeIdentityPubKey
	}

	if len(updates) == 0 {
		return nil
	}

	return s.db.Model(&models.ServerNode{}).Where("id = ? AND is_revoked = ?", nodeID, false).Updates(updates).Error
}

func (s *NodeService) RevokeNode(nodeID uuid.UUID) error {
	return s.db.Model(&models.ServerNode{}).Where("id = ?", nodeID).Updates(map[string]interface{}{
		"is_revoked": true,
		"is_online":  false,
	}).Error
}
