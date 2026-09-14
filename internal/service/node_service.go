package service

import (
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
}

func (s *NodeService) CreateNode(dto CreateNodeDTO) (*models.ServerNode, error) {
	// Auto-generate Reality keypair and ShortID
	realityKeys, err := xray.GenerateRealityKeyPair()
	if err != nil {
		return nil, err
	}

	// Auto-generate AmneziaWG keypair and obfuscation params
	awgKeys, err := amneziawg.GenerateAWGKeyPair()
	if err != nil {
		return nil, err
	}

	awgParams, err := amneziawg.GenerateDefaultObfuscationParams()
	if err != nil {
		return nil, err
	}

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

	node := models.ServerNode{
		Name:              dto.Name,
		Country:           dto.Country,
		CountryCode:       dto.CountryCode,
		Host:              dto.Host,
		IsOnline:          true,
		VlessEnabled:      true,
		VlessPort:         vlessPort,
		RealityPrivKey:    realityKeys.PrivateKey,
		RealityPubKey:     realityKeys.PublicKey,
		RealityShortID:    realityKeys.ShortID,
		RealityServerName: sni,

		AwgEnabled:      true,
		AwgPort:         awgPort,
		AwgServerSubnet: "10.8.0.0/24",
		AwgPrivKey:      awgKeys.PrivateKey,
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
		return nil, err
	}

	return &node, nil
}

func (s *NodeService) GetAll() ([]models.ServerNode, error) {
	var nodes []models.ServerNode
	if err := s.db.Find(&nodes).Error; err != nil {
		return nil, err
	}
	return nodes, nil
}

func (s *NodeService) GetActiveNodes() ([]models.ServerNode, error) {
	var nodes []models.ServerNode
	if err := s.db.Where("is_online = ?", true).Find(&nodes).Error; err != nil {
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
	res := s.db.Model(&models.ServerNode{}).Where("id = ?", nodeID).Updates(map[string]interface{}{
		"load_percent": loadPercent,
		"is_online":    true,
		"last_seen_at": &now,
	})
	if res.Error != nil {
		return res.Error
	}
	if res.RowsAffected == 0 {
		return errors.New("node not found")
	}
	return nil
}
