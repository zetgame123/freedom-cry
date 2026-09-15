package service

import (
	"encoding/json"
	"errors"
	"fmt"

	"freedom-cry/internal/models"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

type MultiHopService struct {
	db      *gorm.DB
	subServ *SubscriptionService
}

func NewMultiHopService(db *gorm.DB, subServ *SubscriptionService) *MultiHopService {
	return &MultiHopService{
		db:      db,
		subServ: subServ,
	}
}

type NodePairDTO struct {
	EntryNode models.ServerNode `json:"entry_node"`
	ExitNode  models.ServerNode `json:"exit_node"`
	ChainName string            `json:"chain_name"`
}

// GetAvailableChains returns all valid Entry -> Exit combinations
func (s *MultiHopService) GetAvailableChains() ([]NodePairDTO, error) {
	var entries []models.ServerNode
	var exits []models.ServerNode

	if err := s.db.Where("is_online = ? AND is_revoked = ? AND (role = ? OR role = ?)",
		true, false, models.RoleEntry, models.RoleStandalone).Find(&entries).Error; err != nil {
		return nil, err
	}

	if err := s.db.Where("is_online = ? AND is_revoked = ? AND (role = ? OR role = ?)",
		true, false, models.RoleExit, models.RoleStandalone).Find(&exits).Error; err != nil {
		return nil, err
	}

	var pairs []NodePairDTO
	for _, entry := range entries {
		for _, exit := range exits {
			// Don't pair node with itself
			if entry.ID == exit.ID {
				continue
			}
			pairs = append(pairs, NodePairDTO{
				EntryNode: entry,
				ExitNode:  exit,
				ChainName: fmt.Sprintf("%s (%s) ➔ %s (%s)", entry.Name, entry.CountryCode, exit.Name, exit.CountryCode),
			})
		}
	}

	return pairs, nil
}

// GenerateChainedSingBoxConfig builds a client sing-box JSON configuration with outbound chaining:
// Outbound 1 (Entry): VLESS Reality directly to Entry Node
// Outbound 2 (Exit): Outbound via Entry Node proxying to Exit Node
func (s *MultiHopService) GenerateChainedSingBoxConfig(subToken string, entryID, exitID uuid.UUID) (string, error) {
	sub, err := s.subServ.GetByToken(subToken)
	if err != nil || !sub.IsValid() {
		return "", errors.New("invalid or expired subscription")
	}

	var entryNode models.ServerNode
	if err := s.db.First(&entryNode, "id = ? AND is_online = ? AND is_revoked = ?", entryID, true, false).Error; err != nil {
		return "", errors.New("entry node not found or offline")
	}

	var exitNode models.ServerNode
	if err := s.db.First(&exitNode, "id = ? AND is_online = ? AND is_revoked = ?", exitID, true, false).Error; err != nil {
		return "", errors.New("exit node not found or offline")
	}

	// Find user VLESS UUID for entry node and exit node
	var entryKey *models.ClientKey
	var exitKey *models.ClientKey
	for i := range sub.ClientKeys {
		if sub.ClientKeys[i].NodeID == entryID {
			entryKey = &sub.ClientKeys[i]
		}
		if sub.ClientKeys[i].NodeID == exitID {
			exitKey = &sub.ClientKeys[i]
		}
	}
	if entryKey == nil {
		return "", errors.New("no client key allocated for entry node")
	}
	if exitKey == nil {
		return "", errors.New("no client key allocated for exit node")
	}

	// Construct chained sing-box config
	configMap := map[string]interface{}{
		"log": map[string]interface{}{
			"level": "warn",
		},
		"inbounds": []map[string]interface{}{
			{
				"type":        "mixed",
				"tag":         "mixed-in",
				"listen":      "127.0.0.1",
				"listen_port": 10808,
			},
		},
		"outbounds": []map[string]interface{}{
			// Entry hop
			{
				"type":        "vless",
				"tag":         "proxy-entry",
				"server":      entryNode.Host,
				"server_port": entryNode.VlessPort,
				"uuid":        entryKey.VlessUUID,
				"tls": map[string]interface{}{
					"enabled":     true,
					"server_name": entryNode.RealityServerName,
					"reality": map[string]interface{}{
						"enabled":    true,
						"public_key": entryNode.RealityPubKey,
						"short_id":   entryNode.RealityShortID,
					},
				},
			},
			// Exit hop (proxied through entry)
			{
				"type":        "vless",
				"tag":         "proxy-exit",
				"server":      exitNode.Host,
				"server_port": exitNode.VlessPort,
				"uuid":        exitKey.VlessUUID,
				"detour":      "proxy-entry", // Multi-hop detour!
				"tls": map[string]interface{}{
					"enabled":     true,
					"server_name": exitNode.RealityServerName,
					"reality": map[string]interface{}{
						"enabled":    true,
						"public_key": exitNode.RealityPubKey,
						"short_id":   exitNode.RealityShortID,
					},
				},
			},
			{
				"type": "direct",
				"tag":  "direct",
			},
		},
		"route": map[string]interface{}{
			"final": "proxy-exit",
			"rules": []map[string]interface{}{
				{
					"protocol": "dns",
					"outbound": "direct",
				},
				{
					"geoip":    []string{"private", "ru"},
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
