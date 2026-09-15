package service

import (
	"encoding/json"
	"testing"
	"time"

	"freedom-cry/internal/models"

	"github.com/google/uuid"
)

func TestGenerateSingBoxUniversalConfig(t *testing.T) {
	nodeID1 := uuid.New()
	nodeID2 := uuid.New()

	sub := &models.Subscription{
		ID:        uuid.New(),
		Token:     "test-token-1234567890abcdef",
		Status:    models.SubActive,
		ExpiresAt: time.Now().Add(30 * 24 * time.Hour),
		ClientKeys: []models.ClientKey{
			{
				NodeID:    nodeID1,
				VlessUUID: "44ba2b50-0000-0000-0000-000000000001",
				Node: models.ServerNode{
					ID:                nodeID1,
					Name:              "Frankfurt Entry",
					Country:           "Germany",
					CountryCode:       "DE",
					Host:              "198.51.100.10",
					VlessEnabled:      true,
					VlessPort:         443,
					RealityPubKey:     "pubkey123",
					RealityShortID:    "abcd1234",
					RealityServerName: "dl.google.com",
					HysteriaEnabled:   true,
					HysteriaPort:      8443,
				},
			},
			{
				NodeID:    nodeID2,
				VlessUUID: "44ba2b50-0000-0000-0000-000000000002",
				Node: models.ServerNode{
					ID:                nodeID2,
					Name:              "Amsterdam Exit",
					Country:           "Netherlands",
					CountryCode:       "NL",
					Host:              "198.51.100.20",
					VlessEnabled:      true,
					VlessPort:         443,
					RealityPubKey:     "pubkey456",
					RealityShortID:    "ef015678",
					RealityServerName: "gateway.icloud.com",
					IsRevoked:         false,
				},
			},
		},
	}

	serv := &SubscriptionService{}
	confStr, err := serv.GenerateSingBoxUniversalConfig(sub)
	if err != nil {
		t.Fatalf("GenerateSingBoxUniversalConfig failed: %v", err)
	}

	var parsed map[string]interface{}
	if err := json.Unmarshal([]byte(confStr), &parsed); err != nil {
		t.Fatalf("config is not valid JSON: %v", err)
	}

	outbounds, ok := parsed["outbounds"].([]interface{})
	if !ok || len(outbounds) == 0 {
		t.Fatalf("expected non-empty outbounds list")
	}

	// Verify urltest and selector exist
	foundAuto := false
	foundSelect := false
	for _, o := range outbounds {
		omap := o.(map[string]interface{})
		tag := omap["tag"].(string)
		if tag == "FreedomCry-Auto" {
			foundAuto = true
		}
		if tag == "FreedomCry-Manual" {
			foundSelect = true
		}
	}

	if !foundAuto || !foundSelect {
		t.Fatalf("expected FreedomCry-Auto and FreedomCry-Manual outbounds, got auto=%v, select=%v", foundAuto, foundSelect)
	}
}
