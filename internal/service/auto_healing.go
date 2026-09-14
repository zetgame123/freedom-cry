package service

import (
	"context"
	"fmt"
	"log"
	"sync"
	"time"

	"freedom-cry/internal/models"
	"freedom-cry/internal/service/cloud"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

type ProbeIncident struct {
	ProbeID       string
	ProbeLocation string
	IsReachable   bool
	LastReport    time.Time
}

type AutoHealingService struct {
	db          *gorm.DB
	cloudProv   cloud.CloudProvider
	mu          sync.Mutex
	nodeIncidents map[uuid.UUID]map[string]*ProbeIncident // nodeID -> probeID -> Incident
	alertHandler  func(alertMsg string)
}

func NewAutoHealingService(db *gorm.DB, prov cloud.CloudProvider) *AutoHealingService {
	if prov == nil {
		prov = cloud.NewMockCloudProvider()
	}

	return &AutoHealingService{
		db:            db,
		cloudProv:     prov,
		nodeIncidents: make(map[uuid.UUID]map[string]*ProbeIncident),
	}
}

func (s *AutoHealingService) SetAlertHandler(handler func(string)) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.alertHandler = handler
}

// RecordProbeResult ingests results from a sensor probe and checks quorum for unblocking
func (s *AutoHealingService) RecordProbeResult(probeID, probeLocation string, nodeID uuid.UUID, isReachable bool) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now()
	if s.nodeIncidents[nodeID] == nil {
		s.nodeIncidents[nodeID] = make(map[string]*ProbeIncident)
	}

	s.nodeIncidents[nodeID][probeID] = &ProbeIncident{
		ProbeID:       probeID,
		ProbeLocation: probeLocation,
		IsReachable:   isReachable,
		LastReport:    now,
	}

	// Evaluate censorship quorum
	if !isReachable {
		s.evaluateCensorshipQuorum(nodeID)
	}

	return nil
}

// evaluateCensorshipQuorum evaluates if >= 2 independent sensors report node as blocked
func (s *AutoHealingService) evaluateCensorshipQuorum(nodeID uuid.UUID) {
	incidents := s.nodeIncidents[nodeID]
	if len(incidents) < 2 {
		return
	}

	blockedCount := 0
	recentWindow := time.Now().Add(-90 * time.Second)

	for _, inc := range incidents {
		if !inc.IsReachable && inc.LastReport.After(recentWindow) {
			blockedCount++
		}
	}

	// Trigger auto-healing if quorum >= 2
	if blockedCount >= 2 {
		go s.TriggerAutoHealing(nodeID)
	}
}

// TriggerAutoHealing invokes the Cloud Provider API to replace the blocked IP with a fresh IP
func (s *AutoHealingService) TriggerAutoHealing(nodeID uuid.UUID) {
	var node models.ServerNode
	if err := s.db.First(&node, "id = ?", nodeID).Error; err != nil {
		log.Printf("[Auto-Healing] Node %s not found: %v", nodeID, err)
		return
	}

	if !node.IsOnline || node.IsRevoked {
		return
	}

	oldIP := node.Host
	log.Printf("[Auto-Healing] 🚨 Censorship detected on node %s (%s). Invoking Cloud Provider (%s)...",
		node.Name, oldIP, s.cloudProv.Name())

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	newIP, err := s.cloudProv.ReplaceFloatingIP(ctx, oldIP)
	if err != nil {
		log.Printf("[Auto-Healing] ❌ Cloud API replacement failed for %s: %v", node.Name, err)
		return
	}

	// Update node in database
	if err := s.db.Model(&node).Update("host", newIP).Error; err != nil {
		log.Printf("[Auto-Healing] ❌ Failed to update node host in DB: %v", err)
		return
	}

	// Reset incident records for this node
	s.mu.Lock()
	delete(s.nodeIncidents, nodeID)
	alertFn := s.alertHandler
	s.mu.Unlock()

	alertMsg := fmt.Sprintf("🚨 ТСПУ БЛОКИРОВКА! Нода %s (%s) была заблокирована сенсорами.\n🔄 Авто-хилинг: присвоен новый IP: %s (Провайдер: %s).",
		node.Name, oldIP, newIP, s.cloudProv.Name())
	log.Println("[Auto-Healing] " + alertMsg)

	if alertFn != nil {
		alertFn(alertMsg)
	}
}
