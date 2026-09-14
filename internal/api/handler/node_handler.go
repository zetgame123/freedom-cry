package handler

import (
	"net/http"
	"time"

	"freedom-cry/internal/api/middleware"
	"freedom-cry/internal/models"
	"freedom-cry/internal/service"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"gorm.io/gorm"
)

type NodeHandler struct {
	nodeServ *service.NodeService
	db       *gorm.DB
}

func NewNodeHandler(nodeServ *service.NodeService, db *gorm.DB) *NodeHandler {
	return &NodeHandler{nodeServ: nodeServ, db: db}
}

func (h *NodeHandler) ListNodes(c *gin.Context) {
	nodes, err := h.nodeServ.GetActiveNodes()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	type PublicNode struct {
		ID          uuid.UUID `json:"id"`
		Name        string    `json:"name"`
		Country     string    `json:"country"`
		CountryCode string    `json:"country_code"`
		Host        string    `json:"host"`
		IsOnline    bool      `json:"is_online"`
		LoadPercent int       `json:"load_percent"`
	}

	var res []PublicNode
	for _, n := range nodes {
		res = append(res, PublicNode{
			ID:          n.ID,
			Name:        n.Name,
			Country:     n.Country,
			CountryCode: n.CountryCode,
			Host:        n.Host,
			IsOnline:    n.IsOnline,
			LoadPercent: n.LoadPercent,
		})
	}

	c.JSON(http.StatusOK, gin.H{"nodes": res})
}

func (h *NodeHandler) AdminCreateNode(c *gin.Context) {
	var dto service.CreateNodeDTO
	if err := c.ShouldBindJSON(&dto); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	node, enrollmentToken, err := h.nodeServ.CreateNode(dto)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusCreated, gin.H{
		"node":             node,
		"enrollment_token": enrollmentToken,
		"instructions":     "Pass this enrollment_token to the node agent. It cannot be retrieved again.",
	})
}

type NodeSyncRequest struct {
	NodeID      uuid.UUID `json:"node_id"`
	LoadPercent int       `json:"load_percent"`
}

type NodeSyncResponse struct {
	Node         models.ServerNode `json:"node"`
	VlessClients []VlessClientSync `json:"vless_clients"`
	AwgPeers     []AwgPeerSync     `json:"awg_peers"`
}

type VlessClientSync struct {
	UUID  string `json:"uuid"`
	Email string `json:"email"`
}

type AwgPeerSync struct {
	PublicKey    string `json:"public_key"`
	PresharedKey string `json:"preshared_key"`
	AllowedIPs   string `json:"allowed_ips"`
}

func (h *NodeHandler) NodeSync(c *gin.Context) {
	// Authenticate node identity from cryptographic context
	authNodeIDVal, exists := c.Get(middleware.ContextAuthenticatedNodeID)
	if !exists {
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "node authentication required"})
		return
	}
	authenticatedNodeID := authNodeIDVal.(uuid.UUID)

	var req NodeSyncRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// ZERO TRUST / IDOR PREVENTION:
	// If a node attempts to sync resources for another node ID, fail-closed with 403 Forbidden!
	if req.NodeID != uuid.Nil && req.NodeID != authenticatedNodeID {
		c.JSON(http.StatusForbidden, gin.H{"error": "forbidden: cross-node access denied"})
		return
	}

	targetNodeID := authenticatedNodeID

	// Update heartbeat for the authenticated node
	_ = h.nodeServ.RecordHeartbeat(targetNodeID, req.LoadPercent)

	var node models.ServerNode
	if err := h.db.First(&node, "id = ? AND is_revoked = ?", targetNodeID, false).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "node not found or revoked"})
		return
	}

	// Fetch active client keys for this node
	var keys []models.ClientKey
	now := time.Now()
	err := h.db.
		Joins("JOIN subscriptions ON subscriptions.id = client_keys.subscription_id").
		Where("client_keys.node_id = ? AND subscriptions.status = ? AND subscriptions.expires_at > ?",
			targetNodeID, models.SubActive, now).
		Find(&keys).Error

	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	var vlessClients []VlessClientSync
	var awgPeers []AwgPeerSync

	for _, k := range keys {
		if k.VlessUUID != "" {
			vlessClients = append(vlessClients, VlessClientSync{
				UUID:  k.VlessUUID,
				Email: k.SubscriptionID.String()[:8] + "@fc.net",
			})
		}
		if k.AwgPublicKey != "" && k.AwgAddress != "" {
			awgPeers = append(awgPeers, AwgPeerSync{
				PublicKey:    k.AwgPublicKey,
				PresharedKey: k.AwgPresharedKey,
				AllowedIPs:   k.AwgAddress,
			})
		}
	}

	// NOTE: Notice that RealityPrivateKey and AwgPrivateKey are NEVER returned.
	// Private keys are strictly held on the node itself.
	c.JSON(http.StatusOK, NodeSyncResponse{
		Node:         node,
		VlessClients: vlessClients,
		AwgPeers:     awgPeers,
	})
}

type RegisterKeysRequest struct {
	RealityPubKey  string `json:"reality_pub_key"`
	RealityShortID string `json:"reality_short_id"`
	AwgPubKey      string `json:"awg_pub_key"`
	PublicKey      string `json:"public_key"`
}

func (h *NodeHandler) RegisterKeys(c *gin.Context) {
	authNodeIDVal, exists := c.Get(middleware.ContextAuthenticatedNodeID)
	if !exists {
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "node authentication required"})
		return
	}
	authenticatedNodeID := authNodeIDVal.(uuid.UUID)

	var req RegisterKeysRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if err := h.nodeServ.RegisterNodeKeys(authenticatedNodeID, req.RealityPubKey, req.RealityShortID, req.AwgPubKey, req.PublicKey); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "node public keys registered successfully"})
}
