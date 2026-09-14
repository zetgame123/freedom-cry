package handler

import (
	"net/http"
	"time"

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

	node, err := h.nodeServ.CreateNode(dto)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusCreated, node)
}

type NodeSyncRequest struct {
	NodeID      uuid.UUID `json:"node_id" binding:"required"`
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
	var req NodeSyncRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Update heartbeat
	_ = h.nodeServ.RecordHeartbeat(req.NodeID, req.LoadPercent)

	var node models.ServerNode
	if err := h.db.First(&node, "id = ?", req.NodeID).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "node not found"})
		return
	}

	// Fetch active client keys for this node
	var keys []models.ClientKey
	now := time.Now()
	err := h.db.
		Joins("JOIN subscriptions ON subscriptions.id = client_keys.subscription_id").
		Where("client_keys.node_id = ? AND subscriptions.status = ? AND subscriptions.expires_at > ?",
			req.NodeID, models.SubActive, now).
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

	c.JSON(http.StatusOK, NodeSyncResponse{
		Node:         node,
		VlessClients: vlessClients,
		AwgPeers:     awgPeers,
	})
}
