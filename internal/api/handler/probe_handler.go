package handler

import (
	"crypto/subtle"
	"net/http"
	"time"

	"freedom-cry/internal/probe"
	"freedom-cry/internal/service"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"gorm.io/gorm"
)

type ProbeHandler struct {
	db              *gorm.DB
	nodeServ        *service.NodeService
	autoHealingServ *service.AutoHealingService
	secret          string
}

func NewProbeHandler(
	db *gorm.DB,
	nodeServ *service.NodeService,
	autoHealingServ *service.AutoHealingService,
	secret string,
) *ProbeHandler {
	return &ProbeHandler{
		db:              db,
		nodeServ:        nodeServ,
		autoHealingServ: autoHealingServ,
		secret:          secret,
	}
}

func (h *ProbeHandler) verifySecret(c *gin.Context) bool {
	if h.secret == "" {
		c.AbortWithStatusJSON(http.StatusServiceUnavailable, gin.H{"error": "probe sensor system not configured"})
		return false
	}
	provided := c.GetHeader("X-Probe-Secret")
	if provided == "" || subtle.ConstantTimeCompare([]byte(provided), []byte(h.secret)) != 1 {
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "unauthorized probe access"})
		return false
	}
	return true
}

// GetProbeTargets handles GET /api/v1/node/probe-targets
func (h *ProbeHandler) GetProbeTargets(c *gin.Context) {
	if !h.verifySecret(c) {
		return
	}

	nodes, err := h.nodeServ.GetActiveNodes()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	var targets []probe.NodeTarget
	for _, n := range nodes {
		sni := n.RealityServerName
		if sni == "" {
			sni = "dl.google.com"
		}
		targets = append(targets, probe.NodeTarget{
			NodeID:    n.ID.String(),
			Host:      n.Host,
			VlessPort: n.VlessPort,
			AwgPort:   n.AwgPort,
			SNI:       sni,
			AwgH1:     n.AwgH1,
		})
	}

	c.JSON(http.StatusOK, gin.H{
		"targets": targets,
	})
}

type ProbeReportRequest struct {
	ProbeID       string              `json:"probe_id" binding:"required"`
	ProbeLocation string              `json:"probe_location" binding:"required"`
	Timestamp     time.Time           `json:"timestamp"`
	Results       []probe.ProbeResult `json:"results" binding:"required"`
}

// SubmitProbeReport handles POST /api/v1/node/probe-report
func (h *ProbeHandler) SubmitProbeReport(c *gin.Context) {
	if !h.verifySecret(c) {
		return
	}

	var req ProbeReportRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	for _, res := range req.Results {
		nodeID, err := uuid.Parse(res.NodeID)
		if err != nil {
			continue
		}
		_ = h.autoHealingServ.RecordProbeResult(req.ProbeID, req.ProbeLocation, nodeID, res.IsReachable)
	}

	c.JSON(http.StatusOK, gin.H{
		"status":   "processed",
		"received": len(req.Results),
	})
}
