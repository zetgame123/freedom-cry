package handler

import (
	"fmt"
	"net/http"

	"freedom-cry/internal/service"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

type RouteHandler struct {
	hopServ *service.MultiHopService
}

func NewRouteHandler(hopServ *service.MultiHopService) *RouteHandler {
	return &RouteHandler{hopServ: hopServ}
}

// ListChains handles GET /api/v1/routes/chains
func (h *RouteHandler) ListChains(c *gin.Context) {
	chains, err := h.hopServ.GetAvailableChains()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"chains": chains,
	})
}

// GetChainedConfig handles GET /sub/:token/chain/:entry_id/:exit_id
func (h *RouteHandler) GetChainedConfig(c *gin.Context) {
	token := c.Param("token")
	entryIDStr := c.Param("entry_id")
	exitIDStr := c.Param("exit_id")

	entryID, err := uuid.Parse(entryIDStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid entry_id"})
		return
	}

	exitID, err := uuid.Parse(exitIDStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid exit_id"})
		return
	}

	conf, err := h.hopServ.GenerateChainedSingBoxConfig(token, entryID, exitID)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	c.Header("Content-Disposition", fmt.Sprintf("attachment; filename=FreedomCry-Chain-%s-%s.json", entryIDStr[:6], exitIDStr[:6]))
	c.Header("Content-Type", "application/json")
	c.String(http.StatusOK, conf)
}
