package handler

import (
	"fmt"
	"net/http"

	"freedom-cry/internal/api/middleware"
	"freedom-cry/internal/config"
	"freedom-cry/internal/service"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

type SubscriptionHandler struct {
	subServ     *service.SubscriptionService
	billingServ *service.BillingService
	cfg         *config.Config
}

func NewSubscriptionHandler(subServ *service.SubscriptionService, billingServ *service.BillingService, cfg *config.Config) *SubscriptionHandler {
	return &SubscriptionHandler{subServ: subServ, billingServ: billingServ, cfg: cfg}
}

func (h *SubscriptionHandler) GetMySubscriptions(c *gin.Context) {
	userIDVal, _ := c.Get(middleware.ContextUserID)
	userID := userIDVal.(uuid.UUID)

	subs, err := h.subServ.GetUserSubscriptions(userID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	type SubResponseItem struct {
		ID               uuid.UUID `json:"id"`
		PlanName         string    `json:"plan_name"`
		Status           string    `json:"status"`
		ExpiresAt        string    `json:"expires_at"`
		TrafficLimitGB   float64   `json:"traffic_limit_gb"`
		TrafficUsedGB    float64   `json:"traffic_used_gb"`
		SubscriptionURL  string    `json:"subscription_url"`
		VlessLinkURL     string    `json:"vless_link_url"`
	}

	var res []SubResponseItem
	for _, s := range subs {
		subURL := fmt.Sprintf("%s/sub/%s", h.cfg.App.BaseURL, s.Token)
		vlessURL := fmt.Sprintf("%s/sub/%s/vless", h.cfg.App.BaseURL, s.Token)

		res = append(res, SubResponseItem{
			ID:              s.ID,
			PlanName:        s.Plan.Name,
			Status:          string(s.Status),
			ExpiresAt:       s.ExpiresAt.Format("2006-01-02 15:04:05"),
			TrafficLimitGB:  float64(s.TrafficLimitBytes) / (1024 * 1024 * 1024),
			TrafficUsedGB:   float64(s.TrafficUsedBytes) / (1024 * 1024 * 1024),
			SubscriptionURL: subURL,
			VlessLinkURL:    vlessURL,
		})
	}

	c.JSON(http.StatusOK, gin.H{"subscriptions": res})
}

type BuySubscriptionDTO struct {
	PlanID uuid.UUID `json:"plan_id" binding:"required"`
}

func (h *SubscriptionHandler) BuySubscription(c *gin.Context) {
	userIDVal, _ := c.Get(middleware.ContextUserID)
	userID := userIDVal.(uuid.UUID)

	var dto BuySubscriptionDTO
	if err := c.ShouldBindJSON(&dto); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	sub, err := h.billingServ.PurchaseSubscription(userID, dto.PlanID)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	subURL := fmt.Sprintf("%s/sub/%s", h.cfg.App.BaseURL, sub.Token)

	c.JSON(http.StatusCreated, gin.H{
		"message":          "Subscription purchased successfully!",
		"subscription_id":  sub.ID,
		"subscription_url": subURL,
		"expires_at":       sub.ExpiresAt,
	})
}

func (h *SubscriptionHandler) RotateToken(c *gin.Context) {
	userIDVal, _ := c.Get(middleware.ContextUserID)
	userID := userIDVal.(uuid.UUID)

	subIDStr := c.Param("id")
	subID, err := uuid.Parse(subIDStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid subscription id"})
		return
	}

	sub, err := h.subServ.RotateSubscriptionToken(userID, subID)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	subURL := fmt.Sprintf("%s/sub/%s", h.cfg.App.BaseURL, sub.Token)
	c.JSON(http.StatusOK, gin.H{
		"message":          "Token rotated successfully. Previous URL is now invalid.",
		"subscription_id":  sub.ID,
		"new_token":        sub.Token,
		"subscription_url": subURL,
	})
}

func (h *SubscriptionHandler) RevokeSubscription(c *gin.Context) {
	userIDVal, _ := c.Get(middleware.ContextUserID)
	userID := userIDVal.(uuid.UUID)

	subIDStr := c.Param("id")
	subID, err := uuid.Parse(subIDStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid subscription id"})
		return
	}

	if err := h.subServ.RevokeSubscription(userID, subID); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message": "Subscription revoked and tunnel keys purged from nodes.",
	})
}

type UpdateAWGKeyDTO struct {
	NodeID    uuid.UUID `json:"node_id" binding:"required"`
	PublicKey string    `json:"public_key" binding:"required"`
}

func (h *SubscriptionHandler) UpdateAWGKey(c *gin.Context) {
	userIDVal, _ := c.Get(middleware.ContextUserID)
	userID := userIDVal.(uuid.UUID)

	subIDStr := c.Param("id")
	subID, err := uuid.Parse(subIDStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid subscription id"})
		return
	}

	var dto UpdateAWGKeyDTO
	if err := c.ShouldBindJSON(&dto); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if err := h.subServ.UpdateClientAWGKey(userID, subID, dto.NodeID, dto.PublicKey); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message": "Custom AmneziaWG public key registered successfully. Encrypted private key on server cleared.",
	})
}
