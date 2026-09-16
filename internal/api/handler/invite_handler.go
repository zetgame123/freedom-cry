package handler

import (
	"net/http"

	"freedom-cry/internal/service"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

type InviteHandler struct {
	inviteServ *service.InviteService
}

func NewInviteHandler(inviteServ *service.InviteService) *InviteHandler {
	return &InviteHandler{inviteServ: inviteServ}
}

type RegisterWithInviteDTO struct {
	InviteCode string `json:"invite_code" binding:"required"`
}

func (h *InviteHandler) RegisterWithInvite(c *gin.Context) {
	var dto RegisterWithInviteDTO
	if err := c.ShouldBindJSON(&dto); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invite_code is required"})
		return
	}

	resp, err := h.inviteServ.RegisterWithInvite(dto.InviteCode)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusCreated, gin.H{
		"message":            "Account registered and subscription activated successfully!",
		"account_number":     resp.AccountNumber,
		"token":              resp.Token,
		"subscription_token": resp.SubscriptionToken,
		"plan_name":          resp.PlanName,
		"expires_at":         resp.ExpiresAt,
	})
}

type ValidateInviteDTO struct {
	InviteCode string `json:"invite_code" binding:"required"`
}

func (h *InviteHandler) ValidateInvite(c *gin.Context) {
	var dto ValidateInviteDTO
	if err := c.ShouldBindJSON(&dto); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invite_code is required"})
		return
	}

	valid, err := h.inviteServ.ValidateInvite(dto.InviteCode)
	if err != nil || !valid {
		c.JSON(http.StatusOK, gin.H{"valid": false})
		return
	}

	c.JSON(http.StatusOK, gin.H{"valid": true})
}

type CreateInviteDTO struct {
	Code        string     `json:"code"`
	Description string     `json:"description"`
	MaxUses     int        `json:"max_uses"` // 0 for unlimited, 1 for single-use
	PlanID      *uuid.UUID `json:"plan_id"`
}

func (h *InviteHandler) CreateInvite(c *gin.Context) {
	var dto CreateInviteDTO
	if err := c.ShouldBindJSON(&dto); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	inv, err := h.inviteServ.CreateInvite(dto.Code, dto.Description, dto.MaxUses, dto.PlanID)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusCreated, gin.H{
		"message": "Invite code created successfully",
		"invite":  inv,
	})
}

func (h *InviteHandler) ListInvites(c *gin.Context) {
	list, err := h.inviteServ.ListInvites()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"invites": list})
}

func (h *InviteHandler) RevokeInvite(c *gin.Context) {
	idOrCode := c.Param("id")
	if idOrCode == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid invite identifier"})
		return
	}

	result, err := h.inviteServ.RevokeInviteByCode(idOrCode)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message": "Invite code revoked and associated user access terminated successfully",
		"result":  result,
	})
}
