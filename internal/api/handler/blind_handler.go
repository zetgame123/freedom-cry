package handler

import (
	"net/http"

	"freedom-cry/internal/api/middleware"
	"freedom-cry/internal/service"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

type BlindHandler struct {
	blindServ *service.BlindTokenService
}

func NewBlindHandler(blindServ *service.BlindTokenService) *BlindHandler {
	return &BlindHandler{blindServ: blindServ}
}

func (h *BlindHandler) GetPublicKey(c *gin.Context) {
	pem, err := h.blindServ.GetPublicKeyPEM()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to export public key"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"public_key_pem": pem,
		"algorithm":      "RSA-2048-CHAUM-BLIND",
	})
}

type SignRequestDTO struct {
	BlindedMessageHex string `json:"blinded_message_hex" binding:"required"`
}

func (h *BlindHandler) SignBlindedToken(c *gin.Context) {
	userIDVal, _ := c.Get(middleware.ContextUserID)
	userID := userIDVal.(uuid.UUID)

	var dto SignRequestDTO
	if err := c.ShouldBindJSON(&dto); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	blindedSigHex, err := h.blindServ.SignBlindedToken(userID, dto.BlindedMessageHex)
	if err != nil {
		c.JSON(http.StatusForbidden, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"blinded_signature_hex": blindedSigHex,
	})
}

type RedeemRequestDTO struct {
	TokenSeedHex string `json:"token_seed_hex" binding:"required"`
	SignatureHex string `json:"signature_hex" binding:"required"`
}

func (h *BlindHandler) RedeemToken(c *gin.Context) {
	var dto RedeemRequestDTO
	if err := c.ShouldBindJSON(&dto); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	res, err := h.blindServ.RedeemToken(dto.TokenSeedHex, dto.SignatureHex)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"status":        "redeemed",
		"session_token": res.SessionToken,
		"vless_uuid":    res.VlessUUID,
		"expires_at":    res.ExpiresAt,
	})
}
