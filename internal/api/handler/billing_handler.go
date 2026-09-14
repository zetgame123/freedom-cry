package handler

import (
	"net/http"

	"freedom-cry/internal/api/middleware"
	"freedom-cry/internal/models"
	"freedom-cry/internal/service"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"gorm.io/gorm"
)

type BillingHandler struct {
	billingServ *service.BillingService
	db          *gorm.DB
}

func NewBillingHandler(billingServ *service.BillingService, db *gorm.DB) *BillingHandler {
	return &BillingHandler{billingServ: billingServ, db: db}
}

func (h *BillingHandler) CreateDeposit(c *gin.Context) {
	userIDVal, _ := c.Get(middleware.ContextUserID)
	userID := userIDVal.(uuid.UUID)

	var dto service.DepositDTO
	if err := c.ShouldBindJSON(&dto); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	dto.UserID = userID

	tx, err := h.billingServ.CreateDeposit(dto)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusCreated, gin.H{
		"transaction": tx,
		"payment_url": "https://pay.freedomcry.net/checkout/" + tx.ID.String(),
	})
}

func (h *BillingHandler) CompleteDepositManual(c *gin.Context) {
	txIDStr := c.Param("id")
	txID, err := uuid.Parse(txIDStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid transaction id"})
		return
	}

	tx, err := h.billingServ.CompleteDeposit(txID, "manual-admin-confirm")
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message":     "Transaction completed and user balance updated",
		"transaction": tx,
	})
}

func (h *BillingHandler) GetUserTransactions(c *gin.Context) {
	userIDVal, _ := c.Get(middleware.ContextUserID)
	userID := userIDVal.(uuid.UUID)

	var txs []models.Transaction
	if err := h.db.Where("user_id = ?", userID).Order("created_at desc").Find(&txs).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"transactions": txs})
}
