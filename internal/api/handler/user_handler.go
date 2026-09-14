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

type UserHandler struct {
	userServ *service.UserService
	db       *gorm.DB
}

func NewUserHandler(userServ *service.UserService, db *gorm.DB) *UserHandler {
	return &UserHandler{userServ: userServ, db: db}
}

func (h *UserHandler) GetMe(c *gin.Context) {
	userIDVal, _ := c.Get(middleware.ContextUserID)
	userID := userIDVal.(uuid.UUID)

	user, err := h.userServ.GetByID(userID)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "user not found"})
		return
	}

	c.JSON(http.StatusOK, user)
}

func (h *UserHandler) GetPlans(c *gin.Context) {
	var plans []models.Plan
	if err := h.db.Where("is_active = ?", true).Order("price asc").Find(&plans).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"plans": plans})
}

func (h *UserHandler) DeleteMe(c *gin.Context) {
	userIDVal, _ := c.Get(middleware.ContextUserID)
	userID := userIDVal.(uuid.UUID)

	if err := h.userServ.HardDeleteUser(userID); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"status":  "deleted",
		"message": "User account, subscriptions, cryptographic keys, and billing records permanently erased.",
	})
}
