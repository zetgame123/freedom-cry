package handler

import (
	"net/http"

	"freedom-cry/internal/service"

	"github.com/gin-gonic/gin"
)

type AuthHandler struct {
	userServ *service.UserService
}

func NewAuthHandler(userServ *service.UserService) *AuthHandler {
	return &AuthHandler{userServ: userServ}
}

func (h *AuthHandler) Register(c *gin.Context) {
	var dto service.RegisterDTO
	if err := c.ShouldBindJSON(&dto); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	res, err := h.userServ.Register(dto)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusCreated, res)
}

func (h *AuthHandler) Login(c *gin.Context) {
	var dto service.LoginDTO
	if err := c.ShouldBindJSON(&dto); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	res, err := h.userServ.Login(dto)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, res)
}
