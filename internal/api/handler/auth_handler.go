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

type AccountLoginDTO struct {
	AccountNumber string `json:"account_number" binding:"required"`
}

func (h *AuthHandler) AccountRegister(c *gin.Context) {
	res, err := h.userServ.CreateAnonymousAccount()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusCreated, gin.H{
		"message":        "Anonymous Zero-Knowledge account created successfully",
		"account_number": res.User.AccountNumber,
		"token":          res.Token,
		"user":           res.User,
	})
}

func (h *AuthHandler) AccountLogin(c *gin.Context) {
	var dto AccountLoginDTO
	if err := c.ShouldBindJSON(&dto); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	res, err := h.userServ.LoginByAccountNumber(dto.AccountNumber)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, res)
}
