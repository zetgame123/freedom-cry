package middleware

import (
	"fmt"
	"net/http"
	"strings"

	"freedom-cry/internal/config"
	"freedom-cry/internal/models"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

const (
	ContextUserID   = "userID"
	ContextUserRole = "userRole"
)

func AuthMiddleware(cfg *config.Config) gin.HandlerFunc {
	return func(c *gin.Context) {
		authHeader := c.GetHeader("Authorization")
		if authHeader == "" {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "authorization header required"})
			return
		}

		parts := strings.Split(authHeader, " ")
		if len(parts) != 2 || strings.ToLower(parts[0]) != "bearer" {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "authorization format must be Bearer <token>"})
			return
		}

		tokenStr := parts[1]
		token, err := jwt.Parse(tokenStr, func(token *jwt.Token) (interface{}, error) {
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
			}
			return []byte(cfg.JWT.Secret), nil
		})

		if err != nil || !token.Valid {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "invalid or expired token"})
			return
		}

		claims, ok := token.Claims.(jwt.MapClaims)
		if !ok {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "invalid token claims"})
			return
		}

		subStr, ok := claims["sub"].(string)
		if !ok {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "invalid user id in token"})
			return
		}

		userUUID, err := uuid.Parse(subStr)
		if err != nil {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "invalid uuid in token"})
			return
		}

		role, _ := claims["role"].(string)

		c.Set(ContextUserID, userUUID)
		c.Set(ContextUserRole, models.UserRole(role))
		c.Next()
	}
}

func RequireAdmin() gin.HandlerFunc {
	return func(c *gin.Context) {
		roleVal, exists := c.Get(ContextUserRole)
		if !exists || roleVal != models.RoleAdmin {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "admin access required"})
			return
		}
		c.Next()
	}
}

func RequireNodeSecret(cfg *config.Config) gin.HandlerFunc {
	return func(c *gin.Context) {
		secret := c.GetHeader("X-Node-Secret")
		if secret == "" || secret != cfg.App.NodeSecret {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "invalid node secret"})
			return
		}
		c.Next()
	}
}
