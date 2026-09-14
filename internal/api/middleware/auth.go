package middleware

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"math"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"freedom-cry/internal/config"
	"freedom-cry/internal/models"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"gorm.io/gorm"
)

var (
	nodeSigCacheMu sync.Mutex
	nodeSigCache   = make(map[string]int64)
)

func checkAndRecordSig(sig string, now int64) bool {
	nodeSigCacheMu.Lock()
	defer nodeSigCacheMu.Unlock()

	cutoff := now - 70
	for k, t := range nodeSigCache {
		if t < cutoff {
			delete(nodeSigCache, k)
		}
	}

	if _, exists := nodeSigCache[sig]; exists {
		return false
	}
	nodeSigCache[sig] = now
	return true
}

const (
	ContextUserID              = "userID"
	ContextUserRole            = "userRole"
	ContextAuthenticatedNodeID = "authenticatedNodeID"
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
			// Enforce explicit HMAC SHA256 only - reject "none" or asymmetric algorithms
			if token.Method.Alg() != jwt.SigningMethodHS256.Alg() {
				return nil, fmt.Errorf("unexpected signing algorithm: %v", token.Header["alg"])
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

// RequireNodeAuth enforces cryptographic node identity and zero-trust authentication.
// Replaces the insecure global static X-Node-Secret.
// Authenticates the node either via Ed25519 signature or unique per-node token.
func RequireNodeAuth(db *gorm.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		nodeIDStr := c.GetHeader("X-Node-ID")
		if nodeIDStr == "" {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "X-Node-ID header required"})
			return
		}

		nodeID, err := uuid.Parse(nodeIDStr)
		if err != nil {
			c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": "invalid X-Node-ID format"})
			return
		}

		var node models.ServerNode
		if err := db.First(&node, "id = ?", nodeID).Error; err != nil {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "node not found"})
			return
		}

		if node.IsRevoked {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "node has been revoked"})
			return
		}

		// 1. Signature-based authentication (Ed25519) if signature header is provided
		sigHeader := c.GetHeader("X-Node-Signature")
		tsHeader := c.GetHeader("X-Node-Timestamp")

		if sigHeader != "" && tsHeader != "" && node.PublicKey != "" {
			ts, err := strconv.ParseInt(tsHeader, 10, 64)
			if err != nil {
				c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "invalid timestamp"})
				return
			}

			now := time.Now().Unix()
			// Reject timestamps older than 60 seconds to prevent replay attacks
			if math.Abs(float64(now-ts)) > 60 {
				c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "timestamp expired or out of sync"})
				return
			}

			// Prevent replay attack within the 60-second window
			if !checkAndRecordSig(sigHeader, now) {
				c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "replay attack detected: signature already used"})
				return
			}

			pubKeyBytes, err := hex.DecodeString(node.PublicKey)
			if err != nil || len(pubKeyBytes) != ed25519.PublicKeySize {
				c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": "invalid node public key in db"})
				return
			}

			sigBytes, err := base64.StdEncoding.DecodeString(sigHeader)
			if err != nil {
				c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "invalid signature encoding"})
				return
			}

			// Read and restore request body to bind signature to payload
			var bodyBytes []byte
			if c.Request.Body != nil {
				bodyBytes, _ = io.ReadAll(c.Request.Body)
				c.Request.Body = io.NopCloser(bytes.NewBuffer(bodyBytes))
			}
			bodyHash := sha256.Sum256(bodyBytes)
			bodyHashHex := hex.EncodeToString(bodyHash[:])

			// Expected payload: FC-NODE-AUTH:<nodeID>:<timestamp>:<method>:<path>:<bodyHashHex>
			msg := fmt.Sprintf("FC-NODE-AUTH:%s:%s:%s:%s:%s", node.ID.String(), tsHeader, c.Request.Method, c.Request.URL.Path, bodyHashHex)
			if !ed25519.Verify(pubKeyBytes, []byte(msg), sigBytes) {
				c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "cryptographic signature verification failed"})
				return
			}

			c.Set(ContextAuthenticatedNodeID, node.ID)
			c.Next()
			return
		}

		// 2. Initial enrollment token authentication (ONLY allowed if node has not registered an Ed25519 key yet)
		nodeToken := c.GetHeader("X-Node-Token")
		if nodeToken != "" && node.AuthTokenHash != "" {
			if node.PublicKey != "" {
				c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "token authentication disabled: node must authenticate via Ed25519 signature"})
				return
			}

			tokenHash := sha256.Sum256([]byte(nodeToken))
			tokenHashHex := hex.EncodeToString(tokenHash[:])

			if subtle.ConstantTimeCompare([]byte(tokenHashHex), []byte(node.AuthTokenHash)) == 1 {
				c.Set(ContextAuthenticatedNodeID, node.ID)
				c.Next()
				return
			}
		}

		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "invalid node authentication credentials"})
	}
}
