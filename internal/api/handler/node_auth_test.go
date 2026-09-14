package handler_test

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	"freedom-cry/internal/api"
	"freedom-cry/internal/config"
	"freedom-cry/internal/models"
	"freedom-cry/internal/service"

	"github.com/gin-gonic/gin"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

// Setup in-memory sqlite or mock for testing
func setupTestDB(t *testing.T) *gorm.DB {
	// Use sqlite in-memory for unit testing if postgres isn't running in tests
	// Or check if postgres is reachable
	dsn := "host=localhost user=freedomcry password=freedomcry_secret dbname=freedomcry_db port=5432 sslmode=disable"
	db, err := gorm.Open(postgres.Open(dsn), &gorm.Config{
		Logger: logger.Default.LogMode(logger.Silent),
	})
	if err != nil {
		t.Skipf("Postgres not available for integration tests: %v", err)
	}

	if err := db.AutoMigrate(&models.User{}, &models.Plan{}, &models.ServerNode{}, &models.Subscription{}, &models.ClientKey{}); err != nil {
		t.Fatalf("AutoMigrate failed: %v", err)
	}
	return db
}

func TestNodeSync_IDOR_And_Auth(t *testing.T) {
	gin.SetMode(gin.TestMode)
	db := setupTestDB(t)

	cfg := &config.Config{
		JWT: config.JWTConfig{Secret: "test-secret-key-must-be-long-enough-for-hs256", Expiry: time.Hour},
		App: config.AppConfig{BaseURL: "http://localhost:8080", DefaultDNS: "1.1.1.1"},
	}

	userServ := service.NewUserService(db, cfg)
	nodeServ := service.NewNodeService(db)
	subServ := service.NewSubscriptionService(db, cfg)
	billingServ := service.NewBillingService(db, subServ)

	router := api.SetupRouter(cfg, db, userServ, nodeServ, subServ, billingServ)

	// Create Node A
	nodeA, tokenA, err := nodeServ.CreateNode(service.CreateNodeDTO{
		Name: "Node-A", Country: "DE", CountryCode: "DE", Host: "node-a.fc.net",
	})
	if err != nil {
		t.Fatalf("Failed to create Node A: %v", err)
	}

	// Create Node B
	nodeB, tokenB, err := nodeServ.CreateNode(service.CreateNodeDTO{
		Name: "Node-B", Country: "NL", CountryCode: "NL", Host: "node-b.fc.net",
	})
	if err != nil {
		t.Fatalf("Failed to create Node B: %v", err)
	}

	// Clean up after test
	defer func() {
		db.Unscoped().Delete(&nodeA)
		db.Unscoped().Delete(&nodeB)
	}()

	// 1. Valid Node A syncing its own ID -> Should Succeed (200 OK)
	{
		reqBody, _ := json.Marshal(map[string]interface{}{
			"node_id":      nodeA.ID.String(),
			"load_percent": 10,
		})
		req, _ := http.NewRequest("POST", "/api/v1/node/sync", bytes.NewBuffer(reqBody))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-Node-ID", nodeA.ID.String())
		req.Header.Set("X-Node-Token", tokenA)

		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Fatalf("Expected 200 OK for valid Node A sync, got %d: %s", w.Code, w.Body.String())
		}
	}

	// 2. Adversarial: Node A attempts to sync Node B's resources (IDOR) -> MUST BE REJECTED (403 Forbidden)
	{
		reqBody, _ := json.Marshal(map[string]interface{}{
			"node_id":      nodeB.ID.String(), // Attacker specifies Node B's ID!
			"load_percent": 10,
		})
		req, _ := http.NewRequest("POST", "/api/v1/node/sync", bytes.NewBuffer(reqBody))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-Node-ID", nodeA.ID.String()) // Authenticated as Node A
		req.Header.Set("X-Node-Token", tokenA)

		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		if w.Code != http.StatusForbidden {
			t.Fatalf("IDOR VULNERABILITY! Node A requested Node B and got status %d (expected 403 Forbidden)! Response: %s", w.Code, w.Body.String())
		}
	}

	// 3. Adversarial: Invalid token -> MUST BE REJECTED (401 Unauthorized)
	{
		reqBody, _ := json.Marshal(map[string]interface{}{
			"node_id": nodeA.ID.String(),
		})
		req, _ := http.NewRequest("POST", "/api/v1/node/sync", bytes.NewBuffer(reqBody))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-Node-ID", nodeA.ID.String())
		req.Header.Set("X-Node-Token", "completely-fake-wrong-token")

		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		if w.Code != http.StatusUnauthorized {
			t.Fatalf("Expected 401 Unauthorized for invalid token, got %d", w.Code)
		}
	}

	// 4. Adversarial: Revoked Node -> MUST BE REJECTED (403 Forbidden)
	{
		_ = nodeServ.RevokeNode(nodeB.ID)

		reqBody, _ := json.Marshal(map[string]interface{}{
			"node_id": nodeB.ID.String(),
		})
		req, _ := http.NewRequest("POST", "/api/v1/node/sync", bytes.NewBuffer(reqBody))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-Node-ID", nodeB.ID.String())
		req.Header.Set("X-Node-Token", tokenB)

		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		if w.Code != http.StatusForbidden {
			t.Fatalf("Expected 403 Forbidden for revoked Node B, got %d", w.Code)
		}
	}
}

func TestNodeSync_Ed25519SignatureAuth(t *testing.T) {
	gin.SetMode(gin.TestMode)
	db := setupTestDB(t)

	pubEd, privEd, _ := ed25519.GenerateKey(nil)

	node := models.ServerNode{
		Name:        "Ed25519-Node",
		Country:     "SE",
		CountryCode: "SE",
		Host:        "se.fc.net",
		IsOnline:    true,
		PublicKey:   hex.EncodeToString(pubEd),
	}
	_ = db.Create(&node)
	defer db.Unscoped().Delete(&node)

	cfg := &config.Config{
		JWT: config.JWTConfig{Secret: "test-secret-key-must-be-long-enough-for-hs256", Expiry: time.Hour},
		App: config.AppConfig{BaseURL: "http://localhost:8080", DefaultDNS: "1.1.1.1"},
	}

	userServ := service.NewUserService(db, cfg)
	nodeServ := service.NewNodeService(db)
	subServ := service.NewSubscriptionService(db, cfg)
	billingServ := service.NewBillingService(db, subServ)

	router := api.SetupRouter(cfg, db, userServ, nodeServ, subServ, billingServ)

	// Valid signature
	tsStr := strconv.FormatInt(time.Now().Unix(), 10)
	msg := fmt.Sprintf("FC-NODE-AUTH:%s:%s:POST:/api/v1/node/sync", node.ID.String(), tsStr)
	sig := ed25519.Sign(privEd, []byte(msg))

	reqBody, _ := json.Marshal(map[string]interface{}{"node_id": node.ID.String()})
	req, _ := http.NewRequest("POST", "/api/v1/node/sync", bytes.NewBuffer(reqBody))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Node-ID", node.ID.String())
	req.Header.Set("X-Node-Timestamp", tsStr)
	req.Header.Set("X-Node-Signature", base64.StdEncoding.EncodeToString(sig))

	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("Expected 200 OK for valid Ed25519 signature, got %d: %s", w.Code, w.Body.String())
	}

	// Adversarial: Expired timestamp (> 60 seconds old) -> MUST BE REJECTED
	oldTsStr := strconv.FormatInt(time.Now().Unix()-120, 10)
	oldMsg := fmt.Sprintf("FC-NODE-AUTH:%s:%s:POST:/api/v1/node/sync", node.ID.String(), oldTsStr)
	oldSig := ed25519.Sign(privEd, []byte(oldMsg))

	reqOld, _ := http.NewRequest("POST", "/api/v1/node/sync", bytes.NewBuffer(reqBody))
	reqOld.Header.Set("Content-Type", "application/json")
	reqOld.Header.Set("X-Node-ID", node.ID.String())
	reqOld.Header.Set("X-Node-Timestamp", oldTsStr)
	reqOld.Header.Set("X-Node-Signature", base64.StdEncoding.EncodeToString(oldSig))

	wOld := httptest.NewRecorder()
	router.ServeHTTP(wOld, reqOld)

	if wOld.Code != http.StatusUnauthorized {
		t.Fatalf("Expected 401 Unauthorized for expired timestamp signature, got %d", wOld.Code)
	}
}
