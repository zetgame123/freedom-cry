package handler_test

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"freedom-cry/internal/api"
	"freedom-cry/internal/config"
	"freedom-cry/internal/models"
	"freedom-cry/internal/service"

	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
)

func setupInviteTestEnv(t *testing.T) (*gorm.DB, *config.Config, http.Handler) {
	gin.SetMode(gin.TestMode)
	db := setupTestDB(t)

	if err := db.AutoMigrate(
		&models.User{},
		&models.Plan{},
		&models.ServerNode{},
		&models.Subscription{},
		&models.ClientKey{},
		&models.Transaction{},
		&models.RedeemedBlindToken{},
		&models.InviteCode{},
	); err != nil {
		t.Fatalf("Failed to automigrate: %v", err)
	}

	cfg := &config.Config{
		Server: config.ServerConfig{Port: "8080", Mode: "test"},
		JWT:    config.JWTConfig{Secret: "test-secret-key-1234567890123456", Expiry: time.Hour},
		App: config.AppConfig{
			BaseURL:          "http://127.0.0.1:8080",
			AdminSecret:      "test-admin-secret",
			MasterInviteCode: "FC-MASTER-TEST",
		},
	}

	// Ensure at least one active plan
	var planCount int64
	db.Model(&models.Plan{}).Count(&planCount)
	if planCount == 0 {
		plan := models.Plan{
			Name:           "Test Starter Plan",
			DurationDays:   30,
			TrafficLimitGB: 50,
			IsActive:       true,
		}
		_ = db.Create(&plan)
	}

	userServ := service.NewUserService(db, cfg)
	nodeServ := service.NewNodeService(db)
	subServ := service.NewSubscriptionService(db, cfg)
	billingServ := service.NewBillingService(db, subServ)
	blindServ, _ := service.NewBlindTokenService(db)
	multiHopServ := service.NewMultiHopService(db, subServ)
	autoHealingServ := service.NewAutoHealingService(db, nil)
	inviteServ := service.NewInviteService(db, cfg, userServ, subServ)

	router := api.SetupRouter(cfg, db, userServ, nodeServ, subServ, billingServ, blindServ, multiHopServ, autoHealingServ, inviteServ)
	return db, cfg, router
}

func TestInviteRegistrationFlow(t *testing.T) {
	db, _, handler := setupInviteTestEnv(t)

	// 1. Create a single-use invite in DB
	singleCode := "FC-TEST-SINGLE-1"
	_ = db.Where("code = ?", singleCode).Delete(&models.InviteCode{})
	singleInvite := models.InviteCode{
		Code:      singleCode,
		MaxUses:   1,
		UsesCount: 0,
		IsActive:  true,
	}
	_ = db.Create(&singleInvite)
	defer db.Where("code = ?", singleCode).Delete(&models.InviteCode{})

	// 2. Validate invite
	valBody, _ := json.Marshal(map[string]string{"invite_code": singleCode})
	valReq := httptest.NewRequest("POST", "/api/v1/auth/invite/validate", bytes.NewReader(valBody))
	valReq.Header.Set("Content-Type", "application/json")
	valW := httptest.NewRecorder()
	handler.ServeHTTP(valW, valReq)

	if valW.Code != http.StatusOK {
		t.Fatalf("Expected 200 from validate, got %d: %s", valW.Code, valW.Body.String())
	}
	var valRes map[string]interface{}
	_ = json.Unmarshal(valW.Body.Bytes(), &valRes)
	if valRes["valid"] != true {
		t.Fatalf("Expected valid=true, got %v", valRes["valid"])
	}

	// 3. Register first user with this invite
	regBody, _ := json.Marshal(map[string]string{"invite_code": singleCode})
	regReq := httptest.NewRequest("POST", "/api/v1/auth/invite/register", bytes.NewReader(regBody))
	regReq.Header.Set("Content-Type", "application/json")
	regW := httptest.NewRecorder()
	handler.ServeHTTP(regW, regReq)

	if regW.Code != http.StatusCreated {
		t.Fatalf("Expected 201 from register, got %d: %s", regW.Code, regW.Body.String())
	}
	var regRes map[string]interface{}
	_ = json.Unmarshal(regW.Body.Bytes(), &regRes)
	if regRes["account_number"] == nil || regRes["subscription_token"] == nil {
		t.Fatalf("Expected account_number and subscription_token in response: %v", regRes)
	}

	// 4. Try registering a SECOND user with the same single-use invite -> must fail!
	regReq2 := httptest.NewRequest("POST", "/api/v1/auth/invite/register", bytes.NewReader(regBody))
	regReq2.Header.Set("Content-Type", "application/json")
	regW2 := httptest.NewRecorder()
	handler.ServeHTTP(regW2, regReq2)

	if regW2.Code != http.StatusBadRequest {
		t.Fatalf("Expected 400 when reusing single-use invite, got %d", regW2.Code)
	}

	// 5. Test Master Invite Code
	masterBody, _ := json.Marshal(map[string]string{"invite_code": "FC-MASTER-TEST"})
	masterReq := httptest.NewRequest("POST", "/api/v1/auth/invite/register", bytes.NewReader(masterBody))
	masterReq.Header.Set("Content-Type", "application/json")
	masterW := httptest.NewRecorder()
	handler.ServeHTTP(masterW, masterReq)

	if masterW.Code != http.StatusCreated {
		t.Fatalf("Expected 201 with master invite, got %d: %s", masterW.Code, masterW.Body.String())
	}
}

func TestAdminInviteManagement(t *testing.T) {
	_, _, handler := setupInviteTestEnv(t)

	// Create invite via Admin API with X-Admin-Secret
	createBody, _ := json.Marshal(map[string]interface{}{
		"max_uses":    5,
		"description": "Family invite",
	})
	req := httptest.NewRequest("POST", "/api/v1/admin/invites", bytes.NewReader(createBody))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Admin-Secret", "test-admin-secret")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusCreated {
		t.Fatalf("Expected 201 for admin create invite, got %d: %s", w.Code, w.Body.String())
	}

	// List invites
	listReq := httptest.NewRequest("GET", "/api/v1/admin/invites", nil)
	listReq.Header.Set("X-Admin-Secret", "test-admin-secret")
	listW := httptest.NewRecorder()
	handler.ServeHTTP(listW, listReq)

	if listW.Code != http.StatusOK {
		t.Fatalf("Expected 200 for admin list invites, got %d: %s", listW.Code, listW.Body.String())
	}
}
