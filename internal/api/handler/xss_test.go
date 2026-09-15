package handler_test

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"freedom-cry/internal/api"
	"freedom-cry/internal/config"
	"freedom-cry/internal/models"
	"freedom-cry/internal/service"

	"github.com/gin-gonic/gin"
)

func TestSubscriptionPage_XSS_And_CSP(t *testing.T) {
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
	blindServ, _ := service.NewBlindTokenService(db)
	multiHopServ := service.NewMultiHopService(db, subServ)
	autoHealingServ := service.NewAutoHealingService(db, nil)
	inviteServ := service.NewInviteService(db, cfg, userServ, subServ)

	router := api.SetupRouter(cfg, db, userServ, nodeServ, subServ, billingServ, blindServ, multiHopServ, autoHealingServ, inviteServ)

	// Create test user and plan with XSS payload in Plan name
	user := models.User{
		Email:        "xss_test@freedomcry.net",
		PasswordHash: "hashed",
		IsActive:     true,
	}
	_ = db.Create(&user)
	defer db.Unscoped().Delete(&user)

	xssPayload := `<script>alert("XSS_INJECTION_SUCCESS")</script>`
	plan := models.Plan{
		Name:         "Plan " + xssPayload,
		DurationDays: 30,
		IsActive:     true,
	}
	_ = db.Create(&plan)
	defer db.Unscoped().Delete(&plan)

	// Create a node with XSS in name and country
	node := models.ServerNode{
		Name:        `Node <img src=x onerror=alert(1)>`,
		Country:     `"><script>alert(2)</script>`,
		CountryCode: "XX",
		Host:        "safe.host.net",
		IsOnline:    true,
	}
	_ = db.Create(&node)
	defer db.Unscoped().Delete(&node)

	// Create subscription
	sub, err := subServ.CreateSubscription(user.ID, plan.ID)
	if err != nil {
		t.Fatalf("Failed to create subscription: %v", err)
	}
	defer func() {
		db.Unscoped().Where("subscription_id = ?", sub.ID).Delete(&models.ClientKey{})
		db.Unscoped().Delete(&sub)
	}()

	// Perform HTTP GET request to HTML subscription page
	req, _ := http.NewRequest("GET", "/sub/"+sub.Token, nil)
	req.Header.Set("Accept", "text/html,application/xhtml+xml")
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0")

	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("Expected 200 OK from subscription page, got %d", w.Code)
	}

	body := w.Body.String()

	// 1. ADVERSARIAL CHECK: Raw XSS payloads must NEVER be rendered unescaped in HTML!
	dangerousSnippets := []string{
		`<script>alert("XSS_INJECTION_SUCCESS")</script>`,
		`<img src=x onerror=alert(1)>`,
		`"><script>alert(2)</script>`,
	}

	for _, snippet := range dangerousSnippets {
		if strings.Contains(body, snippet) {
			t.Fatalf("CRITICAL XSS VULNERABILITY DETECTED! Unescaped payload present in response: %s", snippet)
		}
	}

	// 2. Verify proper HTML entity escaping is present
	if !strings.Contains(body, "&lt;script&gt;") {
		t.Errorf("Expected escaped '<script>' as '&lt;script&gt;', body: %s", body)
	}

	// 3. Verify CSP and Privacy Security Headers
	csp := w.Header().Get("Content-Security-Policy")
	if csp == "" || !strings.Contains(csp, "default-src 'none'") {
		t.Errorf("Missing or weak Content-Security-Policy header: %s", csp)
	}

	refPolicy := w.Header().Get("Referrer-Policy")
	if refPolicy != "no-referrer" {
		t.Errorf("Expected Referrer-Policy: no-referrer, got: %s", refPolicy)
	}

	xfo := w.Header().Get("X-Frame-Options")
	if xfo != "DENY" {
		t.Errorf("Expected X-Frame-Options: DENY, got: %s", xfo)
	}

	cacheCtrl := w.Header().Get("Cache-Control")
	if !strings.Contains(cacheCtrl, "no-store") {
		t.Errorf("Expected Cache-Control to contain no-store, got: %s", cacheCtrl)
	}
}
