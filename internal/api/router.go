package api

import (
	"net/http"
	"os"
	"strings"
	"time"

	"freedom-cry/internal/api/handler"
	"freedom-cry/internal/api/middleware"
	"freedom-cry/internal/cache"
	"freedom-cry/internal/config"
	"freedom-cry/internal/service"

	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
)

func SetupRouter(
	cfg *config.Config,
	db *gorm.DB,
	userServ *service.UserService,
	nodeServ *service.NodeService,
	subServ *service.SubscriptionService,
	billingServ *service.BillingService,
	blindServ *service.BlindTokenService,
	multiHopServ *service.MultiHopService,
	autoHealingServ *service.AutoHealingService,
	inviteServ *service.InviteService,
	cacheClient ...*cache.Client,
) *gin.Engine {
	var rdb *cache.Client
	if len(cacheClient) > 0 {
		rdb = cacheClient[0]
	}

	if cfg.Server.Mode == "release" {
		gin.SetMode(gin.ReleaseMode)
	}

	r := gin.New()
	trustedProxies := []string{"127.0.0.1", "::1", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"}
	if envProxies := os.Getenv("TRUSTED_PROXIES"); envProxies != "" {
		parts := strings.Split(envProxies, ",")
		var cleaned []string
		for _, p := range parts {
			if s := strings.TrimSpace(p); s != "" {
				cleaned = append(cleaned, s)
			}
		}
		if len(cleaned) > 0 {
			trustedProxies = cleaned
		}
	}
	_ = r.SetTrustedProxies(trustedProxies)
	r.Use(gin.Recovery())
	// SECURITY & PRIVACY (FC-04): Use PrivacyLogger to mask subscription tokens
	// and suppress recording user home IP addresses in logs.
	r.Use(middleware.PrivacyLogger())

	// Global Security Headers Middleware
	r.Use(func(c *gin.Context) {
		c.Writer.Header().Set("X-Content-Type-Options", "nosniff")
		c.Writer.Header().Set("X-Frame-Options", "DENY")
		c.Writer.Header().Set("Referrer-Policy", "no-referrer")
		c.Writer.Header().Set("Permissions-Policy", "interest-cohort=()")
		if c.Request.TLS != nil || c.GetHeader("X-Forwarded-Proto") == "https" {
			c.Writer.Header().Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains; preload")
		}
		c.Next()
	})

	// CORS Middleware (Strict standards-compliant headers with allowlist verification, FC-SEC-01)
	r.Use(func(c *gin.Context) {
		origin := c.Request.Header.Get("Origin")
		if origin != "" {
			if isAllowedOrigin(origin, cfg) {
				c.Writer.Header().Set("Access-Control-Allow-Origin", origin)
				c.Writer.Header().Set("Access-Control-Allow-Credentials", "true")
			}
			c.Writer.Header().Set("Vary", "Origin")
		}
		c.Writer.Header().Set("Access-Control-Allow-Headers", "Content-Type, Content-Length, Accept-Encoding, X-CSRF-Token, Authorization, accept, origin, Cache-Control, X-Requested-With, X-Node-ID, X-Node-Token, X-Node-Timestamp, X-Node-Signature, X-Probe-Secret")
		c.Writer.Header().Set("Access-Control-Allow-Methods", "POST, OPTIONS, GET, PUT, DELETE, PATCH")

		if c.Request.Method == "OPTIONS" {
			c.AbortWithStatus(204)
			return
		}
		c.Next()
	})

	// Handlers
	authH := handler.NewAuthHandler(userServ)
	userH := handler.NewUserHandler(userServ, db)
	subH := handler.NewSubscriptionHandler(subServ, billingServ, cfg)
	nodeH := handler.NewNodeHandler(nodeServ, db)
	billingH := handler.NewBillingHandler(billingServ, db)
	configH := handler.NewConfigHandler(subServ, cfg)
	blindH := handler.NewBlindHandler(blindServ)
	routeH := handler.NewRouteHandler(multiHopServ)
	probeH := handler.NewProbeHandler(db, nodeServ, autoHealingServ, os.Getenv("PROBE_SECRET"))
	inviteH := handler.NewInviteHandler(inviteServ)

	// Health check
	r.GET("/health", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"status": "ok", "service": "Freedom Cry VPN API"})
	})

	// Public Ping endpoint for browser latency probes & uptime monitoring
	r.GET("/ping", func(c *gin.Context) {
		c.Writer.Header().Set("Access-Control-Allow-Origin", "*")
		c.String(http.StatusOK, "pong")
	})

	// Public Subscription Endpoints (Protected by 256-bit secret token & rate-limiting: 60 req/min per IP)
	subLimiter := middleware.NewRateLimiter(60, time.Minute)
	subGroup := r.Group("/sub")
	subGroup.Use(subLimiter.Middleware())
	{
		subGroup.GET("/:token", configH.GetSubscription)
		subGroup.GET("/:token/vless", configH.GetRawVless)
		subGroup.GET("/:token/awg/:node_id", configH.GetAmneziaWGConfig)
		subGroup.POST("/:token/awg/:node_id/pubkey", configH.RegisterClientPubKey)
		subGroup.GET("/:token/info", configH.GetSubInfo)
		// Universal sing-box full profile with urltest & split-routing
		subGroup.GET("/:token/singbox", configH.GetSingBoxUniversalConfig)
		// Phase 2: Multi-Hop dynamic sing-box chained subscription
		subGroup.GET("/:token/chain/:entry_id/:exit_id", routeH.GetChainedConfig)
	}

	// API v1
	v1 := r.Group("/api/v1")
	{
		// Public Auth protected by rate-limiting (10 attempts / min per IP)
		authLimiter := middleware.NewRateLimiter(10, time.Minute)
		authGroup := v1.Group("/auth")
		authGroup.Use(authLimiter.Middleware())
		{
			authGroup.POST("/register", authH.Register)
			authGroup.POST("/login", authH.Login)
			// Phase 1: Zero-Knowledge Anonymous 16-digit Account registration & login
			authGroup.POST("/account/register", authH.AccountRegister)
			authGroup.POST("/account/login", authH.AccountLogin)
			// Phase 1.5: Option A Whitelist & Invite-code registration
			authGroup.POST("/invite/register", inviteH.RegisterWithInvite)
			authGroup.POST("/invite/validate", inviteH.ValidateInvite)
		}

		// Public Plans & Fleet Status
		v1.GET("/plans", userH.GetPlans)
		v1.GET("/public/status", nodeH.PublicFleetStatus)

		// Phase 1: Blind Token / Privacy Pass Endpoints
		blindGroup := v1.Group("/blind")
		{
			blindGroup.GET("/public-key", blindH.GetPublicKey)
			blindGroup.POST("/redeem", blindH.RedeemToken) // Unauthenticated / Zero-Knowledge
		}
		// Blind Token Signing (requires authenticated active user session)
		v1.POST("/blind/sign", middleware.AuthMiddleware(cfg, db), blindH.SignBlindedToken)

		// Phase 2: Multi-Hop Available Chains
		v1.GET("/routes/chains", routeH.ListChains)

		// Phase 4: Fleet Sensor Probing Endpoints (Protected by rate-limiting & shared secret)
		probeLimiter := middleware.NewRateLimiter(30, time.Minute)
		v1.GET("/node/probe-targets", probeLimiter.Middleware(), probeH.GetProbeTargets)
		v1.POST("/node/probe-report", probeLimiter.Middleware(), probeH.SubmitProbeReport)

		// Node Agent Sync endpoints (Protected by cryptographic per-node identity verification)
		nodeAgentGroup := v1.Group("/node")
		nodeAgentGroup.Use(middleware.RequireNodeAuth(db, rdb))
		{
			nodeAgentGroup.POST("/sync", nodeH.NodeSync)
			nodeAgentGroup.POST("/keys", nodeH.RegisterKeys)
		}

		// Authenticated User Area
		userGroup := v1.Group("/user")
		userGroup.Use(middleware.AuthMiddleware(cfg, db))
		{
			userGroup.GET("/me", userH.GetMe)
			userGroup.DELETE("/me", userH.DeleteMe) // GDPR hard-delete / Right-to-be-forgotten
			userGroup.GET("/nodes", nodeH.ListNodes) // FC-05: Authenticated nodes list
			userGroup.GET("/subscriptions", subH.GetMySubscriptions)
			userGroup.POST("/subscriptions/buy", subH.BuySubscription)
			userGroup.POST("/subscriptions/:id/rotate", subH.RotateToken)
			userGroup.POST("/subscriptions/:id/revoke", subH.RevokeSubscription)
			userGroup.PUT("/subscriptions/:id/awg-key", subH.UpdateAWGKey)

			// Billing
			userGroup.POST("/billing/deposit", billingH.CreateDeposit)
			userGroup.GET("/billing/transactions", billingH.GetUserTransactions)
		}

		// Admin Area
		adminGroup := v1.Group("/admin")
		adminGroup.Use(middleware.AuthMiddleware(cfg, db), middleware.RequireAdmin())
		{
			adminGroup.POST("/nodes", nodeH.AdminCreateNode)
			adminGroup.POST("/billing/transactions/:id/complete", billingH.CompleteDepositManual)

			// Invite Code Management
			adminGroup.GET("/invites", inviteH.ListInvites)
			adminGroup.POST("/invites", inviteH.CreateInvite)
			adminGroup.DELETE("/invites/:id", inviteH.RevokeInvite)

			// User Access Revocation
			adminGroup.DELETE("/users/:account", userH.AdminRevokeUser)
		}
	}

	return r
}

func isAllowedOrigin(origin string, cfg *config.Config) bool {
	if origin == "" {
		return false
	}
	base := strings.TrimRight(cfg.App.BaseURL, "/")
	if base != "" && origin == base {
		return true
	}
	// In debug mode, allow localhost for development
	if cfg.Server.Mode != "release" {
		if origin == "http://localhost" || origin == "http://127.0.0.1" ||
			strings.HasPrefix(origin, "http://localhost:") || strings.HasPrefix(origin, "http://127.0.0.1:") {
			return true
		}
	}
	return false
}
