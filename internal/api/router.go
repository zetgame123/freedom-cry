package api

import (
	"net/http"

	"freedom-cry/internal/api/handler"
	"freedom-cry/internal/api/middleware"
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
) *gin.Engine {
	if cfg.Server.Mode == "release" {
		gin.SetMode(gin.ReleaseMode)
	}

	r := gin.Default()

	// CORS Middleware
	r.Use(func(c *gin.Context) {
		c.Writer.Header().Set("Access-Control-Allow-Origin", "*")
		c.Writer.Header().Set("Access-Control-Allow-Credentials", "true")
		c.Writer.Header().Set("Access-Control-Allow-Headers", "Content-Type, Content-Length, Accept-Encoding, X-CSRF-Token, Authorization, accept, origin, Cache-Control, X-Requested-With, X-Node-Secret")
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

	// Health check
	r.GET("/health", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"status": "ok", "service": "Freedom Cry VPN API"})
	})

	// Public Subscription Endpoints (No auth needed, token protected)
	subGroup := r.Group("/sub")
	{
		subGroup.GET("/:token", configH.GetSubscription)
		subGroup.GET("/:token/vless", configH.GetRawVless)
		subGroup.GET("/:token/awg/:node_id", configH.GetAmneziaWGConfig)
		subGroup.GET("/:token/info", configH.GetSubInfo)
	}

	// API v1
	v1 := r.Group("/api/v1")
	{
		// Public Auth
		authGroup := v1.Group("/auth")
		{
			authGroup.POST("/register", authH.Register)
			authGroup.POST("/login", authH.Login)
		}

		// Public Plans & Nodes
		v1.GET("/plans", userH.GetPlans)
		v1.GET("/nodes", nodeH.ListNodes)

		// Node Agent Sync endpoint (protected by X-Node-Secret)
		nodeAgentGroup := v1.Group("/node")
		nodeAgentGroup.Use(middleware.RequireNodeSecret(cfg))
		{
			nodeAgentGroup.POST("/sync", nodeH.NodeSync)
		}

		// Authenticated User Area
		userGroup := v1.Group("/user")
		userGroup.Use(middleware.AuthMiddleware(cfg))
		{
			userGroup.GET("/me", userH.GetMe)
			userGroup.GET("/subscriptions", subH.GetMySubscriptions)
			userGroup.POST("/subscriptions/buy", subH.BuySubscription)

			// Billing
			userGroup.POST("/billing/deposit", billingH.CreateDeposit)
			userGroup.GET("/billing/transactions", billingH.GetUserTransactions)
		}

		// Admin Area
		adminGroup := v1.Group("/admin")
		adminGroup.Use(middleware.AuthMiddleware(cfg), middleware.RequireAdmin())
		{
			adminGroup.POST("/nodes", nodeH.AdminCreateNode)
			adminGroup.POST("/billing/transactions/:id/complete", billingH.CompleteDepositManual)
		}
	}

	return r
}
