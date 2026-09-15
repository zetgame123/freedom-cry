package main

import (
	"context"
	"errors"
	"flag"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"freedom-cry/internal/api"
	"freedom-cry/internal/cache"
	"freedom-cry/internal/config"
	"freedom-cry/internal/database"
	"freedom-cry/internal/service"
	"freedom-cry/internal/service/cloud"
)

func main() {
	configPath := flag.String("config", "config.yaml", "path to configuration file")
	flag.Parse()

	log.Println("==================================================")
	log.Println("      🦅 Starting Freedom Cry VPN Backend       ")
	log.Println("==================================================")

	cfg, err := config.Load(*configPath)
	if err != nil {
		log.Fatalf("[Config] Failed to load config: %v", err)
	}

	// Database connection & migrations
	db, err := database.Connect(&cfg.Database)
	if err != nil {
		log.Fatalf("[Database] Failed to initialize database: %v", err)
	}

	// Redis connection
	rdb, err := cache.Connect(&cfg.Redis)
	if err != nil {
		log.Printf("[Redis] Notice: %v", err)
	}
	_ = rdb

	// Services initialization
	userServ := service.NewUserService(db, cfg)
	nodeServ := service.NewNodeService(db)
	subServ := service.NewSubscriptionService(db, cfg)
	billingServ := service.NewBillingService(db, subServ)

	blindServ, err := service.NewBlindTokenService(db)
	if err != nil {
		log.Fatalf("[BlindToken] Failed to initialize service: %v", err)
	}
	multiHopServ := service.NewMultiHopService(db, subServ)

	// Auto-healing service with Hetzner or Mock cloud provider
	var cloudProv cloud.CloudProvider
	if hetznerToken := os.Getenv("HETZNER_API_TOKEN"); hetznerToken != "" {
		cloudProv = cloud.NewHetznerProvider(hetznerToken)
	} else {
		cloudProv = cloud.NewMockCloudProvider()
	}
	autoHealingServ := service.NewAutoHealingService(db, cloudProv)

	// Invite Code & Whitelist service
	inviteServ := service.NewInviteService(db, cfg, userServ, subServ)

	// Router setup
	router := api.SetupRouter(
		cfg, db, userServ, nodeServ, subServ, billingServ,
		blindServ, multiHopServ, autoHealingServ, inviteServ,
	)

	srv := &http.Server{
		Addr:    ":" + cfg.Server.Port,
		Handler: router,
	}

	go func() {
		log.Printf("[Server] Freedom Cry API listening on port %s", cfg.Server.Port)
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Fatalf("[Server] Listen error: %v", err)
		}
	}()

	// Graceful shutdown
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit
	log.Println("[Server] Shutting down gracefully...")

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := srv.Shutdown(ctx); err != nil {
		log.Fatalf("[Server] Forced shutdown: %v", err)
	}

	log.Println("[Server] Freedom Cry exited cleanly")
}
