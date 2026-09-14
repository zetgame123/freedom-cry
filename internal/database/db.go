package database

import (
	"fmt"
	"log"
	"time"

	"freedom-cry/internal/config"
	"freedom-cry/internal/models"
	"freedom-cry/internal/protocol/amneziawg"
	"freedom-cry/internal/protocol/xray"

	"golang.org/x/crypto/bcrypt"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

func Connect(cfg *config.DatabaseConfig) (*gorm.DB, error) {
	dsn := fmt.Sprintf(
		"host=%s user=%s password=%s dbname=%s port=%d sslmode=%s TimeZone=UTC",
		cfg.Host, cfg.User, cfg.Password, cfg.DBName, cfg.Port, cfg.SSLMode,
	)

	db, err := gorm.Open(postgres.Open(dsn), &gorm.Config{
		Logger: logger.Default.LogMode(logger.Warn),
	})
	if err != nil {
		return nil, fmt.Errorf("failed to connect to database: %w", err)
	}

	sqlDB, err := db.DB()
	if err != nil {
		return nil, err
	}

	sqlDB.SetMaxIdleConns(10)
	sqlDB.SetMaxOpenConns(100)
	sqlDB.SetConnMaxLifetime(time.Hour)

	// Run migrations
	if err := db.AutoMigrate(
		&models.User{},
		&models.Plan{},
		&models.ServerNode{},
		&models.Subscription{},
		&models.ClientKey{},
		&models.Transaction{},
	); err != nil {
		return nil, fmt.Errorf("failed to run migrations: %w", err)
	}

	log.Println("[Database] Migrations applied successfully")

	// Seed default data if empty
	SeedDefaults(db)

	return db, nil
}

func SeedDefaults(db *gorm.DB) {
	// Seed Admin user if not exists
	var userCount int64
	db.Model(&models.User{}).Count(&userCount)
	if userCount == 0 {
		hashed, _ := bcrypt.GenerateFromPassword([]byte("admin123"), bcrypt.DefaultCost)
		admin := models.User{
			Email:        "admin@freedomcry.net",
			PasswordHash: string(hashed),
			Role:         models.RoleAdmin,
			Balance:      1000.00,
			IsActive:     true,
		}
		if err := db.Create(&admin).Error; err == nil {
			log.Println("[Seed] Default admin created: admin@freedomcry.net / admin123")
		}
	}

	// Seed Default Plans
	var planCount int64
	db.Model(&models.Plan{}).Count(&planCount)
	if planCount == 0 {
		plans := []models.Plan{
			{
				Name:             "Freedom Starter (1 Month)",
				Description:      "Uncapped speed, VLESS-Reality & AmneziaWG, 100 GB traffic",
				Price:            199.00,
				DurationDays:     30,
				TrafficLimitGB:   100,
				AllowedProtocols: "vless,awg",
				IsActive:         true,
			},
			{
				Name:             "Freedom Unlimited (3 Months)",
				Description:      "Unlimited traffic, All locations, Priority nodes",
				Price:            499.00,
				DurationDays:     90,
				TrafficLimitGB:   0, // Unlimited
				AllowedProtocols: "vless,awg",
				IsActive:         true,
			},
			{
				Name:             "Freedom Year Pass (12 Months)",
				Description:      "Maximum savings, All protocols + Early access to new bypasses",
				Price:            1490.00,
				DurationDays:     365,
				TrafficLimitGB:   0,
				AllowedProtocols: "vless,awg",
				IsActive:         true,
			},
		}
		for _, p := range plans {
			db.Create(&p)
		}
		log.Println("[Seed] Default plans created")
	}

	// Seed Demo Node if no nodes exist
	var nodeCount int64
	db.Model(&models.ServerNode{}).Count(&nodeCount)
	if nodeCount == 0 {
		xrayKeys, _ := xray.GenerateRealityKeyPair()
		awgKeys, _ := amneziawg.GenerateAWGKeyPair()
		awgParams, _ := amneziawg.GenerateDefaultObfuscationParams()

		if xrayKeys != nil && awgKeys != nil && awgParams != nil {
			demoNode := models.ServerNode{
				Name:              "Amsterdam #1 (Fast)",
				Country:           "Netherlands",
				CountryCode:       "NL",
				Host:              "nl1.freedomcry.net",
				IsOnline:          true,
				LoadPercent:       12,
				VlessEnabled:      true,
				VlessPort:         443,
				RealityPrivKey:    xrayKeys.PrivateKey,
				RealityPubKey:     xrayKeys.PublicKey,
				RealityShortID:    xrayKeys.ShortID,
				RealityServerName: "dl.google.com",

				AwgEnabled:      true,
				AwgPort:         51820,
				AwgServerSubnet: "10.8.0.0/24",
				AwgPrivKey:      awgKeys.PrivateKey,
				AwgPubKey:       awgKeys.PublicKey,
				AwgJc:           awgParams.Jc,
				AwgJmin:         awgParams.Jmin,
				AwgJmax:         awgParams.Jmax,
				AwgS1:           awgParams.S1,
				AwgS2:           awgParams.S2,
				AwgH1:           awgParams.H1,
				AwgH2:           awgParams.H2,
				AwgH3:           awgParams.H3,
				AwgH4:           awgParams.H4,
			}
			db.Create(&demoNode)
			log.Println("[Seed] Demo server node created (Amsterdam)")
		}
	}
}
