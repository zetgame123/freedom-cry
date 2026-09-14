package service_test

import (
	"sync"
	"testing"

	"freedom-cry/internal/config"
	"freedom-cry/internal/models"
	"freedom-cry/internal/service"

	"github.com/google/uuid"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

func setupServiceTestDB(t *testing.T) *gorm.DB {
	dsn := "host=localhost user=freedomcry password=freedomcry_secret dbname=freedomcry_db port=5432 sslmode=disable"
	db, err := gorm.Open(postgres.Open(dsn), &gorm.Config{
		Logger: logger.Default.LogMode(logger.Silent),
	})
	if err != nil {
		t.Skipf("Postgres not available for concurrency tests: %v", err)
	}

	_ = db.AutoMigrate(&models.ServerNode{}, &models.Subscription{}, &models.ClientKey{}, &models.User{}, &models.Plan{})
	return db
}

func TestIPAllocation_Concurrency_NoDuplicates(t *testing.T) {
	db := setupServiceTestDB(t)

	cfg := &config.Config{
		App: config.AppConfig{DefaultDNS: "1.1.1.1"},
	}
	subServ := service.NewSubscriptionService(db, cfg)

	// Create test node
	node := models.ServerNode{
		Name:            "Concurrency-Test-Node",
		Country:         "DE",
		CountryCode:     "DE",
		Host:            "test-node.fc.net",
		IsOnline:        true,
		LastAllocatedIP: 1,
	}
	if err := db.Create(&node).Error; err != nil {
		t.Fatalf("Failed to create test node: %v", err)
	}
	defer func() {
		db.Unscoped().Where("node_id = ?", node.ID).Delete(&models.ClientKey{})
		db.Unscoped().Delete(&node)
	}()

	// Create test plan
	plan := models.Plan{
		Name:         "Concurrency Plan",
		DurationDays: 30,
		IsActive:     true,
	}
	if err := db.Create(&plan).Error; err != nil {
		t.Fatalf("Failed to create test plan: %v", err)
	}
	defer db.Unscoped().Delete(&plan)

	// Launch concurrent requests allocating IPs on the exact same node simultaneously
	const numConcurrent = 20
	var wg sync.WaitGroup
	allocatedIPs := make([]string, numConcurrent)
	errs := make([]error, numConcurrent)

	// Create users beforehand
	userIDs := make([]uuid.UUID, numConcurrent)
	for i := 0; i < numConcurrent; i++ {
		user := models.User{
			Email:        uuid.New().String() + "@fc-test.net",
			PasswordHash: "test",
			IsActive:     true,
		}
		_ = db.Create(&user)
		userIDs[i] = user.ID
		defer db.Unscoped().Delete(&user)
	}

	startBarrier := make(chan struct{})

	for i := 0; i < numConcurrent; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			<-startBarrier // Start all requests at the exact same instant

			sub, err := subServ.CreateSubscription(userIDs[idx], plan.ID)
			if err != nil {
				errs[idx] = err
				return
			}
			defer func() {
				db.Unscoped().Where("subscription_id = ?", sub.ID).Delete(&models.ClientKey{})
				db.Unscoped().Delete(sub)
			}()

			for _, k := range sub.ClientKeys {
				if k.NodeID == node.ID {
					allocatedIPs[idx] = k.AwgAddress
				}
			}
		}(i)
	}

	// Release barrier
	close(startBarrier)
	wg.Wait()

	// Verify all succeeded
	seenIPs := make(map[string]bool)
	for i := 0; i < numConcurrent; i++ {
		if errs[i] != nil {
			t.Fatalf("Worker %d failed to create subscription: %v", i, errs[i])
		}
		ip := allocatedIPs[i]
		if ip == "" {
			t.Fatalf("Worker %d got empty IP", i)
		}
		if seenIPs[ip] {
			t.Fatalf("RACE CONDITION DETECTED! Duplicate IP allocated: %s", ip)
		}
		seenIPs[ip] = true
	}

	t.Logf("Successfully allocated %d unique sequential IPs under high concurrency without collisions", len(seenIPs))
}
