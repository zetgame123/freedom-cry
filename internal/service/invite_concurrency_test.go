package service_test

import (
	"fmt"
	"sync"
	"sync/atomic"
	"testing"

	"freedom-cry/internal/config"
	"freedom-cry/internal/models"
	"freedom-cry/internal/service"
)

func TestInviteRedemption_100ConcurrentRequests_SingleUse(t *testing.T) {
	db := setupServiceTestDB(t)

	cfg := &config.Config{
		App: config.AppConfig{
			DefaultDNS: "1.1.1.1",
		},
	}
	userServ := service.NewUserService(db, cfg)
	subServ := service.NewSubscriptionService(db, cfg)
	inviteServ := service.NewInviteService(db, cfg, userServ, subServ)

	// Ensure active plan exists
	var plan models.Plan
	if err := db.Where("is_active = ?", true).First(&plan).Error; err != nil {
		plan = models.Plan{
			Name:           "Invite Test Plan",
			DurationDays:   30,
			TrafficLimitGB: 50,
			IsActive:       true,
		}
		if err := db.Create(&plan).Error; err != nil {
			t.Fatalf("Failed to create plan: %v", err)
		}
		defer db.Unscoped().Delete(&plan)
	}

	// Create single-use invite code in database
	testCode := "FC-CONCURRENCY-SINGLE-100"
	db.Unscoped().Where("code = ?", testCode).Delete(&models.InviteCode{})

	invite := models.InviteCode{
		Code:      testCode,
		MaxUses:   1,
		UsesCount: 0,
		IsActive:  true,
		PlanID:    &plan.ID,
	}
	if err := db.Create(&invite).Error; err != nil {
		t.Fatalf("Failed to create invite: %v", err)
	}
	defer db.Unscoped().Where("code = ?", testCode).Delete(&models.InviteCode{})

	const numGoroutines = 100
	var wg sync.WaitGroup
	var successCount atomic.Int32
	var failCount atomic.Int32
	successfulAccounts := make([]string, 0, numGoroutines)
	var mu sync.Mutex

	startBarrier := make(chan struct{})

	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			<-startBarrier // Release all 100 goroutines simultaneously

			resp, err := inviteServ.RegisterWithInvite(testCode)
			if err == nil && resp != nil {
				successCount.Add(1)
				mu.Lock()
				successfulAccounts = append(successfulAccounts, resp.AccountNumber)
				mu.Unlock()
			} else {
				failCount.Add(1)
			}
		}(i)
	}

	// Trigger all 100 requests concurrently
	close(startBarrier)
	wg.Wait()

	t.Logf("100 Concurrent invite redemptions: Successes = %d, Failures = %d", successCount.Load(), failCount.Load())

	// REQUIREMENT: Exactly 1 success for single-use invite!
	if successCount.Load() != 1 {
		t.Fatalf("CRITICAL RACE CONDITION: Expected exactly 1 successful redemption for single-use invite, got %d (successful accounts: %v)",
			successCount.Load(), successfulAccounts)
	}

	if failCount.Load() != numGoroutines-1 {
		t.Fatalf("Expected %d failures, got %d", numGoroutines-1, failCount.Load())
	}

	// Verify final DB state of invite
	var finalInvite models.InviteCode
	if err := db.Where("code = ?", testCode).First(&finalInvite).Error; err != nil {
		t.Fatalf("Failed to query final invite state: %v", err)
	}

	if finalInvite.UsesCount != 1 {
		t.Errorf("Expected final UsesCount = 1, got %d", finalInvite.UsesCount)
	}
	if finalInvite.IsActive != false {
		t.Errorf("Expected final IsActive = false, got %v", finalInvite.IsActive)
	}

	// Clean up created user accounts
	for _, acc := range successfulAccounts {
		db.Unscoped().Where("account_number = ?", acc).Delete(&models.User{})
	}
	fmt.Printf("[Test] Passed: Exactly 1 out of 100 concurrent redemptions succeeded.\n")
}
