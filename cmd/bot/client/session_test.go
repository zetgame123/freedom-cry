package main

import (
	"crypto/rand"
	"io"
	"testing"
	"time"
)

func TestSessionKey_ZeroKnowledgeHMAC(t *testing.T) {
	bootSecret := make([]byte, 32)
	_, _ = io.ReadFull(rand.Reader, bootSecret)

	app := &ClientBotApp{
		bootSecret: bootSecret,
		sessions:   make(map[string]*UserSession),
	}

	key1 := app.sessionKey(123456789)
	key2 := app.sessionKey(123456789)
	key3 := app.sessionKey(987654321)

	if key1 == "" {
		t.Fatal("sessionKey returned empty string")
	}
	if key1 != key2 {
		t.Fatalf("sessionKey is not deterministic for the same chatID: %s != %s", key1, key2)
	}
	if key1 == key3 {
		t.Fatalf("sessionKey collision for different chatIDs: %s == %s", key1, key3)
	}
}

func TestSession_TTLAndLogout(t *testing.T) {
	bootSecret := make([]byte, 32)
	_, _ = io.ReadFull(rand.Reader, bootSecret)

	app := &ClientBotApp{
		bootSecret: bootSecret,
		sessions:   make(map[string]*UserSession),
	}

	chatID := int64(1122334455)
	sess := &UserSession{
		AccountNumber: "1234-5678-9012-3456",
		AuthToken:     "test-jwt-token",
		SubToken:      "test-sub-token",
	}

	app.setSession(chatID, sess)

	// Verify retrieval
	retrieved := app.getSession(chatID)
	if retrieved == nil {
		t.Fatal("expected session to exist, got nil")
	}
	if retrieved.AccountNumber != sess.AccountNumber {
		t.Fatalf("expected account number %s, got %s", sess.AccountNumber, retrieved.AccountNumber)
	}

	// Verify TTL expiry: simulate 31 minutes inactivity
	retrieved.LastActive = time.Now().Add(-31 * time.Minute)
	if expired := app.getSession(chatID); expired != nil {
		t.Fatalf("expected session to be expired and return nil, got %+v", expired)
	}

	// Re-add and test explicit logout deletion
	app.setSession(chatID, sess)
	if app.getSession(chatID) == nil {
		t.Fatal("expected re-added session to exist")
	}

	app.deleteSession(chatID)
	if app.getSession(chatID) != nil {
		t.Fatal("expected session to be deleted after deleteSession")
	}
}

func TestSession_SweepExpiredSessions(t *testing.T) {
	bootSecret := make([]byte, 32)
	_, _ = io.ReadFull(rand.Reader, bootSecret)

	app := &ClientBotApp{
		bootSecret: bootSecret,
		sessions:   make(map[string]*UserSession),
	}

	app.setSession(1, &UserSession{AccountNumber: "ACC-1"})
	app.setSession(2, &UserSession{AccountNumber: "ACC-2"})

	// Force session 1 to be old
	key1 := app.sessionKey(1)
	app.sessions[key1].LastActive = time.Now().Add(-35 * time.Minute)

	app.sweepExpiredSessions()

	if app.getSession(1) != nil {
		t.Fatal("session 1 should have been swept")
	}
	if app.getSession(2) == nil {
		t.Fatal("session 2 should remain active")
	}
}
