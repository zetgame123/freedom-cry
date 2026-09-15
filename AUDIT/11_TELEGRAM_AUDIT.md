# Freedom Cry — Telegram Bot Audit

## Architecture

- **Client Bot**: Handles user registration via invite codes, config delivery
- **Admin Bot**: Administrative commands with Telegram ID allowlist

## Authentication Analysis

### Client Bot
- No direct Telegram ID → VPN mapping prevention in bot code (only library-level code reviewed)
- Bot receives full Telegram user object (ID, first_name, username) with every message
- Bot communicates with API via internal HTTP (no TLS within Docker network)

### Admin Bot
- `ADMIN_TELEGRAM_IDS` env var defines allowed admin Telegram IDs
- `ADMIN_MFA_SECRET` provides additional auth layer
- ⚠️ Default `ADMIN_MFA_SECRET: fc-admin-secret-2026` if not overridden

## Critical Privacy Issue

The bot receives Telegram user IDs and the `RegisterDTO` struct accepts `telegram_id`:
```go
type RegisterDTO struct {
    TelegramID *int64 `json:"telegram_id"`
}
```

If the bot passes the Telegram user's ID during registration, it creates the DIRECT link between Telegram and VPN account.

## Race Condition Risk

If the bot sends invite registration requests to the API, the invite race condition (FC-SEC-05) also applies to bot-initiated registrations.

## Status: PARTIAL AUDIT

The full bot client/admin entry points (`cmd/bot/client/main.go`, `cmd/bot/admin/main.go`) were not fully reviewed as the primary `bot.go` is a library. The actual command handling logic needs separate review.
