# Freedom Cry — Remediation Plan

## Priority Execution Order

### 🔴 Phase 1: Critical (Block ALL deployment)

#### 1.1 Fix CORS (FC-SEC-01) — ~1 hour
- Replace origin reflection with strict allowlist
- Test with curl: `curl -H "Origin: https://evil.com" ...`
- Verify: response should NOT reflect evil.com

#### 1.2 Remove hardcoded secrets (FC-SEC-02) — ~2 hours
- Remove ALL default values for secrets from `config.go`
- Add startup validation: fail if JWT_SECRET, ADMIN_MFA_SECRET, MASTER_INVITE_CODE are default/empty in release mode
- Remove `COPY config.example.yaml` from Dockerfile.server
- Remove default values from docker-compose.prod.yml (use `${VAR:?error}` syntax)
- Remove hardcoded probe secret fallback

#### 1.3 Fix API binding (FC-SEC-03) — ~5 minutes
```yaml
# docker-compose.prod.yml
ports:
  - "127.0.0.1:8080:8080"
```

#### 1.4 Fix Hysteria 2 insecure TLS (FC-SEC-04) — ~15 minutes
```go
// subscription_service.go — remove insecure:true
"tls": map[string]interface{}{
    "enabled":     true,
    "server_name": k.Node.RealityServerName,
    // "insecure": true,  ← REMOVE THIS
},
```

#### 1.5 Remove/isolate telegram_id (FC-PRIV-01) — ~4-8 hours
**Option A (Recommended):** Remove `telegram_id` column entirely. Use blind token protocol for Telegram→VPN binding.
**Option B:** Move Telegram mapping to a separate, isolated service/DB that cannot be joined with VPN data.

### 🟠 Phase 2: High Priority (Before closed beta)

#### 2.1 Fix invite race condition (FC-SEC-05) — ~1 hour
```go
func (s *InviteService) RegisterWithInvite(rawCode string) (*InviteRegisterResponse, error) {
    return s.db.Transaction(func(tx *gorm.DB) error {
        var invite models.InviteCode
        // SELECT FOR UPDATE to prevent concurrent reads
        err := tx.Clauses(clause.Locking{Strength: "UPDATE"}).
            Where("LOWER(code) = LOWER(?) AND is_active = ?", code, true).
            First(&invite).Error
        // ... rest of logic using tx instead of s.db
    })
}
```

#### 2.2 Harden probe endpoints (FC-SEC-06, FC-SEC-07) — ~30 minutes
- Use `subtle.ConstantTimeCompare` for probe secret
- Remove hardcoded fallback
- Add rate limiting

#### 2.3 Increase invite entropy (FC-SEC-10) — ~30 minutes
```go
bytes := make([]byte, 16)  // 128 bits instead of 32 bits
```

#### 2.4 Rate limit subscription endpoints — ~1 hour

#### 2.5 Prevent Ed25519 key overwrite — ~30 minutes
```go
if nodeIdentityPubKey != "" {
    var node models.ServerNode
    tx.First(&node, "id = ?", nodeID)
    if node.PublicKey != "" {
        return errors.New("Ed25519 key already registered; rotation requires admin action")
    }
    updates["public_key"] = nodeIdentityPubKey
}
```

#### 2.6 Encrypt AWG PresharedKey — ~2 hours

### 🟡 Phase 3: Medium Priority (Before public beta)

- Move replay cache to Redis
- Add JWT revocation (Redis-backed blacklist)
- Enable PostgreSQL SSL
- Pin Docker images to digest
- Add Redis ACL
- Add USER directive to Dockerfiles
- Add AEAD additional data to key encryption
