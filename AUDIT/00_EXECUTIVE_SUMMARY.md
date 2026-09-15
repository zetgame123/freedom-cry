# Freedom Cry Security & Privacy Audit — Executive Summary

**Audit date:** 2026-09-15
**Version/commit:** `3c43296` (master)
**Environment:** Source code review, static analysis
**Auditor role:** Independent Lead Security & Privacy Engineer

---

## Overall Rating

```
NO-GO
```

## Finding Summary

| Severity | Count |
|----------|-------|
| CRITICAL | 5     |
| HIGH     | 8     |
| MEDIUM   | 7     |
| LOW      | 5     |
| INFO     | 4     |

---

## Top 10 Risks (Ordered by Real User Impact)

### 1. 🔴 CRITICAL — CORS Reflects Any Origin with Credentials
**File:** [`router.go#L52-L69`](file:///home/zet/Projects/Freedom%20Cry/internal/api/router.go#L52-L69)
**Impact:** Any malicious website can make authenticated API requests on behalf of a user whose browser has a valid JWT.

The CORS middleware reflects the `Origin` header directly into `Access-Control-Allow-Origin` AND sets `Access-Control-Allow-Credentials: true`. This is a textbook CORS misconfiguration that enables cross-origin credential theft.

```go
origin := c.Request.Header.Get("Origin")
if origin != "" {
    c.Writer.Header().Set("Access-Control-Allow-Origin", origin)
    c.Writer.Header().Set("Access-Control-Allow-Credentials", "true")
}
```

**Severity:** CRITICAL | **Confidence:** CONFIRMED

---

### 2. 🔴 CRITICAL — TelegramID Stored in Users Table (Zero-Knowledge Claim Violated)
**File:** [`user.go#L24`](file:///home/zet/Projects/Freedom%20Cry/internal/models/user.go#L24)
**Impact:** Complete de-anonymization of users. The `users` table has a `telegram_id` column with a `uniqueIndex`. If PostgreSQL is compromised, the attacker gets `telegram_id` → `user_id` → `subscription_id` → `client_keys` → VPN credentials chain.

```go
TelegramID    *int64         `gorm:"uniqueIndex" json:"telegram_id,omitempty"`
```

The project claims "Zero-Knowledge" and "no link between Telegram and VPN account." **This is demonstrably false.** The direct `telegram_id` column is present and indexed.

Additionally, [`RegisterDTO`](file:///home/zet/Projects/Freedom%20Cry/internal/service/user_service.go#L30) accepts `telegram_id` during registration.

**Severity:** CRITICAL | **Confidence:** CONFIRMED

---

### 3. 🔴 CRITICAL — Hardcoded Master Invite Code and Admin Secret in Source Code
**File:** [`config.go#L78-L84`](file:///home/zet/Projects/Freedom%20Cry/internal/config/config.go#L78-L84)
**Impact:** Anyone who reads the source code (or a Docker image built from it) can register unlimited accounts using the master invite code `FC-FREEDOM-2026` and use admin secret `fc-admin-secret-2026`.

```go
AdminSecret:      "fc-admin-secret-2026",
MasterInviteCode: "FC-FREEDOM-2026",
```

The `docker-compose.prod.yml` also has fallback defaults:
```yaml
ADMIN_MFA_SECRET: "${ADMIN_MFA_SECRET:-fc-admin-secret-2026}"
MASTER_INVITE_CODE: "${MASTER_INVITE_CODE:-FC-FREEDOM-2026}"
```

The AdminSecret grants **full admin privileges** via `X-Admin-Secret` header — bypassing JWT entirely ([`auth.go#L59-L66`](file:///home/zet/Projects/Freedom%20Cry/internal/api/middleware/auth.go#L59-L66)).

**Severity:** CRITICAL | **Confidence:** CONFIRMED

---

### 4. 🔴 CRITICAL — Production API Bound to 0.0.0.0:8080 (Without TLS)
**File:** [`docker-compose.prod.yml#L83`](file:///home/zet/Projects/Freedom%20Cry/docker-compose.prod.yml#L83)
**Impact:** The API is exposed on all interfaces on port 8080 without encryption. Combined with the admin secret hardcoded in Docker image, any network-adjacent attacker can gain full admin control.

```yaml
ports:
  - "0.0.0.0:8080:8080"
```

While a Caddy reverse proxy exists on 80/443, port 8080 is ALSO publicly accessible, bypassing TLS entirely.

**Severity:** CRITICAL | **Confidence:** CONFIRMED

---

### 5. 🔴 CRITICAL — Hysteria 2 TLS Insecure: true in Generated Client Configs
**File:** [`subscription_service.go#L348`](file:///home/zet/Projects/Freedom%20Cry/internal/service/subscription_service.go#L348)
**Impact:** Generated sing-box client configurations have `"insecure": true` for Hysteria 2 TLS, disabling certificate validation. This enables MITM attacks on all Hysteria 2 connections.

```go
"tls": map[string]interface{}{
    "enabled":     true,
    "server_name": k.Node.RealityServerName,
    "insecure":    true,   // ← CRITICAL: MITM vulnerability
},
```

**Severity:** CRITICAL | **Confidence:** CONFIRMED

---

### 6. 🟠 HIGH — Invite Code Race Condition (Non-Atomic Use-Count Check)
**File:** [`invite_service.go#L56-L68`](file:///home/zet/Projects/Freedom%20Cry/internal/service/invite_service.go#L56-L68)
**Impact:** A single-use invite code can be reused by multiple concurrent requests. The check `invite.UsesCount >= invite.MaxUses` and the increment `uses_count + 1` are NOT protected by `SELECT ... FOR UPDATE` row-level locking, creating a TOCTOU race condition.

**Severity:** HIGH | **Confidence:** LIKELY

---

### 7. 🟠 HIGH — Probe Endpoints Have Hardcoded Fallback Secret
**File:** [`probe_handler.go#L28-L29`](file:///home/zet/Projects/Freedom%20Cry/internal/api/handler/probe_handler.go#L28-L29)
**Impact:** If `PROBE_SECRET` env var is not set, the probe handler falls back to `fc-probe-shared-secret-2026`. An attacker can submit fake probe reports to trigger auto-healing, causing IP exhaustion DoS.

```go
if secret == "" {
    secret = "fc-probe-shared-secret-2026"
}
```

**Severity:** HIGH | **Confidence:** CONFIRMED

---

### 8. 🟠 HIGH — Probe Secret Comparison Not Constant-Time
**File:** [`probe_handler.go#L40-L41`](file:///home/zet/Projects/Freedom%20Cry/internal/api/handler/probe_handler.go#L40-L41)
**Impact:** Timing side-channel allows brute-forcing the probe secret.

```go
if provided == "" || provided != h.secret {  // ← string == comparison, NOT constant-time
```

**Severity:** HIGH | **Confidence:** CONFIRMED

---

### 9. 🟠 HIGH — Subscription Token Grants Full Access Without Authentication
**Files:** [`config_handler.go#L31-L81`](file:///home/zet/Projects/Freedom%20Cry/internal/api/handler/config_handler.go#L31-L81)
**Impact:** The 64-char hex subscription token is the ONLY credential protecting all VPN configs, private keys, and subscription management. There is no authentication layer on `/sub/:token/*` endpoints. If the token leaks (via logs, referrer, browser history), full VPN credentials are compromised.

**Severity:** HIGH | **Confidence:** CONFIRMED

---

### 10. 🟠 HIGH — Low Invite Code Entropy (32-bit / 4 bytes)
**File:** [`invite.go#L30`](file:///home/zet/Projects/Freedom%20Cry/internal/models/invite.go#L30)
**Impact:** Invite codes have only 32 bits (4 bytes) of entropy → ~4 billion possible codes. Format: `FC-XXXX-XXXX` (8 hex chars). With 10 req/min rate limiting on auth endpoints, this is still brutable in theory, though practically slow.

```go
bytes := make([]byte, 4)  // Only 4 bytes = 32 bits of entropy
```

**Severity:** HIGH | **Confidence:** CONFIRMED

---

## Top 10 Fixes Before Closed Beta (Priority Order)

| # | Fix | Severity | Effort |
|---|-----|----------|--------|
| 1 | **Remove TelegramID from users table** or isolate in separate DB with no FK link to VPN data | CRITICAL | Medium |
| 2 | **Fix CORS** — implement strict origin allowlist, remove credential reflection | CRITICAL | Low |
| 3 | **Remove all hardcoded secrets** — generate cryptographically random defaults, never ship defaults in code/compose | CRITICAL | Low |
| 4 | **Bind API to 127.0.0.1 in prod** — remove `0.0.0.0:8080` binding, use Caddy only | CRITICAL | Low |
| 5 | **Fix Hysteria 2 TLS insecure:true** — use proper certificate validation or pin | CRITICAL | Low |
| 6 | **Add row-level locking for invite consumption** — `SELECT FOR UPDATE` in transaction | HIGH | Low |
| 7 | **Remove hardcoded probe fallback secret** — require explicit configuration | HIGH | Low |
| 8 | **Use constant-time comparison for probe secret** — `subtle.ConstantTimeCompare` | HIGH | Low |
| 9 | **Increase invite code entropy** — minimum 128 bits (16 bytes) | HIGH | Low |
| 10 | **Add rate limiting on /sub/:token endpoints** — prevent token brute-force | HIGH | Medium |

---

## Privacy Verdict

### Can the operator link Telegram identity to VPN identity?

**YES — CONFIRMED.** The `users` table contains `telegram_id` with a direct foreign key chain to `subscriptions` → `client_keys`. A simple SQL join reveals the complete Telegram → VPN mapping. The "Zero-Knowledge" claim is **FALSE** in the current implementation.

### Can the operator link VPN account to IP?

**PARTIALLY.** The privacy logger masks client IPs in application logs (`[PRIVACY_PROTECTED]`). However:
- Auto-healing logs include node IPs.
- Xray/AmneziaWG system-level logs may record client IPs unless explicitly configured not to.
- The kill switch and agent run at system level where kernel logs may capture IPs.

### What metadata is preserved?

- Account creation timestamp
- Invite code used (inferrable from `uses_count` timing)  
- Subscription creation/expiration timestamps
- Node assignment
- Key rotation timestamps
- AWG PresharedKey (stored plaintext in DB)

### What remains after account deletion?

The `HardDeleteUser` function uses `Unscoped().Delete()` which performs hard deletes of User, Subscriptions, ClientKeys, and Transactions. However:
- PostgreSQL WAL/backups may retain data
- Docker volume snapshots retain data
- Xray/AWG configs on nodes retain VPN UUIDs and public keys until next sync
- Redis cache may retain stale data
- System logs retain historical entries

---

## Security Verdict

### Can an external attacker obtain VPN access?

**YES — CONFIRMED.** Using the hardcoded master invite code `FC-FREEDOM-2026` (if env var not overridden), any attacker can register an account and get full VPN access.

### Can one user obtain credentials of another?

**NO evidence found** in API endpoints. Authorization checks use JWT-extracted `userID`, and IDOR protections are present in handlers. Node sync has explicit cross-node access prevention.

### Can compromise of one node lead to compromise of the entire service?

**PARTIALLY.** A compromised node has:
- All VPN UUIDs and AWG public keys for its users (via sync)
- AWG preshared keys for its users (sent in sync — stored in plaintext)
- Node enrollment token hash (if not yet upgraded to Ed25519)
- NO access to: master DB, Redis, other nodes, Telegram secrets, private keys of users

However, a compromised node CANNOT impersonate another node (Ed25519 keys are per-node).

### Are there traffic leaks?

**NOT TESTED (client-side).** Static analysis of the kill switch code shows proper iptables/nftables rules with IPv6 DROP. However, there is a potential race condition between VPN connection establishment and kill switch activation — no pre-connection leak protection was observed.

### Is there fail-open behavior?

**POSSIBLE.** The StubKillSwitch on non-Linux platforms provides no protection (just sets a boolean). On Linux, if iptables/nftables commands fail, the cleanup function is called, which restores default ACCEPT policies.

---

## Beta Verdict

```
NO-GO
```

### Justification

The project has **5 CRITICAL vulnerabilities** that must be fixed before any user-facing deployment:

1. **CORS misconfiguration** enables cross-site credential theft
2. **TelegramID in users table** completely breaks the Zero-Knowledge privacy model — this is the project's core promise
3. **Hardcoded secrets** in source code provide admin access and unlimited account registration
4. **0.0.0.0 API binding** exposes unencrypted API publicly in production
5. **Hysteria 2 insecure TLS** enables MITM attacks on client connections

Additionally, there are **8 HIGH severity issues** including invite race conditions, probe DoS vectors, and low-entropy invite codes.

The system cannot safely be deployed for closed beta testing until at minimum the 5 CRITICAL issues are resolved.
