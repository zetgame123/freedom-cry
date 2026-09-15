# 🦅 Freedom Cry — Complete Security & Privacy Audit Report (Consolidated)

**Audit Date:** 2026-09-15  
**Version/Commit:** `3c43296` (master)  
**Auditor:** Independent Lead Security, Privacy & DevSecOps Auditor  
**Overall Verdict:** **NO-GO** (Critical vulnerabilities require remediation prior to closed beta)  

---

## Table of Contents

- [00_EXECUTIVE_SUMMARY](#00-executive-summary)
- [01_ARCHITECTURE](#01-architecture)
- [02_ATTACK_SURFACE](#02-attack-surface)
- [03_THREAT_MODEL](#03-threat-model)
- [04_SECURITY_FINDINGS](#04-security-findings)
- [05_PRIVACY_FINDINGS](#05-privacy-findings)
- [06_ANONYMITY_ANALYSIS](#06-anonymity-analysis)
- [07_NETWORK_LEAK_TESTS](#07-network-leak-tests)
- [08_AUTHORIZATION_MATRIX](#08-authorization-matrix)
- [09_KEY_MANAGEMENT](#09-key-management)
- [10_DATABASE_PRIVACY](#10-database-privacy)
- [11_TELEGRAM_AUDIT](#11-telegram-audit)
- [12_API_AUDIT](#12-api-audit)
- [13_INFRASTRUCTURE_AUDIT](#13-infrastructure-audit)
- [14_DOCKER_AUDIT](#14-docker-audit)
- [15_FAIL_CLOSED](#15-fail-closed)
- [16_RELIABILITY](#16-reliability)
- [17_SECRET_SCANNING](#17-secret-scanning)
- [18_COVERT_TRANSPORT](#18-covert-transport)
- [19_AUTO_HEALING](#19-auto-healing)
- [20_REMEDIATION_PLAN](#20-remediation-plan)
- [21_RELEASE_READINESS](#21-release-readiness)

---

<a id="00-executive-summary"></a>

# SECTION: 00_EXECUTIVE_SUMMARY

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

---

<a id="01-architecture"></a>

# SECTION: 01_ARCHITECTURE

# Freedom Cry — Architecture Map

## System Topology

```
Internet
   │
   ├── TCP/80,443 ──── Caddy (TLS Termination)
   │                         │
   │                         └── HTTP/8080 → API Container (Gin/Go)
   │                                             │
   │                                             ├── PostgreSQL 16 (freedomcry-internal network)
   │                                             └── Redis 7 (freedomcry-internal network)
   │
   ├── TCP/8080 ──── API Container (⚠️ ALSO exposed directly in prod!)
   │
   ├── TCP/443 ───── Xray/Reality (VLESS) [on VPN nodes]
   │
   ├── UDP/51820 ─── AmneziaWG [on VPN nodes]
   │
   ├── UDP/8443 ──── Hysteria 2 (QUIC) [on VPN nodes]
   │
   └── Telegram API ──── Bot Client Container
                    └── Bot Admin Container
```

## Services Inventory

| Service | Container Name | Image | Ports | Network |
|---------|---------------|-------|-------|---------|
| PostgreSQL | freedom-cry-postgres | postgres:16-alpine | Internal only | freedomcry-internal |
| Redis | freedom-cry-redis | redis:7-alpine | Internal only | freedomcry-internal |
| API | freedom-cry-api | Custom (Dockerfile.server) | 0.0.0.0:8080 ⚠️ | freedomcry-internal |
| Caddy | freedom-cry-caddy | caddy:2-alpine | 80, 443 | freedomcry-internal |
| Bot Client | freedom-cry-bot-client | Custom (Dockerfile.bot) | None | freedomcry-internal |
| Bot Admin | freedom-cry-bot-admin | Custom (Dockerfile.bot) | None | freedomcry-internal |
| Xray | systemd on node | Installed via script | TCP/443 | Host |
| AmneziaWG | kernel module | Installed via script | UDP/51820 | Host |
| Agent | systemd on node | Custom binary | None | Host |

## Credentials Map

| Credential | Storage Location | Type |
|-----------|-----------------|------|
| DB_PASSWORD | .env → docker-compose env | Password |
| REDIS_PASSWORD | .env → docker-compose env | Password |
| JWT_SECRET | .env → docker-compose env | HMAC key |
| ADMIN_MFA_SECRET | .env → docker-compose env (default in code!) | Shared secret |
| MASTER_INVITE_CODE | .env → docker-compose env (default in code!) | Shared secret |
| PROBE_SECRET | .env → docker-compose env (default in code!) | Shared secret |
| CLIENT_BOT_TOKEN | .env → docker-compose env | Telegram API token |
| ADMIN_BOT_TOKEN | .env → docker-compose env | Telegram API token |
| ADMIN_TELEGRAM_IDS | .env → docker-compose env | Telegram user IDs |
| Node enrollment tokens | Generated on node creation, hash in DB | Per-node secret |
| Ed25519 node keys | Private on node, public in DB | Asymmetric key pair |
| Reality X25519 keys | Private on node, public in DB | Asymmetric key pair |
| AWG server keys | Private on node, public in DB | Asymmetric key pair |

## Trust Boundaries

```
┌─────────────────────────────────────────────────┐
│                   INTERNET                       │
│   (Untrusted — all external traffic)             │
└─────────────────────┬───────────────────────────┘
                      │
┌─────────────────────┴───────────────────────────┐
│             CADDY / TLS TERMINATION              │
│   (Trust: TLS certificate validation)            │
└─────────────────────┬───────────────────────────┘
                      │
┌─────────────────────┴───────────────────────────┐
│           DOCKER INTERNAL NETWORK                │
│   (Trust: containers share network)              │
│                                                  │
│   API ←──── Bots                                 │
│    │                                             │
│    ├── PostgreSQL (password auth)                │
│    └── Redis (password auth)                     │
└──────────────────────────────────────────────────┘
         │
┌────────┴─────────────────────────────────────────┐
│              VPN NODE (separate VPS)              │
│   (Trust: Ed25519 mutual auth with Master API)   │
│                                                  │
│   Agent ←→ Master API (HTTPS + Ed25519 sig)      │
│   Xray  ←  User VPN traffic                     │
│   AWG   ←  User VPN traffic                     │
└──────────────────────────────────────────────────┘
```

## Data Stores

| Store | Data | Encryption at Rest | Network Exposure |
|-------|------|-------------------|-----------------|
| PostgreSQL | Users, subs, keys, nodes, invites, transactions | NO (DB-level encryption not configured) | Internal Docker network |
| Redis | Cache (usage not fully traced in code) | NO | Internal Docker network |
| Xray config (node) | VPN user UUIDs, Reality keys | NO (filesystem) | Local to node |
| AWG config (node) | WG peers, PSKs, keys | NO (filesystem) | Local to node |
| agent.env (node) | API URL, node ID, node secret | File permissions 0600 | Local to node |
| Docker volumes | postgres_data, redis_data | NO | Docker host |

---

<a id="02-attack-surface"></a>

# SECTION: 02_ATTACK_SURFACE

# Freedom Cry — Attack Surface

## External TCP/UDP Ports (Production)

| Port | Protocol | Service | Exposed | Auth | Assessment |
|------|----------|---------|---------|------|-----------|
| 80 | TCP | Caddy HTTP→HTTPS redirect | 0.0.0.0 | None | ✅ OK (redirect only) |
| 443 | TCP | Caddy TLS → API reverse proxy | 0.0.0.0 | TLS + JWT/Token | ✅ OK |
| 443 | TCP | Xray Reality (VPN nodes) | 0.0.0.0 | VLESS UUID | ✅ OK |
| 8080 | TCP | API (unencrypted!) | **0.0.0.0** ⚠️ | JWT/Token/AdminSecret | ❌ **CRITICAL** |
| 8443 | UDP | Hysteria 2 (VPN nodes) | 0.0.0.0 | Password | ⚠️ insecure TLS |
| 51820 | UDP | AmneziaWG (VPN nodes) | 0.0.0.0 | WG handshake | ✅ OK |

## Internal-Only Services

| Service | Port | Network | Assessment |
|---------|------|---------|-----------|
| PostgreSQL | 5432 | freedomcry-internal | ✅ Not exposed |
| Redis | 6379 | freedomcry-internal | ✅ Not exposed |

## API Endpoint Map

### Unauthenticated Endpoints

| Method | Path | Rate Limited | Risk |
|--------|------|-------------|------|
| GET | `/health` | No | INFO — service/version fingerprint |
| GET | `/api/v1/plans` | No | LOW — reveals pricing info |
| POST | `/api/v1/auth/register` | 10/min/IP | MEDIUM — account enumeration |
| POST | `/api/v1/auth/login` | 10/min/IP | MEDIUM — credential stuffing |
| POST | `/api/v1/auth/account/register` | 10/min/IP | MEDIUM — mass account creation |
| POST | `/api/v1/auth/account/login` | 10/min/IP | MEDIUM — account brute-force |
| POST | `/api/v1/auth/invite/register` | 10/min/IP | HIGH — invite race condition |
| POST | `/api/v1/auth/invite/validate` | 10/min/IP | MEDIUM — invite enumeration |
| GET | `/api/v1/blind/public-key` | No | LOW — public info |
| POST | `/api/v1/blind/redeem` | No | ⚠️ No rate limit on redemption |
| GET | `/api/v1/routes/chains` | No | LOW — public route info |
| GET | `/api/v1/node/probe-targets` | No (probe secret) | HIGH — hardcoded fallback |
| POST | `/api/v1/node/probe-report` | No (probe secret) | HIGH — auto-healing DoS |

### Token-Authenticated Endpoints (Bearer = subscription token in URL)

| Method | Path | Rate Limited | Risk |
|--------|------|-------------|------|
| GET | `/sub/:token` | **No** | ⚠️ Config exposure |
| GET | `/sub/:token/vless` | **No** | ⚠️ VLESS links exposure |
| GET | `/sub/:token/awg/:node_id` | **No** | ⚠️ AWG config + decrypted private key |
| POST | `/sub/:token/awg/:node_id/pubkey` | **No** | ⚠️ Key replacement |
| GET | `/sub/:token/info` | **No** | ⚠️ Full subscription metadata |
| GET | `/sub/:token/singbox` | **No** | ⚠️ Full sing-box profile |
| GET | `/sub/:token/chain/:entry_id/:exit_id` | **No** | ⚠️ Multi-hop config |

### JWT-Authenticated Endpoints

| Method | Path | Admin Required | Risk |
|--------|------|---------------|------|
| GET | `/api/v1/user/me` | No | LOW |
| DELETE | `/api/v1/user/me` | No | LOW (intended) |
| GET | `/api/v1/user/nodes` | No | LOW |
| GET | `/api/v1/user/subscriptions` | No | LOW |
| POST | `/api/v1/user/subscriptions/buy` | No | MEDIUM |
| POST | `/api/v1/user/subscriptions/:id/rotate` | No | LOW |
| POST | `/api/v1/user/subscriptions/:id/revoke` | No | LOW |
| PUT | `/api/v1/user/subscriptions/:id/awg-key` | No | LOW |
| POST | `/api/v1/user/billing/deposit` | No | MEDIUM |
| GET | `/api/v1/user/billing/transactions` | No | LOW |
| POST | `/api/v1/blind/sign` | No | MEDIUM |

### Admin Endpoints

| Method | Path | Auth | Risk |
|--------|------|------|------|
| POST | `/api/v1/admin/nodes` | JWT Admin OR X-Admin-Secret | HIGH |
| POST | `/api/v1/admin/billing/transactions/:id/complete` | JWT Admin OR X-Admin-Secret | HIGH |
| GET | `/api/v1/admin/invites` | JWT Admin OR X-Admin-Secret | MEDIUM |
| POST | `/api/v1/admin/invites` | JWT Admin OR X-Admin-Secret | HIGH |
| DELETE | `/api/v1/admin/invites/:id` | JWT Admin OR X-Admin-Secret | MEDIUM |

### Node-Authenticated Endpoints (Ed25519 signature)

| Method | Path | Auth | Risk |
|--------|------|------|------|
| POST | `/api/v1/node/sync` | Ed25519 or enrollment token | LOW |
| POST | `/api/v1/node/keys` | Ed25519 or enrollment token | MEDIUM |

---

<a id="03-threat-model"></a>

# SECTION: 03_THREAT_MODEL

# Freedom Cry — Threat Model

## Adversaries and Assessed Capabilities

### A. External Attacker (Internet)
| Capability | Assessment |
|-----------|-----------|
| Enumerate valid invite codes | POSSIBLE — 32-bit entropy, rate-limited (10/min) |
| Brute-force account numbers | POSSIBLE — 53-bit entropy, rate-limited |
| Access API without auth | **CONFIRMED** — 0.0.0.0:8080 in prod, hardcoded admin secret |
| CORS-based credential theft | **CONFIRMED** — CORS reflects any origin with credentials |
| VPN fingerprinting | LOW — Reality + AmneziaWG provide obfuscation |
| TLS interception | **CONFIRMED (Hysteria 2)** — insecure:true disables cert validation |

### B. Attacker with VPN Account ID
| Capability | Assessment |
|-----------|-----------|
| Access VPN configs | NO — requires subscription token (separate from account ID) |
| Link to Telegram | YES — if DB compromised, telegram_id is in same table |
| Impersonate user | NO — needs JWT from login |
| Brute-force login | POSSIBLE — 53-bit account number, rate-limited |

### C. Attacker with Telegram User ID
| Capability | Assessment |
|-----------|-----------|
| Link to VPN account | **YES — DIRECT** via users.telegram_id FK chain |
| Get VPN credentials | YES — if DB also compromised (telegram_id → user → subscription → keys) |
| Use VPN without account | NO |

### D. Compromised Telegram Bot
| Capability | Assessment |
|-----------|-----------|
| Read user Telegram IDs | YES — bots receive user IDs from Telegram API |
| Access VPN API | YES — bot has API_BASE_URL (internal network) |
| Create accounts | YES — via invite/register endpoint |
| Access existing user data | DEPENDS — needs JWT or admin secret |
| Admin access | NO — admin bot has separate token/IDs |

### E. Compromised VPN Node
| Gains | Doesn't Gain |
|-------|-------------|
| VPN UUIDs for its users | Master database |
| AWG public keys for its users | Other nodes' data |
| AWG PSKs (plaintext via sync) | Telegram IDs |
| Node enrollment token (if pre-Ed25519) | JWT secret |
| User tunnel traffic (if active) | Admin secret |
| Node's own Ed25519 private key | AWG private keys (encrypted) |

### F. Compromised Master API
| Impact | Assessment |
|--------|-----------|
| All user data | YES — full DB access |
| All VPN credentials | YES — tokens + encrypted keys (can decrypt) |
| All Telegram IDs | YES — in users table |
| Node control | YES — can push malicious configs via sync |
| Blast radius | **TOTAL — complete system compromise** |

### G. Compromised PostgreSQL
| Gains | Assessment |
|-------|-----------|
| Telegram IDs | **YES — CRITICAL** |
| Account numbers | YES |
| Subscription tokens | YES — can decrypt AWG private keys |
| VLESS UUIDs | YES — plaintext |
| AWG PSKs | YES — plaintext |
| AWG private keys | REQUIRES token (also in DB!) — YES |
| Ed25519 node public keys | YES |

### H. Compromised Redis
| Potential Data | Assessment |
|---------------|-----------|
| Session data | NOT TESTED — Redis usage in code not fully traced |
| Cache data | NOT TESTED |
| Temporary mappings | NOT TESTED |

### I. Compromised Admin Account
| Capability | Assessment |
|-----------|-----------|
| Create nodes | YES |
| Create invites | YES |
| Revoke invites | YES |
| Complete billing transactions | YES |
| Access user VPN keys | NO — admin endpoints don't expose this |
| Access Telegram IDs | INDIRECT — via DB if admin has DB access |
| Mass operations | LIMITED — no mass ban/revoke endpoint |

### J. Global Observer (State-Level)
| Metadata | Correlation Risk |
|----------|-----------------|
| Connection timing | Correlatable with Telegram bot interactions |
| VPN server IP | Reveals node assignment |
| Packet sizes | AmneziaWG obfuscation helps, but timing remains |
| Account lifecycle | Registration → activation → usage pattern |
| DNS queries | Split-DNS may leak .ru domain access patterns |
| Reconnect frequency | User behavior fingerprint |

---

<a id="04-security-findings"></a>

# SECTION: 04_SECURITY_FINDINGS

# Freedom Cry — Security Findings

## Finding FC-SEC-01: CORS Reflects Any Origin with Credentials

```
ID:         FC-SEC-01
Severity:   CRITICAL
Category:   Web Security / CORS
Title:      CORS middleware reflects arbitrary Origin with credentials enabled
Confidence: CONFIRMED
```

**Affected component:** [`internal/api/router.go#L52-L69`](file:///home/zet/Projects/Freedom%20Cry/internal/api/router.go#L52-L69)

**Preconditions:** Victim has a valid JWT in their browser (e.g., from using the HTML subscription page)

**Attack scenario:**
1. Attacker hosts malicious website at `evil.com`
2. Victim visits `evil.com` while having a valid Freedom Cry session
3. JavaScript on `evil.com` sends `fetch('https://api.freedomcry.net/api/v1/user/me', {credentials: 'include'})` 
4. API reflects `Origin: evil.com` → `Access-Control-Allow-Origin: evil.com` with `Access-Control-Allow-Credentials: true`
5. Browser allows the cross-origin request with cookies/credentials
6. Attacker reads user data, subscription tokens, VPN configurations

**Evidence:**
```go
// router.go:52-69
origin := c.Request.Header.Get("Origin")
if origin != "" {
    c.Writer.Header().Set("Access-Control-Allow-Origin", origin)  // Reflects ANY origin
    c.Writer.Header().Set("Access-Control-Allow-Credentials", "true")  // With credentials
} else {
    c.Writer.Header().Set("Access-Control-Allow-Origin", "*")
}
```

**Expected behavior:** Strict allowlist of trusted origins, or no credentials reflection

**Security impact:** Full account takeover via cross-origin requests
**Privacy impact:** All VPN credentials, subscription tokens, account data exposed
**Affected users:** All users who access the API from a browser
**Exploitability:** Low complexity, remote, no authentication required on attacker side

**Recommended remediation:**
```go
allowedOrigins := map[string]bool{
    cfg.App.BaseURL: true,
}
origin := c.Request.Header.Get("Origin")
if origin != "" && allowedOrigins[origin] {
    c.Writer.Header().Set("Access-Control-Allow-Origin", origin)
    c.Writer.Header().Set("Access-Control-Allow-Credentials", "true")
} else {
    c.Writer.Header().Set("Access-Control-Allow-Origin", cfg.App.BaseURL)
}
```

---

## Finding FC-SEC-02: Hardcoded Secrets in Source Code and Docker Defaults

```
ID:         FC-SEC-02
Severity:   CRITICAL
Category:   Secret Management
Title:      Multiple hardcoded secrets serve as operational defaults
Confidence: CONFIRMED
```

**Affected component:** 
- [`internal/config/config.go#L75-L84`](file:///home/zet/Projects/Freedom%20Cry/internal/config/config.go#L75-L84)
- [`docker-compose.prod.yml#L79-L81`](file:///home/zet/Projects/Freedom%20Cry/docker-compose.prod.yml#L79-L81)
- [`config.example.yaml#L19,24`](file:///home/zet/Projects/Freedom%20Cry/config.example.yaml#L19-L24)
- [`probe_handler.go#L29`](file:///home/zet/Projects/Freedom%20Cry/internal/api/handler/probe_handler.go#L29)

**Evidence — hardcoded defaults that become operational:**

| Secret | Default Value | Location | Impact |
|--------|--------------|----------|--------|
| JWT Secret | `freedom-cry-super-secure-jwt-secret-change-in-prod` | config.go:75 | Token forgery in debug mode |
| Admin Secret | `fc-admin-secret-2026` | config.go:82 | Full admin access |
| Master Invite | `FC-FREEDOM-2026` | config.go:83 | Unlimited account registration |
| Node Secret | `fc-node-secret-token-key-2026` | config.go:80 | Legacy node impersonation |
| Probe Secret | `fc-probe-shared-secret-2026` | probe_handler.go:29 | Auto-healing DoS |
| DB Password | `freedomcry_secret` | config.go:66 | Database access |

**Docker-compose.prod.yml uses shell-variable defaults that fall through:**
```yaml
ADMIN_MFA_SECRET: "${ADMIN_MFA_SECRET:-fc-admin-secret-2026}"
MASTER_INVITE_CODE: "${MASTER_INVITE_CODE:-FC-FREEDOM-2026}"
```

**Additionally,** Dockerfile.server copies `config.example.yaml` (with hardcoded secrets) into the Docker image:
```dockerfile
COPY config.example.yaml /app/config.yaml
```

**Security impact:** Complete system compromise via hardcoded admin secret; unlimited account creation via master invite code
**Exploitability:** Trivial — read source code, send header `X-Admin-Secret: fc-admin-secret-2026`

**Recommended remediation:**
1. Remove ALL hardcoded default secrets
2. Require explicit configuration (fail-fast if not set)
3. Generate random secrets on first boot (the JWT handling already does this for release mode — extend to all secrets)
4. Do NOT copy config.example.yaml into production Docker images
5. Add startup validation that rejects known-insecure defaults

---

## Finding FC-SEC-03: Production API Exposed on 0.0.0.0:8080 Without TLS

```
ID:         FC-SEC-03
Severity:   CRITICAL
Category:   Network Exposure
Title:      API container publishes port 8080 on all interfaces in prod
Confidence: CONFIRMED
```

**Affected component:** [`docker-compose.prod.yml#L82-L83`](file:///home/zet/Projects/Freedom%20Cry/docker-compose.prod.yml#L82-L83)

**Evidence:**
```yaml
ports:
  - "0.0.0.0:8080:8080"
```

While the dev compose correctly binds to `127.0.0.1:8080`, the production compose binds to `0.0.0.0`. Caddy handles TLS on 80/443, but port 8080 is also publicly accessible without encryption.

**Attack scenario:**
1. Attacker scans target IP → port 8080 open
2. Sends `curl -H 'X-Admin-Secret: fc-admin-secret-2026' http://target:8080/api/v1/admin/invites`
3. Full admin access without TLS

**Recommended remediation:**
```yaml
ports:
  - "127.0.0.1:8080:8080"
```

---

## Finding FC-SEC-04: Hysteria 2 TLS Certificate Validation Disabled

```
ID:         FC-SEC-04
Severity:   CRITICAL
Category:   Transport Security / MITM
Title:      Sing-box Hysteria 2 configs generated with insecure:true
Confidence: CONFIRMED
```

**Affected component:** [`internal/service/subscription_service.go#L345-L349`](file:///home/zet/Projects/Freedom%20Cry/internal/service/subscription_service.go#L345-L349)

**Evidence:**
```go
"tls": map[string]interface{}{
    "enabled":     true,
    "server_name": k.Node.RealityServerName,
    "insecure":    true,  // ← Disables certificate validation
},
```

**Security impact:** All Hysteria 2 VPN connections can be intercepted via MITM. An attacker who can intercept the network path (ISP, network operator, state-level adversary) can:
- Decrypt all VPN traffic
- Inject/modify traffic
- Identify users by their VPN UUID (sent during handshake)

**Recommended remediation:** Remove `"insecure": true` and use proper certificate pinning or verification.

---

## Finding FC-SEC-05: Invite Code Race Condition — TOCTOU

```
ID:         FC-SEC-05
Severity:   HIGH
Category:   Race Condition / Authorization Bypass
Title:      Single-use invite codes can be consumed multiple times concurrently
Confidence: LIKELY
```

**Affected component:** [`internal/service/invite_service.go#L56-L103`](file:///home/zet/Projects/Freedom%20Cry/internal/service/invite_service.go#L56-L103)

**Attack scenario:**
1. Admin creates single-use invite code (max_uses=1)
2. Attacker sends 100 concurrent `POST /api/v1/auth/invite/register` with same invite code
3. Multiple requests read `uses_count=0`, pass the check, create accounts
4. All succeed before any one increments `uses_count`

**Evidence:** The invite lookup and count check are NOT in a transaction with FOR UPDATE:
```go
// SELECT without locking
err := s.db.Where("LOWER(code) = LOWER(?) AND is_active = ?", code, true).First(&invite).Error

// Check (non-atomic)
if invite.MaxUses > 0 && invite.UsesCount >= invite.MaxUses { ... }

// ... create user and subscription ...

// Update (non-atomic)
s.db.Model(matchedInvite).Updates(map[string]interface{}{
    "uses_count": gorm.Expr("uses_count + 1"),
})
```

**Recommended remediation:** Wrap the entire flow in a database transaction with `SELECT ... FOR UPDATE` on the invite row before checking `uses_count`.

---

## Finding FC-SEC-06: Auto-Healing Probe Endpoints — DoS via Fake Block Reports

```
ID:         FC-SEC-06
Severity:   HIGH
Category:   Denial of Service / Sensor Spoofing
Title:      Unauthenticated or weakly-authenticated probe reports can trigger IP rotation
Confidence: LIKELY
```

**Affected components:**
- [`internal/api/handler/probe_handler.go#L88-L112`](file:///home/zet/Projects/Freedom%20Cry/internal/api/handler/probe_handler.go#L88-L112)
- [`internal/service/auto_healing.go#L76-L95`](file:///home/zet/Projects/Freedom%20Cry/internal/service/auto_healing.go#L76-L95)

**Attack chain:**
1. Attacker learns/guesses probe secret (hardcoded default `fc-probe-shared-secret-2026`)
2. Sends 2 fake probe reports with different `probe_id` values claiming node is unreachable
3. Quorum (>=2 probes) is met → auto-healing triggers
4. Cloud API replaces node's floating IP
5. Repeat → IP exhaustion, service disruption

**Additional issues:**
- No authentication of probe identity (just a shared secret)
- No rate limiting on probe report submissions
- Non-constant-time secret comparison (timing attack)
- Probe endpoints are not behind RequireNodeAuth middleware

---

## Finding FC-SEC-07: AWG PresharedKey Stored in Plaintext

```
ID:         FC-SEC-07
Severity:   HIGH
Category:   Key Management
Title:      AmneziaWG preshared keys stored unencrypted in PostgreSQL
Confidence: CONFIRMED
```

**Affected component:** [`internal/models/key.go#L34`](file:///home/zet/Projects/Freedom%20Cry/internal/models/key.go#L34)

**Evidence:**
```go
AwgPresharedKey    string `gorm:"type:varchar(100)" json:"-"`
```

While the AWG private key is encrypted with `HKDF(sub.Token)`, the preshared key (PSK) is stored in **plaintext**. A database compromise reveals all PSKs. The PSK is also transmitted in plaintext during node sync ([`node_handler.go#L167`](file:///home/zet/Projects/Freedom%20Cry/internal/api/handler/node_handler.go#L167)).

**Security impact:** The PSK provides an additional layer of WireGuard authentication. Its exposure allows impersonation of a user to the VPN server if the attacker also obtains the user's public key.

---

## Finding FC-SEC-08: No Rate Limiting on Subscription Token Endpoints

```
ID:         FC-SEC-08
Severity:   HIGH
Category:   Brute Force / Token Exposure
Title:      /sub/:token/* endpoints have no rate limiting
Confidence: CONFIRMED
```

**Affected component:** [`internal/api/router.go#L89-L100`](file:///home/zet/Projects/Freedom%20Cry/internal/api/router.go#L89-L100)

**Evidence:** The subscription group has NO middleware for rate limiting:
```go
subGroup := r.Group("/sub")
{
    subGroup.GET("/:token", configH.GetSubscription)
    // ... no rate limiter applied
}
```

While subscription tokens are 256-bit (infeasible to brute-force), the lack of rate limiting means:
- Leaked partial tokens could be brute-forced
- Timing attacks on token validation
- Resource exhaustion via rapid requests

---

## Finding FC-SEC-09: Node Ed25519 Public Key Can Be Overwritten

```
ID:         FC-SEC-09
Severity:   MEDIUM
Category:   Authentication Bypass
Title:      RegisterNodeKeys allows overwriting a node's Ed25519 public key
Confidence: LIKELY
```

**Affected component:** [`internal/service/node_service.go#L146-L166`](file:///home/zet/Projects/Freedom%20Cry/internal/service/node_service.go#L146-L166)

**Evidence:**
```go
func (s *NodeService) RegisterNodeKeys(nodeID uuid.UUID, ..., nodeIdentityPubKey string) error {
    updates := map[string]interface{}{}
    if nodeIdentityPubKey != "" {
        updates["public_key"] = nodeIdentityPubKey  // Overwrites existing!
    }
    return s.db.Model(&models.ServerNode{}).Where("id = ? AND is_revoked = ?", nodeID, false).Updates(updates).Error
}
```

If an attacker compromises a node and calls `POST /api/v1/node/keys` with a new `public_key`, the node's Ed25519 identity is overwritten. After this, the attacker uses THEIR private key for all future authentication. There is no check that `public_key` was already set.

**Recommended remediation:** Prevent overwriting `public_key` once it's been set (one-time enrollment).

---

## Finding FC-SEC-10: Node Signature Replay Cache is In-Memory Only

```
ID:         FC-SEC-10
Severity:   MEDIUM
Category:   Replay Attack
Title:      Node signature replay cache lost on API restart
Confidence: CONFIRMED
```

**Affected component:** [`internal/api/middleware/auth.go#L28-L49`](file:///home/zet/Projects/Freedom%20Cry/internal/api/middleware/auth.go#L28-L49)

The replay protection for Ed25519 node signatures uses an in-memory map (`nodeSigCache`). If the API server restarts, the cache is empty, and all signatures from the last 60 seconds become replayable.

---

## Finding FC-SEC-11: Unlimited Anonymous Account Registration

```
ID:         FC-SEC-11
Severity:   MEDIUM
Category:   Abuse / Resource Exhaustion
Title:      POST /api/v1/auth/account/register creates accounts without invite code
Confidence: CONFIRMED
```

**Affected component:** [`internal/api/handler/auth_handler.go#L55-L67`](file:///home/zet/Projects/Freedom%20Cry/internal/api/handler/auth_handler.go#L55-L67)

The `AccountRegister` endpoint creates anonymous accounts without requiring an invite code. While rate-limited to 10/min per IP, this still allows mass account creation via IP rotation. These accounts don't get subscriptions automatically, but they pollute the database.

---

## Finding FC-SEC-12: Account Number as Authentication (Brute-Forceable)

```
ID:         FC-SEC-12
Severity:   MEDIUM
Category:   Authentication Weakness
Title:      16-digit account number serves as the sole authentication credential
Confidence: CONFIRMED
```

**Affected component:** [`internal/service/user_service.go#L135-L152`](file:///home/zet/Projects/Freedom%20Cry/internal/service/user_service.go#L135-L152)

16-digit decimal account number = ~53 bits of entropy. With 10 req/min rate limiting, brute-force is slow but non-trivially feasible for targeted attacks. No account lockout mechanism exists.

---

## Finding FC-SEC-13: DB SSLMode Disabled in Production

```
ID:         FC-SEC-13
Severity:   MEDIUM
Category:   Transport Security
Title:      PostgreSQL connection uses sslmode=disable
Confidence: CONFIRMED
```

**Affected components:**
- [`docker-compose.prod.yml#L73`](file:///home/zet/Projects/Freedom%20Cry/docker-compose.prod.yml#L73): `DB_SSLMODE: "disable"`
- [`config.example.yaml#L11`](file:///home/zet/Projects/Freedom%20Cry/config.example.yaml#L11): `sslmode: "disable"`

While the DB is on an internal Docker network, any container compromise enables unencrypted sniffing of database credentials and queries.

---

## Finding FC-SEC-14: Dockerfile Copies config.example.yaml with Secrets

```
ID:         FC-SEC-14
Severity:   MEDIUM
Category:   Secret Leakage
Title:      Docker image contains config.yaml with hardcoded development secrets
Confidence: CONFIRMED
```

**Affected component:** [`Dockerfile.server#L21`](file:///home/zet/Projects/Freedom%20Cry/Dockerfile.server#L21)

```dockerfile
COPY config.example.yaml /app/config.yaml
```

The config.example.yaml contains: `password: "freedomcry_secret"`, `secret: "freedom-cry-super-secure-jwt-secret-change-in-prod"`, `node_secret: "fc-node-secret-token-key-2026"`.

While env vars override these, they persist in Docker image layers.

---

## Finding FC-SEC-15: Compiled Binaries Committed to Git

```
ID:         FC-SEC-15
Severity:   LOW
Category:   Supply Chain
Title:      10 compiled binaries (>170MB) committed to bin/ directory
Confidence: CONFIRMED
```

**Affected component:** `/home/zet/Projects/Freedom Cry/bin/`

While `.gitignore` lists `bin/`, the directory exists with compiled binaries. If these were committed before the gitignore entry, they're in git history and could contain embedded secrets or outdated vulnerable code.

---

## Finding FC-SEC-16: Redis ACL Not Configured

```
ID:         FC-SEC-16
Severity:   LOW
Category:   Hardening
Title:      Redis uses only password authentication without ACL restrictions
Confidence: CONFIRMED
```

Redis is started with `--requirepass` but no ACL commands to restrict dangerous operations like `CONFIG`, `FLUSHALL`, `EVAL`, `MODULE`.

---

## Finding FC-SEC-17: No JWT Token Revocation

```
ID:         FC-SEC-17
Severity:   LOW
Category:   Session Management
Title:      JWT tokens cannot be revoked before expiry (72 hours)
Confidence: CONFIRMED
```

JWT tokens are valid for 72 hours with no server-side revocation mechanism. If a user deletes their account, their JWT remains valid for up to 72 hours.

---

## Finding FC-SEC-18: StubKillSwitch on Non-Linux

```
ID:         FC-SEC-18
Severity:   LOW
Category:   Client Security
Title:      Kill switch is a no-op on macOS, Windows, and other non-Linux platforms
Confidence: CONFIRMED
```

```go
func NewKillSwitch() KillSwitch {
    if runtime.GOOS == "linux" { ... }
    return &StubKillSwitch{}  // No-op on all other platforms
}
```

---

## Finding FC-SEC-19: Auto-Healing No Cooldown / Rate Limit

```
ID:         FC-SEC-19
Severity:   LOW
Category:   Availability
Title:      Auto-healing has no cooldown between IP rotations for same node
Confidence: CONFIRMED
```

The auto-healing service has no debounce/cooldown mechanism. Repeated false-positive probe reports can trigger rapid IP rotation, exhausting available IPs.

---

<a id="05-privacy-findings"></a>

# SECTION: 05_PRIVACY_FINDINGS

# Freedom Cry — Privacy Findings

## FC-PRIV-01: CRITICAL — TelegramID Directly Stored in Users Table

**The most significant privacy violation in the system.**

The `users` table contains a `telegram_id` column ([`user.go#L24`](file:///home/zet/Projects/Freedom%20Cry/internal/models/user.go#L24)):

```go
TelegramID    *int64   `gorm:"uniqueIndex" json:"telegram_id,omitempty"`
```

This creates a **DIRECT, indexable link** between Telegram identity and VPN account. The claim of "Zero-Knowledge" or "no link between Telegram and VPN account" is **demonstrably false**.

### Linkability Graph

```
Telegram Identity (telegram_id)
       |
       | DIRECT (users.telegram_id → users.id)
       |
VPN Account (users.id)
       |
       | DIRECT (subscriptions.user_id)
       |
Subscription (subscription.id, subscription.token)
       |
       | DIRECT (client_keys.subscription_id)
       |
VPN Key (client_keys.vless_uuid, awg_public_key)
       |
       | DIRECT (client_keys.node_id)
       |
Node (server_nodes.host)
```

### Attacker with Database Dump

```sql
SELECT u.telegram_id, u.account_number, s.token, 
       ck.vless_uuid, ck.awg_public_key, n.host
FROM users u
JOIN subscriptions s ON s.user_id = u.id
JOIN client_keys ck ON ck.subscription_id = s.id
JOIN server_nodes n ON n.id = ck.node_id
WHERE u.telegram_id IS NOT NULL;
```

This single query **completely de-anonymizes** all users who registered via Telegram.

---

## FC-PRIV-02: HIGH — RegisterDTO Accepts and Stores TelegramID

**File:** [`user_service.go#L27-L31`](file:///home/zet/Projects/Freedom%20Cry/internal/service/user_service.go#L27-L31)

```go
type RegisterDTO struct {
    Email      string `json:"email" binding:"required,email"`
    Password   string `json:"password" binding:"required,min=6"`
    TelegramID *int64 `json:"telegram_id"`
}
```

The Register function stores the TelegramID directly:
```go
user := models.User{
    Email:        dto.Email,
    TelegramID:   dto.TelegramID,  // ← Stored!
    ...
}
```

---

## FC-PRIV-03: MEDIUM — Email Stored in Users Table

The `users` table has an `email` column that is indexed. While anonymous accounts use `AccountNumber` without email, the email-based registration path stores a potentially identifying piece of data alongside VPN credentials.

---

## FC-PRIV-04: MEDIUM — Indirect Identifier Correlation Possible

Even without `telegram_id`, the following indirect identifiers could enable correlation:

| Identifier | Location | Correlation Risk |
|-----------|----------|-----------------|
| `created_at` | users, subscriptions | Temporal correlation with Telegram bot interaction |
| `invite_code.uses_count` + timing | invite_codes | If invite sent via Telegram → timing matches registration |
| `node_id` assignment | client_keys | Node selection combined with timing |
| `vless_rotated_at` | client_keys | Rotation timing is predictable (24h) |
| `last_seen_at` | server_nodes | Node activity correlation |

---

## FC-PRIV-05: HIGH — AWG PresharedKey Stored Unencrypted

**File:** [`key.go#L34`](file:///home/zet/Projects/Freedom%20Cry/internal/models/key.go#L34)

The preshared key provides unique per-user identification and is stored in plaintext. A database dump reveals all PSKs, which can be correlated with network traffic.

---

## FC-PRIV-06: MEDIUM — Subscription Token is a De Facto Identity

The 256-bit subscription token serves as:
1. Authentication for config endpoints
2. Encryption key for AWG private keys
3. The subscription URL path component

If the token leaks, the entire VPN identity is compromised. The token is:
- Included in vless:// URIs shown in plaintext
- Part of AWG config download URLs
- Displayed on the HTML subscription page
- Potentially logged by browser history, referrer, or intermediary proxies

---

## FC-PRIV-07: INFO — Privacy Logger Has Gaps

**File:** [`privacy_logger.go`](file:///home/zet/Projects/Freedom%20Cry/internal/api/middleware/privacy_logger.go)

The privacy logger correctly:
- Masks `/sub/:token` paths → `/sub/[REDACTED]`
- Replaces client IP with `[PRIVACY_PROTECTED]`
- Skips health check logs
- Masks query string parameters named `token`, `secret`, `key`, `password`

However, it does NOT mask:
- Authorization headers (JWT tokens visible in non-privacy-logger log outputs)
- Account numbers in paths
- User UUIDs in paths
- Error messages that might contain user data
- Gin's built-in error logging (separate from privacy logger)

---

## Privacy Attack Modeling

### Attack 1: Attacker knows Telegram account

| What | How | Result |
|------|-----|--------|
| Link to VPN account | `SELECT * FROM users WHERE telegram_id = ?` | **DIRECT — full VPN identity** |

### Attack 2: Attacker has VPN account ID

| What | How | Result |
|------|-----|--------|
| Get Telegram identity | `SELECT telegram_id FROM users WHERE id = ?` | **DIRECT** |
| Get VPN credentials | Join to subscriptions → client_keys | **DIRECT** |
| Get assigned nodes | Via client_keys.node_id | **DIRECT** |

### Attack 3: Attacker has database dump

**Complete de-anonymization of all users.** Full Telegram → VPN → Node mapping via simple SQL joins.

### Attack 4: Attacker controls a node

| What | Available | How |
|------|-----------|-----|
| User VPN UUIDs | Yes | Received via node sync |
| User AWG public keys | Yes | Received via node sync |
| User AWG PSKs | Yes | Received via node sync (plaintext) |
| Other nodes' data | No | IDOR protection on sync |
| Database access | No | Internal network only |
| Telegram IDs | No | Not in sync response |

### Attack 5: Attacker has bot logs

**NOT TESTED** — bot code is a library only (no logging seen in `bot.go`). The bot client (`cmd/bot/client/main.go`) needs review for logging of Telegram user IDs.

### Attack 6: Network metadata correlation

| Observable | Correlation |
|-----------|------------|
| Telegram bot interaction timing | Can correlate with VPN account creation timestamps |
| VPN connection timing | Correlatable with Telegram command timestamps |
| Bot → API HTTP requests | API receives bot requests from same Docker network |
| Subscription token access timing | Correlatable with bot message delivery |

**Verdict:** A global observer CAN correlate Telegram events → VPN activation through timing analysis.

---

## Data Retention After Account Deletion

| Data Type | Status After Delete | Location |
|----------|-------------------|----------|
| User row | Hard deleted (Unscoped) | PostgreSQL |
| Subscriptions | Hard deleted | PostgreSQL |
| Client keys | Hard deleted | PostgreSQL |
| Transactions | Hard deleted | PostgreSQL |
| Node-side VPN configs | **STILL ACTIVE until next sync** | Node filesystem |
| Redis cache | **May retain stale data** | Redis |
| Application logs | **Retained** | Docker logs, journald |
| PostgreSQL WAL | **Retained** | Docker volume |
| Database backups | **Retained** | If any exist |
| Telegram chat history | **Retained** | Telegram servers |
| Bot interaction logs | **Unknown** | Bot process |

---

<a id="06-anonymity-analysis"></a>

# SECTION: 06_ANONYMITY_ANALYSIS

# Freedom Cry — Anonymity Analysis

## Four-Dimensional Assessment

### 1. Confidentiality (Can someone read traffic?)

| Protocol | Assessment | Confidence |
|----------|-----------|------------|
| VLESS Reality | ✅ Strong — XTLS-Reality with Chrome fingerprint | CONFIRMED |
| AmneziaWG | ✅ Strong — ChaCha20-Poly1305 + obfuscation | CONFIRMED |
| Hysteria 2 | ❌ **BROKEN** — `insecure: true` disables TLS verification | CONFIRMED |
| API (port 8080) | ❌ **BROKEN** — plaintext HTTP exposed publicly | CONFIRMED |
| API (via Caddy) | ✅ Strong — TLS via Caddy | CONFIRMED |

### 2. Privacy (What does the operator know?)

| Data | Operator Knowledge | Evidence |
|------|-------------------|---------|
| User identity | **FULL** — telegram_id + email in DB | users.telegram_id |
| VPN credentials | **FULL** — tokens + encrypted keys (both in same DB) | subscriptions.token + client_keys |
| Node assignment | **FULL** — client_keys.node_id | Direct FK |
| Usage patterns | **PARTIAL** — traffic_used_bytes, timestamps | subscriptions table |
| Connection times | **INDIRECT** — via Xray/AWG logs on nodes | Not verified |
| Browsing activity | **NO** — no content inspection | Architecture design |

**Verdict:** The operator has sufficient data to fully de-anonymize every user.

### 3. Anonymity (Can user be linked to activity?)

| Link | Exists? | Mechanism |
|------|---------|-----------|
| Telegram → VPN account | **YES** | users.telegram_id |
| VPN account → VPN traffic | **YES** | subscription.token → client_keys.vless_uuid |
| VPN traffic → Node | **YES** | client_keys.node_id |
| Telegram → VPN traffic | **YES** | Transitive through database |

**Verdict:** Complete linkability from Telegram identity to VPN activity.

### 4. Unlinkability (Can two activities of same user be linked?)

| Scenario | Linkable? | Mechanism |
|----------|----------|-----------|
| Two sessions on same node | YES | Same VPN UUID / AWG public key |
| Sessions across VLESS rotation | YES (within 1hr) | previous_vless_uuid overlap |
| Sessions across token rotation | YES | Same user_id, re-encrypted keys |
| Sessions on different nodes | YES | Same subscription_id |
| Sessions after account deletion | NO | Hard delete removes all data |

**Verdict:** All activities within a subscription lifetime are fully linkable.

---

## Blind Token Protocol Assessment

The blind signature implementation ([`blind.go`](file:///home/zet/Projects/Freedom%20Cry/internal/protocol/blind/blind.go)) uses Chaum's RSA blind signatures:

**Positive:**
- Mathematically correct implementation of blind/sign/unblind/verify
- Uses `crypto/rand` for blinding factor generation
- Proper coprimality check for blinding factor

**Concerns:**
- RSA-2048 with raw exponentiation (not RSASSA-PSS or PKCS1v15)
- Private key `D` used directly (no CRT optimization — but this is a correctness concern, not security)
- No double-spend prevention database (token reuse check)
- The blind token protocol is not integrated into the subscription flow — `/blind/redeem` exists but its integration with VPN access is unclear

**Verdict:** The blind signature cryptography is correctly implemented but appears to be in an early/experimental state. It is NOT currently providing the privacy guarantees it's designed for, because the main registration flow still uses direct Telegram ID storage.

---

<a id="07-network-leak-tests"></a>

# SECTION: 07_NETWORK_LEAK_TESTS

# Freedom Cry — Network Leak Tests

## Status: Requires Runtime Environment

These tests require a live deployment with active VPN connections. Static code analysis results only.

## DNS Leak Analysis (Static)

### Sing-box DNS Configuration
- Remote DNS: `https://1.1.1.1/dns-query` (DoH) via VPN tunnel ✅
- Direct DNS: `local` for split-routed domains ⚠️
- Russian domains (gov, yandex, vk, mailru) → `dns-direct` (local resolver)

### Risk: Split-DNS may reveal .ru domain queries to ISP
When accessing Russian services, DNS queries go through the `direct` outbound (local resolver), which means the user's ISP can see DNS queries for these domains.

### AmneziaWG DNS Configuration
- Client config uses: `DNS = 1.1.1.1, 8.8.8.8` (plaintext DNS)
- ⚠️ Not encrypted DNS — DNS queries visible to VPN server operator

### Kill Switch DNS Protection
- Kill switch blocks all outbound except VPN tunnel and LAN
- DNS queries must go through VPN interface (enforced by iptables)
- ⚠️ During kill switch enable/disable transition, brief DNS leak possible

## IPv6 Leak Analysis (Static)

### Kill Switch IPv6 Handling
```go
// killswitch.go:107-109
{"ip6tables", "-P", "INPUT", "DROP"},
{"ip6tables", "-P", "OUTPUT", "DROP"},
{"ip6tables", "-P", "FORWARD", "DROP"},
```
✅ Kill switch sets IPv6 default policies to DROP

### AmneziaWG IPv6 Support
- Client AllowedIPs include `::/0` → all IPv6 routed through tunnel ✅
- Client gets IPv6 address: `fd00:8::x:x/128` ✅
- Server-side NAT66 configured for `fd00:8::/64` ✅

## Required Runtime Tests

| Test | Method | Status |
|------|--------|--------|
| DNS leak (VPN active) | dnsleaktest.com, ipleak.net | NOT TESTED |
| DNS leak (VPN reconnect) | Kill/restart VPN, check DNS | NOT TESTED |
| IPv6 leak (VPN active) | ipv6leak.com, test-ipv6.com | NOT TESTED |
| IPv6 leak (VPN off) | Verify IPv6 blocked by KS | NOT TESTED |
| WebRTC leak | browserleaks.com/webrtc | NOT TESTED |
| IP leak during reconnect | Rapid reconnect cycle | NOT TESTED |
| Split-DNS Russian domains | Query .ru domain, verify resolver | NOT TESTED |

---

<a id="08-authorization-matrix"></a>

# SECTION: 08_AUTHORIZATION_MATRIX

# Freedom Cry — Authorization Matrix

See [21_RELEASE_READINESS.md](file:///home/zet/Projects/Freedom%20Cry/AUDIT/21_RELEASE_READINESS.md) for the full authorization matrix.

## Summary

| Actor | Auth Method | Scope |
|-------|-----------|-------|
| Unauthenticated | None | Health, plans, auth endpoints, blind public-key |
| Sub Token Bearer | 256-bit token in URL | Own subscription configs only |
| JWT User | Bearer JWT (HS256) | Own resources only |
| JWT Admin | Bearer JWT with role=admin | Node/invite/billing management |
| X-Admin-Secret | Static header | Full admin (bypasses JWT) |
| Node Agent | Ed25519 signature | Own node sync/keys only |
| Probe Agent | Shared secret header | Probe targets/reports |

## IDOR/BOLA Assessment

| Endpoint | IDOR Protected? | Evidence |
|----------|----------------|---------|
| GET /user/me | ✅ Yes | Uses JWT-extracted userID |
| DELETE /user/me | ✅ Yes | Uses JWT-extracted userID |
| GET /user/subscriptions | ✅ Yes | WHERE user_id = JWT.sub |
| POST /user/subscriptions/:id/rotate | ✅ Yes | WHERE id=? AND user_id=? |
| POST /user/subscriptions/:id/revoke | ✅ Yes | WHERE id=? AND user_id=? |
| PUT /user/subscriptions/:id/awg-key | ✅ Yes | WHERE id=? AND user_id=? |
| POST /node/sync | ✅ Yes | Checks authenticated node ID matches request |
| POST /node/keys | ✅ Yes | Uses authenticated node ID |
| GET /sub/:token/* | N/A | Token IS the identity — no user context |

---

<a id="09-key-management"></a>

# SECTION: 09_KEY_MANAGEMENT

# Freedom Cry — Key Management Audit

## Key Lifecycle Summary

### AWG Client Private Key

| Phase | Implementation | Assessment |
|-------|---------------|------------|
| **Generate** | `crypto/rand` → 32 bytes → Curve25519 clamping | ✅ Correct |
| **Store** | AES-256-GCM encrypted with HKDF-SHA256(sub.Token) | ✅ Good |
| **Encrypt** | HKDF: IKM=token, salt=static, info=static → AES-256-GCM with random nonce | ✅ Acceptable |
| **Transmit** | Decrypted on-demand when client requests AWG config via /sub/:token | ⚠️ Token in URL |
| **Provision** | Generated server-side, encrypted immediately, plaintext never persisted | ✅ Good |
| **Rotate** | Re-encrypted with new token during token rotation | ✅ Good |
| **Revoke** | Hard deleted on subscription revocation | ✅ Good |
| **Delete** | Hard deleted on user account deletion | ✅ Good |

### HKDF Encryption Scheme Detail

```
IKM   = subscription.Token (256-bit hex string, 64 chars)
Salt  = "freedom-cry-awg-token-salt-v1" (constant)
Info  = "freedom-cry-client-privkey-encryption" (constant)
KDF   = HKDF-SHA256
Key   = 32 bytes (AES-256)
AEAD  = AES-256-GCM
Nonce = 12 bytes random (prepended to ciphertext)
AAD   = nil (⚠️ no binding to key ID or subscription ID)
```

### Security Assessment of Encryption:

1. **Can DB-only attacker decrypt?** NO — requires subscription token (not stored alongside encrypted data)
2. **Can app-compromise attacker decrypt?** YES — application has access to tokens in DB (subscriptions.token)
3. **Can backup attacker decrypt?** PARTIALLY — backup contains both encrypted keys AND tokens, so YES
4. **Is the salt per-key?** NO — static salt, but IKM (token) is unique per subscription
5. **Is the nonce unique?** YES — `crypto/rand` generated per encryption call

### VLESS UUID

| Phase | Implementation | Assessment |
|-------|---------------|------------|
| **Generate** | `uuid.New()` (crypto/rand-based UUID v4) | ✅ Correct |
| **Store** | Plaintext in client_keys table | ⚠️ Not encrypted |
| **Rotate** | Every 24 hours, previous UUID kept for 1-hour grace period | ✅ Good |
| **Provision** | Synced to node via NodeSync endpoint | ✅ Proper auth |

### Reality X25519 Keys

| Phase | Implementation | Assessment |
|-------|---------------|------------|
| **Generate** | `crypto/rand` → 32 bytes → Curve25519 clamping | ✅ Correct |
| **Store** | Private key on node only; public key in master DB | ✅ Good architecture |
| **Rotate** | NOT ROTATED | ⚠️ No rotation mechanism |

### Ed25519 Node Identity Keys

| Phase | Implementation | Assessment |
|-------|---------------|------------|
| **Generate** | Node-side (not reviewed — agent binary) | NOT TESTED |
| **Store** | Public key in server_nodes table | ✅ OK |
| **Verify** | Ed25519 signature over `FC-NODE-AUTH:nodeID:timestamp:method:path:bodyHash` | ✅ Good |
| **Replay** | 60-second window + in-memory signature cache | ⚠️ Cache lost on restart |
| **Rotate** | Not prevented — public key can be overwritten | ❌ Security issue |

### Enrollment Token

| Phase | Implementation | Assessment |
|-------|---------------|------------|
| **Generate** | `crypto/rand` → 32 bytes → SHA256 hash stored | ✅ Good |
| **Store** | Hash only (SHA256) | ✅ Correct |
| **Verify** | SHA256(provided) compared constant-time to stored hash | ✅ Good |
| **Disable** | Auto-disabled after Ed25519 key registration | ✅ Good |

### Blind Signature Keys (RSA-2048)

| Phase | Implementation | Assessment |
|-------|---------------|------------|
| **Generate** | `rsa.GenerateKey(rand.Reader, 2048)` | ✅ Correct |
| **Scheme** | Chaum blind signatures | ✅ Correct implementation |
| **Risk** | RSA-2048 with raw exponentiation (not PSS/PKCS1v15) | ⚠️ Non-standard |

---

<a id="10-database-privacy"></a>

# SECTION: 10_DATABASE_PRIVACY

# Freedom Cry — Database Privacy Audit

## Schema Map

### Table: `users`

| Column | Type | Sensitive? | Can Identify User? | Retention |
|--------|------|-----------|-------------------|-----------|
| `id` | uuid | Yes (PK) | Indirect | Hard delete on user delete |
| `account_number` | varchar(32) | Yes | **YES — authentication credential** | Hard delete |
| `email` | string | **YES** | **YES — PII** | Hard delete |
| `password_hash` | string | Yes | Indirect | Hard delete |
| `telegram_id` | int64 | **CRITICAL YES** | **YES — directly identifies Telegram account** | Hard delete |
| `balance` | decimal | No | No | Hard delete |
| `role` | varchar(20) | No | No | Hard delete |
| `is_active` | bool | No | No | Hard delete |
| `created_at` | timestamp | Yes | Indirect (temporal correlation) | Hard delete |
| `updated_at` | timestamp | Yes | Indirect | Hard delete |
| `deleted_at` | timestamp | Yes | Indirect | Hard delete (Unscoped) |

### Table: `subscriptions`

| Column | Type | Sensitive? | Can Identify User? | Retention |
|--------|------|-----------|-------------------|-----------|
| `id` | uuid | Yes (PK) | Indirect | Hard delete |
| `user_id` | uuid (FK→users) | **YES** | **Links subscription to user** | Hard delete |
| `plan_id` | uuid | No | No | Hard delete |
| `token` | varchar(64) | **CRITICAL** | **YES — bearer credential & encryption key** | Hard delete |
| `status` | varchar(20) | No | No | Hard delete |
| `traffic_limit_bytes` | int64 | No | No | Hard delete |
| `traffic_used_bytes` | int64 | Yes | Indirect (usage pattern) | Hard delete |
| `expires_at` | timestamp | Yes | Indirect | Hard delete |
| `created_at` | timestamp | Yes | Indirect | Hard delete |

### Table: `client_keys`

| Column | Type | Sensitive? | Can Identify User? | Retention |
|--------|------|-----------|-------------------|-----------|
| `id` | uuid | Yes (PK) | Indirect | Hard delete |
| `subscription_id` | uuid (FK) | **YES** | **Links key to subscription→user** | Hard delete |
| `node_id` | uuid (FK) | Yes | Indirect (reveals node assignment) | Hard delete |
| `protocol` | varchar(20) | No | No | Hard delete |
| `vless_uuid` | varchar(64) | **YES** | **YES — VPN identity on Xray** | Hard delete |
| `previous_vless_uuid` | varchar(64) | **YES** | **YES — previous VPN identity** | Hard delete |
| `vless_rotated_at` | timestamp | Yes | Indirect | Hard delete |
| `awg_address` | varchar(100) | **YES** | **YES — VPN tunnel IP** | Hard delete |
| `awg_public_key` | varchar(100) | **YES** | **YES — WireGuard identity** | Hard delete |
| `awg_private_key_enc` | text | **CRITICAL** | **YES — encrypted VPN credential** | Hard delete |
| `awg_preshared_key` | varchar(100) | **CRITICAL (PLAINTEXT)** | **YES — WireGuard PSK** | Hard delete |

### Table: `server_nodes`

| Column | Type | Sensitive? | Can Identify User? | Retention |
|--------|------|-----------|-------------------|-----------|
| `host` | string | Yes | No (server IP) | Retained |
| `public_key` | varchar(128) | Yes | No (node identity) | Retained |
| `auth_token_hash` | varchar(64) | Yes | No (node auth) | Retained |
| `reality_pub_key` | string | Yes | No (public key) | Retained |
| `reality_short_id` | string | Yes | No (shared config) | Retained |
| `awg_pub_key` | string | Yes | No (server public key) | Retained |
| `awg_h1-h4` | uint32 | Yes | No (obfuscation params) | Retained |

### Table: `invite_codes`

| Column | Type | Sensitive? | Can Identify User? | Retention |
|--------|------|-----------|-------------------|-----------|
| `code` | varchar(64) | Yes | Indirect (distribution channel) | Soft delete |
| `uses_count` | int | Yes | Indirect (timing correlation) | Soft delete |
| `plan_id` | uuid | No | No | Soft delete |

### Table: `transactions`

| Column | Type | Sensitive? | Can Identify User? | Retention |
|--------|------|-----------|-------------------|-----------|
| `user_id` | uuid (FK) | **YES** | Links to user | Hard delete |

## Critical Finding: Full De-Anonymization Chain

```sql
-- This query reveals the COMPLETE identity of every user
SELECT 
    u.telegram_id,
    u.email,
    u.account_number,
    u.created_at as user_created,
    s.token as sub_token,
    s.status,
    s.expires_at,
    ck.vless_uuid,
    ck.awg_public_key,
    ck.awg_preshared_key,  -- PLAINTEXT!
    ck.awg_address,
    n.name as node_name,
    n.host as node_ip
FROM users u
JOIN subscriptions s ON s.user_id = u.id
JOIN client_keys ck ON ck.subscription_id = s.id
JOIN server_nodes n ON n.id = ck.node_id
WHERE u.deleted_at IS NULL;
```

This single query provides:
- **Who** (telegram_id, email)
- **What** (VPN credentials, keys)
- **Where** (node assignment, tunnel IP)
- **When** (timestamps)

---

<a id="11-telegram-audit"></a>

# SECTION: 11_TELEGRAM_AUDIT

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

---

<a id="12-api-audit"></a>

# SECTION: 12_API_AUDIT

# Freedom Cry — API Security Audit

## Authentication Mechanisms

### 1. JWT (HS256) — User Authentication
- **Algorithm enforcement**: ✅ Explicit HS256 check, rejects "none" and asymmetric algorithms
- **Token expiry**: 72 hours (⚠️ long, no revocation)
- **Claims**: sub (UUID), role, account_number, email (if present), exp, iat
- **Secret**: Environment variable, fail-safe auto-generation in release mode

### 2. X-Admin-Secret — Admin Bypass
- **Comparison**: ✅ `subtle.ConstantTimeCompare`
- **Risk**: ❌ Hardcoded default `fc-admin-secret-2026`
- **Scope**: Full admin access without JWT

### 3. Ed25519 Signatures — Node Authentication  
- **Message format**: `FC-NODE-AUTH:{nodeID}:{timestamp}:{method}:{path}:{bodyHash}`
- **Replay protection**: 60-second window + in-memory cache
- **Body binding**: SHA256 of request body included in signed message ✅

### 4. Enrollment Token — Initial Node Auth
- **Storage**: SHA256 hash in DB
- **Comparison**: ✅ `subtle.ConstantTimeCompare`
- **Auto-disable**: After Ed25519 key registration ✅

### 5. Subscription Token — Config Authentication
- **Entropy**: 256 bits (64 hex chars) ✅
- **Validation**: Length check (>=16 chars) + DB lookup

## Input Validation

### SQL Injection
All database queries use GORM parameterized queries:
```go
s.db.Where("token = ?", token)
s.db.First(&user, "id = ?", userID)
s.db.Where("LOWER(code) = LOWER(?)", code)
```
✅ No raw SQL injection vectors found.

### Command Injection
Kill switch uses `exec.Command` with separate args (not shell interpolation):
```go
cmd := exec.Command("iptables", "-A", "FC_KILLSWITCH", ...)
```
✅ No command injection vectors found in API code.

### XSS
HTML rendering uses Go's `html/template` with auto-escaping:
```go
template.Must(template.New("subscriptionPage").Parse(subscriptionTemplateHTML))
```
✅ Contextual auto-escaping prevents XSS.

### JSON Parsing
Uses `gin.ShouldBindJSON` with Go's `encoding/json` — no known vulnerabilities.
⚠️ No explicit request body size limit configured.

## Rate Limiting

| Scope | Limit | Implementation |
|-------|-------|---------------|
| Auth endpoints | 10/min/IP | In-memory sliding window |
| Admin endpoints | None | ❌ No rate limiting |
| Subscription endpoints | None | ❌ No rate limiting |
| Node sync | None | ❌ No rate limiting |
| Probe endpoints | None | ❌ No rate limiting |

## Security Headers ✅

```
X-Content-Type-Options: nosniff
X-Frame-Options: DENY
Referrer-Policy: no-referrer
Permissions-Policy: interest-cohort=()
Strict-Transport-Security: max-age=31536000 (when HTTPS)
Content-Security-Policy: (on HTML pages)
Cache-Control: no-store (on config pages)
```

---

<a id="13-infrastructure-audit"></a>

# SECTION: 13_INFRASTRUCTURE_AUDIT

# Freedom Cry — Infrastructure Audit

## Node Setup Script Assessment

**File:** [`scripts/setup-node.sh`](file:///home/zet/Projects/Freedom%20Cry/scripts/setup-node.sh)

### Positive Findings
- ✅ Systemd service has comprehensive sandboxing directives
- ✅ `NoNewPrivileges=yes`, `ProtectSystem=strict`, `ProtectHome=yes`
- ✅ Minimal capabilities: `CAP_NET_ADMIN`, `CAP_NET_BIND_SERVICE`
- ✅ Env file permissions set to 0600
- ✅ Config directory permissions set to 700
- ✅ BBR congestion control enabled
- ✅ Client-to-client VPN isolation (iptables DROP 10.8.0.0/16 → 10.8.0.0/16)
- ✅ Cloud metadata blocking (169.254.0.0/16 DROP)
- ✅ Host isolation (VPN clients can only reach host DNS on port 53)
- ✅ IPv6 NAT66 and dual-stack firewall rules

### Concerns
- ⚠️ Xray installed from beta channel: `install-release.sh @ install --beta`
- ⚠️ Script runs as root (required but noted)
- ⚠️ AmneziaWG PPA added without GPG key verification in fallback path
- ⚠️ Multiple `|| true` silent failure suppression
- ⚠️ Node secret visible in process list during script execution

## Firewall Rules Summary (on VPN nodes)

### IPv4
| Rule | Direction | Assessment |
|------|-----------|-----------|
| NAT MASQUERADE 10.8.0.0/16 | POSTROUTING | ✅ Required |
| DROP 10.8.0.0/16 → 10.8.0.0/16 | FORWARD | ✅ Client isolation |
| DROP 10.8.0.0/16 → 169.254.0.0/16 | FORWARD | ✅ Metadata protection |
| ACCEPT 10.8.0.0/16 → :53 (UDP/TCP) | INPUT | ✅ DNS only |
| ACCEPT RELATED,ESTABLISHED | INPUT | ✅ Standard |
| DROP 10.8.0.0/16 → * | INPUT | ✅ Host isolation |
| ACCEPT 10.8.0.0/16 | FORWARD | ✅ Internet access |

### IPv6
| Rule | Assessment |
|------|-----------|
| NAT66 fd00:8::/64 | ✅ Dual-stack |
| DROP fd00:8::/64 → fd00:8::/64 | ✅ Client isolation |
| Host isolation (DNS only) | ✅ Matching IPv4 rules |

## Deployment Script (deploy-master.sh)

**Status:** Not reviewed in detail — 2862 bytes. Should be verified for secret handling.

---

<a id="14-docker-audit"></a>

# SECTION: 14_DOCKER_AUDIT

# Freedom Cry — Docker Security Audit

## Container Security Assessment

### API Container (freedom-cry-api)

| Check | Status | Evidence |
|-------|--------|---------|
| `no-new-privileges` | ✅ Set | `security_opt: no-new-privileges:true` |
| Privileged mode | ✅ Not set | — |
| Root user | ⚠️ Runs as root (no USER directive) | `Dockerfile.server` has no USER |
| Read-only filesystem | ❌ Not set | — |
| Docker socket | ✅ Not mounted | — |
| Host networking | ✅ Not used | Uses bridge network |
| Port exposure | ❌ **0.0.0.0:8080** in prod | `docker-compose.prod.yml:83` |
| Secrets in image | ❌ `config.example.yaml` copied to image | `Dockerfile.server:21` |
| Log limits | ✅ Set | `max-size: 10m, max-file: 3` |
| Base image | ⚠️ `alpine:3.20` — check for updates | Unpinned minor |

### PostgreSQL Container

| Check | Status |
|-------|--------|
| `no-new-privileges` | ✅ Set |
| Network exposure | ✅ Internal only |
| Volume | Named volume `postgres_data` |
| Health check | ✅ Configured |
| SSL/TLS | ❌ **SSLMode=disable** |

### Redis Container

| Check | Status |
|-------|--------|
| `no-new-privileges` | ✅ Set |
| Password auth | ✅ `--requirepass` |
| Network exposure | ✅ Internal only |
| ACL restrictions | ❌ No ACL configured |
| Persistence | Enabled (volume mounted) |

### Bot Containers

| Check | Status |
|-------|--------|
| `no-new-privileges` | ✅ Set |
| Network exposure | ✅ No ports published |
| Secrets | Telegram tokens via env vars |

## Network Isolation

```
freedomcry-internal (bridge)
├── postgres  (internal only)
├── redis     (internal only)
├── api       (ports: 0.0.0.0:8080 ⚠️)
├── caddy     (ports: 80, 443)
├── bot-client (no ports)
└── bot-admin  (no ports)
```

All containers are on the same bridge network. This means:
- ✅ PostgreSQL/Redis not exposed to internet
- ✅ Bots communicate with API via internal hostname
- ⚠️ Any container compromise can reach PostgreSQL/Redis
- ❌ API port 8080 exposed publicly alongside Caddy

## Dockerfile Security

### Dockerfile.server
- Multi-stage build ✅
- Build dependencies stripped ✅
- `CGO_ENABLED=0` ✅
- `-ldflags="-w -s"` strips debug info ✅
- ❌ No `USER` directive — runs as root
- ❌ Copies `config.example.yaml` with hardcoded secrets

### Dockerfile.agent
- Multi-stage build ✅
- Includes `iptables` package (needed for kill switch)
- ❌ No `USER` directive

## Systemd Agent Hardening (on VPN nodes)

The setup-node.sh creates a well-hardened systemd service:

```ini
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
ProtectKernelTunables=yes
ProtectControlGroups=yes
RestrictSUIDSGID=yes
LockPersonality=yes
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
```

✅ This is a strong hardening profile. The agent only has `CAP_NET_ADMIN` (needed for WireGuard management) and `CAP_NET_BIND_SERVICE`.

---

<a id="15-fail-closed"></a>

# SECTION: 15_FAIL_CLOSED

# Freedom Cry — Fail-Closed Analysis

## Kill Switch Implementation

**File:** [`internal/client/killswitch/killswitch.go`](file:///home/zet/Projects/Freedom%20Cry/internal/client/killswitch/killswitch.go)

### iptables Rules (Linux)

```
1. IPv6: DROP all (INPUT, OUTPUT, FORWARD)
2. Create FC_KILLSWITCH chain
3. Allow loopback
4. Allow ESTABLISHED,RELATED
5. Allow LAN (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, multicast)
6. Allow VPN server IP:port (UDP + TCP)
7. Allow VPN interface
8. DROP everything else
9. Insert FC_KILLSWITCH at top of OUTPUT
```

### nftables Rules (Linux, preferred)

```nft
table inet fc_killswitch {
    chain output {
        type filter hook output priority 0; policy drop;
        oif "lo" accept
        ct state { established, related } accept
        ip daddr { LAN ranges } accept
        ip daddr VPN_IP udp/tcp dport VPN_PORT accept
        oif "VPN_IFACE" accept
    }
}
```

### Assessment

| Scenario | Expected | Code Analysis | Leak Risk |
|----------|----------|--------------|-----------|
| VPN process dies | Traffic blocked | ✅ FC_KILLSWITCH persists in iptables | No |
| VPN reconnect | Traffic blocked during gap | ✅ Rules persist, only VPN iface allowed | No |
| Network switch | Traffic blocked | ✅ Rules are interface-agnostic (except VPN iface) | No |
| IPv6 available | Blocked | ✅ ip6tables DROP all | No |
| KS enable fails | ⚠️ **POSSIBLE LEAK** | cleanup() called → restores ACCEPT | **YES** |
| Non-Linux OS | **LEAK** | StubKillSwitch is no-op | **YES** |
| Docker restart (server) | Traffic continues on last config | ✅ Node configs persist on disk | No |
| API unavailable | Existing sessions work | ✅ Node uses last-synced config | No |
| Agent crash | Existing sessions work | ✅ Xray/AWG configs on disk persist | No |

### CRITICAL: Kill Switch Failure Path

```go
func (k *LinuxKillSwitch) Enable(...) error {
    // ... apply rules ...
    if err != nil {
        _ = k.cleanup()  // ← Restores ACCEPT policies!
        return fmt.Errorf("failed to enable killswitch: %w", err)
    }
}
```

If ANY iptables command fails during activation, `cleanup()` runs and:
```go
func (k *LinuxKillSwitch) cleanup() error {
    // ...
    _ = exec.Command("ip6tables", "-P", "INPUT", "ACCEPT").Run()
    _ = exec.Command("ip6tables", "-P", "OUTPUT", "ACCEPT").Run()
    _ = exec.Command("ip6tables", "-P", "FORWARD", "ACCEPT").Run()
}
```

This **restores default ACCEPT policies**, potentially leaving the user unprotected.

**Recommended fix:** On failure, attempt to at least keep the DROP policies in place rather than reverting to ACCEPT.

---

<a id="16-reliability"></a>

# SECTION: 16_RELIABILITY

# Freedom Cry — Reliability, Performance, Supply Chain & Test Results

## 16. Reliability Assessment

### Service Recovery

| Component | Restart Method | Recovery | Assessment |
|-----------|---------------|----------|-----------|
| API | Docker `restart: unless-stopped` | Automatic | ✅ |
| PostgreSQL | Docker `restart: unless-stopped` | Automatic, data persisted | ✅ |
| Redis | Docker `restart: unless-stopped` | Automatic, data persisted | ✅ |
| Xray | systemd `Restart=always` | Automatic, config on disk | ✅ |
| Agent | systemd `Restart=always, RestartSec=5` | Automatic | ✅ |
| AmneziaWG | Kernel module | Persistent across restarts | ✅ |

### Known Reliability Risks
- Node signature replay cache lost on API restart (in-memory)
- Auto-healing state lost on API restart (in-memory `nodeIncidents`)
- No health check or liveness probe for bot containers

## 17. Performance Assessment

**Status: NOT TESTED — Requires runtime benchmarks**

### Estimated Bottlenecks (from code review)

| Component | Potential Bottleneck |
|-----------|---------------------|
| Rate limiter | In-memory map with mutex — may contend under high load |
| Node sync | Database queries per sync (every 15s per node) |
| Config generation | JSON marshaling of sing-box config (minimal overhead) |
| Key encryption | AES-256-GCM per key decryption on config request |
| IP allocation | Row-level lock per node during subscription creation |

### Recommended Benchmarks
1. Concurrent subscription creation (test IP allocation contention)
2. Concurrent config downloads (test DB query performance)
3. Concurrent auth attempts (test rate limiter performance)
4. Node sync frequency under load

## 18. Supply Chain Assessment

### Go Dependencies (from go.mod)

| Dependency | Version | Risk |
|-----------|---------|------|
| `github.com/gin-gonic/gin` | v1.x | LOW — well-maintained |
| `github.com/golang-jwt/jwt/v5` | v5.x | LOW — standard JWT library |
| `gorm.io/gorm` | v1.x | LOW — popular ORM |
| `golang.org/x/crypto` | current | LOW — Go team maintained |
| `github.com/google/uuid` | current | LOW — Google maintained |

### Docker Base Images

| Image | Tag | Pinned? | Risk |
|-------|-----|---------|------|
| `golang:alpine` | Latest | ❌ No | MEDIUM — build-time only |
| `alpine:3.20` | Version | ⚠️ Minor pinned | LOW |
| `postgres:16-alpine` | Major pinned | ⚠️ | LOW |
| `redis:7-alpine` | Major pinned | ⚠️ | LOW |
| `caddy:2-alpine` | Major pinned | ⚠️ | LOW |

### External Binaries

| Binary | Source | Pinned? | Risk |
|--------|--------|---------|------|
| Xray-core | GitHub install script (beta!) | ❌ **No** | HIGH — beta channel, unpinned |
| AmneziaWG | PPA or package manager | ❌ No | MEDIUM |

**Recommendation:** Pin Xray to a specific release version, not beta channel.

## 19. Test Results

### Unit Tests Found

| File | Coverage |
|------|----------|
| `internal/protocol/amneziawg/crypto_test.go` | Key encryption/decryption |
| `internal/protocol/amneziawg/keygen_test.go` | Key generation, config generation |
| `internal/protocol/blind/blind_test.go` | Blind signature protocol |
| `internal/protocol/xray/reality_test.go` | Reality key generation |
| `internal/protocol/xray/sni_pool_test.go` | SNI pool selection |
| `internal/api/handler/invite_test.go` | Invite handler |
| `internal/api/handler/node_auth_test.go` | Node authentication |
| `internal/api/handler/xss_test.go` | XSS prevention |
| `internal/api/middleware/privacy_logger_test.go` | Privacy logger |
| `internal/api/middleware/ratelimit_test.go` | Rate limiter |
| `internal/client/killswitch/killswitch_test.go` | Kill switch |
| `internal/client/dns/split_dns_test.go` | Split DNS |
| `internal/client/routing/rules_test.go` | Routing rules |
| `internal/client/discovery/discovery_test.go` | Node discovery |
| `internal/service/ip_concurrency_test.go` | IP allocation concurrency |
| `internal/service/singbox_test.go` | Sing-box config generation |

### Missing Critical Tests

| Area | Missing Test |
|------|-------------|
| Invite race condition | No concurrent usage test |
| CORS security | No CORS validation test |
| Admin secret bypass | No auth bypass test |
| Token brute-force | No entropy validation test |
| Account deletion completeness | No deletion verification test |
| Grace period behavior | No grace period expiry test |

---

<a id="17-secret-scanning"></a>

# SECTION: 17_SECRET_SCANNING

# Freedom Cry — Secret Scanning Results

## Method

Static analysis of source code, configuration files, and Docker compose files.
Git history scan limited to recent commits (log-based review).

## Hardcoded Secrets Found

| Secret | File | Line | Value | Severity |
|--------|------|------|-------|----------|
| JWT Secret (default) | `config.go` | 75 | `freedom-cry-super-secure-jwt-secret-change-in-prod` | CRITICAL |
| Admin Secret (default) | `config.go` | 82 | `fc-admin-secret-2026` | CRITICAL |
| Master Invite (default) | `config.go` | 83 | `FC-FREEDOM-2026` | CRITICAL |
| Node Secret (default) | `config.go` | 80 | `fc-node-secret-token-key-2026` | HIGH |
| Probe Secret (fallback) | `probe_handler.go` | 29 | `fc-probe-shared-secret-2026` | HIGH |
| DB Password (default) | `config.go` | 66 | `freedomcry_secret` | MEDIUM |
| Admin MFA (compose default) | `docker-compose.prod.yml` | 79 | `fc-admin-secret-2026` | CRITICAL |
| Master Invite (compose default) | `docker-compose.prod.yml` | 80 | `FC-FREEDOM-2026` | CRITICAL |
| JWT Secret (example) | `config.example.yaml` | 19 | `freedom-cry-super-secure-jwt-secret-change-in-prod` | LOW (example file) |
| Node Secret (example) | `config.example.yaml` | 24 | `fc-node-secret-token-key-2026` | LOW (example file) |

## .gitignore Assessment

| Pattern | Covered? |
|---------|---------|
| `.env` | ✅ Yes |
| `config.yaml` | ❌ **NOT covered** — real config could be committed |
| `bin/` | ✅ Yes |
| `*.key`, `*.pem` | ❌ **NOT covered** |
| `node-keys.json` | ❌ **NOT covered** |

## Recommendations

1. Add `config.yaml` to `.gitignore`
2. Add `*.key`, `*.pem`, `node-keys.json` to `.gitignore`
3. Run `git log -p -- config.yaml` to check if real config was ever committed
4. Consider using `git-secrets` or `trufflehog` for automated scanning

---

<a id="18-covert-transport"></a>

# SECTION: 18_COVERT_TRANSPORT

# Freedom Cry — Covert Transport Audit

## Status: PARTIAL — Code structure reviewed, no runtime testing

## Architecture

The covert transport system provides emergency communication channels through whitelisted services:

| Transport | Module | Purpose |
|-----------|--------|---------|
| Yandex Docs | `covert/yandex/transport.go` | Collaborative document as covert channel |
| CUPS (Printing) | `covert/cups/transport.go` | IPP protocol as covert channel |
| WebRTC | `covert/webrtc/webrtc.go` | Peer-to-peer data channels |
| Frame mux | `covert/frame.go` | Packet framing for tunnel |
| Safe Dial | `covert/safedial/safedial.go` | SSRF-protected dialer |
| Tunnel | `covert/tunnel/client.go` + `exit_node.go` | Client/exit node setup |

## Safe Dial Assessment (SSRF Protection)

**File:** [`covert/safedial/safedial.go`](file:///home/zet/Projects/Freedom%20Cry/internal/protocol/covert/safedial/safedial.go)

Blocked subnets:
- `0.0.0.0/8`, `10.0.0.0/8`, `100.64.0.0/10`, `127.0.0.0/8`
- `169.254.0.0/16` (link-local), `172.16.0.0/12`, `192.0.0.0/24`
- `192.168.0.0/16`, `198.18.0.0/15`, `240.0.0.0/4`
- IPv6: `::1/128`, `fc00::/7`, `fe80::/10`, `::/128`

✅ Comprehensive private/reserved IP blocking — prevents SSRF to internal networks.

## Yandex Transport Assessment

The Yandex Docs transport uses collaborative document editing as a covert channel. Traffic appears as normal Yandex Docs API requests with proper User-Agent spoofing.

## WebRTC Assessment

Uses `pion/webrtc` with manual signaling. **No STUN/TURN hardening observed** — default ICE configuration.

## Covert Node Service Configuration

The setup-node.sh creates a covert exit service:
```bash
ExecStart=/opt/freedom-cry/covert --mode exit --transport cups --room "$FC_NODE_ID" --key "$FC_NODE_SECRET"
```

⚠️ Uses `FC_NODE_SECRET` as the encryption key for the covert channel. This is the same secret used for node API auth.

---

<a id="19-auto-healing"></a>

# SECTION: 19_AUTO_HEALING

# Freedom Cry — Auto-Healing & Probe System Audit

## Auto-Healing Architecture

```
Sensor Probe(s) → POST /api/v1/node/probe-report → AutoHealingService
                                                         │
                                                   Quorum Check (≥2 probes)
                                                         │
                                                    Cloud API
                                                         │
                                                   Replace IP
                                                         │
                                                   Update DB
                                                         │
                                                   Alert Handler
```

## Security Findings

### 1. Probe Authentication is Weak
- Single shared secret (`X-Probe-Secret` header)
- Hardcoded fallback: `fc-probe-shared-secret-2026`
- Non-constant-time string comparison
- No probe identity verification

### 2. Quorum Can Be Spoofed
The quorum threshold is ≥2 unique probe IDs within 90 seconds:
```go
for _, inc := range incidents {
    if !inc.IsReachable && inc.LastReport.After(recentWindow) {
        blockedCount++
    }
}
if blockedCount >= 2 {
    go s.TriggerAutoHealing(nodeID)
}
```

An attacker who knows the probe secret can send 2 reports with different `probe_id` values to trigger auto-healing for ANY node.

### 3. No Rate Limiting / Cooldown
- No debounce between healing triggers for same node
- No maximum IP rotations per time period
- Could exhaust cloud provider's IP pool

### 4. State is In-Memory
`nodeIncidents` map is lost on API restart. This means:
- All quorum state lost
- Possible race between restart and new probe data

### 5. Cloud Provider Fallback
If no cloud provider is configured, `MockCloudProvider` is used (test mode):
```go
if prov == nil {
    prov = cloud.NewMockCloudProvider()
}
```

## Probe Target Exposure

`GET /api/v1/node/probe-targets` returns:
- Node IDs
- Host IPs
- VLESS ports
- AWG ports
- SNI values
- AWG H1 values

This is effectively a **complete infrastructure map** available to anyone with the probe secret.

## Recommendations

1. Replace shared secret with per-probe Ed25519 authentication
2. Add constant-time comparison for probe secret
3. Add auto-healing cooldown (e.g., max 1 rotation per 30 minutes per node)
4. Add rate limiting on probe endpoints
5. Persist probe state in Redis/PostgreSQL
6. Require minimum 3 probes from different ASNs/locations
7. Add alert for unusual probe activity patterns

---

<a id="20-remediation-plan"></a>

# SECTION: 20_REMEDIATION_PLAN

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

---

<a id="21-release-readiness"></a>

# SECTION: 21_RELEASE_READINESS

# Freedom Cry — Release Readiness & Remediation Plan

## Release Gate

| Area           | Status | Critical Issue | Required Before Closed Beta |
|----------------|--------|---------------|----------------------------|
| Authentication | ⚠️ WARN | Account number brute-force (53-bit), no lockout | Add lockout + stronger auth |
| Authorization  | ✅ PASS | IDOR protections present in handlers | — |
| API            | ❌ FAIL | CORS reflects any origin with credentials | Fix CORS allowlist |
| Database       | ❌ FAIL | TelegramID stored, PSK plaintext, SSL disabled | Remove telegram_id, encrypt PSK |
| Telegram       | ❌ FAIL | Direct telegram_id → VPN link in DB | Separate identity stores |
| Key Management | ✅ PASS | AWG private keys properly encrypted with HKDF+AES-256-GCM | Encrypt PSK too |
| Xray           | ✅ PASS | Reality keys properly generated, private key stays on node | — |
| AmneziaWG      | ✅ PASS | Keys generated with crypto/rand, proper Curve25519 clamping | — |
| DNS            | ⚠️ NOT TESTED | DNS leak testing requires runtime environment | Test before beta |
| IPv6           | ⚠️ NOT TESTED | Kill switch drops IPv6 (code review only) | Runtime verification needed |
| Traffic Leaks  | ⚠️ NOT TESTED | Kill switch exists but race condition possible | Runtime testing needed |
| Firewall       | ✅ PASS | Proper iptables rules in setup-node.sh | — |
| Docker         | ❌ FAIL | API on 0.0.0.0:8080, config.yaml with secrets | Fix binding, remove secrets from image |
| Secrets        | ❌ FAIL | 6+ hardcoded secrets in source code | Remove all hardcoded defaults |
| Logging        | ✅ PASS | Privacy logger masks IPs and tokens | Minor gaps to address |
| Privacy        | ❌ FAIL | telegram_id stored, Zero-Knowledge claim false | Architecture redesign needed |
| Anonymity      | ❌ FAIL | Full de-anonymization possible via DB | Separate identity stores |
| Reliability    | ⚠️ NOT TESTED | Auto-healing exists but vulnerable to DoS | Test with safeguards |
| Recovery       | ⚠️ NOT TESTED | Hard delete implemented, node sync exists | Runtime verification |
| Performance    | ⚠️ NOT TESTED | No benchmarks available | Run load tests |
| Supply Chain   | ⚠️ WARN | Unpinned Docker base images, Xray beta channel | Pin versions |

## Overall Verdict

```
NO-GO
```

### Blocking Issues (Must fix before ANY user-facing deployment)

1. **[CRITICAL] CORS misconfiguration** — enables cross-origin credential theft
2. **[CRITICAL] TelegramID in users table** — completely invalidates Zero-Knowledge claim
3. **[CRITICAL] Hardcoded secrets** — admin access and unlimited registration possible
4. **[CRITICAL] 0.0.0.0:8080 API binding** — exposes unencrypted API publicly  
5. **[CRITICAL] Hysteria 2 insecure TLS** — enables MITM on VPN connections

---

## Remediation Plan (Ordered by Priority)

### Phase 1: Critical Fixes (MUST DO before any deployment)

| # | Task | Files | Effort | Risk if Skipped |
|---|------|-------|--------|----------------|
| 1 | Fix CORS — strict origin allowlist | `router.go` | 1 hour | Cross-origin account takeover |
| 2 | Remove hardcoded secrets, require env vars | `config.go`, `docker-compose.prod.yml`, `probe_handler.go`, `Dockerfile.server` | 2 hours | Complete system compromise |
| 3 | Bind API to 127.0.0.1 in prod | `docker-compose.prod.yml` | 5 minutes | Public API without TLS |
| 4 | Fix Hysteria 2 insecure:true | `subscription_service.go` | 15 minutes | MITM on VPN traffic |
| 5 | Remove/isolate telegram_id from users table | `user.go`, `user_service.go`, DB migration | 4-8 hours | Total de-anonymization |

### Phase 2: High Priority (SHOULD DO before closed beta)

| # | Task | Files | Effort |
|---|------|-------|--------|
| 6 | Add row-level locking for invite consumption | `invite_service.go` | 1 hour |
| 7 | Remove probe secret fallback, use constant-time compare | `probe_handler.go` | 30 minutes |
| 8 | Increase invite code entropy to 128-bit | `invite.go` | 30 minutes |
| 9 | Add rate limiting on /sub/:token endpoints | `router.go` | 1 hour |
| 10 | Prevent Ed25519 key overwrite after initial enrollment | `node_service.go` | 30 minutes |
| 11 | Encrypt AWG PresharedKey at rest | `key.go`, `crypto.go` | 2 hours |

### Phase 3: Medium Priority (Before public beta)

| # | Task | Effort |
|---|------|--------|
| 12 | Move signature replay cache to Redis | 2 hours |
| 13 | Add JWT revocation mechanism | 4 hours |
| 14 | Enable PostgreSQL SSL within Docker network | 1 hour |
| 15 | Pin Docker base image versions | 30 minutes |
| 16 | Add Redis ACL restrictions | 1 hour |
| 17 | Kill switch for macOS/Windows | Significant |

---

## Closed Beta Safety Limits (If Critical Issues Fixed)

| Parameter | Recommended Limit |
|-----------|------------------|
| Maximum users | 10-25 |
| Maximum nodes | 2-3 |
| Maximum test duration | 2 weeks |
| API rate limit | 10 req/min per IP (already implemented) |
| Invite codes | Single-use only, generate per-user |
| Emergency kill switch | Admin can revoke all subscriptions via API |
| Emergency key revocation | Revoke subscription → keys deleted immediately |
| Emergency node isolation | Set `is_revoked=true` on node |
| Backup frequency | Daily PostgreSQL dump |
| Monitoring | Monitor API logs, node sync frequency, auto-healing triggers |
| Alerting | Alert on: failed auth attempts, probe reports, auto-healing triggers |

---

## Key Management Assessment

### What works well:

1. **AWG private key encryption** — AES-256-GCM with HKDF-SHA256 key derivation from subscription token. Random nonce per encryption. Salt and info strings are constant but appropriate for this use case. The token (256-bit random) provides sufficient entropy as the IKM.

2. **Key generation** — Uses `crypto/rand` for all key material (WireGuard keys, Reality keys, subscription tokens, invite codes, account numbers). Proper Curve25519 clamping applied.

3. **Node authentication** — Ed25519 signature with timestamp-bound messages, body hash binding, and replay detection. The 60-second window is reasonable.

4. **Server private keys stay on nodes** — Reality private key and AWG server private key are generated on the node and never transmitted to master. Only public keys are registered.

### What needs improvement:

1. **PSK stored in plaintext** — Should be encrypted like the private key
2. **HKDF salt is static** — While acceptable for this use case (the token provides randomness), a per-key random salt would be stronger
3. **No key rotation for Reality** — Only VLESS UUID is rotated (24h), not the underlying Reality X25519 keys
4. **No AEAD additional data** — `gcm.Seal(nonce, nonce, []byte(plainPrivKey), nil)` passes `nil` for additional data. Should bind the encryption to the subscription ID or key ID

---

## Authorization Matrix

| Actor | Resource | Read | Create | Update | Delete |
|-------|----------|------|--------|--------|--------|
| Unauthenticated | Health check | ✅ | — | — | — |
| Unauthenticated | Plans | ✅ | — | — | — |
| Unauthenticated | Auth (register/login) | — | ✅ | — | — |
| Unauthenticated | Invite register | — | ✅ | — | — |
| Unauthenticated | Blind public key | ✅ | — | — | — |
| Unauthenticated | Blind redeem | — | ✅ | — | — |
| Sub token bearer | Subscription config | ✅ | — | — | — |
| Sub token bearer | AWG config | ✅ | — | — | — |
| Sub token bearer | Sing-box config | ✅ | — | — | — |
| Sub token bearer | Client pubkey | — | ✅ | — | — |
| JWT User | Own profile | ✅ | — | — | ✅ |
| JWT User | Own subscriptions | ✅ | ✅ | ✅ | ✅ |
| JWT User | Nodes list | ✅ | — | — | — |
| JWT User | Other user's data | ❌ | ❌ | ❌ | ❌ |
| JWT Admin | Nodes | ✅ | ✅ | — | — |
| JWT Admin | Invites | ✅ | ✅ | — | ✅ |
| JWT Admin | Billing | — | — | ✅ | — |
| X-Admin-Secret | Everything admin can do | ✅ | ✅ | ✅ | ✅ |
| Node (Ed25519) | Own node sync | ✅ | — | ✅ | — |
| Node (Ed25519) | Other node sync | ❌ | ❌ | ❌ | ❌ |
| Node (Ed25519) | Key registration | — | ✅ | ✅ | — |
| Probe (shared secret) | Probe targets | ✅ | — | — | — |
| Probe (shared secret) | Probe reports | — | ✅ | — | — |

---

## Anonymity Analysis

### Confidentiality
Can someone read VPN traffic? **NO** — VLESS Reality provides strong encryption. AmneziaWG uses standard WireGuard crypto (ChaCha20-Poly1305). **However**, Hysteria 2 with `insecure:true` breaks this guarantee.

### Privacy
What does the operator know? **EVERYTHING** — Due to telegram_id storage, the operator knows who each user is, what nodes they're assigned to, and their VPN credentials.

### Anonymity
Can a user be linked to their activity? **YES** — Via telegram_id → subscription → client_keys → node mapping.

### Unlinkability
Can two activities of the same user be linked? **YES** — Same subscription token, same VPN UUID, same AWG public key across all sessions.

---

## Fail-Closed Test Matrix (Static Analysis)

| Failure | Expected | Actual (Code Review) | Leak? | Severity |
|---------|----------|---------------------|-------|----------|
| Xray killed | No Internet | Kill switch blocks all (if enabled) | No (if KS active) | OK |
| WG killed | No Internet | Kill switch blocks all (if enabled) | No (if KS active) | OK |
| API down | Existing sessions only | Nodes use last-synced config | No | OK |
| DNS down | Fail closed | DNS via VPN tunnel (DoH to 1.1.1.1) | No | OK |
| Agent down | Safe stale config | Config on disk persists | No | OK |
| Docker restart | Safe | containers restart=unless-stopped | Brief gap | LOW |
| IPv6 available | Blocked | ip6tables DROP all (if KS active) | No (if KS active) | OK |
| Network reconnect | Safe | Kill switch persists across reconnect | No | OK |
| KS enable fails | **POSSIBLE LEAK** | cleanup() restores ACCEPT policies | **YES** | **HIGH** |
| Non-Linux OS | **LEAK** | StubKillSwitch is no-op | **YES** | **HIGH** |

---

