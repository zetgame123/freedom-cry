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
