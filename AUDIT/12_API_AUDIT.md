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
