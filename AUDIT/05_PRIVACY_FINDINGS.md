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
