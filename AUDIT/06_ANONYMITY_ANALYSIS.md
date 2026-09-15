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
