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
