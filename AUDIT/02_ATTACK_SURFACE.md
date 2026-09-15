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
