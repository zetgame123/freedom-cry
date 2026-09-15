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
