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
