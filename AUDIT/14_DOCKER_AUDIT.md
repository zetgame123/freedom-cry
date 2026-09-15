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
