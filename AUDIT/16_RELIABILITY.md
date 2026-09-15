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
