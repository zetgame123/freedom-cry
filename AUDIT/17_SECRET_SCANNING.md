# Freedom Cry — Secret Scanning Results

## Method

Static analysis of source code, configuration files, and Docker compose files.
Git history scan limited to recent commits (log-based review).

## Hardcoded Secrets Found

| Secret | File | Line | Value | Severity |
|--------|------|------|-------|----------|
| JWT Secret (default) | `config.go` | 75 | `freedom-cry-super-secure-jwt-secret-change-in-prod` | CRITICAL |
| Admin Secret (default) | `config.go` | 82 | `fc-admin-secret-2026` | CRITICAL |
| Master Invite (default) | `config.go` | 83 | `FC-FREEDOM-2026` | CRITICAL |
| Node Secret (default) | `config.go` | 80 | `fc-node-secret-token-key-2026` | HIGH |
| Probe Secret (fallback) | `probe_handler.go` | 29 | `fc-probe-shared-secret-2026` | HIGH |
| DB Password (default) | `config.go` | 66 | `freedomcry_secret` | MEDIUM |
| Admin MFA (compose default) | `docker-compose.prod.yml` | 79 | `fc-admin-secret-2026` | CRITICAL |
| Master Invite (compose default) | `docker-compose.prod.yml` | 80 | `FC-FREEDOM-2026` | CRITICAL |
| JWT Secret (example) | `config.example.yaml` | 19 | `freedom-cry-super-secure-jwt-secret-change-in-prod` | LOW (example file) |
| Node Secret (example) | `config.example.yaml` | 24 | `fc-node-secret-token-key-2026` | LOW (example file) |

## .gitignore Assessment

| Pattern | Covered? |
|---------|---------|
| `.env` | ✅ Yes |
| `config.yaml` | ❌ **NOT covered** — real config could be committed |
| `bin/` | ✅ Yes |
| `*.key`, `*.pem` | ❌ **NOT covered** |
| `node-keys.json` | ❌ **NOT covered** |

## Recommendations

1. Add `config.yaml` to `.gitignore`
2. Add `*.key`, `*.pem`, `node-keys.json` to `.gitignore`
3. Run `git log -p -- config.yaml` to check if real config was ever committed
4. Consider using `git-secrets` or `trufflehog` for automated scanning
