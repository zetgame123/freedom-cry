# Freedom Cry — Authorization Matrix

See [21_RELEASE_READINESS.md](file:///home/zet/Projects/Freedom%20Cry/AUDIT/21_RELEASE_READINESS.md) for the full authorization matrix.

## Summary

| Actor | Auth Method | Scope |
|-------|-----------|-------|
| Unauthenticated | None | Health, plans, auth endpoints, blind public-key |
| Sub Token Bearer | 256-bit token in URL | Own subscription configs only |
| JWT User | Bearer JWT (HS256) | Own resources only |
| JWT Admin | Bearer JWT with role=admin | Node/invite/billing management |
| X-Admin-Secret | Static header | Full admin (bypasses JWT) |
| Node Agent | Ed25519 signature | Own node sync/keys only |
| Probe Agent | Shared secret header | Probe targets/reports |

## IDOR/BOLA Assessment

| Endpoint | IDOR Protected? | Evidence |
|----------|----------------|---------|
| GET /user/me | ✅ Yes | Uses JWT-extracted userID |
| DELETE /user/me | ✅ Yes | Uses JWT-extracted userID |
| GET /user/subscriptions | ✅ Yes | WHERE user_id = JWT.sub |
| POST /user/subscriptions/:id/rotate | ✅ Yes | WHERE id=? AND user_id=? |
| POST /user/subscriptions/:id/revoke | ✅ Yes | WHERE id=? AND user_id=? |
| PUT /user/subscriptions/:id/awg-key | ✅ Yes | WHERE id=? AND user_id=? |
| POST /node/sync | ✅ Yes | Checks authenticated node ID matches request |
| POST /node/keys | ✅ Yes | Uses authenticated node ID |
| GET /sub/:token/* | N/A | Token IS the identity — no user context |
