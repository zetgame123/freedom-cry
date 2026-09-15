# Freedom Cry — Auto-Healing & Probe System Audit

## Auto-Healing Architecture

```
Sensor Probe(s) → POST /api/v1/node/probe-report → AutoHealingService
                                                         │
                                                   Quorum Check (≥2 probes)
                                                         │
                                                    Cloud API
                                                         │
                                                   Replace IP
                                                         │
                                                   Update DB
                                                         │
                                                   Alert Handler
```

## Security Findings

### 1. Probe Authentication is Weak
- Single shared secret (`X-Probe-Secret` header)
- Hardcoded fallback: `fc-probe-shared-secret-2026`
- Non-constant-time string comparison
- No probe identity verification

### 2. Quorum Can Be Spoofed
The quorum threshold is ≥2 unique probe IDs within 90 seconds:
```go
for _, inc := range incidents {
    if !inc.IsReachable && inc.LastReport.After(recentWindow) {
        blockedCount++
    }
}
if blockedCount >= 2 {
    go s.TriggerAutoHealing(nodeID)
}
```

An attacker who knows the probe secret can send 2 reports with different `probe_id` values to trigger auto-healing for ANY node.

### 3. No Rate Limiting / Cooldown
- No debounce between healing triggers for same node
- No maximum IP rotations per time period
- Could exhaust cloud provider's IP pool

### 4. State is In-Memory
`nodeIncidents` map is lost on API restart. This means:
- All quorum state lost
- Possible race between restart and new probe data

### 5. Cloud Provider Fallback
If no cloud provider is configured, `MockCloudProvider` is used (test mode):
```go
if prov == nil {
    prov = cloud.NewMockCloudProvider()
}
```

## Probe Target Exposure

`GET /api/v1/node/probe-targets` returns:
- Node IDs
- Host IPs
- VLESS ports
- AWG ports
- SNI values
- AWG H1 values

This is effectively a **complete infrastructure map** available to anyone with the probe secret.

## Recommendations

1. Replace shared secret with per-probe Ed25519 authentication
2. Add constant-time comparison for probe secret
3. Add auto-healing cooldown (e.g., max 1 rotation per 30 minutes per node)
4. Add rate limiting on probe endpoints
5. Persist probe state in Redis/PostgreSQL
6. Require minimum 3 probes from different ASNs/locations
7. Add alert for unusual probe activity patterns
