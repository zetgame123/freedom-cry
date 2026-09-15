# Freedom Cry — Covert Transport Audit

## Status: PARTIAL — Code structure reviewed, no runtime testing

## Architecture

The covert transport system provides emergency communication channels through whitelisted services:

| Transport | Module | Purpose |
|-----------|--------|---------|
| Yandex Docs | `covert/yandex/transport.go` | Collaborative document as covert channel |
| CUPS (Printing) | `covert/cups/transport.go` | IPP protocol as covert channel |
| WebRTC | `covert/webrtc/webrtc.go` | Peer-to-peer data channels |
| Frame mux | `covert/frame.go` | Packet framing for tunnel |
| Safe Dial | `covert/safedial/safedial.go` | SSRF-protected dialer |
| Tunnel | `covert/tunnel/client.go` + `exit_node.go` | Client/exit node setup |

## Safe Dial Assessment (SSRF Protection)

**File:** [`covert/safedial/safedial.go`](file:///home/zet/Projects/Freedom%20Cry/internal/protocol/covert/safedial/safedial.go)

Blocked subnets:
- `0.0.0.0/8`, `10.0.0.0/8`, `100.64.0.0/10`, `127.0.0.0/8`
- `169.254.0.0/16` (link-local), `172.16.0.0/12`, `192.0.0.0/24`
- `192.168.0.0/16`, `198.18.0.0/15`, `240.0.0.0/4`
- IPv6: `::1/128`, `fc00::/7`, `fe80::/10`, `::/128`

✅ Comprehensive private/reserved IP blocking — prevents SSRF to internal networks.

## Yandex Transport Assessment

The Yandex Docs transport uses collaborative document editing as a covert channel. Traffic appears as normal Yandex Docs API requests with proper User-Agent spoofing.

## WebRTC Assessment

Uses `pion/webrtc` with manual signaling. **No STUN/TURN hardening observed** — default ICE configuration.

## Covert Node Service Configuration

The setup-node.sh creates a covert exit service:
```bash
ExecStart=/opt/freedom-cry/covert --mode exit --transport cups --room "$FC_NODE_ID" --key "$FC_NODE_SECRET"
```

⚠️ Uses `FC_NODE_SECRET` as the encryption key for the covert channel. This is the same secret used for node API auth.
