# Freedom Cry — Infrastructure Audit

## Node Setup Script Assessment

**File:** [`scripts/setup-node.sh`](file:///home/zet/Projects/Freedom%20Cry/scripts/setup-node.sh)

### Positive Findings
- ✅ Systemd service has comprehensive sandboxing directives
- ✅ `NoNewPrivileges=yes`, `ProtectSystem=strict`, `ProtectHome=yes`
- ✅ Minimal capabilities: `CAP_NET_ADMIN`, `CAP_NET_BIND_SERVICE`
- ✅ Env file permissions set to 0600
- ✅ Config directory permissions set to 700
- ✅ BBR congestion control enabled
- ✅ Client-to-client VPN isolation (iptables DROP 10.8.0.0/16 → 10.8.0.0/16)
- ✅ Cloud metadata blocking (169.254.0.0/16 DROP)
- ✅ Host isolation (VPN clients can only reach host DNS on port 53)
- ✅ IPv6 NAT66 and dual-stack firewall rules

### Concerns
- ⚠️ Xray installed from beta channel: `install-release.sh @ install --beta`
- ⚠️ Script runs as root (required but noted)
- ⚠️ AmneziaWG PPA added without GPG key verification in fallback path
- ⚠️ Multiple `|| true` silent failure suppression
- ⚠️ Node secret visible in process list during script execution

## Firewall Rules Summary (on VPN nodes)

### IPv4
| Rule | Direction | Assessment |
|------|-----------|-----------|
| NAT MASQUERADE 10.8.0.0/16 | POSTROUTING | ✅ Required |
| DROP 10.8.0.0/16 → 10.8.0.0/16 | FORWARD | ✅ Client isolation |
| DROP 10.8.0.0/16 → 169.254.0.0/16 | FORWARD | ✅ Metadata protection |
| ACCEPT 10.8.0.0/16 → :53 (UDP/TCP) | INPUT | ✅ DNS only |
| ACCEPT RELATED,ESTABLISHED | INPUT | ✅ Standard |
| DROP 10.8.0.0/16 → * | INPUT | ✅ Host isolation |
| ACCEPT 10.8.0.0/16 | FORWARD | ✅ Internet access |

### IPv6
| Rule | Assessment |
|------|-----------|
| NAT66 fd00:8::/64 | ✅ Dual-stack |
| DROP fd00:8::/64 → fd00:8::/64 | ✅ Client isolation |
| Host isolation (DNS only) | ✅ Matching IPv4 rules |

## Deployment Script (deploy-master.sh)

**Status:** Not reviewed in detail — 2862 bytes. Should be verified for secret handling.
