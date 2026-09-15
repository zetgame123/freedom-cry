# Freedom Cry — Network Leak Tests

## Status: Requires Runtime Environment

These tests require a live deployment with active VPN connections. Static code analysis results only.

## DNS Leak Analysis (Static)

### Sing-box DNS Configuration
- Remote DNS: `https://1.1.1.1/dns-query` (DoH) via VPN tunnel ✅
- Direct DNS: `local` for split-routed domains ⚠️
- Russian domains (gov, yandex, vk, mailru) → `dns-direct` (local resolver)

### Risk: Split-DNS may reveal .ru domain queries to ISP
When accessing Russian services, DNS queries go through the `direct` outbound (local resolver), which means the user's ISP can see DNS queries for these domains.

### AmneziaWG DNS Configuration
- Client config uses: `DNS = 1.1.1.1, 8.8.8.8` (plaintext DNS)
- ⚠️ Not encrypted DNS — DNS queries visible to VPN server operator

### Kill Switch DNS Protection
- Kill switch blocks all outbound except VPN tunnel and LAN
- DNS queries must go through VPN interface (enforced by iptables)
- ⚠️ During kill switch enable/disable transition, brief DNS leak possible

## IPv6 Leak Analysis (Static)

### Kill Switch IPv6 Handling
```go
// killswitch.go:107-109
{"ip6tables", "-P", "INPUT", "DROP"},
{"ip6tables", "-P", "OUTPUT", "DROP"},
{"ip6tables", "-P", "FORWARD", "DROP"},
```
✅ Kill switch sets IPv6 default policies to DROP

### AmneziaWG IPv6 Support
- Client AllowedIPs include `::/0` → all IPv6 routed through tunnel ✅
- Client gets IPv6 address: `fd00:8::x:x/128` ✅
- Server-side NAT66 configured for `fd00:8::/64` ✅

## Required Runtime Tests

| Test | Method | Status |
|------|--------|--------|
| DNS leak (VPN active) | dnsleaktest.com, ipleak.net | NOT TESTED |
| DNS leak (VPN reconnect) | Kill/restart VPN, check DNS | NOT TESTED |
| IPv6 leak (VPN active) | ipv6leak.com, test-ipv6.com | NOT TESTED |
| IPv6 leak (VPN off) | Verify IPv6 blocked by KS | NOT TESTED |
| WebRTC leak | browserleaks.com/webrtc | NOT TESTED |
| IP leak during reconnect | Rapid reconnect cycle | NOT TESTED |
| Split-DNS Russian domains | Query .ru domain, verify resolver | NOT TESTED |
