# Freedom Cry — Fail-Closed Analysis

## Kill Switch Implementation

**File:** [`internal/client/killswitch/killswitch.go`](file:///home/zet/Projects/Freedom%20Cry/internal/client/killswitch/killswitch.go)

### iptables Rules (Linux)

```
1. IPv6: DROP all (INPUT, OUTPUT, FORWARD)
2. Create FC_KILLSWITCH chain
3. Allow loopback
4. Allow ESTABLISHED,RELATED
5. Allow LAN (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, multicast)
6. Allow VPN server IP:port (UDP + TCP)
7. Allow VPN interface
8. DROP everything else
9. Insert FC_KILLSWITCH at top of OUTPUT
```

### nftables Rules (Linux, preferred)

```nft
table inet fc_killswitch {
    chain output {
        type filter hook output priority 0; policy drop;
        oif "lo" accept
        ct state { established, related } accept
        ip daddr { LAN ranges } accept
        ip daddr VPN_IP udp/tcp dport VPN_PORT accept
        oif "VPN_IFACE" accept
    }
}
```

### Assessment

| Scenario | Expected | Code Analysis | Leak Risk |
|----------|----------|--------------|-----------|
| VPN process dies | Traffic blocked | ✅ FC_KILLSWITCH persists in iptables | No |
| VPN reconnect | Traffic blocked during gap | ✅ Rules persist, only VPN iface allowed | No |
| Network switch | Traffic blocked | ✅ Rules are interface-agnostic (except VPN iface) | No |
| IPv6 available | Blocked | ✅ ip6tables DROP all | No |
| KS enable fails | ⚠️ **POSSIBLE LEAK** | cleanup() called → restores ACCEPT | **YES** |
| Non-Linux OS | **LEAK** | StubKillSwitch is no-op | **YES** |
| Docker restart (server) | Traffic continues on last config | ✅ Node configs persist on disk | No |
| API unavailable | Existing sessions work | ✅ Node uses last-synced config | No |
| Agent crash | Existing sessions work | ✅ Xray/AWG configs on disk persist | No |

### CRITICAL: Kill Switch Failure Path

```go
func (k *LinuxKillSwitch) Enable(...) error {
    // ... apply rules ...
    if err != nil {
        _ = k.cleanup()  // ← Restores ACCEPT policies!
        return fmt.Errorf("failed to enable killswitch: %w", err)
    }
}
```

If ANY iptables command fails during activation, `cleanup()` runs and:
```go
func (k *LinuxKillSwitch) cleanup() error {
    // ...
    _ = exec.Command("ip6tables", "-P", "INPUT", "ACCEPT").Run()
    _ = exec.Command("ip6tables", "-P", "OUTPUT", "ACCEPT").Run()
    _ = exec.Command("ip6tables", "-P", "FORWARD", "ACCEPT").Run()
}
```

This **restores default ACCEPT policies**, potentially leaving the user unprotected.

**Recommended fix:** On failure, attempt to at least keep the DROP policies in place rather than reverting to ACCEPT.
