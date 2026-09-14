package mesh

import (
	"bytes"
	"fmt"
	"text/template"
)

type MeshPeer struct {
	PublicKey  string
	Endpoint   string // host:port
	AllowedIPs string // e.g. 10.99.2.1/32 or 10.8.0.0/16
}

type MeshConfigParams struct {
	PrivateKey string
	Address    string // e.g. 10.99.1.1/16
	ListenPort int    // default 51821
	Peers      []MeshPeer
}

const meshConfTemplate = `[Interface]
PrivateKey = {{.PrivateKey}}
Address = {{.Address}}
ListenPort = {{.ListenPort}}

{{range .Peers}}
[Peer]
PublicKey = {{.PublicKey}}
Endpoint = {{.Endpoint}}
AllowedIPs = {{.AllowedIPs}}
PersistentKeepalive = 25

{{end}}`

// GenerateMeshConfig generates the WireGuard configuration for fc-mesh0 interface
func GenerateMeshConfig(params MeshConfigParams) (string, error) {
	tmpl, err := template.New("meshConf").Parse(meshConfTemplate)
	if err != nil {
		return "", err
	}

	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, params); err != nil {
		return "", err
	}

	return buf.String(), nil
}

// GenerateEntryPolicyRoutingScript generates the Linux policy routing commands for Entry nodes:
// Traffic from client VPN (10.8.0.0/16) is marked with 0x99 and forced into fc-mesh0 towards the Exit node.
// Local direct WAN breakout for clients is strictly blocked.
func GenerateEntryPolicyRoutingScript(wanIface string, exitMeshIP string) string {
	return fmt.Sprintf(`#!/bin/bash
set -e

WAN="%s"
EXIT_IP="%s"

# 1. Enable packet forwarding
sysctl -w net.ipv4.ip_forward=1 >/dev/null 2>&1 || true

# 2. Block direct client WAN breakout on Entry node (Fail-Closed Unlinkability)
iptables -C FORWARD -s 10.8.0.0/16 -o "$WAN" -j DROP 2>/dev/null || \
iptables -I FORWARD 1 -s 10.8.0.0/16 -o "$WAN" -j DROP

# 3. Mark client VPN traffic destined for the internet with fwmark 0x99
iptables -t mangle -C PREROUTING -s 10.8.0.0/16 -i awg0 -j MARK --set-mark 0x99 2>/dev/null || \
iptables -t mangle -A PREROUTING -s 10.8.0.0/16 -i awg0 -j MARK --set-mark 0x99

# 4. Policy routing table 99 -> route via fc-mesh0 to exit node
ip rule del fwmark 0x99 table 99 2>/dev/null || true
ip rule add fwmark 0x99 table 99

ip route flush table 99 2>/dev/null || true
ip route add default via "$EXIT_IP" dev fc-mesh0 table 99

echo "[Mesh] Policy routing active: client traffic forced through Exit ($EXIT_IP)"
`, wanIface, exitMeshIP)
}

// GenerateExitNATScript generates the Linux forwarding/NAT commands for Exit nodes:
// Client traffic arriving via fc-mesh0 is NATed out to the public internet.
func GenerateExitNATScript(wanIface string) string {
	return fmt.Sprintf(`#!/bin/bash
set -e

WAN="%s"

# 1. Enable packet forwarding
sysctl -w net.ipv4.ip_forward=1 >/dev/null 2>&1 || true

# 2. Allow forwarding from fc-mesh0 to WAN
iptables -C FORWARD -i fc-mesh0 -o "$WAN" -j ACCEPT 2>/dev/null || \
iptables -A FORWARD -i fc-mesh0 -o "$WAN" -j ACCEPT

iptables -C FORWARD -i "$WAN" -o fc-mesh0 -m state --state RELATED,ESTABLISHED -j ACCEPT 2>/dev/null || \
iptables -A FORWARD -i "$WAN" -o fc-mesh0 -m state --state RELATED,ESTABLISHED -j ACCEPT

# 3. Outbound WAN NAT MASQUERADE for clients exiting from mesh
iptables -t nat -C POSTROUTING -s 10.8.0.0/16 -o "$WAN" -j MASQUERADE 2>/dev/null || \
iptables -t nat -A POSTROUTING -s 10.8.0.0/16 -o "$WAN" -j MASQUERADE

echo "[Mesh] Exit node NAT active on interface $WAN"
`, wanIface)
}
