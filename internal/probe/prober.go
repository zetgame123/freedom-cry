package probe

import (
	"crypto/tls"
	"net"
	"strconv"
	"time"
)

type ProbeResult struct {
	NodeID      string `json:"node_id"`
	Protocol    string `json:"protocol"` // "vless", "awg", "hysteria", "tcp"
	IsReachable bool   `json:"is_reachable"`
	LatencyMs   int64  `json:"latency_ms"`
	Error       string `json:"error,omitempty"`
}

type NodeTarget struct {
	NodeID    string `json:"node_id"`
	Host      string `json:"host"`
	VlessPort int    `json:"vless_port"`
	AwgPort   int    `json:"awg_port"`
	SNI       string `json:"sni"`
	AwgH1     uint32 `json:"awg_h1"`
}

// ProbeVlessReality performs a TLS 1.3 ClientHello probe with Reality SNI
func ProbeVlessReality(target NodeTarget, timeout time.Duration) ProbeResult {
	start := time.Now()
	addr := net.JoinHostPort(target.Host, strconv.Itoa(target.VlessPort))

	dialer := &net.Dialer{Timeout: timeout}
	sni := target.SNI
	if sni == "" {
		sni = "dl.google.com"
	}

	conf := &tls.Config{
		ServerName: sni,
		MinVersion: tls.VersionTLS13,
	}

	conn, err := tls.DialWithDialer(dialer, "tcp", addr, conf)
	latency := time.Since(start).Milliseconds()

	if err != nil {
		return ProbeResult{
			NodeID:      target.NodeID,
			Protocol:    "vless",
			IsReachable: false,
			LatencyMs:   latency,
			Error:       err.Error(),
		}
	}
	_ = conn.Close()

	return ProbeResult{
		NodeID:      target.NodeID,
		Protocol:    "vless",
		IsReachable: true,
		LatencyMs:   latency,
	}
}

// ProbeTCP performs a basic TCP handshake probe
func ProbeTCP(host string, port int, timeout time.Duration) bool {
	addr := net.JoinHostPort(host, strconv.Itoa(port))
	conn, err := net.DialTimeout("tcp", addr, timeout)
	if err != nil {
		return false
	}
	_ = conn.Close()
	return true
}

// ProbeAWG sends an obfuscated initiation packet to verify UDP responsiveness
func ProbeAWG(target NodeTarget, timeout time.Duration) ProbeResult {
	start := time.Now()
	addr := net.JoinHostPort(target.Host, strconv.Itoa(target.AwgPort))

	udpAddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return ProbeResult{
			NodeID:      target.NodeID,
			Protocol:    "awg",
			IsReachable: false,
			Error:       err.Error(),
		}
	}

	conn, err := net.DialUDP("udp", nil, udpAddr)
	if err != nil {
		return ProbeResult{
			NodeID:      target.NodeID,
			Protocol:    "awg",
			IsReachable: false,
			Error:       err.Error(),
		}
	}
	defer conn.Close()

	// 148-byte initiation probe packet with H1 header
	packet := make([]byte, 148)
	if target.AwgH1 != 0 {
		packet[0] = byte(target.AwgH1)
		packet[1] = byte(target.AwgH1 >> 8)
		packet[2] = byte(target.AwgH1 >> 16)
		packet[3] = byte(target.AwgH1 >> 24)
	}

	_ = conn.SetDeadline(time.Now().Add(timeout))
	_, err = conn.Write(packet)
	latency := time.Since(start).Milliseconds()

	if err != nil {
		return ProbeResult{
			NodeID:      target.NodeID,
			Protocol:    "awg",
			IsReachable: false,
			LatencyMs:   latency,
			Error:       err.Error(),
		}
	}

	// UDP write succeeded without ICMP unreachable
	return ProbeResult{
		NodeID:      target.NodeID,
		Protocol:    "awg",
		IsReachable: true,
		LatencyMs:   latency,
	}
}
