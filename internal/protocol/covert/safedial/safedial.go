package safedial

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"syscall"
	"time"
)

var (
	// Blocked CIDR ranges for SSRF prevention
	blockedCIDRs []*net.IPNet

	// Known Cloud Metadata IPs
	cloudMetadataIPs = []net.IP{
		net.ParseIP("169.254.169.254"),
		net.ParseIP("fd00:ec2::254"),
	}
)

func init() {
	cidrs := []string{
		"0.0.0.0/8",          // Current network
		"10.0.0.0/8",         // Private-use networks (RFC 1918)
		"100.64.0.0/10",      // Shared Address Space / Carrier-Grade NAT (RFC 6598)
		"127.0.0.0/8",        // Loopback (RFC 1122)
		"169.254.0.0/16",     // Link Local (RFC 3927, includes cloud metadata)
		"172.16.0.0/12",      // Private-use networks (RFC 1918)
		"192.0.0.0/24",       // IETF Protocol Assignments
		"192.0.2.0/24",       // TEST-NET-1 (RFC 5737)
		"192.168.0.0/16",     // Private-use networks (RFC 1918)
		"198.18.0.0/15",      // Network Interconnect Device Benchmark Testing (RFC 2544)
		"198.51.100.0/24",    // TEST-NET-2 (RFC 5737)
		"203.0.113.0/24",     // TEST-NET-3 (RFC 5737)
		"224.0.0.0/4",        // Multicast (RFC 5771)
		"240.0.0.0/4",        // Reserved for future use (RFC 1112)
		"255.255.255.255/32", // Limited Broadcast
		"::/128",             // Unspecified
		"::1/128",            // Loopback
		"fc00::/7",           // Unique Local Addresses (RFC 4193)
		"fe80::/10",          // Link Local Unicast (RFC 4291)
		"ff00::/8",           // Multicast
		"2001:db8::/32",      // Documentation IPv6
	}

	for _, cidr := range cidrs {
		_, ipNet, err := net.ParseCIDR(cidr)
		if err == nil {
			blockedCIDRs = append(blockedCIDRs, ipNet)
		}
	}
}

type SafeDialer struct {
	Timeout  time.Duration
	Resolver *net.Resolver
}

func NewSafeDialer(timeout time.Duration) *SafeDialer {
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	return &SafeDialer{
		Timeout:  timeout,
		Resolver: net.DefaultResolver,
	}
}

// DialContext establishes a TCP connection after strictly validating that NO resolved IP
// falls into loopback, private, link-local, cloud metadata, or other prohibited ranges.
// It directly dials the validated IP to defeat DNS rebinding attacks.
func (d *SafeDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	if network != "tcp" && network != "tcp4" && network != "tcp6" {
		return nil, fmt.Errorf("unsupported network: %s", network)
	}

	host, portStr, err := net.SplitHostPort(address)
	if err != nil {
		return nil, fmt.Errorf("invalid address format: %w", err)
	}

	port, err := strconv.Atoi(portStr)
	if err != nil || port < 1 || port > 65535 {
		return nil, fmt.Errorf("invalid port: %s", portStr)
	}

	// Validate against explicit localhost aliases
	lowerHost := strings.ToLower(strings.TrimSuffix(host, "."))
	if lowerHost == "localhost" || strings.HasSuffix(lowerHost, ".localhost") || lowerHost == "ip6-localhost" || lowerHost == "ip6-loopback" {
		return nil, errors.New("SSRF: access to localhost is prohibited")
	}

	// Resolve all IP addresses
	resolveCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	ipAddrs, err := d.Resolver.LookupIPAddr(resolveCtx, host)
	if err != nil {
		return nil, fmt.Errorf("DNS resolution failed for %s: %w", host, err)
	}

	if len(ipAddrs) == 0 {
		return nil, fmt.Errorf("DNS resolution returned no addresses for %s", host)
	}

	// Validate EVERY resolved IP address
	var validatedIPs []net.IP
	for _, addr := range ipAddrs {
		ip := addr.IP
		if err := ValidateIP(ip); err != nil {
			return nil, fmt.Errorf("SSRF protection: host %s resolved to forbidden address %s: %w", host, ip.String(), err)
		}
		validatedIPs = append(validatedIPs, ip)
	}

	// Anti-DNS-Rebinding & Resilience:
	// 1. Iterate over validated IPs so that dual-stack or multi-homed destinations have fallback.
	// 2. Connect directly to numeric IP address.
	// 3. Use Control socket hook to verify the sockaddr at the OS kernel connect() syscall.
	var lastErr error
	for _, targetIP := range validatedIPs {
		dialTarget := net.JoinHostPort(targetIP.String(), portStr)
		dialer := net.Dialer{
			Timeout:   d.Timeout,
			KeepAlive: 30 * time.Second,
			Control: func(network, address string, c syscall.RawConn) error {
				h, _, err := net.SplitHostPort(address)
				if err == nil {
					if parsedIP := net.ParseIP(h); parsedIP != nil {
						return ValidateIP(parsedIP)
					}
				}
				return nil
			},
		}

		conn, err := dialer.DialContext(ctx, network, dialTarget)
		if err == nil {
			return conn, nil
		}
		lastErr = err
	}

	return nil, fmt.Errorf("connection to validated addresses for %s failed: %w", host, lastErr)
}

// ValidateIP returns an error if the provided IP address is in any restricted, private,
// loopback, link-local, multicast, or cloud metadata range.
func ValidateIP(ip net.IP) error {
	if ip == nil {
		return errors.New("nil IP address")
	}

	// Unmap IPv4-mapped IPv6 addresses (e.g. ::ffff:127.0.0.1 -> 127.0.0.1)
	if v4 := ip.To4(); v4 != nil {
		ip = v4
	}

	// Check special IP types
	if ip.IsLoopback() {
		return errors.New("loopback address prohibited")
	}
	if ip.IsPrivate() {
		return errors.New("private network address prohibited")
	}
	if ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
		return errors.New("link-local address prohibited")
	}
	if ip.IsInterfaceLocalMulticast() || ip.IsMulticast() {
		return errors.New("multicast address prohibited")
	}
	if ip.IsUnspecified() {
		return errors.New("unspecified address prohibited")
	}

	// Check exact cloud metadata matches
	for _, metaIP := range cloudMetadataIPs {
		if ip.Equal(metaIP) {
			return errors.New("cloud metadata endpoint prohibited")
		}
	}

	// Check CIDR blocks
	for _, ipNet := range blockedCIDRs {
		if ipNet.Contains(ip) {
			return fmt.Errorf("address falls into blocked CIDR: %s", ipNet.String())
		}
	}

	return nil
}
