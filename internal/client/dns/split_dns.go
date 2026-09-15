package dns

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"freedom-cry/internal/client/routing"
)

var (
	ErrResolutionFailed = errors.New("dns resolution failed")
)

type DNSAnswer struct {
	IP        net.IP
	TTL       time.Duration
	ExpiresAt time.Time
}

type cachedEntry struct {
	answers   []net.IP
	expiresAt time.Time
}

type SplitDNSResolver struct {
	directResolver *net.Resolver
	dohClient      *http.Client
	dohURL         string
	cache          map[string]cachedEntry
	cacheMu        sync.RWMutex
}

func NewSplitDNSResolver(dohURL string) *SplitDNSResolver {
	if dohURL == "" {
		dohURL = "https://1.1.1.1/dns-query"
	}
	return &SplitDNSResolver{
		directResolver: net.DefaultResolver,
		dohClient: &http.Client{
			Timeout: 4 * time.Second,
		},
		dohURL: dohURL,
		cache:  make(map[string]cachedEntry),
	}
}

// IsDomestic checks if the hostname belongs to Russian direct split-routing
func (r *SplitDNSResolver) IsDomestic(host string) bool {
	host = strings.TrimSuffix(strings.ToLower(host), ".")

	action := routing.DetermineRouting(host)
	return action == routing.ActionDirect
}

// ResolveHost resolves an IPv4 or IPv6 address using Split-DNS logic:
// - Domestic domains: resolved via system/ISP resolver
// - Foreign / blocked domains: resolved via Encrypted DNS-over-HTTPS (DoH) to eliminate DNS leaks
func (r *SplitDNSResolver) ResolveHost(ctx context.Context, host string) ([]net.IP, error) {
	host = strings.TrimSuffix(strings.ToLower(host), ".")

	// If already an IP address
	if ip := net.ParseIP(host); ip != nil {
		return []net.IP{ip}, nil
	}

	// Check cache
	r.cacheMu.RLock()
	if entry, found := r.cache[host]; found && time.Now().Before(entry.expiresAt) {
		r.cacheMu.RUnlock()
		return entry.answers, nil
	}
	r.cacheMu.RUnlock()

	var ips []net.IP
	var err error

	if r.IsDomestic(host) {
		ips, err = r.resolveDirect(ctx, host)
	} else {
		ips, err = r.resolveDoH(ctx, host)
	}

	if err != nil {
		return nil, err
	}

	// Cache result for 5 minutes
	r.cacheMu.Lock()
	r.cache[host] = cachedEntry{
		answers:   ips,
		expiresAt: time.Now().Add(5 * time.Minute),
	}
	r.cacheMu.Unlock()

	return ips, nil
}

func (r *SplitDNSResolver) resolveDirect(ctx context.Context, host string) ([]net.IP, error) {
	addrs, err := r.directResolver.LookupIPAddr(ctx, host)
	if err != nil {
		return nil, fmt.Errorf("direct dns lookup error: %w", err)
	}
	var res []net.IP
	for _, a := range addrs {
		res = append(res, a.IP)
	}
	return res, nil
}

type dohWireAnswer struct {
	Name string `json:"name"`
	Type int    `json:"type"` // 1 for A, 28 for AAAA
	TTL  int    `json:"TTL"`
	Data string `json:"data"`
}

type dohWireResponse struct {
	Status int              `json:"Status"`
	Answer []dohWireAnswer  `json:"Answer"`
}

func (r *SplitDNSResolver) resolveDoH(ctx context.Context, host string) ([]net.IP, error) {
	u, err := url.Parse(r.dohURL)
	if err != nil {
		return nil, err
	}

	q := u.Query()
	q.Set("name", host)
	q.Set("type", "A")
	u.RawQuery = q.Encode()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/dns-json")

	resp, err := r.dohClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("DoH request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("DoH upstream returned HTTP %d", resp.StatusCode)
	}

	var dohResp dohWireResponse
	if err := json.NewDecoder(resp.Body).Decode(&dohResp); err != nil {
		return nil, err
	}

	var ips []net.IP
	for _, ans := range dohResp.Answer {
		if ans.Type == 1 || ans.Type == 28 {
			if parsed := net.ParseIP(ans.Data); parsed != nil {
				ips = append(ips, parsed)
			}
		}
	}

	if len(ips) == 0 {
		return nil, ErrResolutionFailed
	}

	return ips, nil
}
