package discovery

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"
)

var (
	ErrNoEndpointsFound = errors.New("no fallback endpoints discovered")
	ErrAllProvidersFailed = errors.New("all DoH discovery providers failed")
)

// Public censorship-resistant DoH endpoints
var DefaultDoHProviders = []string{
	"https://1.1.1.1/dns-query",
	"https://dns.google/dns-query",
	"https://dns.quad9.net/dns-query",
}

// DoHJSONResponse maps standard JSON DNS response from Cloudflare / Google DoH
type DoHJSONResponse struct {
	Status int `json:"Status"`
	Answer []struct {
		Name string `json:"name"`
		Type int    `json:"type"` // 16 for TXT
		TTL  int    `json:"TTL"`
		Data string `json:"data"`
	} `json:"Answer"`
}

type DiscoveryService struct {
	client    *http.Client
	providers []string
}

func NewDiscoveryService(providers []string) *DiscoveryService {
	if len(providers) == 0 {
		providers = DefaultDoHProviders
	}
	return &DiscoveryService{
		client: &http.Client{
			Timeout: 5 * time.Second,
		},
		providers: providers,
	}
}

// DiscoverFallbackEndpoints queries DoH providers for TXT records on the specified discovery domain.
// Example TXT record: "v=fc1;nodes=185.120.45.199:443,195.201.88.23:443"
func (s *DiscoveryService) DiscoverFallbackEndpoints(ctx context.Context, domain string) ([]string, error) {
	if domain == "" {
		return nil, errors.New("discovery domain cannot be empty")
	}

	var lastErr error
	for _, provider := range s.providers {
		endpoints, err := s.queryDoHProvider(ctx, provider, domain)
		if err == nil && len(endpoints) > 0 {
			return endpoints, nil
		}
		if err != nil {
			lastErr = err
		}
	}

	if lastErr != nil {
		return nil, fmt.Errorf("%w: %v", ErrAllProvidersFailed, lastErr)
	}
	return nil, ErrNoEndpointsFound
}

func (s *DiscoveryService) queryDoHProvider(ctx context.Context, providerURL, domain string) ([]string, error) {
	u, err := url.Parse(providerURL)
	if err != nil {
		return nil, err
	}

	q := u.Query()
	q.Set("name", domain)
	q.Set("type", "TXT")
	u.RawQuery = q.Encode()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/dns-json")

	resp, err := s.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("DoH server returned status %d", resp.StatusCode)
	}

	var dohResp DoHJSONResponse
	if err := json.NewDecoder(resp.Body).Decode(&dohResp); err != nil {
		return nil, err
	}

	var discovered []string
	for _, ans := range dohResp.Answer {
		if ans.Type == 16 { // TXT record
			cleanData := strings.Trim(ans.Data, "\"")
			nodes := ParseTXTRecordNodes(cleanData)
			discovered = append(discovered, nodes...)
		}
	}

	return discovered, nil
}

// ParseTXTRecordNodes parses TXT data string: "v=fc1;nodes=ip1:port,ip2:port"
func ParseTXTRecordNodes(txt string) []string {
	var results []string
	parts := strings.Split(txt, ";")
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if strings.HasPrefix(p, "nodes=") {
			listStr := strings.TrimPrefix(p, "nodes=")
			items := strings.Split(listStr, ",")
			for _, item := range items {
				item = strings.TrimSpace(item)
				if item != "" {
					results = append(results, item)
				}
			}
		}
	}
	return results
}
