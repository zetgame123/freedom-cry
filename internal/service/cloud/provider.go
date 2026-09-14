package cloud

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"sync"
	"time"
)

type CloudProvider interface {
	Name() string
	ReplaceFloatingIP(ctx context.Context, serverID string) (string, error)
	RebuildServer(ctx context.Context, serverID string) error
}

// HetznerCloudProvider interacts with the Hetzner Cloud REST API
type HetznerCloudProvider struct {
	apiToken   string
	httpClient *http.Client
}

func NewHetznerProvider(apiToken string) *HetznerCloudProvider {
	return &HetznerCloudProvider{
		apiToken: apiToken,
		httpClient: &http.Client{
			Timeout: 15 * time.Second,
		},
	}
}

func (h *HetznerCloudProvider) Name() string {
	return "hetzner"
}

func (h *HetznerCloudProvider) ReplaceFloatingIP(ctx context.Context, serverID string) (string, error) {
	if h.apiToken == "" {
		return "", errors.New("Hetzner API token not configured")
	}

	// 1. Create a new Floating IP in the same location
	reqBody := map[string]interface{}{
		"type":          "ipv4",
		"home_location": "fsn1",
		"description":   fmt.Sprintf("Auto-healing failover for server %s", serverID),
	}
	bodyData, _ := json.Marshal(reqBody)

	req, err := http.NewRequestWithContext(ctx, "POST", "https://api.hetzner.cloud/v1/floating_ips", bytes.NewReader(bodyData))
	if err != nil {
		return "", err
	}
	req.Header.Set("Authorization", "Bearer "+h.apiToken)
	req.Header.Set("Content-Type", "application/json")

	resp, err := h.httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("hetzner API request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("hetzner API returned status %d", resp.StatusCode)
	}

	var result struct {
		FloatingIP struct {
			ID int    `json:"id"`
			IP string `json:"ip"`
		} `json:"floating_ip"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", err
	}

	newIP := result.FloatingIP.IP
	if newIP == "" {
		return "", errors.New("empty IP returned from Hetzner API")
	}

	return newIP, nil
}

func (h *HetznerCloudProvider) RebuildServer(ctx context.Context, serverID string) error {
	if h.apiToken == "" {
		return errors.New("Hetzner API token not configured")
	}

	reqBody := map[string]interface{}{
		"image": "ubuntu-24.04",
	}
	bodyData, _ := json.Marshal(reqBody)

	url := fmt.Sprintf("https://api.hetzner.cloud/v1/servers/%s/actions/rebuild", serverID)
	req, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewReader(bodyData))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+h.apiToken)
	req.Header.Set("Content-Type", "application/json")

	resp, err := h.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		return fmt.Errorf("rebuild request failed with status %d", resp.StatusCode)
	}

	return nil
}

// MockCloudProvider simulates cloud API operations for testing and offline environments
type MockCloudProvider struct {
	mu          sync.Mutex
	ipCounter   int
	RebuiltList []string
}

func NewMockCloudProvider() *MockCloudProvider {
	return &MockCloudProvider{ipCounter: 100}
}

func (m *MockCloudProvider) Name() string {
	return "mock"
}

func (m *MockCloudProvider) ReplaceFloatingIP(ctx context.Context, serverID string) (string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.ipCounter++
	return fmt.Sprintf("185.120.45.%d", m.ipCounter), nil
}

func (m *MockCloudProvider) RebuildServer(ctx context.Context, serverID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.RebuiltList = append(m.RebuiltList, serverID)
	return nil
}
