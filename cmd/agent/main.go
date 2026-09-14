package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/exec"
	"time"

	"freedom-cry/internal/api/handler"
	"freedom-cry/internal/protocol/amneziawg"
	"freedom-cry/internal/protocol/xray"

	"github.com/google/uuid"
)

type AgentConfig struct {
	APIURL         string `json:"api_url"`
	NodeID         string `json:"node_id"`
	NodeSecret     string `json:"node_secret"`
	SyncIntervalSec int   `json:"sync_interval_sec"`
	XrayConfigPath string `json:"xray_config_path"`
	AwgConfigPath  string `json:"awg_config_path"`
	DryRun         bool   `json:"dry_run"`
}

func main() {
	apiURL := flag.String("api", getEnv("FC_API_URL", "http://localhost:8080"), "Freedom Cry API URL")
	nodeID := flag.String("node-id", getEnv("FC_NODE_ID", ""), "Node UUID")
	nodeSecret := flag.String("secret", getEnv("FC_NODE_SECRET", "fc-node-secret-token-key-2026"), "Node Secret")
	interval := flag.Int("interval", 15, "Sync interval in seconds")
	xrayPath := flag.String("xray-config", getEnv("XRAY_CONFIG_PATH", "/usr/local/etc/xray/config.json"), "Path to xray config.json")
	awgPath := flag.String("awg-config", getEnv("AWG_CONFIG_PATH", "/etc/amnezia/amneziawg/awg0.conf"), "Path to awg0.conf")
	dryRun := flag.Bool("dry-run", true, "Dry run mode (logs instead of calling systemctl)")
	flag.Parse()

	if *nodeID == "" {
		log.Println("[Agent Warning] FC_NODE_ID is empty! Agent will run in standby mode.")
	}

	log.Println("==================================================")
	log.Println("       🦅 Freedom Cry VPN - Node Agent           ")
	log.Println("==================================================")
	log.Printf("Connecting to API: %s (Interval: %ds, DryRun: %v)", *apiURL, *interval, *dryRun)

	ticker := time.NewTicker(time.Duration(*interval) * time.Second)
	defer ticker.Stop()

	for {
		if *nodeID != "" {
			if err := syncNode(*apiURL, *nodeID, *nodeSecret, *xrayPath, *awgPath, *dryRun); err != nil {
				log.Printf("[Agent Error] Sync failed: %v", err)
			}
		}
		<-ticker.C
	}
}

func syncNode(apiURL, nodeID, secret, xrayPath, awgPath string, dryRun bool) error {
	nodeUUID, err := uuid.Parse(nodeID)
	if err != nil {
		return fmt.Errorf("invalid node uuid: %w", err)
	}

	syncReq := handler.NodeSyncRequest{
		NodeID:      nodeUUID,
		LoadPercent: getSystemLoad(),
	}

	body, err := json.Marshal(syncReq)
	if err != nil {
		return err
	}

	req, err := http.NewRequest("POST", fmt.Sprintf("%s/api/v1/node/sync", apiURL), bytes.NewBuffer(body))
	if err != nil {
		return err
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Node-Secret", secret)

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("unexpected status: %d", resp.StatusCode)
	}

	var syncResp handler.NodeSyncResponse
	if err := json.NewDecoder(resp.Body).Decode(&syncResp); err != nil {
		return err
	}

	log.Printf("[Agent] Sync success: Node=%s, Active VLESS Clients=%d, AWG Peers=%d",
		syncResp.Node.Name, len(syncResp.VlessClients), len(syncResp.AwgPeers))

	// 1. Generate & Update Xray Config
	if syncResp.Node.VlessEnabled {
		var xrayClients []xray.VlessClient
		for _, c := range syncResp.VlessClients {
			xrayClients = append(xrayClients, xray.VlessClient{
				ID:    c.UUID,
				Flow:  "xtls-rprx-vision",
				Email: c.Email,
			})
		}

		privKey := syncResp.RealityPrivateKey
		if privKey == "" {
			privKey = syncResp.Node.RealityPrivKey
		}

		xrayJSON, err := xray.GenerateServerConfig(
			syncResp.Node.VlessPort,
			privKey,
			syncResp.Node.RealityServerName,
			[]string{syncResp.Node.RealityShortID},
			xrayClients,
		)
		if err == nil {
			if err := updateConfigFile(xrayPath, xrayJSON, dryRun, "xray"); err != nil {
				log.Printf("[Agent Xray] Failed to apply config: %v", err)
			}
		}
	}

	// 2. Generate & Update AmneziaWG Config
	if syncResp.Node.AwgEnabled {
		var awgPeers []amneziawg.ServerPeerConfig
		for _, p := range syncResp.AwgPeers {
			awgPeers = append(awgPeers, amneziawg.ServerPeerConfig{
				PublicKey:    p.PublicKey,
				PresharedKey: p.PresharedKey,
				AllowedIPs:   p.AllowedIPs,
			})
		}

		awgPrivKey := syncResp.AwgPrivateKey
		if awgPrivKey == "" {
			awgPrivKey = syncResp.Node.AwgPrivKey
		}

		awgConf, err := amneziawg.GenerateServerConfig(amneziawg.ServerConfigParams{
			ServerPrivateKey: awgPrivKey,
			ListenPort:       syncResp.Node.AwgPort,
			Address:          syncResp.Node.AwgServerSubnet,
			Jc:               syncResp.Node.AwgJc,
			Jmin:             syncResp.Node.AwgJmin,
			Jmax:             syncResp.Node.AwgJmax,
			S1:               syncResp.Node.AwgS1,
			S2:               syncResp.Node.AwgS2,
			H1:               syncResp.Node.AwgH1,
			H2:               syncResp.Node.AwgH2,
			H3:               syncResp.Node.AwgH3,
			H4:               syncResp.Node.AwgH4,
			Peers:            awgPeers,
		})
		if err == nil {
			if err := updateConfigFile(awgPath, []byte(awgConf), dryRun, "awg-quick@awg0"); err != nil {
				log.Printf("[Agent AWG] Failed to apply config: %v", err)
			}
		}
	}

	return nil
}

func updateConfigFile(path string, content []byte, dryRun bool, serviceName string) error {
	existing, _ := os.ReadFile(path)
	if bytes.Equal(existing, content) {
		// No changes
		return nil
	}

	if dryRun {
		log.Printf("[Agent DryRun] Config changed for %s (%d bytes). Reload skipped.", serviceName, len(content))
		return nil
	}

	if err := os.WriteFile(path, content, 0600); err != nil {
		return err
	}

	log.Printf("[Agent] Updated %s config. Reloading %s...", path, serviceName)
	cmd := exec.Command("systemctl", "restart", serviceName)
	return cmd.Run()
}

func getSystemLoad() int {
	return 15 // Mock load for demonstration
}

func getEnv(key, def string) string {
	if val, ok := os.LookupEnv(key); ok && val != "" {
		return val
	}
	return def
}
