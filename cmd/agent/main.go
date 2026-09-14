package main

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"time"

	"freedom-cry/internal/api/handler"
	"freedom-cry/internal/protocol/amneziawg"
	"freedom-cry/internal/protocol/xray"

	"github.com/google/uuid"
)

type NodeLocalKeys struct {
	NodePrivateKey  string `json:"node_private_key"`  // Ed25519 private key hex
	NodePublicKey   string `json:"node_public_key"`   // Ed25519 public key hex
	RealityPrivKey  string `json:"reality_priv_key"`  // X25519 private key base64
	RealityPubKey   string `json:"reality_pub_key"`   // X25519 public key base64
	RealityShortID  string `json:"reality_short_id"`  // Short ID hex
	AwgPrivateKey   string `json:"awg_priv_key"`      // WireGuard private key base64
	AwgPublicKey    string `json:"awg_pub_key"`       // WireGuard public key base64
}

func main() {
	apiURL := flag.String("api", getEnv("FC_API_URL", "http://localhost:8080"), "Freedom Cry API URL")
	nodeID := flag.String("node-id", getEnv("FC_NODE_ID", ""), "Node UUID")
	nodeSecret := flag.String("secret", getEnv("FC_NODE_SECRET", ""), "Node Secret Token")
	keyStorePath := flag.String("keys-path", getEnv("FC_KEYS_PATH", "/etc/freedom-cry/node-keys.json"), "Path to node local private keys")
	interval := flag.Int("interval", 15, "Sync interval in seconds")
	xrayPath := flag.String("xray-config", getEnv("XRAY_CONFIG_PATH", "/usr/local/etc/xray/config.json"), "Path to xray config.json")
	awgPath := flag.String("awg-config", getEnv("AWG_CONFIG_PATH", "/etc/amnezia/amneziawg/awg0.conf"), "Path to awg0.conf")
	dryRun := flag.Bool("dry-run", false, "Dry run mode (logs instead of writing system files)")
	flag.Parse()

	if *nodeID == "" {
		log.Println("[Agent Warning] FC_NODE_ID is empty! Agent will run in standby mode.")
	}

	log.Println("==================================================")
	log.Println("    🦅 Freedom Cry VPN - Hardened Node Agent      ")
	log.Println("==================================================")
	log.Printf("Connecting to API: %s (Interval: %ds, DryRun: %v)", *apiURL, *interval, *dryRun)

	// 1. Load or generate local cryptographic node keys (Zero Trust: private keys never leave node)
	localKeys, err := loadOrGenerateLocalKeys(*keyStorePath, *dryRun)
	if err != nil {
		log.Fatalf("[Agent Fatal] Failed to initialize local node keys: %v", err)
	}

	// 2. Register public keys with Master on initial boot
	if *nodeID != "" && !*dryRun {
		if err := registerPublicKeysWithMaster(*apiURL, *nodeID, *nodeSecret, localKeys); err != nil {
			log.Printf("[Agent Warning] Failed to register public keys with master: %v", err)
		}
	}

	ticker := time.NewTicker(time.Duration(*interval) * time.Second)
	defer ticker.Stop()

	for {
		if *nodeID != "" {
			if err := syncNode(*apiURL, *nodeID, *nodeSecret, localKeys, *xrayPath, *awgPath, *dryRun); err != nil {
				log.Printf("[Agent Error] Sync failed: %v", err)
			}
		}
		<-ticker.C
	}
}

func loadOrGenerateLocalKeys(path string, dryRun bool) (*NodeLocalKeys, error) {
	if data, err := os.ReadFile(path); err == nil {
		var keys NodeLocalKeys
		if err := json.Unmarshal(data, &keys); err == nil && keys.RealityPrivKey != "" && keys.AwgPrivateKey != "" {
			log.Printf("[Agent] Loaded existing local keys from %s", path)
			return &keys, nil
		}
	}

	// Generate fresh local keys
	log.Printf("[Agent] Generating new local private keys...")

	// 1. Ed25519 Node Identity keypair
	pubEd, privEd, err := ed25519.GenerateKey(nil)
	if err != nil {
		return nil, err
	}

	// 2. Xray Reality keypair
	realityKP, err := xray.GenerateRealityKeyPair()
	if err != nil {
		return nil, err
	}

	// 3. AmneziaWG server keypair
	awgKP, err := amneziawg.GenerateAWGKeyPair()
	if err != nil {
		return nil, err
	}

	keys := &NodeLocalKeys{
		NodePrivateKey: hex.EncodeToString(privEd),
		NodePublicKey:  hex.EncodeToString(pubEd),
		RealityPrivKey: realityKP.PrivateKey,
		RealityPubKey:  realityKP.PublicKey,
		RealityShortID: realityKP.ShortID,
		AwgPrivateKey:  awgKP.PrivateKey,
		AwgPublicKey:   awgKP.PublicKey,
	}

	if !dryRun {
		dir := filepath.Dir(path)
		_ = os.MkdirAll(dir, 0700)

		data, _ := json.MarshalIndent(keys, "", "  ")
		if err := atomicWriteConfigFile(path, data, 0600); err != nil {
			log.Printf("[Agent Warning] Could not save keys to %s (permissions?): %v", path, err)
		} else {
			log.Printf("[Agent] Successfully stored private keys in %s (mode 0600)", path)
		}
	}

	return keys, nil
}

func registerPublicKeysWithMaster(apiURL, nodeID, secret string, keys *NodeLocalKeys) error {
	reqBody, _ := json.Marshal(handler.RegisterKeysRequest{
		RealityPubKey:  keys.RealityPubKey,
		RealityShortID: keys.RealityShortID,
		AwgPubKey:      keys.AwgPublicKey,
		PublicKey:      keys.NodePublicKey,
	})

	url := fmt.Sprintf("%s/api/v1/node/keys", apiURL)
	req, err := http.NewRequest("POST", url, bytes.NewBuffer(reqBody))
	if err != nil {
		return err
	}

	signAndAuthenticateRequest(req, nodeID, secret, keys.NodePrivateKey, reqBody)

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("unexpected status registering keys: %d", resp.StatusCode)
	}

	log.Printf("[Agent] Public keys registered successfully with Master")
	return nil
}

func syncNode(apiURL, nodeID, secret string, keys *NodeLocalKeys, xrayPath, awgPath string, dryRun bool) error {
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

	url := fmt.Sprintf("%s/api/v1/node/sync", apiURL)
	req, err := http.NewRequest("POST", url, bytes.NewBuffer(body))
	if err != nil {
		return err
	}

	signAndAuthenticateRequest(req, nodeID, secret, keys.NodePrivateKey, body)

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("unexpected sync status: %d", resp.StatusCode)
	}

	var syncResp handler.NodeSyncResponse
	if err := json.NewDecoder(resp.Body).Decode(&syncResp); err != nil {
		return err
	}

	log.Printf("[Agent] Sync success: Node=%s, Active VLESS Clients=%d, AWG Peers=%d",
		syncResp.Node.Name, len(syncResp.VlessClients), len(syncResp.AwgPeers))

	// 1. Generate & Apply Xray Config
	if syncResp.Node.VlessEnabled {
		var xrayClients []xray.VlessClient
		for _, c := range syncResp.VlessClients {
			xrayClients = append(xrayClients, xray.VlessClient{
				ID:    c.UUID,
				Flow:  "xtls-rprx-vision",
				Email: c.Email,
			})
		}

		// Use local reality private key
		xrayJSON, err := xray.GenerateServerConfig(
			syncResp.Node.VlessPort,
			keys.RealityPrivKey,
			syncResp.Node.RealityServerName,
			[]string{keys.RealityShortID},
			xrayClients,
		)
		if err == nil {
			// Pre-validate configuration schema before writing
			if valErr := xray.ValidateServerConfig(xrayJSON); valErr != nil {
				log.Printf("[Agent Xray] Validation failed, skipping corrupted config: %v", valErr)
			} else {
				if err := updateConfigFile(xrayPath, xrayJSON, dryRun, "xray"); err != nil {
					log.Printf("[Agent Xray] Failed to apply config: %v", err)
				}
			}
		}
	}

	// 2. Generate & Apply AmneziaWG Config
	if syncResp.Node.AwgEnabled {
		var awgPeers []amneziawg.ServerPeerConfig
		for _, p := range syncResp.AwgPeers {
			awgPeers = append(awgPeers, amneziawg.ServerPeerConfig{
				PublicKey:    p.PublicKey,
				PresharedKey: p.PresharedKey,
				AllowedIPs:   p.AllowedIPs,
			})
		}

		// Use local AWG private key
		awgConf, err := amneziawg.GenerateServerConfig(amneziawg.ServerConfigParams{
			ServerPrivateKey: keys.AwgPrivateKey,
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
			if valErr := amneziawg.ValidateServerConfig(awgConf); valErr != nil {
				log.Printf("[Agent AWG] Validation failed, skipping corrupted config: %v", valErr)
			} else {
				if err := updateConfigFile(awgPath, []byte(awgConf), dryRun, "awg-quick@awg0"); err != nil {
					log.Printf("[Agent AWG] Failed to apply config: %v", err)
				}
			}
		}
	}

	return nil
}

func signAndAuthenticateRequest(req *http.Request, nodeID, token, privKeyHex string, body []byte) {
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Node-ID", nodeID)

	if token != "" {
		req.Header.Set("X-Node-Token", token)
	}

	// Add Ed25519 signature authentication
	if privKeyHex != "" {
		privKeyBytes, err := hex.DecodeString(privKeyHex)
		if err == nil && len(privKeyBytes) == ed25519.PrivateKeySize {
			tsStr := strconv.FormatInt(time.Now().Unix(), 10)
			msg := fmt.Sprintf("FC-NODE-AUTH:%s:%s:%s:%s", nodeID, tsStr, req.Method, req.URL.Path)
			sig := ed25519.Sign(privKeyBytes, []byte(msg))

			req.Header.Set("X-Node-Timestamp", tsStr)
			req.Header.Set("X-Node-Signature", base64.StdEncoding.EncodeToString(sig))
		}
	}
}

// updateConfigFile performs atomic file replacement with 0600 permissions
// and reloads the service only when contents actually changed.
func updateConfigFile(path string, content []byte, dryRun bool, serviceName string) error {
	existing, _ := os.ReadFile(path)
	if bytes.Equal(existing, content) {
		// No change, skip unnecessary service reload
		return nil
	}

	if dryRun {
		log.Printf("[Agent DryRun] Config changed for %s (%d bytes). Reload skipped.", serviceName, len(content))
		return nil
	}

	if err := atomicWriteConfigFile(path, content, 0600); err != nil {
		return fmt.Errorf("atomic write to %s failed: %w", path, err)
	}

	log.Printf("[Agent] Atomically updated %s. Reloading %s...", path, serviceName)

	// Reload instead of restart where possible to avoid dropping connected users
	if serviceName == "xray" {
		cmd := exec.Command("systemctl", "reload-or-restart", "xray")
		return cmd.Run()
	}

	cmd := exec.Command("systemctl", "restart", serviceName)
	return cmd.Run()
}

// atomicWriteConfigFile writes to a temporary file in the same directory,
// calls fsync, sets mode 0600, and performs an atomic rename.
func atomicWriteConfigFile(path string, content []byte, perm os.FileMode) error {
	dir := filepath.Dir(path)
	_ = os.MkdirAll(dir, 0700)

	tmpFile, err := os.CreateTemp(dir, ".tmp-cfg-*")
	if err != nil {
		return err
	}
	tmpPath := tmpFile.Name()
	defer os.Remove(tmpPath)

	if _, err := tmpFile.Write(content); err != nil {
		tmpFile.Close()
		return err
	}
	if err := tmpFile.Sync(); err != nil {
		tmpFile.Close()
		return err
	}
	if err := tmpFile.Chmod(perm); err != nil {
		tmpFile.Close()
		return err
	}
	if err := tmpFile.Close(); err != nil {
		return err
	}

	return os.Rename(tmpPath, path)
}

func getSystemLoad() int {
	return 15
}

func getEnv(key, def string) string {
	if val, ok := os.LookupEnv(key); ok && val != "" {
		return val
	}
	return def
}
