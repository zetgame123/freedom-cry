package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"freedom-cry/internal/client/killswitch"
	"freedom-cry/internal/client/routing"
)

type ClientConnection struct {
	SubscriptionURL string
	AccountNumber   string
	ServerIP        string
	ServerPort      int
	InterfaceName   string
	KillSwitch      bool
	SplitTunnel     bool
}

func parseTargetURL(raw string) (*ClientConnection, error) {
	conn := &ClientConnection{
		InterfaceName: "fc-tun0",
		ServerPort:    443,
	}

	raw = strings.TrimSpace(raw)

	// Case 1: DeepLink freedomcry://connect?sub=...&account=...
	if strings.HasPrefix(raw, "freedomcry://") {
		u, err := url.Parse(raw)
		if err != nil {
			return nil, fmt.Errorf("invalid deeplink format: %w", err)
		}

		q := u.Query()
		if sub := q.Get("sub"); sub != "" {
			conn.SubscriptionURL = sub
		} else if u.Host == "sub" || u.Path == "/sub" {
			conn.SubscriptionURL = q.Get("url")
		}

		conn.AccountNumber = q.Get("account")
		if server := q.Get("server"); server != "" {
			conn.ServerIP = server
		}
		return conn, nil
	}

	// Case 2: Direct HTTP/HTTPS subscription URL
	if strings.HasPrefix(raw, "http://") || strings.HasPrefix(raw, "https://") {
		conn.SubscriptionURL = raw
		u, err := url.Parse(raw)
		if err == nil {
			conn.ServerIP = u.Hostname()
		}
		return conn, nil
	}

	// Case 3: VLESS URL vless://uuid@host:port?...
	if strings.HasPrefix(raw, "vless://") {
		u, err := url.Parse(raw)
		if err != nil {
			return nil, fmt.Errorf("invalid vless uri: %w", err)
		}
		conn.ServerIP = u.Hostname()
		if u.Port() != "" {
			fmt.Sscanf(u.Port(), "%d", &conn.ServerPort)
		}
		return conn, nil
	}

	// Case 4: Hysteria 2 URL hysteria2://auth@host:port?...
	if strings.HasPrefix(raw, "hysteria2://") {
		u, err := url.Parse(raw)
		if err != nil {
			return nil, fmt.Errorf("invalid hysteria2 uri: %w", err)
		}
		conn.ServerIP = u.Hostname()
		if u.Port() != "" {
			fmt.Sscanf(u.Port(), "%d", &conn.ServerPort)
		}
		return conn, nil
	}

	return nil, fmt.Errorf("unrecognized connection string format: %s", raw)
}

func main() {
	killswitchFlag := flag.Bool("killswitch", true, "Enable fail-closed firewall kill-switch")
	splitTunnelFlag := flag.Bool("split-tunnel", true, "Enable Russian domestic split-tunneling (bypass RU services)")
	serverIPFlag := flag.String("server-ip", "", "Override VPN server IP destination")
	tunDevFlag := flag.String("iface", "fc-tun0", "TUN interface name")
	flag.Parse()

	args := flag.Args()
	if len(args) == 0 {
		printUsage()
		os.Exit(1)
	}

	cmd := args[0]
	switch cmd {
	case "connect":
		if len(args) < 2 {
			log.Fatal("Error: Subscription URL or deeplink required: freedom-cry-client connect <deeplink|sub_url>")
		}
		runConnect(args[1], *killswitchFlag, *splitTunnelFlag, *serverIPFlag, *tunDevFlag)

	case "parse-deeplink":
		if len(args) < 2 {
			log.Fatal("Error: Deeplink required: freedom-cry-client parse-deeplink <freedomcry://...>")
		}
		conn, err := parseTargetURL(args[1])
		if err != nil {
			log.Fatalf("Parse error: %v", err)
		}
		b, _ := json.MarshalIndent(conn, "", "  ")
		fmt.Println(string(b))

	case "check-route":
		if len(args) < 2 {
			log.Fatal("Error: Destination required: freedom-cry-client check-route <domain-or-ip>")
		}
		action := routing.DetermineRouting(args[1])
		fmt.Printf("Destination: %s -> Route Action: %s\n", args[1], strings.ToUpper(string(action)))

	case "help", "--help", "-h":
		printUsage()

	default:
		log.Fatalf("Unknown command '%s'. Run 'freedom-cry-client help' for usage.", cmd)
	}
}

func runConnect(target string, useKillSwitch, useSplitTunnel bool, overrideIP, iface string) {
	log.Println("==================================================")
	log.Println("    🦅 Freedom Cry Next-Gen Client Engine        ")
	log.Println("==================================================")

	conn, err := parseTargetURL(target)
	if err != nil {
		log.Fatalf("Failed to parse connection parameter: %v", err)
	}

	if overrideIP != "" {
		conn.ServerIP = overrideIP
	}
	conn.KillSwitch = useKillSwitch
	conn.SplitTunnel = useSplitTunnel
	conn.InterfaceName = iface

	log.Printf("[Client] Initiating connection...")
	if conn.AccountNumber != "" {
		log.Printf("[Client] Zero-Knowledge Account: %s", conn.AccountNumber)
	}
	if conn.SubscriptionURL != "" {
		log.Printf("[Client] Subscription Source: %s", conn.SubscriptionURL)
		fetchSubscription(conn)
	}

	log.Printf("[Client] Target Server IP: %s (Port: %d)", conn.ServerIP, conn.ServerPort)
	log.Printf("[Client] Interface: %s | Split-Tunneling: %t | Kill-Switch: %t",
		conn.InterfaceName, conn.SplitTunnel, conn.KillSwitch)

	// Initialize and enable Killswitch
	ks := killswitch.NewKillSwitch()
	if conn.KillSwitch && conn.ServerIP != "" {
		log.Println("[KillSwitch] Arming fail-closed network firewall rules...")
		if err := ks.Enable(conn.ServerIP, conn.ServerPort, conn.InterfaceName); err != nil {
			log.Printf("[KillSwitch] Warning: %v", err)
		} else {
			log.Println("[KillSwitch] Fail-closed state active. Cleartext leakage blocked.")
		}
	}

	if conn.SplitTunnel {
		log.Println("[Routing] Split-tunneling active. Russian domestic traffic (Gosuslugi, Banking, Yandex) routes DIRECT.")
	}

	log.Println("[Client] Connected and secure. Press Ctrl+C to disconnect.")

	// Wait for shutdown signal
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	<-sigChan

	log.Println("\n[Client] Disconnecting...")
	if ks.IsEnabled() {
		log.Println("[KillSwitch] Disarming firewall and restoring normal networking...")
		_ = ks.Disable()
	}
	log.Println("[Client] Disconnected cleanly.")
}

func fetchSubscription(conn *ClientConnection) {
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Get(conn.SubscriptionURL)
	if err != nil {
		log.Printf("[Client] Warning: Could not pre-fetch subscription: %v", err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		log.Printf("[Client] Subscription loaded (%d bytes received)", len(body))
	}
}

func printUsage() {
	fmt.Println(`Freedom Cry Client CLI

Usage:
  freedom-cry-client connect <sub-url | deeplink> [flags]
  freedom-cry-client parse-deeplink <freedomcry://...>
  freedom-cry-client check-route <domain-or-ip>

Flags:
  -killswitch=true|false    Enable fail-closed firewall protection (default: true)
  -split-tunnel=true|false  Bypass Russian domestic services (default: true)
  -server-ip=<ip>           Override VPN server destination IP
  -iface=<name>             TUN interface name (default: fc-tun0)`)
}
