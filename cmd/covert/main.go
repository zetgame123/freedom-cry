package main

import (
	"context"
	"flag"
	"log"
	"os"
	"os/signal"
	"syscall"

	"freedom-cry/internal/protocol/covert"
	"freedom-cry/internal/protocol/covert/cups"
	"freedom-cry/internal/protocol/covert/tunnel"
	"freedom-cry/internal/protocol/covert/yandex"
)

func main() {
	mode := flag.String("mode", "client", "Run mode: 'client' (SOCKS5 proxy) or 'exit' (Exit node on VPS)")
	transportType := flag.String("transport", "cups", "Covert transport: 'cups' (Cups.online Centrifugo) or 'yandex' (Yandex Docs)")
	socks5Addr := flag.String("socks5", "127.0.0.1:1080", "SOCKS5 listen address (client mode)")
	secretKey := flag.String("key", "freedom-cry-covert-secret-2026-key", "32-byte pre-shared encryption key")

	// Yandex Docs flags
	docURL := flag.String("ydoc-url", "", "Yandex Docs document URL")
	docWS := flag.String("ydoc-ws", "wss://doc.yandex.ru/websocket", "Yandex Docs WebSocket URL")
	docID := flag.String("ydoc-id", "freedom-cry-emergency-doc", "Yandex Doc ID")
	docToken := flag.String("ydoc-token", "anonymous", "Yandex Doc session token")

	// Cups.online flags
	roomUUID := flag.String("room", "freedom-cry-emergency-room", "Cups.online Room UUID")

	flag.Parse()

	log.Println("==================================================")
	log.Println("   🦅 Freedom Cry - Covert Whitelist Tunnel       ")
	log.Println("==================================================")
	log.Printf("Mode: %s | Transport: %s | Secret Key Encrypted: true", *mode, *transportType)

	var tr covert.Transport
	switch *transportType {
	case "yandex":
		tr = yandex.NewTransport(*docURL, *docWS, *docID, *docToken)
	case "cups":
		tr = cups.NewTransport(*roomUUID)
	default:
		log.Fatalf("Unknown transport: %s (supported: 'cups', 'yandex')", *transportType)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if *mode == "exit" {
		exitNode, err := tunnel.NewExitNode(tr, []byte(*secretKey))
		if err != nil {
			log.Fatalf("Failed to initialize exit node: %v", err)
		}

		if err := exitNode.Start(ctx); err != nil {
			log.Fatalf("Exit node failed to start: %v", err)
		}
		defer exitNode.Stop()
	} else {
		clientTunnel, err := tunnel.NewSOCKS5ClientTunnel(*socks5Addr, tr, []byte(*secretKey))
		if err != nil {
			log.Fatalf("Failed to initialize SOCKS5 client: %v", err)
		}

		if err := clientTunnel.Start(ctx); err != nil {
			log.Fatalf("SOCKS5 client failed to start: %v", err)
		}
		defer clientTunnel.Stop()
	}

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	<-sigChan

	log.Println("[Covert] Stopping tunnel...")
}
