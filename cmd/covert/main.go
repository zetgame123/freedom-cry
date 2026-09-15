package main

import (
	"context"
	"crypto/sha256"
	"flag"
	"log"
	"os"
	"os/signal"
	"syscall"

	"freedom-cry/internal/protocol/covert"
	"freedom-cry/internal/protocol/covert/cups"
	"freedom-cry/internal/protocol/covert/tunnel"
	"freedom-cry/internal/protocol/covert/webrtc"
	"freedom-cry/internal/protocol/covert/yandex"

	"github.com/google/uuid"
)

func main() {
	mode := flag.String("mode", "client", "Run mode: 'client' (SOCKS5 proxy) or 'exit' (Exit node on VPS)")
	transportType := flag.String("transport", "cups", "Covert transport: 'cups' (Cups.online Centrifugo) or 'yandex' (Yandex Docs)")
	socks5Addr := flag.String("socks5", "127.0.0.1:1080", "SOCKS5 listen address (client mode)")
	secretKey := flag.String("key", "", "Pre-shared encryption key (min 16 bytes, can also be provided via COVERT_KEY environment variable)")

	// Yandex Docs flags
	docURL := flag.String("ydoc-url", "", "Yandex Docs document URL (e.g. https://docs.yandex.ru/docs/view?url=...)")
	docCookie := flag.String("ydoc-cookie", "", "Yandex session cookie string (optional, for auth or captcha bypass)")
	docWS := flag.String("ydoc-ws", "", "Yandex Docs WebSocket URL (optional manual override)")
	docID := flag.String("ydoc-id", "", "Yandex Doc ID (optional manual override)")
	docToken := flag.String("ydoc-token", "", "Yandex Doc session token (optional manual override)")

	// Cups.online flags
	roomUUID := flag.String("room", "", "Cups.online Room UUID (if not provided, securely derived from -key)")
	sessionID := flag.Uint64("session", 1, "Session ID for covert stream isolation")

	flag.Parse()

	keyVal := *secretKey
	if keyVal == "" {
		keyVal = os.Getenv("COVERT_KEY")
	}
	if len(keyVal) < 16 {
		log.Fatalf("Fatal: Covert encryption key must be provided via -key or COVERT_KEY environment variable (minimum 16 bytes)")
	}

	// FC-08 Hardening: Derive room UUID deterministically from secretKey if not explicitly provided
	if *roomUUID == "" || *roomUUID == "freedom-cry-emergency-room" {
		h := sha256.Sum256([]byte("freedom-cry-cups-room-v1:" + keyVal))
		derivedUUID, err := uuid.FromBytes(h[:16])
		if err == nil {
			*roomUUID = derivedUUID.String()
			log.Printf("[Covert] Derived private room UUID: %s", *roomUUID)
		}
	}

	log.Println("==================================================")
	log.Println("   🦅 Freedom Cry - Covert Whitelist Tunnel       ")
	log.Println("==================================================")
	log.Printf("Mode: %s | Transport: %s | Session: %d | Replay Protection: true", *mode, *transportType, *sessionID)

	var tr covert.Transport
	switch *transportType {
	case "yandex":
		tr = yandex.NewTransport(yandex.Config{
			DocURL:    *docURL,
			CookieStr: *docCookie,
			WsURL:     *docWS,
			DocID:     *docID,
			Token:     *docToken,
		})
	case "cups":
		tr = cups.NewTransport(*roomUUID)
	case "webrtc":
		tr = webrtc.NewTransport(webrtc.Config{
			IsInitiator: *mode == "client",
		})
	default:
		log.Fatalf("Unknown transport: %s (supported: 'webrtc', 'cups', 'yandex')", *transportType)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if *mode == "exit" {
		exitNode, err := tunnel.NewExitNode(tr, *sessionID, []byte(keyVal))
		if err != nil {
			log.Fatalf("Failed to initialize exit node: %v", err)
		}

		if err := exitNode.Start(ctx); err != nil {
			log.Fatalf("Exit node failed to start: %v", err)
		}
		defer exitNode.Stop()
	} else {
		clientTunnel, err := tunnel.NewSOCKS5ClientTunnel(*socks5Addr, tr, *sessionID, []byte(keyVal))
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
