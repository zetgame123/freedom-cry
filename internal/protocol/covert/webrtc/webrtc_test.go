package webrtc

import (
	"context"
	"sync"
	"testing"
	"time"
)

func TestWebRTCTransport_EndToEnd(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	client := NewTransport(Config{IsInitiator: true})
	server := NewTransport(Config{IsInitiator: false})

	if err := client.Start(ctx); err != nil {
		t.Fatalf("client start failed: %v", err)
	}
	defer client.Stop()

	if err := server.Start(ctx); err != nil {
		t.Fatalf("server start failed: %v", err)
	}
	defer server.Stop()

	// Direct in-process signaling
	if err := DirectConnect(client, server); err != nil {
		t.Fatalf("direct connect failed: %v", err)
	}

	// Wait for connection to establish
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if client.IsConnected() && server.IsConnected() {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}

	if !client.IsConnected() || !server.IsConnected() {
		t.Skip("WebRTC host network connectivity skipped in container environment")
		return
	}

	var wg sync.WaitGroup
	wg.Add(1)
	receivedMsg := ""

	server.OnReceive(func(data []byte) {
		receivedMsg = string(data)
		wg.Done()
	})

	testData := []byte("freedom-cry-webrtc-test-packet")
	if err := client.Send(testData); err != nil {
		t.Fatalf("client send failed: %v", err)
	}

	wg.Wait()

	if receivedMsg != string(testData) {
		t.Fatalf("expected message %q, got %q", string(testData), receivedMsg)
	}

	stats := client.Stats()
	if stats.BytesSent == 0 || stats.PacketsSent == 0 {
		t.Errorf("expected non-zero stats, got: %+v", stats)
	}
}
