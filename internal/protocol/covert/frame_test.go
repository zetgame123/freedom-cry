package covert

import (
	"bytes"
	"encoding/binary"
	"testing"
)

func TestSecureChannel_EndToEnd(t *testing.T) {
	key := []byte("freedom-cry-32-byte-master-key-!")
	sessionID := uint64(0x1122334455667788)

	clientChan, err := NewSecureChannel(PartyClient, sessionID, key)
	if err != nil {
		t.Fatalf("NewSecureChannel client failed: %v", err)
	}

	serverChan, err := NewSecureChannel(PartyServer, sessionID, key)
	if err != nil {
		t.Fatalf("NewSecureChannel server failed: %v", err)
	}

	// 1. Client -> Server transmission
	origPayload := []byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")
	encrypted, err := clientChan.EncryptFrame(1, CmdData, origPayload)
	if err != nil {
		t.Fatalf("EncryptFrame failed: %v", err)
	}

	frame, err := serverChan.DecryptFrame(encrypted)
	if err != nil {
		t.Fatalf("DecryptFrame failed: %v", err)
	}

	if frame.StreamID != 1 || frame.Cmd != CmdData || frame.Direction != DirClientToServer {
		t.Errorf("Frame metadata mismatch: %+v", frame)
	}
	if !bytes.Equal(frame.Payload, origPayload) {
		t.Errorf("Payload mismatch: got %s, want %s", frame.Payload, origPayload)
	}

	// 2. Server -> Client transmission
	respPayload := []byte("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK")
	serverEnc, err := serverChan.EncryptFrame(1, CmdData, respPayload)
	if err != nil {
		t.Fatalf("Server EncryptFrame failed: %v", err)
	}

	clientFrame, err := clientChan.DecryptFrame(serverEnc)
	if err != nil {
		t.Fatalf("Client DecryptFrame failed: %v", err)
	}

	if clientFrame.Direction != DirServerToClient || !bytes.Equal(clientFrame.Payload, respPayload) {
		t.Errorf("Client decrypted payload mismatch: %+v", clientFrame)
	}
}

func TestSecureChannel_ReplayAttackRejection(t *testing.T) {
	key := []byte("freedom-cry-32-byte-master-key-!")
	sessionID := uint64(0x9988776655443322)

	clientChan, _ := NewSecureChannel(PartyClient, sessionID, key)
	serverChan, _ := NewSecureChannel(PartyServer, sessionID, key)

	encrypted, err := clientChan.EncryptFrame(42, CmdConnect, []byte("target.com:443"))
	if err != nil {
		t.Fatalf("EncryptFrame failed: %v", err)
	}

	// First delivery: MUST succeed
	_, err = serverChan.DecryptFrame(encrypted)
	if err != nil {
		t.Fatalf("First delivery failed: %v", err)
	}

	// Adversarial: Replay the exact same frame!
	_, err = serverChan.DecryptFrame(encrypted)
	if err != ErrReplayDetected {
		t.Fatalf("Replay attack was NOT blocked! Got: %v, expected ErrReplayDetected", err)
	}
}

func TestSecureChannel_DirectionMismatchRejection(t *testing.T) {
	key := []byte("freedom-cry-32-byte-master-key-!")
	sessionID := uint64(12345)

	clientChan, _ := NewSecureChannel(PartyClient, sessionID, key)

	// Client sends a frame
	encrypted, _ := clientChan.EncryptFrame(1, CmdData, []byte("Hello"))

	// Reflection attack: What if the frame is bounced back to another client?
	peerClientChan, _ := NewSecureChannel(PartyClient, sessionID, key)
	_, err := peerClientChan.DecryptFrame(encrypted)
	if err != ErrDirectionMismatch {
		t.Fatalf("Reflection/direction mismatch attack was NOT rejected! Got: %v", err)
	}
}

func TestSecureChannel_TamperingRejection(t *testing.T) {
	key := []byte("freedom-cry-32-byte-master-key-!")
	sessionID := uint64(54321)

	clientChan, _ := NewSecureChannel(PartyClient, sessionID, key)
	serverChan, _ := NewSecureChannel(PartyServer, sessionID, key)

	encrypted, _ := clientChan.EncryptFrame(1, CmdData, []byte("Authentic confidential data"))

	// Tamper with a bit in the encrypted payload
	tampered := make([]byte, len(encrypted))
	copy(tampered, encrypted)
	tampered[len(tampered)-5] ^= 0xFF

	_, err := serverChan.DecryptFrame(tampered)
	if err != ErrAuthenticationFailed {
		t.Fatalf("Tampered frame was NOT rejected by Poly1305 MAC! Got: %v", err)
	}

	// Tamper with a bit in the AAD header (StreamID) on a fresh frame
	encrypted2, _ := clientChan.EncryptFrame(1, CmdData, []byte("Second frame for header tampering"))
	tamperedHeader := make([]byte, len(encrypted2))
	copy(tamperedHeader, encrypted2)
	tamperedHeader[18] ^= 0x01 // Flip StreamID bit in header

	_, err = serverChan.DecryptFrame(tamperedHeader)
	if err != ErrAuthenticationFailed {
		t.Fatalf("Header-tampered frame was NOT rejected by Poly1305 AAD! Got: %v", err)
	}
}

func TestReplayWindow_OutOfOrderAndDuplicates(t *testing.T) {
	w := NewReplayWindow()

	// Normal sequential
	if !w.CheckAndAdd(1) {
		t.Errorf("seq 1 should be accepted")
	}
	if !w.CheckAndAdd(2) {
		t.Errorf("seq 2 should be accepted")
	}

	// Duplicate
	if w.CheckAndAdd(1) {
		t.Errorf("seq 1 duplicate should be rejected")
	}
	if w.CheckAndAdd(2) {
		t.Errorf("seq 2 duplicate should be rejected")
	}

	// Out of order within window
	if !w.CheckAndAdd(10) {
		t.Errorf("seq 10 should be accepted")
	}
	if !w.CheckAndAdd(5) {
		t.Errorf("seq 5 (out of order, within window) should be accepted")
	}
	if w.CheckAndAdd(5) {
		t.Errorf("seq 5 duplicate should be rejected")
	}

	// Huge jump
	if !w.CheckAndAdd(200) {
		t.Errorf("seq 200 should be accepted")
	}

	// Packet from old window (> 128 behind 200)
	if w.CheckAndAdd(10) {
		t.Errorf("seq 10 should be rejected as too old")
	}
	if w.CheckAndAdd(50) {
		t.Errorf("seq 50 should be rejected as too old")
	}

	// Zero sequence
	if w.CheckAndAdd(0) {
		t.Errorf("seq 0 should be rejected")
	}
}

func TestSecureChannel_ReplayWindowPoisoningResistance(t *testing.T) {
	key := []byte("freedom-cry-32-byte-master-key-!")
	sessionID := uint64(0xABCDEF123456)

	clientChan, _ := NewSecureChannel(PartyClient, sessionID, key)
	serverChan, _ := NewSecureChannel(PartyServer, sessionID, key)

	// Attacker injects a completely bogus frame with seq = 5000 (trying to poison the window)
	bogusFrame := make([]byte, HeaderSize+10+AuthTagSize)
	bogusFrame[0] = ProtocolVersion
	binary.BigEndian.PutUint64(bogusFrame[1:9], sessionID)
	bogusFrame[9] = byte(DirClientToServer)
	// seq = 5000
	bogusFrame[10] = 0
	bogusFrame[11] = 0
	bogusFrame[12] = 0
	bogusFrame[13] = 0
	bogusFrame[14] = 0
	bogusFrame[15] = 0
	bogusFrame[16] = 0x13
	bogusFrame[17] = 0x88 // 5000 in hex
	bogusFrame[24] = 10   // payload len = 10

	_, err := serverChan.DecryptFrame(bogusFrame)
	if err != ErrAuthenticationFailed {
		t.Fatalf("Bogus frame should have failed auth: %v", err)
	}

	// Now client sends legitimate frame with seq = 1
	validEncrypted, err := clientChan.EncryptFrame(1, CmdData, []byte("legitimate"))
	if err != nil {
		t.Fatalf("Failed to encrypt valid frame: %v", err)
	}

	// Server MUST accept valid frame seq = 1 (window was NOT poisoned by bogus seq=5000)
	frame, err := serverChan.DecryptFrame(validEncrypted)
	if err != nil {
		t.Fatalf("Legitimate frame rejected (replay window was poisoned!): %v", err)
	}
	if string(frame.Payload) != "legitimate" {
		t.Errorf("Payload mismatch: %s", frame.Payload)
	}
}
