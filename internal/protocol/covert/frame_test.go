package covert

import (
	"bytes"
	"testing"
)

func TestEncodeDecodeFrame(t *testing.T) {
	orig := Frame{
		StreamID:  42,
		Cmd:       CmdConnect,
		Direction: DirClientToServer,
		Payload:   []byte("api.telegram.org:443"),
	}

	encoded := EncodeFrame(orig)
	decoded, err := DecodeFrame(encoded)
	if err != nil {
		t.Fatalf("DecodeFrame failed: %v", err)
	}

	if decoded.StreamID != orig.StreamID {
		t.Errorf("expected StreamID %d, got %d", orig.StreamID, decoded.StreamID)
	}
	if decoded.Cmd != orig.Cmd {
		t.Errorf("expected Cmd %d, got %d", orig.Cmd, decoded.Cmd)
	}
	if decoded.Direction != orig.Direction {
		t.Errorf("expected Direction %d, got %d", orig.Direction, decoded.Direction)
	}
	if !bytes.Equal(decoded.Payload, orig.Payload) {
		t.Errorf("payload mismatch: %s vs %s", string(decoded.Payload), string(orig.Payload))
	}
}

func TestFrameCipher(t *testing.T) {
	key := []byte("freedom-cry-32-byte-secret-key-1")
	cipher, err := NewFrameCipher(key)
	if err != nil {
		t.Fatalf("NewFrameCipher failed: %v", err)
	}

	plaintext := []byte("Sensitive covert data bypassing DPI")
	ciphertext, err := cipher.Encrypt(plaintext)
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}

	if bytes.Equal(ciphertext, plaintext) {
		t.Fatal("ciphertext equals plaintext")
	}

	decrypted, err := cipher.Decrypt(ciphertext)
	if err != nil {
		t.Fatalf("Decrypt failed: %v", err)
	}

	if !bytes.Equal(decrypted, plaintext) {
		t.Fatalf("decrypted mismatch: %s vs %s", string(decrypted), string(plaintext))
	}
}
