package covert

import (
	"testing"
)

func FuzzDecryptFrame(f *testing.F) {
	key := []byte("freedom-cry-32-byte-master-key-!")
	sessionID := uint64(0x1234567890abcdef)

	serverChan, err := NewSecureChannel(PartyServer, sessionID, key)
	if err != nil {
		f.Fatalf("Failed to initialize server secure channel: %v", err)
	}

	clientChan, err := NewSecureChannel(PartyClient, sessionID, key)
	if err != nil {
		f.Fatalf("Failed to initialize client secure channel: %v", err)
	}

	// Seed with empty slice
	f.Add([]byte{})

	// Seed with short byte slice
	f.Add([]byte{0x01, 0x02, 0x03, 0x04})

	// Seed with valid encrypted frame
	validCiphertext, err := clientChan.EncryptFrame(1, CmdData, []byte("Hello, Covert Fuzzer!"))
	if err == nil {
		f.Add(validCiphertext)
	}

	// Seed with modified valid frame
	if len(validCiphertext) > 0 {
		tampered := make([]byte, len(validCiphertext))
		copy(tampered, validCiphertext)
		tampered[0] = 0xFF // corrupt version
		f.Add(tampered)
	}

	f.Fuzz(func(t *testing.T, data []byte) {
		// DecryptFrame must never panic, crash or allocate uncontrollably
		_, _ = serverChan.DecryptFrame(data)
	})
}
