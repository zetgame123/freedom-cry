package blind

import (
	"crypto/rand"
	"math/big"
	"testing"
)

func TestBlindSignature_FullWorkflow(t *testing.T) {
	// 1. Master generates key pair
	keyPair, err := GenerateBlindKeyPair()
	if err != nil {
		t.Fatalf("GenerateBlindKeyPair failed: %v", err)
	}

	// 2. Client chooses random token seed
	tokenSeed := make([]byte, 32)
	if _, err := rand.Read(tokenSeed); err != nil {
		t.Fatalf("rand.Read failed: %v", err)
	}

	// 3. Client blinds the token seed
	session, err := BlindToken(keyPair.PublicKey, tokenSeed)
	if err != nil {
		t.Fatalf("BlindToken failed: %v", err)
	}

	// Verify blinded message does not match unblinded message
	if session.BlindedMessage.Cmp(session.HashedMessage) == 0 {
		t.Fatalf("Blinded message must not match plaintext hashed message")
	}

	// 4. Master signs the blinded message without seeing tokenSeed
	blindedSig, err := SignBlindedMessage(keyPair.PrivateKey, session.BlindedMessage)
	if err != nil {
		t.Fatalf("SignBlindedMessage failed: %v", err)
	}

	// 5. Client unblinds the signature
	unblindedSig, err := session.UnblindSignature(keyPair.PublicKey, blindedSig)
	if err != nil {
		t.Fatalf("UnblindSignature failed: %v", err)
	}

	// 6. Node or Master verifies the redeemed token
	valid := VerifyRedeemedToken(keyPair.PublicKey, tokenSeed, unblindedSig)
	if !valid {
		t.Fatalf("VerifyRedeemedToken failed: valid Privacy Pass signature was rejected")
	}

	// 7. Test invalid/tampered token seed is rejected
	tamperedSeed := make([]byte, len(tokenSeed))
	copy(tamperedSeed, tokenSeed)
	tamperedSeed[0] ^= 0xFF
	if VerifyRedeemedToken(keyPair.PublicKey, tamperedSeed, unblindedSig) {
		t.Fatalf("Tampered token seed must be rejected")
	}

	// 8. Test invalid signature is rejected
	tamperedSig := new(big.Int).Add(unblindedSig, big.NewInt(1))
	if VerifyRedeemedToken(keyPair.PublicKey, tokenSeed, tamperedSig) {
		t.Fatalf("Tampered signature must be rejected")
	}
}
