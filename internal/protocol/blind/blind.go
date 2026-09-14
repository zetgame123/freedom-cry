package blind

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"errors"
	"fmt"
	"math/big"
)

// BlindKeyPair holds the Master's RSA key pair used for Privacy Pass / Blind Signatures
type BlindKeyPair struct {
	PrivateKey *rsa.PrivateKey
	PublicKey  *rsa.PublicKey
}

// GenerateBlindKeyPair generates an RSA-2048 keypair suitable for Chaum blind signatures
func GenerateBlindKeyPair() (*BlindKeyPair, error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, fmt.Errorf("failed to generate blind signing key: %w", err)
	}
	return &BlindKeyPair{
		PrivateKey: key,
		PublicKey:  &key.PublicKey,
	}, nil
}

// ClientBlindedSession holds the client-side state between blinding and unblinding
type ClientBlindedSession struct {
	TokenSeed      []byte
	BlindedMessage *big.Int
	BlindingFactor *big.Int
	HashedMessage  *big.Int
}

// BlindToken creates a blind token session: client hashes tokenSeed, selects random blinding factor r,
// and computes m' = m * r^e mod N. Master will sign m' without ever knowing m or tokenSeed.
func BlindToken(pubKey *rsa.PublicKey, tokenSeed []byte) (*ClientBlindedSession, error) {
	if len(tokenSeed) == 0 {
		return nil, errors.New("token seed cannot be empty")
	}

	// 1. Compute m = H(tokenSeed) mod N
	h := sha256.Sum256(tokenSeed)
	m := new(big.Int).SetBytes(h[:])
	m.Mod(m, pubKey.N)

	// Ensure m > 1
	if m.Cmp(big.NewInt(1)) <= 0 {
		m.Add(m, big.NewInt(2))
	}

	// 2. Choose random blinding factor r coprime to N
	one := big.NewInt(1)
	var r *big.Int
	var err error
	for {
		r, err = rand.Int(rand.Reader, pubKey.N)
		if err != nil {
			return nil, fmt.Errorf("failed to generate blinding factor: %w", err)
		}
		if r.Cmp(one) > 0 {
			gcd := new(big.Int).GCD(nil, nil, r, pubKey.N)
			if gcd.Cmp(one) == 0 {
				break
			}
		}
	}

	// 3. Compute r^e mod N
	e := big.NewInt(int64(pubKey.E))
	rPowE := new(big.Int).Exp(r, e, pubKey.N)

	// 4. Compute blinded message m' = (m * r^e) mod N
	mPrime := new(big.Int).Mul(m, rPowE)
	mPrime.Mod(mPrime, pubKey.N)

	return &ClientBlindedSession{
		TokenSeed:      tokenSeed,
		BlindedMessage: mPrime,
		BlindingFactor: r,
		HashedMessage:  m,
	}, nil
}

// SignBlindedMessage is performed by Master: computes s' = (m')^d mod N
func SignBlindedMessage(privKey *rsa.PrivateKey, blindedMessage *big.Int) (*big.Int, error) {
	if blindedMessage == nil || blindedMessage.Cmp(privKey.N) >= 0 {
		return nil, errors.New("invalid blinded message")
	}

	// s' = (m')^d mod N
	sPrime := new(big.Int).Exp(blindedMessage, privKey.D, privKey.N)
	return sPrime, nil
}

// UnblindSignature is performed by Client: computes s = s' * r^(-1) mod N
// The resulting (tokenSeed, s) is a valid, unblinded Privacy Pass token that verifies s^e == H(tokenSeed) mod N
func (sess *ClientBlindedSession) UnblindSignature(pubKey *rsa.PublicKey, blindedSignature *big.Int) (*big.Int, error) {
	if blindedSignature == nil {
		return nil, errors.New("blinded signature cannot be nil")
	}

	// rInv = r^(-1) mod N
	rInv := new(big.Int).ModInverse(sess.BlindingFactor, pubKey.N)
	if rInv == nil {
		return nil, errors.New("failed to calculate modular inverse of blinding factor")
	}

	// s = (s' * r^(-1)) mod N
	s := new(big.Int).Mul(blindedSignature, rInv)
	s.Mod(s, pubKey.N)

	return s, nil
}

// VerifyRedeemedToken is performed by Node or Master upon redemption:
// Verifies that s^e mod N == H(tokenSeed) mod N.
// Neither Master nor Node can correlate tokenSeed or signature with the original blinded request.
func VerifyRedeemedToken(pubKey *rsa.PublicKey, tokenSeed []byte, signature *big.Int) bool {
	if pubKey == nil || signature == nil || len(tokenSeed) == 0 {
		return false
	}

	// 1. Recompute expected m = H(tokenSeed) mod N
	h := sha256.Sum256(tokenSeed)
	expectedM := new(big.Int).SetBytes(h[:])
	expectedM.Mod(expectedM, pubKey.N)
	if expectedM.Cmp(big.NewInt(1)) <= 0 {
		expectedM.Add(expectedM, big.NewInt(2))
	}

	// 2. Compute v = s^e mod N
	e := big.NewInt(int64(pubKey.E))
	v := new(big.Int).Exp(signature, e, pubKey.N)

	// 3. Verify v == expectedM
	return v.Cmp(expectedM) == 0
}
