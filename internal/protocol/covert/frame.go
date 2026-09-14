package covert

import (
	"crypto/cipher"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"sync"
	"sync/atomic"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/hkdf"
)

type Command byte

const (
	CmdConnect Command = 1 // Connect to target (e.g. "example.com:443")
	CmdData    Command = 2 // Stream payload
	CmdClose   Command = 3 // Close stream
	CmdPing    Command = 4 // Keep-alive ping
	CmdPong    Command = 5 // Keep-alive pong
)

type Direction byte

const (
	DirUnknown        Direction = 0
	DirClientToServer Direction = 1 // Sent from client (SOCKS5/TUN) to server
	DirServerToClient Direction = 2 // Sent from server (ExitNode) to client
)

const (
	ProtocolVersion    byte   = 1
	MaxPayloadSize     uint16 = 16384 // 16 KB max frame payload to prevent allocation bombs / DoS
	HeaderSize         int    = 25
	AuthTagSize        int    = 16
	MinCiphertextSize int    = HeaderSize + AuthTagSize // 41 bytes
)

var (
	ErrCiphertextTooShort    = errors.New("ciphertext too short")
	ErrCiphertextTooLarge    = errors.New("ciphertext exceeds maximum allowed frame size")
	ErrInvalidVersion        = errors.New("unsupported protocol version")
	ErrDirectionMismatch     = errors.New("frame direction mismatch (reflection/wrong peer)")
	ErrSessionMismatch       = errors.New("frame session id mismatch")
	ErrReplayDetected        = errors.New("replay attack detected: packet already processed or too old")
	ErrAuthenticationFailed  = errors.New("cryptographic authentication failed: frame tampered or bad key")
	ErrPayloadTooLarge       = errors.New("payload length exceeds maximum allowed limit")
)

// Frame represents an authenticated, multiplexed unit of data over the covert transport
type Frame struct {
	Version   byte
	SessionID uint64
	Direction Direction
	Sequence  uint64
	StreamID  uint32
	Cmd       Command
	Payload   []byte
}

type ProtocolParty byte

const (
	PartyClient ProtocolParty = 1
	PartyServer ProtocolParty = 2
)

// ReplayWindow implements a 128-packet sliding window bitmap (RFC 6479)
// for constant-time, zero-allocation duplicate and replay rejection.
type ReplayWindow struct {
	mu      sync.Mutex
	lastSeq uint64
	bitmap  [2]uint64
}

func NewReplayWindow() *ReplayWindow {
	return &ReplayWindow{}
}

// Check tests if a sequence number is acceptable without modifying the window state.
// It returns false if the packet is zero, duplicate, or older than the 128-packet window.
func (w *ReplayWindow) Check(seq uint64) bool {
	w.mu.Lock()
	defer w.mu.Unlock()

	if seq == 0 {
		return false
	}

	if seq > w.lastSeq {
		return true
	}

	diff := w.lastSeq - seq
	if diff >= 128 {
		return false
	}

	var wordIdx int
	var bitIdx uint64
	if diff < 64 {
		wordIdx = 0
		bitIdx = diff
	} else {
		wordIdx = 1
		bitIdx = diff - 64
	}

	mask := uint64(1) << bitIdx
	return (w.bitmap[wordIdx] & mask) == 0
}

// Commit atomically commits a sequence number to the replay window after AEAD authentication.
func (w *ReplayWindow) Commit(seq uint64) bool {
	return w.CheckAndAdd(seq)
}

func (w *ReplayWindow) CheckAndAdd(seq uint64) bool {
	w.mu.Lock()
	defer w.mu.Unlock()

	if seq == 0 {
		return false
	}

	if seq > w.lastSeq {
		diff := seq - w.lastSeq
		if diff >= 128 {
			w.bitmap[0] = 0
			w.bitmap[1] = 0
		} else if diff >= 64 {
			w.bitmap[1] = w.bitmap[0] << (diff - 64)
			w.bitmap[0] = 0
		} else {
			w.bitmap[1] = (w.bitmap[1] << diff) | (w.bitmap[0] >> (64 - diff))
			w.bitmap[0] = w.bitmap[0] << diff
		}
		w.lastSeq = seq
		w.bitmap[0] |= 1
		return true
	}

	// seq <= lastSeq: check if within window
	diff := w.lastSeq - seq
	if diff >= 128 {
		return false // Too old, outside replay window
	}

	var wordIdx int
	var bitIdx uint64
	if diff < 64 {
		wordIdx = 0
		bitIdx = diff
	} else {
		wordIdx = 1
		bitIdx = diff - 64
	}

	mask := uint64(1) << bitIdx
	if (w.bitmap[wordIdx] & mask) != 0 {
		return false // Duplicate packet! Replay detected.
	}

	w.bitmap[wordIdx] |= mask
	return true
}

// SecureChannel provides end-to-end ChaCha20-Poly1305 encryption with:
// 1. Separate Directional Keys (HKDF-SHA256) to defeat packet reflection
// 2. Monotonic Sequence Numbers with Sliding Window Replay Protection
// 3. Authenticated Additional Data (AAD) covering all header fields
// 4. Deterministic Nonces that prevent nonce-reuse attacks
type SecureChannel struct {
	party        ProtocolParty
	sessionID    uint64
	writeAEAD    cipher.AEAD
	readAEAD     cipher.AEAD
	writeDir     Direction
	readDir      Direction
	writeSeq     atomic.Uint64
	replayWindow *ReplayWindow
}

func NewSecureChannel(party ProtocolParty, sessionID uint64, masterKey []byte) (*SecureChannel, error) {
	if len(masterKey) < 16 {
		return nil, errors.New("master key must be at least 16 bytes")
	}

	// HKDF-SHA256 key derivation for directional key separation
	var clientKey [32]byte
	var serverKey [32]byte

	kClient := hkdf.New(sha256.New, masterKey, nil, []byte("freedom-cry-covert-v1-client-write"))
	if _, err := io.ReadFull(kClient, clientKey[:]); err != nil {
		return nil, fmt.Errorf("failed to derive client key: %w", err)
	}

	kServer := hkdf.New(sha256.New, masterKey, nil, []byte("freedom-cry-covert-v1-server-write"))
	if _, err := io.ReadFull(kServer, serverKey[:]); err != nil {
		return nil, fmt.Errorf("failed to derive server key: %w", err)
	}

	clientAEAD, err := chacha20poly1305.New(clientKey[:])
	if err != nil {
		return nil, err
	}

	serverAEAD, err := chacha20poly1305.New(serverKey[:])
	if err != nil {
		return nil, err
	}

	ch := &SecureChannel{
		party:        party,
		sessionID:    sessionID,
		replayWindow: NewReplayWindow(),
	}

	if party == PartyClient {
		ch.writeAEAD = clientAEAD
		ch.readAEAD = serverAEAD
		ch.writeDir = DirClientToServer
		ch.readDir = DirServerToClient
	} else {
		ch.writeAEAD = serverAEAD
		ch.readAEAD = clientAEAD
		ch.writeDir = DirServerToClient
		ch.readDir = DirClientToServer
	}

	return ch, nil
}

// EncryptFrame packages a Frame into an authenticated ciphertext.
// The 25-byte header is authenticated as AAD, and payload is encrypted.
func (c *SecureChannel) EncryptFrame(streamID uint32, cmd Command, payload []byte) ([]byte, error) {
	if len(payload) > int(MaxPayloadSize) {
		return nil, ErrPayloadTooLarge
	}

	seq := c.writeSeq.Add(1)

	// Construct 12-byte deterministic nonce:
	// [0] Version, [1] Direction, [2:4] 0, [4:12] Sequence
	var nonce [chacha20poly1305.NonceSize]byte
	nonce[0] = ProtocolVersion
	nonce[1] = byte(c.writeDir)
	binary.BigEndian.PutUint64(nonce[4:12], seq)

	// Construct 25-byte header
	header := make([]byte, HeaderSize, HeaderSize+len(payload)+AuthTagSize)
	header[0] = ProtocolVersion
	binary.BigEndian.PutUint64(header[1:9], c.sessionID)
	header[9] = byte(c.writeDir)
	binary.BigEndian.PutUint64(header[10:18], seq)
	binary.BigEndian.PutUint32(header[18:22], streamID)
	header[22] = byte(cmd)
	binary.BigEndian.PutUint16(header[23:25], uint16(len(payload)))

	// Encrypt payload with header as Authenticated Additional Data (AAD)
	ciphertext := c.writeAEAD.Seal(header, nonce[:], payload, header)
	return ciphertext, nil
}

// DecryptFrame validates the AAD header, verifies direction and replay window,
// and decrypts the frame payload.
func (c *SecureChannel) DecryptFrame(raw []byte) (*Frame, error) {
	if len(raw) < MinCiphertextSize {
		return nil, ErrCiphertextTooShort
	}
	if len(raw) > HeaderSize+int(MaxPayloadSize)+AuthTagSize {
		return nil, ErrCiphertextTooLarge
	}

	// 1. Parse header fields
	version := raw[0]
	if version != ProtocolVersion {
		return nil, ErrInvalidVersion
	}

	sessionID := binary.BigEndian.Uint64(raw[1:9])
	if c.sessionID != 0 && sessionID != c.sessionID {
		return nil, ErrSessionMismatch
	}

	dir := Direction(raw[9])
	if dir != c.readDir {
		return nil, ErrDirectionMismatch
	}

	seq := binary.BigEndian.Uint64(raw[10:18])
	streamID := binary.BigEndian.Uint32(raw[18:22])
	cmd := Command(raw[22])
	payloadLen := binary.BigEndian.Uint16(raw[23:25])

	if len(raw) != HeaderSize+int(payloadLen)+AuthTagSize {
		return nil, errors.New("frame length mismatch")
	}

	// 2. Pre-verification Replay Protection Window check
	if !c.replayWindow.Check(seq) {
		return nil, ErrReplayDetected
	}

	// 3. Construct expected nonce
	var nonce [chacha20poly1305.NonceSize]byte
	nonce[0] = version
	nonce[1] = byte(dir)
	binary.BigEndian.PutUint64(nonce[4:12], seq)

	// 4. Decrypt and verify Poly1305 authentication tag over ciphertext + AAD header
	header := raw[:HeaderSize]
	ciphertextPayload := raw[HeaderSize:]

	plaintext, err := c.readAEAD.Open(nil, nonce[:], ciphertextPayload, header)
	if err != nil {
		return nil, ErrAuthenticationFailed
	}

	// 5. Commit sequence to replay window ONLY after cryptographic verification.
	// This ensures forged unauthenticated frames cannot advance or poison the window.
	if !c.replayWindow.Commit(seq) {
		return nil, ErrReplayDetected
	}

	return &Frame{
		Version:   version,
		SessionID: sessionID,
		Direction: dir,
		Sequence:  seq,
		StreamID:  streamID,
		Cmd:       cmd,
		Payload:   plaintext,
	}, nil
}
