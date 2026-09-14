package covert

import (
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"

	"golang.org/x/crypto/chacha20poly1305"
)

type Command byte

const (
	CmdConnect Command = 1 // Connect to target (e.g. "instagram.com:443")
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

// Frame represents a multiplexed unit of data over the covert transport
type Frame struct {
	StreamID  uint32
	Cmd       Command
	Direction Direction
	Payload   []byte
}

// EncodeFrame serializes a Frame into bytes:
// [4 bytes StreamID] [1 byte Cmd] [1 byte Direction] [2 bytes PayloadLen] [Payload bytes...]
func EncodeFrame(f Frame) []byte {
	buf := make([]byte, 8+len(f.Payload))
	binary.BigEndian.PutUint32(buf[0:4], f.StreamID)
	buf[4] = byte(f.Cmd)
	buf[5] = byte(f.Direction)
	binary.BigEndian.PutUint16(buf[6:8], uint16(len(f.Payload)))
	copy(buf[8:], f.Payload)
	return buf
}

// DecodeFrame deserializes a Frame from raw bytes
func DecodeFrame(data []byte) (*Frame, error) {
	if len(data) < 8 {
		return nil, errors.New("frame data too short")
	}

	streamID := binary.BigEndian.Uint32(data[0:4])
	cmd := Command(data[4])
	dir := Direction(data[5])
	payloadLen := binary.BigEndian.Uint16(data[6:8])

	if len(data) < int(8+payloadLen) {
		return nil, errors.New("incomplete frame payload")
	}

	payload := make([]byte, payloadLen)
	copy(payload, data[8:8+payloadLen])

	return &Frame{
		StreamID:  streamID,
		Cmd:       cmd,
		Direction: dir,
		Payload:   payload,
	}, nil
}

// FrameCipher provides end-to-end ChaCha20-Poly1305 encryption so the
// intermediate whitelisted platform (e.g. Yandex) cannot read or tamper with traffic.
type FrameCipher struct {
	aead cipher.AEAD
}

func NewFrameCipher(key []byte) (*FrameCipher, error) {
	// Key must be 32 bytes for ChaCha20-Poly1305
	var k [32]byte
	copy(k[:], key)

	aead, err := chacha20poly1305.New(k[:])
	if err != nil {
		return nil, fmt.Errorf("failed to create aead cipher: %w", err)
	}

	return &FrameCipher{aead: aead}, nil
}

func (c *FrameCipher) Encrypt(plaintext []byte) ([]byte, error) {
	if c == nil {
		return plaintext, nil
	}
	nonce := make([]byte, chacha20poly1305.NonceSize)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}
	ciphertext := c.aead.Seal(nonce, nonce, plaintext, nil)
	return ciphertext, nil
}

func (c *FrameCipher) Decrypt(ciphertext []byte) ([]byte, error) {
	if c == nil {
		return ciphertext, nil
	}
	if len(ciphertext) < chacha20poly1305.NonceSize {
		return nil, errors.New("ciphertext too short")
	}
	nonce := ciphertext[:chacha20poly1305.NonceSize]
	data := ciphertext[chacha20poly1305.NonceSize:]
	return c.aead.Open(nil, nonce, data, nil)
}
