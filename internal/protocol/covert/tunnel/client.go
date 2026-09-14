package tunnel

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"sync"
	"sync/atomic"

	"freedom-cry/internal/protocol/covert"
)

const (
	MaxConcurrentStreams = 512
)

type SOCKS5ClientTunnel struct {
	listenAddr string
	transport  covert.Transport
	channel    *covert.SecureChannel
	listener   net.Listener

	streams     map[uint32]net.Conn
	streamIDGen atomic.Uint32
	mu          sync.RWMutex
	running     atomic.Bool
}

func NewSOCKS5ClientTunnel(listenAddr string, transport covert.Transport, sessionID uint64, secretKey []byte) (*SOCKS5ClientTunnel, error) {
	if listenAddr == "" {
		listenAddr = "127.0.0.1:1080"
	}

	channel, err := covert.NewSecureChannel(covert.PartyClient, sessionID, secretKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create secure channel: %w", err)
	}

	client := &SOCKS5ClientTunnel{
		listenAddr: listenAddr,
		transport:  transport,
		channel:    channel,
		streams:    make(map[uint32]net.Conn),
	}

	transport.OnReceive(client.handleIncomingFrameBytes)
	return client, nil
}

func (c *SOCKS5ClientTunnel) Start(ctx context.Context) error {
	if err := c.transport.Start(ctx); err != nil {
		return fmt.Errorf("failed to start transport: %w", err)
	}

	l, err := net.Listen("tcp", c.listenAddr)
	if err != nil {
		return fmt.Errorf("failed to bind SOCKS5 listener: %w", err)
	}
	c.listener = l
	c.running.Store(true)

	log.Printf("[Covert Client] SOCKS5 server listening at %s (Transport: %s, ReplayProtected: true)", c.listenAddr, c.transport.Name())

	go c.acceptLoop(ctx)
	return nil
}

func (c *SOCKS5ClientTunnel) Stop() error {
	c.running.Store(false)
	if c.listener != nil {
		_ = c.listener.Close()
	}

	c.mu.Lock()
	for _, conn := range c.streams {
		_ = conn.Close()
	}
	c.streams = make(map[uint32]net.Conn)
	c.mu.Unlock()

	return c.transport.Stop()
}

func (c *SOCKS5ClientTunnel) acceptLoop(ctx context.Context) {
	for c.running.Load() {
		conn, err := c.listener.Accept()
		if err != nil {
			if !c.running.Load() {
				return
			}
			continue
		}

		go c.handleSOCKS5Connection(conn)
	}
}

func (c *SOCKS5ClientTunnel) handleSOCKS5Connection(conn net.Conn) {
	defer conn.Close()

	// 1. Handshake: Read version and auth methods
	header := make([]byte, 2)
	if _, err := io.ReadFull(conn, header); err != nil || header[0] != 0x05 {
		return
	}

	nMethods := int(header[1])
	methods := make([]byte, nMethods)
	if _, err := io.ReadFull(conn, methods); err != nil {
		return
	}

	// Respond with No-Auth required (0x05, 0x00)
	if _, err := conn.Write([]byte{0x05, 0x00}); err != nil {
		return
	}

	// 2. Read SOCKS5 Request
	reqHeader := make([]byte, 4)
	if _, err := io.ReadFull(conn, reqHeader); err != nil {
		return
	}

	cmd := reqHeader[1]
	if cmd != 0x01 { // Only TCP CONNECT supported
		_, _ = conn.Write([]byte{0x05, 0x07, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}

	atyp := reqHeader[3]
	var targetHost string

	switch atyp {
	case 0x01: // IPv4
		ip := make([]byte, 4)
		if _, err := io.ReadFull(conn, ip); err != nil {
			return
		}
		targetHost = net.IP(ip).String()

	case 0x03: // Domain name
		lenBuf := make([]byte, 1)
		if _, err := io.ReadFull(conn, lenBuf); err != nil {
			return
		}
		domain := make([]byte, lenBuf[0])
		if _, err := io.ReadFull(conn, domain); err != nil {
			return
		}
		targetHost = string(domain)

	case 0x04: // IPv6
		ip := make([]byte, 16)
		if _, err := io.ReadFull(conn, ip); err != nil {
			return
		}
		targetHost = net.IP(ip).String()

	default:
		return
	}

	portBuf := make([]byte, 2)
	if _, err := io.ReadFull(conn, portBuf); err != nil {
		return
	}
	targetPort := binary.BigEndian.Uint16(portBuf)
	target := fmt.Sprintf("%s:%d", targetHost, targetPort)

	// Resource Limit Check
	c.mu.RLock()
	activeCount := len(c.streams)
	c.mu.RUnlock()

	if activeCount >= MaxConcurrentStreams {
		log.Printf("[Covert Client] Max concurrent streams reached (%d), rejecting %s", MaxConcurrentStreams, target)
		_, _ = conn.Write([]byte{0x05, 0x04, 0x00, 0x01, 0, 0, 0, 0, 0, 0}) // Host unreachable
		return
	}

	// Send success reply to browser/app
	if _, err := conn.Write([]byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0}); err != nil {
		return
	}

	// 3. Forward over Covert Transport
	streamID := c.streamIDGen.Add(1)
	c.mu.Lock()
	c.streams[streamID] = conn
	c.mu.Unlock()

	defer c.closeStream(streamID)

	// Send CmdConnect frame
	if err := c.sendFrame(streamID, covert.CmdConnect, []byte(target)); err != nil {
		log.Printf("[Covert Client] Failed to send connect frame: %v", err)
		return
	}

	log.Printf("[Covert Client] Tunneling connection -> %s (Stream %d)", target, streamID)

	// Pump stream data from client into transport
	buf := make([]byte, 1500)
	for {
		nr, err := conn.Read(buf)
		if nr > 0 {
			if err := c.sendFrame(streamID, covert.CmdData, buf[:nr]); err != nil {
				return
			}
		}
		if err != nil {
			return
		}
	}
}

func (c *SOCKS5ClientTunnel) handleIncomingFrameBytes(raw []byte) {
	frame, err := c.channel.DecryptFrame(raw)
	if err != nil {
		// Silently ignore corrupted, replayed, or direction-mismatched packets
		return
	}

	switch frame.Cmd {
	case covert.CmdData:
		c.mu.RLock()
		conn, exists := c.streams[frame.StreamID]
		c.mu.RUnlock()

		if exists && conn != nil {
			_, _ = conn.Write(frame.Payload)
		}

	case covert.CmdClose:
		c.closeStream(frame.StreamID)
	}
}

func (c *SOCKS5ClientTunnel) closeStream(streamID uint32) {
	c.mu.Lock()
	conn, exists := c.streams[streamID]
	delete(c.streams, streamID)
	c.mu.Unlock()

	if exists && conn != nil {
		_ = conn.Close()
		_ = c.sendFrame(streamID, covert.CmdClose, nil)
	}
}

func (c *SOCKS5ClientTunnel) sendFrame(streamID uint32, cmd covert.Command, payload []byte) error {
	if c.channel == nil {
		return errors.New("secure channel not initialized")
	}
	encrypted, err := c.channel.EncryptFrame(streamID, cmd, payload)
	if err != nil {
		return err
	}
	return c.transport.Send(encrypted)
}
