package tunnel

import (
	"context"
	"errors"
	"io"
	"log"
	"net"
	"sync"
	"time"

	"freedom-cry/internal/protocol/covert"
	"freedom-cry/internal/protocol/covert/safedial"
)

type ExitNode struct {
	transport  covert.Transport
	channel    *covert.SecureChannel
	safeDialer *safedial.SafeDialer
	streams    map[uint32]net.Conn
	mu         sync.RWMutex
}

func NewExitNode(transport covert.Transport, sessionID uint64, secretKey []byte) (*ExitNode, error) {
	channel, err := covert.NewSecureChannel(covert.PartyServer, sessionID, secretKey)
	if err != nil {
		return nil, err
	}

	node := &ExitNode{
		transport:  transport,
		channel:    channel,
		safeDialer: safedial.NewSafeDialer(10 * time.Second),
		streams:    make(map[uint32]net.Conn),
	}

	transport.OnReceive(node.handleIncomingFrameBytes)
	return node, nil
}

func (n *ExitNode) Start(ctx context.Context) error {
	log.Printf("[ExitNode] Starting hardened exit node (Transport: %s, SSRFProtection: ENABLED, ReplayProtection: ENABLED)", n.transport.Name())
	return n.transport.Start(ctx)
}

func (n *ExitNode) Stop() error {
	n.mu.Lock()
	for _, conn := range n.streams {
		_ = conn.Close()
	}
	n.streams = make(map[uint32]net.Conn)
	n.mu.Unlock()

	return n.transport.Stop()
}

func (n *ExitNode) handleIncomingFrameBytes(raw []byte) {
	frame, err := n.channel.DecryptFrame(raw)
	if err != nil {
		// corruped, replayed, or direction-mismatched
		return
	}

	switch frame.Cmd {
	case covert.CmdConnect:
		target := string(frame.Payload)
		go n.handleConnect(frame.StreamID, target)

	case covert.CmdData:
		n.mu.RLock()
		conn, exists := n.streams[frame.StreamID]
		n.mu.RUnlock()

		if exists && conn != nil {
			_, _ = conn.Write(frame.Payload)
		}

	case covert.CmdClose:
		n.closeStream(frame.StreamID)

	case covert.CmdPing:
		_ = n.sendFrame(frame.StreamID, covert.CmdPong, nil)
	}
}

func (n *ExitNode) handleConnect(streamID uint32, target string) {
	// 1. Enforce stream count limits
	n.mu.RLock()
	streamCount := len(n.streams)
	n.mu.RUnlock()

	if streamCount >= MaxConcurrentStreams {
		log.Printf("[ExitNode] Max concurrent streams reached (%d), rejecting %s", MaxConcurrentStreams, target)
		_ = n.sendFrame(streamID, covert.CmdClose, nil)
		return
	}

	// 2. Safe dial with strict SSRF blocklist (blocks loopback, RFC1918, link-local, cloud metadata, rebinding)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	conn, err := n.safeDialer.DialContext(ctx, "tcp", target)
	if err != nil {
		log.Printf("[ExitNode SSRF Defense] Dial rejected for target %q: %v", target, err)
		_ = n.sendFrame(streamID, covert.CmdClose, nil)
		return
	}

	n.mu.Lock()
	n.streams[streamID] = conn
	n.mu.Unlock()

	log.Printf("[ExitNode] Stream %d connected to %s", streamID, target)

	// 3. Pump responses from the real destination back through the covert transport
	go func() {
		defer n.closeStream(streamID)
		buf := make([]byte, 1500)

		for {
			nr, err := conn.Read(buf)
			if nr > 0 {
				if err := n.sendFrame(streamID, covert.CmdData, buf[:nr]); err != nil {
					return
				}
			}
			if err != nil {
				if err != io.EOF {
					log.Printf("[ExitNode] Stream %d read error: %v", streamID, err)
				}
				return
			}
		}
	}()
}

func (n *ExitNode) closeStream(streamID uint32) {
	n.mu.Lock()
	conn, exists := n.streams[streamID]
	delete(n.streams, streamID)
	n.mu.Unlock()

	if exists && conn != nil {
		_ = conn.Close()
		_ = n.sendFrame(streamID, covert.CmdClose, nil)
	}
}

func (n *ExitNode) sendFrame(streamID uint32, cmd covert.Command, payload []byte) error {
	if n.channel == nil {
		return errors.New("secure channel not initialized")
	}
	encrypted, err := n.channel.EncryptFrame(streamID, cmd, payload)
	if err != nil {
		return err
	}
	return n.transport.Send(encrypted)
}
