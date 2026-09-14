package tunnel

import (
	"context"
	"io"
	"log"
	"net"
	"sync"
	"time"

	"freedom-cry/internal/protocol/covert"
)

type ExitNode struct {
	transport covert.Transport
	cipher    *covert.FrameCipher
	streams   map[uint32]net.Conn
	mu        sync.RWMutex
}

func NewExitNode(transport covert.Transport, secretKey []byte) (*ExitNode, error) {
	var cipher *covert.FrameCipher
	if len(secretKey) > 0 {
		var err error
		cipher, err = covert.NewFrameCipher(secretKey)
		if err != nil {
			return nil, err
		}
	}

	node := &ExitNode{
		transport: transport,
		cipher:    cipher,
		streams:   make(map[uint32]net.Conn),
	}

	transport.OnReceive(node.handleIncomingFrameBytes)
	return node, nil
}

func (n *ExitNode) Start(ctx context.Context) error {
	log.Printf("[ExitNode] Starting exit node using transport %s", n.transport.Name())
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
	decrypted, err := n.cipher.Decrypt(raw)
	if err != nil {
		return
	}

	frame, err := covert.DecodeFrame(decrypted)
	if err != nil {
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
		pongFrame := covert.Frame{StreamID: frame.StreamID, Cmd: covert.CmdPong}
		n.sendFrame(pongFrame)
	}
}

func (n *ExitNode) handleConnect(streamID uint32, target string) {
	dialer := net.Dialer{Timeout: 10 * time.Second}
	conn, err := dialer.Dial("tcp", target)
	if err != nil {
		log.Printf("[ExitNode] Dial %s failed: %v", target, err)
		closeFrame := covert.Frame{StreamID: streamID, Cmd: covert.CmdClose}
		n.sendFrame(closeFrame)
		return
	}

	n.mu.Lock()
	n.streams[streamID] = conn
	n.mu.Unlock()

	log.Printf("[ExitNode] Stream %d connected to %s", streamID, target)

	// Pump responses from the real website back through the covert transport
	go func() {
		defer n.closeStream(streamID)
		buf := make([]byte, 1500) // Optimal chunk size for covert channels

		for {
			nr, err := conn.Read(buf)
			if nr > 0 {
				dataFrame := covert.Frame{
					StreamID: streamID,
					Cmd:      covert.CmdData,
					Payload:  buf[:nr],
				}
				if err := n.sendFrame(dataFrame); err != nil {
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
		closeFrame := covert.Frame{StreamID: streamID, Cmd: covert.CmdClose}
		_ = n.sendFrame(closeFrame)
	}
}

func (n *ExitNode) sendFrame(f covert.Frame) error {
	raw := covert.EncodeFrame(f)
	encrypted, err := n.cipher.Encrypt(raw)
	if err != nil {
		return err
	}
	return n.transport.Send(encrypted)
}
