package webrtc

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"freedom-cry/internal/protocol/covert"

	"github.com/pion/webrtc/v4"
)

type Config struct {
	IsInitiator bool
	ICEServers  []string // e.g. ["stun:stun.l.google.com:19302", "stun:stun.cloudflare.com:3478"]
}

type WebRTCTransport struct {
	cfg        Config
	pc         *webrtc.PeerConnection
	dc         *webrtc.DataChannel
	mu         sync.RWMutex
	onRecv     func([]byte)
	connected  atomic.Bool
	startTime  time.Time
	bytesSent  atomic.Uint64
	bytesRecv  atomic.Uint64
	pktsSent   atomic.Uint64
	pktsRecv   atomic.Uint64
	stopChan   chan struct{}
	closeOnce  sync.Once
}

func NewTransport(cfg Config) *WebRTCTransport {
	if len(cfg.ICEServers) == 0 {
		cfg.ICEServers = []string{
			"stun:stun.l.google.com:19302",
			"stun:stun.cloudflare.com:3478",
		}
	}

	return &WebRTCTransport{
		cfg:      cfg,
		stopChan: make(chan struct{}),
	}
}

func (t *WebRTCTransport) Name() string {
	return "webrtc-datachannel"
}

func (t *WebRTCTransport) Start(ctx context.Context) error {
	var iceServers []webrtc.ICEServer
	for _, s := range t.cfg.ICEServers {
		iceServers = append(iceServers, webrtc.ICEServer{URLs: []string{s}})
	}

	pcConfig := webrtc.Configuration{
		ICEServers: iceServers,
	}

	pc, err := webrtc.NewPeerConnection(pcConfig)
	if err != nil {
		return fmt.Errorf("failed to create WebRTC PeerConnection: %w", err)
	}

	t.mu.Lock()
	t.pc = pc
	t.startTime = time.Now()
	t.mu.Unlock()

	pc.OnConnectionStateChange(func(state webrtc.PeerConnectionState) {
		if state == webrtc.PeerConnectionStateConnected {
			t.connected.Store(true)
		} else if state == webrtc.PeerConnectionStateDisconnected ||
			state == webrtc.PeerConnectionStateFailed ||
			state == webrtc.PeerConnectionStateClosed {
			t.connected.Store(false)
		}
	})

	if t.cfg.IsInitiator {
		dc, err := pc.CreateDataChannel("fc-covert-data", nil)
		if err != nil {
			return fmt.Errorf("failed to create DataChannel: %w", err)
		}
		t.bindDataChannel(dc)
	} else {
		pc.OnDataChannel(func(dc *webrtc.DataChannel) {
			t.bindDataChannel(dc)
		})
	}

	return nil
}

func (t *WebRTCTransport) bindDataChannel(dc *webrtc.DataChannel) {
	t.mu.Lock()
	t.dc = dc
	t.mu.Unlock()

	dc.OnOpen(func() {
		t.connected.Store(true)
	})

	dc.OnClose(func() {
		t.connected.Store(false)
	})

	dc.OnMessage(func(msg webrtc.DataChannelMessage) {
		t.bytesRecv.Add(uint64(len(msg.Data)))
		t.pktsRecv.Add(1)

		t.mu.RLock()
		handler := t.onRecv
		t.mu.RUnlock()

		if handler != nil && len(msg.Data) > 0 {
			handler(msg.Data)
		}
	})
}

func (t *WebRTCTransport) Send(data []byte) error {
	t.mu.RLock()
	dc := t.dc
	t.mu.RUnlock()

	if dc == nil || !t.connected.Load() {
		return errors.New("WebRTC DataChannel not connected")
	}

	if err := dc.Send(data); err != nil {
		return err
	}

	t.bytesSent.Add(uint64(len(data)))
	t.pktsSent.Add(1)
	return nil
}

func (t *WebRTCTransport) OnReceive(handler func([]byte)) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.onRecv = handler
}

func (t *WebRTCTransport) IsConnected() bool {
	return t.connected.Load()
}

func (t *WebRTCTransport) Stop() error {
	t.closeOnce.Do(func() {
		close(t.stopChan)
		t.connected.Store(false)
		t.mu.Lock()
		if t.dc != nil {
			_ = t.dc.Close()
		}
		if t.pc != nil {
			_ = t.pc.Close()
		}
		t.mu.Unlock()
	})
	return nil
}

func (t *WebRTCTransport) Stats() covert.TransportStats {
	uptime := time.Duration(0)
	if !t.startTime.IsZero() {
		uptime = time.Since(t.startTime)
	}

	return covert.TransportStats{
		BytesSent:     t.bytesSent.Load(),
		BytesReceived: t.bytesRecv.Load(),
		PacketsSent:   t.pktsSent.Load(),
		PacketsRecv:   t.pktsRecv.Load(),
		Connected:     t.connected.Load(),
		Uptime:        uptime,
	}
}

// DirectConnect establishes an in-process signaling connection between two WebRTCTransport peers for unit testing
func DirectConnect(client *WebRTCTransport, server *WebRTCTransport) error {
	client.pc.OnICECandidate(func(c *webrtc.ICECandidate) {
		if c != nil {
			_ = server.pc.AddICECandidate(c.ToJSON())
		}
	})
	server.pc.OnICECandidate(func(c *webrtc.ICECandidate) {
		if c != nil {
			_ = client.pc.AddICECandidate(c.ToJSON())
		}
	})

	offer, err := client.pc.CreateOffer(nil)
	if err != nil {
		return fmt.Errorf("client create offer failed: %w", err)
	}

	if err := client.pc.SetLocalDescription(offer); err != nil {
		return fmt.Errorf("client set local desc failed: %w", err)
	}

	if err := server.pc.SetRemoteDescription(offer); err != nil {
		return fmt.Errorf("server set remote desc failed: %w", err)
	}

	answer, err := server.pc.CreateAnswer(nil)
	if err != nil {
		return fmt.Errorf("server create answer failed: %w", err)
	}

	if err := server.pc.SetLocalDescription(answer); err != nil {
		return fmt.Errorf("server set local desc failed: %w", err)
	}

	if err := client.pc.SetRemoteDescription(answer); err != nil {
		return fmt.Errorf("client set remote desc failed: %w", err)
	}

	return nil
}
