package cups

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"freedom-cry/internal/protocol/covert"

	"github.com/gorilla/websocket"
)

type Transport struct {
	wsURL      string
	channel    string
	conn       *websocket.Conn
	connMu     sync.Mutex
	writeQueue chan []byte

	connected atomic.Bool
	running   atomic.Bool

	receiveCb func([]byte)
	cbMu      sync.RWMutex

	stats covert.TransportStats
	start time.Time
}

func NewTransport(roomUUID string) *Transport {
	if roomUUID == "" {
		roomUUID = "freedom-cry-emergency-room"
	}
	channel := fmt.Sprintf("$shared_editor:room-%s", roomUUID)

	return &Transport{
		wsURL:      "wss://cups.online/connection/websocket",
		channel:    channel,
		writeQueue: make(chan []byte, 2048),
	}
}

func (t *Transport) Name() string {
	return "CupsOnline-CentrifugoChannel"
}

func (t *Transport) Start(ctx context.Context) error {
	t.running.Store(true)
	t.start = time.Now()

	go t.connectionLoop(ctx)
	go t.writerLoop(ctx)

	return nil
}

func (t *Transport) Stop() error {
	t.running.Store(false)
	t.connected.Store(false)

	t.connMu.Lock()
	defer t.connMu.Unlock()
	if t.conn != nil {
		_ = t.conn.Close()
	}
	return nil
}

func (t *Transport) Send(data []byte) error {
	if !t.connected.Load() {
		return fmt.Errorf("cups transport is not connected")
	}

	select {
	case t.writeQueue <- data:
		atomic.AddUint64(&t.stats.BytesSent, uint64(len(data)))
		atomic.AddUint64(&t.stats.PacketsSent, 1)
		return nil
	default:
		return fmt.Errorf("write queue is full")
	}
}

func (t *Transport) OnReceive(cb func([]byte)) {
	t.cbMu.Lock()
	defer t.cbMu.Unlock()
	t.receiveCb = cb
}

func (t *Transport) IsConnected() bool {
	return t.connected.Load()
}

func (t *Transport) Stats() covert.TransportStats {
	return covert.TransportStats{
		BytesSent:     atomic.LoadUint64(&t.stats.BytesSent),
		BytesReceived: atomic.LoadUint64(&t.stats.BytesReceived),
		PacketsSent:   atomic.LoadUint64(&t.stats.PacketsSent),
		PacketsRecv:   atomic.LoadUint64(&t.stats.PacketsRecv),
		Connected:     t.connected.Load(),
		Uptime:        time.Since(t.start),
	}
}

func (t *Transport) connectionLoop(ctx context.Context) {
	for t.running.Load() {
		select {
		case <-ctx.Done():
			return
		default:
		}

		if err := t.connect(); err != nil {
			log.Printf("[Covert Cups] Connect error: %v, retrying in 3s...", err)
			time.Sleep(3 * time.Second)
			continue
		}

		t.readLoop()
		t.connected.Store(false)
		time.Sleep(1 * time.Second)
	}
}

func (t *Transport) connect() error {
	dialer := websocket.Dialer{HandshakeTimeout: 15 * time.Second}
	headers := http.Header{}
	headers.Set("User-Agent", "Mozilla/5.0")
	headers.Set("Origin", "https://cups.online")

	conn, _, err := dialer.Dial(t.wsURL, headers)
	if err != nil {
		return err
	}

	t.connMu.Lock()
	t.conn = conn
	t.connMu.Unlock()

	// Centrifugo connect protocol
	// Step 1: Connect command
	connectCmd := `{"id":1,"method":0,"params":{}}`
	if err := conn.WriteMessage(websocket.TextMessage, []byte(connectCmd)); err != nil {
		conn.Close()
		return err
	}

	// Step 2: Subscribe to channel
	subCmd := fmt.Sprintf(`{"id":2,"method":1,"params":{"channel":"%s"}}`, t.channel)
	if err := conn.WriteMessage(websocket.TextMessage, []byte(subCmd)); err != nil {
		conn.Close()
		return err
	}

	t.connected.Store(true)
	log.Printf("[Covert Cups] Successfully subscribed to Centrifugo channel %s", t.channel)
	return nil
}

func (t *Transport) readLoop() {
	for t.running.Load() {
		t.connMu.Lock()
		conn := t.conn
		t.connMu.Unlock()

		if conn == nil {
			return
		}

		_, msg, err := conn.ReadMessage()
		if err != nil {
			return
		}

		// Parse Centrifugo publication
		var resp struct {
			Result struct {
				Type int `json:"type"`
				Data struct {
					Data struct {
						Payload string `json:"payload"`
					} `json:"data"`
				} `json:"data"`
			} `json:"result"`
		}

		if err := json.Unmarshal(msg, &resp); err == nil && resp.Result.Data.Data.Payload != "" {
			payload, err := base64.StdEncoding.DecodeString(resp.Result.Data.Data.Payload)
			if err == nil && len(payload) > 0 {
				atomic.AddUint64(&t.stats.BytesReceived, uint64(len(payload)))
				atomic.AddUint64(&t.stats.PacketsRecv, 1)

				t.cbMu.RLock()
				cb := t.receiveCb
				t.cbMu.RUnlock()

				if cb != nil {
					cb(payload)
				}
			}
		}
	}
}

func (t *Transport) writerLoop(ctx context.Context) {
	msgID := int64(10)

	for t.running.Load() {
		select {
		case <-ctx.Done():
			return

		case packet := <-t.writeQueue:
			if !t.connected.Load() {
				continue
			}

			encoded := base64.StdEncoding.EncodeToString(packet)
			msgID++
			publishCmd := fmt.Sprintf(
				`{"id":%d,"method":3,"params":{"channel":"%s","data":{"type":"editor_data","payload":"%s"}}}`,
				msgID, t.channel, encoded,
			)

			t.connMu.Lock()
			if t.conn != nil {
				_ = t.conn.WriteMessage(websocket.TextMessage, []byte(publishCmd))
			}
			t.connMu.Unlock()
		}
	}
}
