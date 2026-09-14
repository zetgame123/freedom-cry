package yandex

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"freedom-cry/internal/protocol/covert"

	"github.com/gorilla/websocket"
)

type Transport struct {
	docURL     string
	wsURL      string
	docID      string
	token      string
	userID     string
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

func NewTransport(docURL, wsURL, docID, token string) *Transport {
	randBytes := make([]byte, 4)
	_, _ = rand.Read(randBytes)
	userID := "fc-usr-" + hex.EncodeToString(randBytes)

	if wsURL == "" {
		wsURL = "wss://doc.yandex.ru/websocket"
	}

	return &Transport{
		docURL:     docURL,
		wsURL:      wsURL,
		docID:      docID,
		token:      token,
		userID:     userID,
		writeQueue: make(chan []byte, 2048),
	}
}

func (t *Transport) Name() string {
	return "YandexDocs-CovertChannel"
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
		return fmt.Errorf("yandex transport is not connected")
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
			log.Printf("[Covert Yandex] Connect error: %v, retrying in 3s...", err)
			time.Sleep(3 * time.Second)
			continue
		}

		t.readLoop()
		t.connected.Store(false)
		time.Sleep(1 * time.Second)
	}
}

func (t *Transport) connect() error {
	dialer := websocket.Dialer{
		HandshakeTimeout: 15 * time.Second,
	}

	headers := http.Header{}
	headers.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")
	headers.Set("Origin", "https://docs.yandex.ru")

	conn, _, err := dialer.Dial(t.wsURL, headers)
	if err != nil {
		return err
	}

	t.connMu.Lock()
	t.conn = conn
	t.connMu.Unlock()

	// 1. Initial Handshake / Auth token (Socket.IO packet)
	authMsg := fmt.Sprintf(`40{"token":"%s"}`, t.token)
	if err := conn.WriteMessage(websocket.TextMessage, []byte(authMsg)); err != nil {
		conn.Close()
		return err
	}

	// 2. Join document session
	authData := map[string]interface{}{
		"type":          "auth",
		"docid":         t.docID,
		"token":         t.token,
		"user":          map[string]interface{}{"id": t.userID},
		"coEditingMode": "fast",
	}
	payloadJSON, _ := json.Marshal([]interface{}{"message", authData})
	joinMsg := fmt.Sprintf("42%s", string(payloadJSON))
	if err := conn.WriteMessage(websocket.TextMessage, []byte(joinMsg)); err != nil {
		conn.Close()
		return err
	}

	t.connected.Store(true)
	log.Printf("[Covert Yandex] Successfully connected to document %s (user: %s)", t.docID, t.userID)
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

		text := string(msg)

		// Socket.IO Ping (2) -> Respond with Pong (3)
		if text == "2" {
			t.connMu.Lock()
			_ = conn.WriteMessage(websocket.TextMessage, []byte("3"))
			t.connMu.Unlock()
			continue
		}

		// Cursor payload detection
		if strings.Contains(text, `"cursor":"18;`) {
			t.extractAndDispatchPayload(text)
		}
	}
}

func (t *Transport) extractAndDispatchPayload(raw string) {
	// Look for pattern: "cursor":"18;<base64_payload>"
	idx := strings.Index(raw, `"cursor":"18;`)
	if idx == -1 {
		return
	}
	start := idx + len(`"cursor":"18;`)
	end := strings.Index(raw[start:], `"`)
	if end == -1 {
		return
	}

	encoded := raw[start : start+end]
	if encoded == "---KA---" || encoded == "" {
		return // Keep-alive or empty
	}

	data, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return
	}

	atomic.AddUint64(&t.stats.BytesReceived, uint64(len(data)))
	atomic.AddUint64(&t.stats.PacketsRecv, 1)

	t.cbMu.RLock()
	cb := t.receiveCb
	t.cbMu.RUnlock()

	if cb != nil {
		cb(data)
	}
}

func (t *Transport) writerLoop(ctx context.Context) {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	for t.running.Load() {
		select {
		case <-ctx.Done():
			return

		case packet := <-t.writeQueue:
			if !t.connected.Load() {
				continue
			}
			t.sendCursorPacket(packet)

		case <-ticker.C:
			// Send keep-alive cursor
			if t.connected.Load() {
				t.sendRawCursor("---KA---")
			}
		}
	}
}

func (t *Transport) sendCursorPacket(data []byte) {
	encoded := base64.StdEncoding.EncodeToString(data)
	t.sendRawCursor(encoded)
}

func (t *Transport) sendRawCursor(cursorVal string) {
	msg := fmt.Sprintf(`42["message",{"type":"cursor","cursor":"18;%s"}]`, cursorVal)

	t.connMu.Lock()
	defer t.connMu.Unlock()

	if t.conn != nil {
		_ = t.conn.WriteMessage(websocket.TextMessage, []byte(msg))
	}
}
