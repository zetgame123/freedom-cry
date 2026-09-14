package yandex

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"freedom-cry/internal/protocol/covert"

	"github.com/gorilla/websocket"
)

// Config configures the Yandex Docs covert channel transport
type Config struct {
	DocURL    string // Public Yandex Document URL (e.g. https://docs.yandex.ru/docs/view?url=...)
	CookieStr string // Optional cookie string for bypass or authenticated access
	WsURL     string // Optional manual override for WebSocket URL
	DocID     string // Optional manual override for Document Key
	Token     string // Optional manual override for Session Token
}

// Transport implements covert communication tunneled through Yandex Docs collaborative editing
type Transport struct {
	cfg        Config
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

type yandexDocInfo struct {
	cookieStr   string
	token       string
	docID       string
	origin      string
	host        string
	wsURL       string
	permissions map[string]interface{}
	openCmd     map[string]interface{}
}

// NewTransport creates a new Yandex Docs covert transport
func NewTransport(cfg Config) *Transport {
	randBytes := make([]byte, 4)
	_, _ = rand.Read(randBytes)
	userID := "fc-usr-" + hex.EncodeToString(randBytes)

	return &Transport{
		cfg:        cfg,
		userID:     userID,
		writeQueue: make(chan []byte, 4096),
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
	attempt := 0
	for t.running.Load() {
		select {
		case <-ctx.Done():
			return
		default:
		}

		info, err := t.resolveDocInfo()
		if err != nil {
			log.Printf("[Covert Yandex] Failed to resolve document info: %v", err)
			attempt++
			t.backoffWait(attempt)
			continue
		}

		if err := t.connectAndServe(ctx, info); err != nil {
			log.Printf("[Covert Yandex] Connection session ended: %v", err)
		}

		t.connected.Store(false)
		attempt++
		t.backoffWait(attempt)
	}
}

func (t *Transport) resolveDocInfo() (*yandexDocInfo, error) {
	// If direct manual parameters are provided, bypass scraping
	if t.cfg.WsURL != "" && t.cfg.DocID != "" && t.cfg.Token != "" {
		host := "doc.yandex.ru"
		if parts := strings.Split(strings.TrimPrefix(t.cfg.WsURL, "wss://"), "/"); len(parts) > 0 {
			host = parts[0]
		}
		return &yandexDocInfo{
			cookieStr:   t.cfg.CookieStr,
			token:       t.cfg.Token,
			docID:       t.cfg.DocID,
			origin:      "https://" + host,
			host:        host,
			wsURL:       t.cfg.WsURL,
			permissions: map[string]interface{}{"edit": true, "download": true},
			openCmd: map[string]interface{}{
				"c":      "open",
				"id":     t.cfg.DocID,
				"userid": t.userID,
			},
		}, nil
	}

	if t.cfg.DocURL == "" {
		return nil, fmt.Errorf("either DocURL or (WsURL, DocID, Token) must be provided")
	}

	return t.fetchDocInfo(t.cfg.DocURL, t.userID, t.cfg.CookieStr)
}

func (t *Transport) fetchDocInfo(docURL, userID, cookieStr string) (*yandexDocInfo, error) {
	client := &http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 10 {
				return fmt.Errorf("stopped after 10 redirects (auth required or invalid document)")
			}
			return nil
		},
		Timeout: 15 * time.Second,
	}

	req, err := http.NewRequest("GET", docURL, nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36")
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
	req.Header.Set("Accept-Language", "ru-RU,ru;q=0.9,en-US;q=0.8,en;q=0.7")
	if cookieStr != "" {
		req.Header.Set("Cookie", cookieStr)
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	html := string(bodyBytes)

	// Collect cookies
	var cookies []string
	if cookieStr != "" {
		cookies = append(cookies, cookieStr)
	}
	for _, c := range resp.Cookies() {
		cookies = append(cookies, fmt.Sprintf("%s=%s", c.Name, c.Value))
	}
	finalCookies := strings.Join(cookies, "; ")

	if strings.Contains(html, "showcaptcha") || strings.Contains(html, "X-Yandex-Captcha") {
		return nil, fmt.Errorf("yandex requested captcha for IP. Consider setting cookie or using cups.online transport")
	}

	re := regexp.MustCompile(`<script[^>]*id="client-config"[^>]*>(.*?)</script>`)
	matches := re.FindStringSubmatch(html)
	if len(matches) < 2 {
		return nil, fmt.Errorf("client-config not found in document page (HTTP %d, final URL: %s)", resp.StatusCode, resp.Request.URL.String())
	}

	var config map[string]interface{}
	if err := json.Unmarshal([]byte(matches[1]), &config); err != nil {
		return nil, fmt.Errorf("invalid client-config JSON: %w", err)
	}

	officeAction, ok := config["officeActionData"].(map[string]interface{})
	if !ok || officeAction == nil {
		return nil, fmt.Errorf("officeActionData missing in config")
	}

	editorConfig, ok := officeAction["editor_config"].(map[string]interface{})
	if !ok || editorConfig == nil {
		return nil, fmt.Errorf("editor_config missing in config")
	}

	balancerURL, _ := officeAction["balancer_url"].(string)
	if balancerURL == "" {
		balancerURL = "https://doc-balancer.yandex.net"
	}
	host := strings.TrimPrefix(balancerURL, "https://")
	host = strings.TrimPrefix(host, "http://")
	if idx := strings.Index(host, "/"); idx != -1 {
		host = host[:idx]
	}

	token, _ := editorConfig["token"].(string)
	if token == "" {
		return nil, fmt.Errorf("editor token missing in config")
	}

	document, ok := editorConfig["document"].(map[string]interface{})
	if !ok || document == nil {
		return nil, fmt.Errorf("document metadata missing in config")
	}

	docKey, _ := document["key"].(string)
	if docKey == "" {
		return nil, fmt.Errorf("document key missing in config")
	}

	perms, _ := document["permissions"].(map[string]interface{})
	if perms == nil {
		perms = map[string]interface{}{"edit": true}
	}

	wsURL := fmt.Sprintf("wss://%s/2024.1.1-375/doc/%s/c/?EIO=4&transport=websocket", host, docKey)

	openCmd := map[string]interface{}{
		"c":      "open",
		"id":     docKey,
		"userid": userID,
		"format": document["fileType"],
		"url":    document["url"],
		"title":  document["title"],
		"lcid":   25,
	}

	return &yandexDocInfo{
		cookieStr:   finalCookies,
		token:       token,
		docID:       docKey,
		origin:      balancerURL,
		host:        host,
		wsURL:       wsURL,
		permissions: perms,
		openCmd:     openCmd,
	}, nil
}

func (t *Transport) connectAndServe(ctx context.Context, info *yandexDocInfo) error {
	dialer := websocket.Dialer{
		HandshakeTimeout: 15 * time.Second,
		NetDialContext: (&net.Dialer{
			Timeout:   10 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
	}

	headers := http.Header{}
	headers.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")
	headers.Set("Origin", info.origin)
	headers.Set("Host", info.host)
	if info.cookieStr != "" {
		headers.Set("Cookie", info.cookieStr)
	}

	conn, _, err := dialer.Dial(info.wsURL, headers)
	if err != nil {
		return fmt.Errorf("websocket dial %s failed: %w", info.wsURL, err)
	}

	t.connMu.Lock()
	t.conn = conn
	t.connMu.Unlock()

	defer func() {
		t.connMu.Lock()
		if t.conn != nil {
			_ = t.conn.Close()
			t.conn = nil
		}
		t.connMu.Unlock()
	}()

	// 1. Engine.IO v4 connect handshake
	auth1 := fmt.Sprintf(`40{"token":"%s"}`, info.token)
	if err := conn.WriteMessage(websocket.TextMessage, []byte(auth1)); err != nil {
		return err
	}

	// 2. OnlyOffice collaborative editor session join
	authData := map[string]interface{}{
		"type":              "auth",
		"docid":             info.docID,
		"token":             "fghhfgsjdgfjs",
		"user":              map[string]interface{}{"id": t.userID},
		"editorType":        0,
		"lastOtherSaveTime": -1,
		"permissions":       info.permissions,
		"openCmd":           info.openCmd,
		"coEditingMode":     "fast",
		"jwtOpen":           info.token,
	}
	payloadJSON, _ := json.Marshal([]interface{}{"message", authData})
	joinMsg := fmt.Sprintf("42%s", string(payloadJSON))
	if err := conn.WriteMessage(websocket.TextMessage, []byte(joinMsg)); err != nil {
		return err
	}

	t.connected.Store(true)
	log.Printf("[Covert Yandex] Connected successfully to doc %s (User: %s)", info.docID, t.userID)

	// Read loop
	for t.running.Load() {
		select {
		case <-ctx.Done():
			return nil
		default:
		}

		_, msg, err := conn.ReadMessage()
		if err != nil {
			return err
		}

		text := string(msg)

		// Socket.IO Ping (2) -> Respond with Pong (3)
		if text == "2" {
			t.connMu.Lock()
			_ = conn.WriteMessage(websocket.TextMessage, []byte("3"))
			t.connMu.Unlock()
			continue
		}

		// Cursor and changes payloads
		if strings.Contains(text, "cursor") || strings.Contains(text, "saveChanges") {
			t.extractAndDispatchPayload(text)
		}
	}

	return nil
}

func (t *Transport) extractAndDispatchPayload(raw string) {
	if strings.Contains(raw, "---KA---") {
		return
	}

	var base64Str string
	// Check cursor format: "cursor":"18;<base64>"
	cursorIdx := strings.Index(raw, `"cursor":"`)
	if cursorIdx != -1 {
		start := cursorIdx + len(`"cursor":"`)
		end := strings.Index(raw[start:], `"`)
		if end != -1 {
			val := raw[start : start+end]
			if semi := strings.Index(val, ";"); semi != -1 {
				base64Str = val[semi+1:]
			} else {
				base64Str = val
			}
		}
	}

	if base64Str == "" && strings.Contains(raw, `"excelAdditionalInfo":"`) {
		marker := `"excelAdditionalInfo":"`
		left := strings.Index(raw, marker) + len(marker)
		right := strings.Index(raw[left:], `"`)
		if right != -1 {
			base64Str = raw[left : left+right]
		}
	}

	if base64Str == "" || base64Str == "---KA---" {
		return
	}

	data, err := base64.StdEncoding.DecodeString(base64Str)
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
	ticker := time.NewTicker(4 * time.Second)
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

func (t *Transport) backoffWait(attempt int) {
	if attempt > 5 {
		attempt = 5
	}
	base := 1500 * (1 << uint(attempt))
	jitter, _ := rand.Int(rand.Reader, big.NewInt(1000))
	duration := time.Duration(base+int(jitter.Int64())) * time.Millisecond
	if duration > 20*time.Second {
		duration = 20 * time.Second
	}
	time.Sleep(duration)
}
