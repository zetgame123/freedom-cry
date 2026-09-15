package main

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"freedom-cry/internal/bot/telegram"
)

type ClientBotApp struct {
	bot          *telegram.Bot
	apiBase      string
	publicBase   string
	sessionsPath string
	httpClient   *http.Client
	mu           sync.RWMutex
	bootSecret   []byte
	// Ephemeral session cache: HMAC-SHA256(bootSecret, chatID) -> UserSession
	sessions map[string]*UserSession
}

type UserSession struct {
	AccountNumber  string    `json:"account_number"`
	AuthToken      string    `json:"auth_token"`
	SubToken       string    `json:"sub_token"`
	SubscriptionID string    `json:"subscription_id,omitempty"`
	PlanName       string    `json:"plan_name,omitempty"`
	ExpiresAt      string    `json:"expires_at,omitempty"`
	LastActive     time.Time `json:"last_active"`
}

func main() {
	token := flag.String("token", os.Getenv("TELEGRAM_BOT_TOKEN"), "Telegram Bot API Token")
	apiURL := flag.String("api", os.Getenv("API_BASE_URL"), "Freedom Cry API Base URL (internal)")
	publicURL := flag.String("public-url", os.Getenv("PUBLIC_BASE_URL"), "Freedom Cry Public Base URL (for client configs)")
	sessionsPath := flag.String("sessions", os.Getenv("SESSIONS_PATH"), "Path to persistent bot sessions file (default: empty for ephemeral in-memory sessions)")
	flag.Parse()

	if *token == "" {
		log.Println("[ClientBot] Warning: TELEGRAM_BOT_TOKEN not provided. Using demo mode.")
		*token = "demo-token"
	}
	if *apiURL == "" {
		*apiURL = "http://127.0.0.1:8080"
	}
	if *publicURL == "" {
		*publicURL = *apiURL
	}

	sessionsMode := "ephemeral in-memory (Zero-Knowledge: no disk writes, HMAC-keyed)"
	if *sessionsPath != "" {
		sessionsMode = *sessionsPath
	}

	bootSecret := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, bootSecret); err != nil {
		log.Fatalf("Failed to generate ephemeral boot secret: %v", err)
	}

	log.Println("==================================================")
	log.Println("    🤖 Freedom Cry Client Telegram Bot Started    ")
	log.Println("==================================================")
	log.Printf("Target API: %s | Public URL: %s | Sessions: %s", *apiURL, *publicURL, sessionsMode)

	app := &ClientBotApp{
		bot:          telegram.NewBot(*token),
		apiBase:      *apiURL,
		publicBase:   *publicURL,
		sessionsPath: *sessionsPath,
		httpClient:   &http.Client{Timeout: 10 * time.Second},
		bootSecret:   bootSecret,
		sessions:     make(map[string]*UserSession),
	}

	app.loadSessions()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigChan
		log.Println("[ClientBot] Shutting down...")
		cancel()
	}()

	// Periodic janitor for expired session eviction (30-minute inactivity TTL)
	go func() {
		ticker := time.NewTicker(5 * time.Minute)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				app.sweepExpiredSessions()
			}
		}
	}()

	// Start update listener
	go func() {
		err := app.bot.PollUpdates(ctx, app.handleUpdate)
		if err != nil && ctx.Err() == nil {
			log.Printf("[ClientBot] Poller terminated: %v", err)
		}
	}()

	<-ctx.Done()
	log.Println("[ClientBot] Exited cleanly.")
}

func (app *ClientBotApp) sessionKey(chatID int64) string {
	mac := hmac.New(sha256.New, app.bootSecret)
	var buf [8]byte
	binary.BigEndian.PutUint64(buf[:], uint64(chatID))
	mac.Write(buf[:])
	return hex.EncodeToString(mac.Sum(nil))
}

func (app *ClientBotApp) getSession(chatID int64) *UserSession {
	key := app.sessionKey(chatID)
	app.mu.Lock()
	defer app.mu.Unlock()

	sess, exists := app.sessions[key]
	if !exists || sess == nil {
		return nil
	}
	if time.Since(sess.LastActive) > 30*time.Minute {
		delete(app.sessions, key)
		app.saveSessionsLocked()
		return nil
	}
	sess.LastActive = time.Now()
	return sess
}

func (app *ClientBotApp) setSession(chatID int64, sess *UserSession) {
	key := app.sessionKey(chatID)
	app.mu.Lock()
	defer app.mu.Unlock()

	if sess != nil {
		sess.LastActive = time.Now()
	}
	app.sessions[key] = sess
	app.saveSessionsLocked()
}

func (app *ClientBotApp) deleteSession(chatID int64) {
	key := app.sessionKey(chatID)
	app.mu.Lock()
	defer app.mu.Unlock()

	delete(app.sessions, key)
	app.saveSessionsLocked()
}

func (app *ClientBotApp) sweepExpiredSessions() {
	app.mu.Lock()
	defer app.mu.Unlock()

	now := time.Now()
	for k, sess := range app.sessions {
		if sess == nil || now.Sub(sess.LastActive) > 30*time.Minute {
			delete(app.sessions, k)
		}
	}
	app.saveSessionsLocked()
}

func (app *ClientBotApp) loadSessions() {
	if app.sessionsPath == "" {
		return
	}
	data, err := os.ReadFile(app.sessionsPath)
	if err != nil {
		return
	}
	app.mu.Lock()
	defer app.mu.Unlock()
	if err := json.Unmarshal(data, &app.sessions); err == nil {
		now := time.Now()
		for _, s := range app.sessions {
			if s != nil && s.LastActive.IsZero() {
				s.LastActive = now
			}
		}
		log.Printf("[ClientBot] Loaded %d active sessions from %s", len(app.sessions), app.sessionsPath)
	}
}

func (app *ClientBotApp) saveSessionsLocked() {
	if app.sessionsPath == "" {
		return
	}
	data, err := json.MarshalIndent(app.sessions, "", "  ")
	if err == nil {
		_ = os.WriteFile(app.sessionsPath, data, 0600)
	}
}

func (app *ClientBotApp) handleUpdate(u telegram.Update) {
	if u.Message != nil && u.Message.Text != "" {
		app.handleMessage(u.Message)
		return
	}
	if u.CallbackQuery != nil {
		app.handleCallback(u.CallbackQuery)
		return
	}
}

func (app *ClientBotApp) handleMessage(msg *telegram.Message) {
	chatID := msg.Chat.ID
	text := strings.TrimSpace(msg.Text)

	// Check if user already has an active session with a valid sub token
	sess := app.getSession(chatID)
	hasSession := (sess != nil && sess.SubToken != "")

	// 1. Deep link support: /start <invite_code>
	if strings.HasPrefix(text, "/start ") {
		arg := strings.TrimSpace(strings.TrimPrefix(text, "/start "))
		if arg != "" {
			app.processInviteCode(chatID, arg)
			return
		}
	}

	// 2. Account restore: /login <account_number>
	if strings.HasPrefix(text, "/login") {
		accNum := strings.TrimSpace(strings.TrimPrefix(text, "/login"))
		if accNum == "" {
			_, _ = app.bot.SendMessage(chatID, "ℹ️ <b>Использование команды:</b>\n<code>/login XXXX-XXXX-XXXX-XXXX</code>", nil)
			return
		}
		app.processLogin(chatID, accNum)
		return
	}

	// 3. User is NOT authenticated yet
	if !hasSession || sess == nil || sess.SubToken == "" {
		switch text {
		case "/start":
			app.sendInviteGate(chatID)
		case "/help":
			app.sendUnauthHelp(chatID)
		default:
			// If message looks like an account number
			cleaned := strings.ReplaceAll(strings.ReplaceAll(text, "-", ""), " ", "")
			if len(cleaned) == 16 && isDigitsOnly(cleaned) {
				app.processLogin(chatID, text)
				return
			}
			// Otherwise treat as invite code
			app.processInviteCode(chatID, text)
		}
		return
	}

	// 4. User IS authenticated
	switch text {
	case "/start", "/menu":
		app.sendMainMenu(chatID, fmt.Sprintf("🦅 <b>Главное меню Freedom Cry</b>\nАккаунт: <code>%s</code>", sess.AccountNumber))
	case "/config", "/qr", "/vless":
		app.sendConfigQR(chatID, sess)
	case "/sub", "/subscription":
		app.sendSubLink(chatID, sess)
	case "/singbox":
		app.sendSingboxConfig(chatID, sess)
	case "/awg", "/amnezia", "/wireguard":
		app.sendAmneziaConfig(chatID, sess)
	case "/status", "/account":
		app.sendAccountStatus(chatID, sess)
	case "/logout":
		app.deleteSession(chatID)
		_, _ = app.bot.SendMessage(chatID, "👋 Вы вышли из аккаунта. Чтобы войти снова, введите <code>/login НОМЕР-АККАУНТА</code> или активируйте новый инвайт-код.", nil)
	case "/help":
		app.sendHelp(chatID)
	default:
		app.sendMainMenu(chatID, "Выберите действие из меню ниже:")
	}
}

func (app *ClientBotApp) sendHelp(chatID int64) {
	text := `ℹ️ <b>Freedom Cry — Доступные команды:</b>

• /menu или /start — Главное меню и конфиги
• /status или /account — Проверить срок действия подписки
• /login НОМЕР-АККАУНТА — Вход по номеру аккаунта
• /logout — Выйти из текущего аккаунта`
	_, _ = app.bot.SendMessage(chatID, text, nil)
}

func isDigitsOnly(s string) bool {
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

func (app *ClientBotApp) sendInviteGate(chatID int64) {
	text := `🔒 <b>Freedom Cry — Доступ ограничен</b>

Сервис работает в режиме приватной сети по приглашениям.

🔑 Отправьте ваш <b>инвайт-код</b> ответным сообщением для активации подписки.

<i>Если у вас уже есть зарегистрированный аккаунт:</i>
<code>/login ВАШ-НОМЕР-АККАУНТА</code>`

	_, _ = app.bot.SendMessage(chatID, text, nil)
}

func (app *ClientBotApp) sendUnauthHelp(chatID int64) {
	text := `ℹ️ <b>Freedom Cry — Справка</b>

Freedom Cry обеспечивает защищенный доступ в интернет без цензуры с технологиями VLESS Reality и AmneziaWG.

• Для первого входа требуется <b>инвайт-код</b> от администратора.
• Если у вас уже есть номер аккаунта, используйте команду:
  <code>/login XXXX-XXXX-XXXX-XXXX</code>`

	_, _ = app.bot.SendMessage(chatID, text, nil)
}

func (app *ClientBotApp) processInviteCode(chatID int64, code string) {
	_, _ = app.bot.SendMessage(chatID, "⏳ Проверка инвайт-кода и выпуск ключей шифрования...", nil)

	sess, err := app.registerWithInvite(code)
	if err != nil {
		msg := fmt.Sprintf("❌ <b>Не удалось активировать инвайт-код:</b>\n%s\n\nПроверьте код или запросите новый у администратора.", err.Error())
		_, _ = app.bot.SendMessage(chatID, msg, nil)
		return
	}

	app.setSession(chatID, sess)

	welcome := fmt.Sprintf(`🎉 <b>Инвайт-код успешно активирован!</b>
 
Добро пожаловать в Freedom Cry!

Ваш анонимный номер аккаунта:
<code>%s</code>

Тариф: <b>%s</b>
Срок действия: <b>до %s</b>

🔒 <b>Zero-Knowledge Privacy:</b>
Мы не сохраняем ваши персональные данные или Telegram username в базе данных туннелей. Сохраните номер аккаунта для восстановления доступа на других устройствах.`, sess.AccountNumber, sess.PlanName, sess.ExpiresAt)

	app.sendMainMenu(chatID, welcome)
}

func (app *ClientBotApp) processLogin(chatID int64, rawAccount string) {
	_, _ = app.bot.SendMessage(chatID, "⏳ Проверка аккаунта...", nil)

	sess, err := app.loginWithAccountNumber(rawAccount)
	if err != nil {
		_, _ = app.bot.SendMessage(chatID, fmt.Sprintf("❌ <b>Ошибка входа:</b> %s", err.Error()), nil)
		return
	}

	app.setSession(chatID, sess)

	msg := fmt.Sprintf(`✅ <b>Вход выполнен успешно!</b>

С возвращением в Freedom Cry!
Аккаунт: <code>%s</code>
Тариф: <b>%s</b>
Действует до: <b>%s</b>`, sess.AccountNumber, sess.PlanName, sess.ExpiresAt)

	app.sendMainMenu(chatID, msg)
}

func (app *ClientBotApp) registerWithInvite(inviteCode string) (*UserSession, error) {
	url := fmt.Sprintf("%s/api/v1/auth/invite/register", app.apiBase)
	reqBody, _ := json.Marshal(map[string]string{
		"invite_code": strings.TrimSpace(inviteCode),
	})

	resp, err := app.httpClient.Post(url, "application/json", bytes.NewReader(reqBody))
	if err != nil {
		return nil, fmt.Errorf("ошибка соединения с сервером: %w", err)
	}
	defer resp.Body.Close()

	bodyBytes, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusCreated {
		var errRes struct {
			Error string `json:"error"`
		}
		_ = json.Unmarshal(bodyBytes, &errRes)
		if errRes.Error != "" {
			return nil, errors.New(errRes.Error)
		}
		return nil, fmt.Errorf("код ответа сервера: %d", resp.StatusCode)
	}

	var res struct {
		AccountNumber     string `json:"account_number"`
		Token             string `json:"token"`
		SubscriptionToken string `json:"subscription_token"`
		PlanName          string `json:"plan_name"`
		ExpiresAt         string `json:"expires_at"`
	}
	if err := json.Unmarshal(bodyBytes, &res); err != nil {
		return nil, err
	}

	sess := &UserSession{
		AccountNumber: res.AccountNumber,
		AuthToken:     res.Token,
		SubToken:      res.SubscriptionToken,
		PlanName:      res.PlanName,
		ExpiresAt:     res.ExpiresAt,
	}

	sess.SubscriptionID = app.fetchActiveSubscriptionID(res.Token)
	return sess, nil
}

func (app *ClientBotApp) loginWithAccountNumber(accountNumber string) (*UserSession, error) {
	url := fmt.Sprintf("%s/api/v1/auth/account/login", app.apiBase)
	reqBody, _ := json.Marshal(map[string]string{
		"account_number": strings.TrimSpace(accountNumber),
	})

	resp, err := app.httpClient.Post(url, "application/json", bytes.NewReader(reqBody))
	if err != nil {
		return nil, fmt.Errorf("ошибка соединения с сервером: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, errors.New("аккаунт не найден или деактивирован")
	}

	var authRes struct {
		Token string `json:"token"`
		User  struct {
			AccountNumber string `json:"account_number"`
		} `json:"user"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&authRes); err != nil {
		return nil, err
	}

	// Fetch user's subscriptions
	subURL := fmt.Sprintf("%s/api/v1/user/subscriptions", app.apiBase)
	req, _ := http.NewRequest("GET", subURL, nil)
	req.Header.Set("Authorization", "Bearer "+authRes.Token)

	subResp, err := app.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer subResp.Body.Close()

	var subData struct {
		Subscriptions []struct {
			ID              string `json:"id"`
			PlanName        string `json:"plan_name"`
			Status          string `json:"status"`
			ExpiresAt       string `json:"expires_at"`
			SubscriptionURL string `json:"subscription_url"`
		} `json:"subscriptions"`
	}
	if err := json.NewDecoder(subResp.Body).Decode(&subData); err != nil {
		return nil, err
	}

	if len(subData.Subscriptions) == 0 {
		return nil, errors.New("у данного аккаунта нет активных подписок")
	}

	activeSub := subData.Subscriptions[0]
	parts := strings.Split(activeSub.SubscriptionURL, "/sub/")
	subToken := ""
	if len(parts) > 1 {
		subToken = parts[1]
	}

	sess := &UserSession{
		AccountNumber:  authRes.User.AccountNumber,
		AuthToken:      authRes.Token,
		SubToken:       subToken,
		SubscriptionID: activeSub.ID,
		PlanName:       activeSub.PlanName,
		ExpiresAt:      activeSub.ExpiresAt,
	}

	return sess, nil
}

func (app *ClientBotApp) fetchActiveSubscriptionID(token string) string {
	url := fmt.Sprintf("%s/api/v1/user/subscriptions", app.apiBase)
	req, _ := http.NewRequest("GET", url, nil)
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := app.httpClient.Do(req)
	if err != nil || resp.StatusCode != http.StatusOK {
		return ""
	}
	defer resp.Body.Close()

	var subData struct {
		Subscriptions []struct {
			ID string `json:"id"`
		} `json:"subscriptions"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&subData); err == nil && len(subData.Subscriptions) > 0 {
		return subData.Subscriptions[0].ID
	}
	return ""
}

func (app *ClientBotApp) sendMainMenu(chatID int64, text string) {
	keyboard := telegram.InlineKeyboardMarkup{
		InlineKeyboard: [][]telegram.InlineKeyboardButton{
			{
				{Text: "⚡ VLESS ключ / QR", CallbackData: "cmd:qr"},
				{Text: "📋 Ссылка подписки", CallbackData: "cmd:sublink"},
			},
			{
				{Text: "📱 Sing-box JSON", CallbackData: "cmd:singbox"},
				{Text: "🛡️ AmneziaWG (.conf)", CallbackData: "cmd:awg"},
			},
			{
				{Text: "🌐 Протоколы", CallbackData: "cmd:proto"},
				{Text: "ℹ️ Мой аккаунт", CallbackData: "cmd:account"},
			},
			{
				{Text: "🔄 Ротация ключей", CallbackData: "cmd:rotate"},
				{Text: "📲 Инструкция", CallbackData: "cmd:guide"},
			},
		},
	}
	_, err := app.bot.SendMessage(chatID, text, keyboard)
	if err != nil {
		log.Printf("[ClientBot] sendMainMenu error: %v", err)
	}
}

func (app *ClientBotApp) handleCallback(cb *telegram.CallbackQuery) {
	_ = app.bot.AnswerCallback(cb.ID, "")
	chatID := cb.From.ID

	sess := app.getSession(chatID)

	if sess == nil || sess.SubToken == "" {
		app.sendInviteGate(chatID)
		return
	}

	switch cb.Data {
	case "cmd:menu":
		app.sendMainMenu(chatID, fmt.Sprintf("🦅 <b>Главное меню Freedom Cry</b>\nАккаунт: <code>%s</code>", sess.AccountNumber))
	case "cmd:qr":
		app.sendConfigQR(chatID, sess)
	case "cmd:sublink":
		app.sendSubLink(chatID, sess)
	case "cmd:singbox":
		app.sendSingboxConfig(chatID, sess)
	case "cmd:awg":
		app.sendAmneziaConfig(chatID, sess)
	case "cmd:proto":
		app.sendProtocolInfo(chatID)
	case "cmd:rotate":
		app.rotateKey(chatID, sess)
	case "cmd:account":
		app.sendAccountStatus(chatID, sess)
	case "cmd:guide":
		app.sendGuides(chatID)
	}
}

func (app *ClientBotApp) sendConfigQR(chatID int64, sess *UserSession) {
	subURL := fmt.Sprintf("%s/sub/%s", app.publicBase, sess.SubToken)

	// Fetch plain VLESS reality link from local API
	vlessURL := fmt.Sprintf("%s/sub/%s/vless", app.apiBase, sess.SubToken)
	vlessResp, err := app.httpClient.Get(vlessURL)
	var vlessLink string
	if err == nil && vlessResp.StatusCode == http.StatusOK {
		defer vlessResp.Body.Close()
		b, _ := io.ReadAll(vlessResp.Body)
		vlessLink = strings.TrimSpace(string(b))
	}

	// For QR code: encode VLESS link so apps can directly import on scan
	qrData := vlessLink
	if qrData == "" {
		qrData = subURL
	}

	qrBytes, err := telegram.GenerateQRCodePNG(qrData, 320)
	if err != nil {
		log.Printf("[ClientBot] QR generation error: %v", err)
		_, _ = app.bot.SendMessage(chatID, "❌ Ошибка генерации QR-кода", nil)
		return
	}

	caption := fmt.Sprintf(`⚡ <b>Ваш VLESS-Reality ключ подключения:</b>

<code>%s</code>
<i>(Нажмите на ключ выше, чтобы скопировать в буфер)</i>

📋 <b>Ссылка на автоподписку:</b>
<code>%s</code>

📱 <b>QR-код</b> выше содержит ключ подключения. Отсканируйте его в приложении (v2rayNG, Streisand, NekoBox, Sing-box).`, vlessLink, subURL)

	keyboard := telegram.InlineKeyboardMarkup{
		InlineKeyboard: [][]telegram.InlineKeyboardButton{
			{
				{Text: "📋 Ссылка на подписку", CallbackData: "cmd:sublink"},
				{Text: "📱 Sing-box JSON", CallbackData: "cmd:singbox"},
			},
			{
				{Text: "🛡️ AmneziaWG (.conf)", CallbackData: "cmd:awg"},
				{Text: "🔄 Ротация ключей", CallbackData: "cmd:rotate"},
			},
			{
				{Text: "⬅️ Главное меню", CallbackData: "cmd:menu"},
			},
		},
	}

	if err := app.bot.SendPhotoBytes(chatID, "freedomcry_qr.png", qrBytes, caption, keyboard); err != nil {
		log.Printf("[ClientBot] SendPhotoBytes failed: %v. Fallback to SendMessage", err)
		_, _ = app.bot.SendMessage(chatID, caption, keyboard)
	}
}

func (app *ClientBotApp) sendSubLink(chatID int64, sess *UserSession) {
	subURL := fmt.Sprintf("%s/sub/%s", app.publicBase, sess.SubToken)
	text := fmt.Sprintf(`📋 <b>Ваша универсальная ссылка на подписку:</b>

<code>%s</code>
<i>(Нажмите на ссылку выше, чтобы скопировать)</i>

Импортируйте её в любой клиент: <b>v2rayNG</b>, <b>Sing-box</b>, <b>NekoBox</b>, <b>Streisand</b>, <b>Clash</b> или <b>Foxtray</b>.
Список серверов обновляется автоматически при смене IP или блокировках.`, subURL)

	keyboard := telegram.InlineKeyboardMarkup{
		InlineKeyboard: [][]telegram.InlineKeyboardButton{
			{
				{Text: "🌐 Открыть ссылку на подписку", URL: subURL},
			},
			{
				{Text: "⚡ VLESS ключ / QR", CallbackData: "cmd:qr"},
				{Text: "📱 Sing-box JSON", CallbackData: "cmd:singbox"},
			},
			{
				{Text: "⬅️ Главное меню", CallbackData: "cmd:menu"},
			},
		},
	}

	_, err := app.bot.SendMessage(chatID, text, keyboard)
	if err != nil {
		log.Printf("[ClientBot] sendSubLink error: %v", err)
	}
}

func (app *ClientBotApp) sendSingboxConfig(chatID int64, sess *UserSession) {
	singboxURL := fmt.Sprintf("%s/sub/%s/singbox", app.publicBase, sess.SubToken)
	text := fmt.Sprintf(`📱 <b>Конфигурация Sing-box (Universal JSON Profile)</b>

Продвинутый профиль со всеми протоколами:
• Автоматический выбор быстрейшего узла (urltest)
• Split-routing: российские сайты (.ru, Госуслуги, банки) идут напрямую
• Безопасный DoH DNS через туннель без утечек
• Поддержка VLESS-Reality + Hysteria 2

📥 <b>Ссылка на конфиг:</b>
<code>%s</code>

<i>Скопируйте ссылку и добавьте как Remote Profile в приложении Sing-box.</i>`, singboxURL)

	keyboard := telegram.InlineKeyboardMarkup{
		InlineKeyboard: [][]telegram.InlineKeyboardButton{
			{
				{Text: "🌐 Открыть ссылку на профиль", URL: singboxURL},
			},
			{
				{Text: "⚡ VLESS ключ / QR", CallbackData: "cmd:qr"},
				{Text: "🛡️ AmneziaWG (.conf)", CallbackData: "cmd:awg"},
			},
			{
				{Text: "⬅️ Главное меню", CallbackData: "cmd:menu"},
			},
		},
	}

	_, err := app.bot.SendMessage(chatID, text, keyboard)
	if err != nil {
		log.Printf("[ClientBot] sendSingboxConfig error: %v", err)
	}
}

func (app *ClientBotApp) sendAmneziaConfig(chatID int64, sess *UserSession) {
	url := fmt.Sprintf("%s/sub/%s/info", app.apiBase, sess.SubToken)
	resp, err := app.httpClient.Get(url)
	if err != nil || resp.StatusCode != http.StatusOK {
		_, _ = app.bot.SendMessage(chatID, "❌ Не удалось получить конфигурацию AmneziaWG.", nil)
		return
	}
	defer resp.Body.Close()

	var info struct {
		Nodes []struct {
			NodeID     string `json:"node_id"`
			NodeName   string `json:"node_name"`
			AwgConfURL string `json:"awg_conf_url"`
		} `json:"nodes"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&info); err != nil || len(info.Nodes) == 0 {
		_, _ = app.bot.SendMessage(chatID, "❌ Активные серверы с поддержкой AmneziaWG не найдены.", nil)
		return
	}

	node := info.Nodes[0]
	confResp, err := app.httpClient.Get(fmt.Sprintf("%s/sub/%s/awg/%s", app.apiBase, sess.SubToken, node.NodeID))
	if err != nil || confResp.StatusCode != http.StatusOK {
		_, _ = app.bot.SendMessage(chatID, "❌ Не удалось загрузить .conf файл с сервера.", nil)
		return
	}
	defer confResp.Body.Close()
	confBytes, _ := io.ReadAll(confResp.Body)
	confText := strings.TrimSpace(string(confBytes))

	publicConfURL := fmt.Sprintf("%s/sub/%s/awg/%s", app.publicBase, sess.SubToken, node.NodeID)

	text := fmt.Sprintf(`🛡️ <b>Конфигурация AmneziaWG (%s):</b>

<code>%s</code>
<i>(Нажмите на конфигурацию выше, чтобы скопировать)</i>

📥 <b>Ссылка для скачивания файла:</b>
<code>%s</code>

📲 <b>Как подключить:</b>
1. Установите <b>AmneziaWG</b> или <b>AmneziaVPN</b>.
2. Создайте файл <code>freedomcry.conf</code> или вставьте текст через буфер обмена.`, node.NodeName, confText, publicConfURL)

	keyboard := telegram.InlineKeyboardMarkup{
		InlineKeyboard: [][]telegram.InlineKeyboardButton{
			{
				{Text: "🌐 Скачать .conf файл", URL: publicConfURL},
			},
			{
				{Text: "⚡ VLESS ключ / QR", CallbackData: "cmd:qr"},
				{Text: "📱 Sing-box JSON", CallbackData: "cmd:singbox"},
			},
			{
				{Text: "⬅️ Главное меню", CallbackData: "cmd:menu"},
			},
		},
	}

	_, err = app.bot.SendMessage(chatID, text, keyboard)
	if err != nil {
		log.Printf("[ClientBot] sendAmneziaConfig error: %v", err)
	}
}

func (app *ClientBotApp) sendProtocolInfo(chatID int64) {
	text := `🌐 <b>Поддерживаемые протоколы Freedom Cry:</b>

1. <b>VLESS + XTLS-Reality:</b>
   • Маскировка под TLS 1.3 трафик доверенных сайтов (Google, Cloudflare)
   • Пробивает активный DPI ТСПУ без снижения скорости.

2. <b>AmneziaWG (AWG):</b>
   • WireGuard с рандомизацией заголовков пакетов (Jc/Jmin/Jmax, S1/S2, H1..H4)
   • Не детектируется сигнатурными детекторами WireGuard.

3. <b>Hysteria 2 (QUIC):</b>
   • UDP транспорт с протоколом контроля перегрузок Brutal
   • Максимальная скорость на нестабильных и перегруженных каналах.`

	_, _ = app.bot.SendMessage(chatID, text, nil)
}

func (app *ClientBotApp) sendAccountStatus(chatID int64, sess *UserSession) {
	plan := sess.PlanName
	if plan == "" {
		plan = "Freedom Starter"
	}
	expires := sess.ExpiresAt
	if expires == "" {
		expires = "Активна"
	}

	text := fmt.Sprintf(`ℹ️ <b>Информация об аккаунте:</b>

• Номер аккаунта: <code>%s</code>
• Тарифный план: <b>%s</b>
• Статус: 🟢 <b>Активен</b>
• Срок действия: <b>до %s</b>

🔒 Аккаунт полностью анонимен. Для входа на другом устройстве используйте <code>/login %s</code>.`, sess.AccountNumber, plan, expires, sess.AccountNumber)

	_, _ = app.bot.SendMessage(chatID, text, nil)
}

func (app *ClientBotApp) rotateKey(chatID int64, sess *UserSession) {
	if sess.SubscriptionID == "" || sess.AuthToken == "" {
		_, _ = app.bot.SendMessage(chatID, "❌ Не удалось выполнить ротацию: данные подписки отсутствуют.", nil)
		return
	}

	url := fmt.Sprintf("%s/api/v1/user/subscriptions/%s/rotate", app.apiBase, sess.SubscriptionID)
	req, _ := http.NewRequest("POST", url, nil)
	req.Header.Set("Authorization", "Bearer "+sess.AuthToken)

	resp, err := app.httpClient.Do(req)
	if err != nil || (resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated) {
		_, _ = app.bot.SendMessage(chatID, "❌ Ошибка при запросе ротации ключей к серверу.", nil)
		return
	}
	defer resp.Body.Close()

	var res struct {
		SubscriptionURL string `json:"subscription_url"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&res); err == nil && res.SubscriptionURL != "" {
		parts := strings.Split(res.SubscriptionURL, "/sub/")
		if len(parts) > 1 {
			sess.SubToken = parts[1]
			app.setSession(chatID, sess)
		}
	}

	text := `🔄 <b>Ключи успешно обновлены!</b>

Ваш токен подписки перевыпущен.
Старый ключ будет активен еще 1 час для плавного переключения без обрыва текущей сессии (Zero-Downtime Grace Period).

Используйте обновленную ссылку на подписку или QR-код из главного меню.`

	_, _ = app.bot.SendMessage(chatID, text, nil)
}

func (app *ClientBotApp) sendGuides(chatID int64) {
	text := `📲 <b>Инструкция по настройке:</b>

<b>iOS:</b>
1. Установите <b>Streisand</b>, <b>Foxtray</b> или <b>AmneziaVPN</b> из App Store.
2. Скопируйте ссылку на подписку или отсканируйте QR-код.

<b>Android:</b>
1. Установите <b>v2rayNG</b>, <b>NekoBox</b> или <b>AmneziaWG</b>.
2. Нажмите ➕ -> Импорт из буфера обмена / сканировать QR.

<b>Windows / Linux / macOS:</b>
Используйте официальный легковесный CLI:
<code>freedom-cry-client connect freedomcry://connect?sub=...</code>`

	_, _ = app.bot.SendMessage(chatID, text, nil)
}
