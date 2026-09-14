package telegram

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"time"
)

type Bot struct {
	token      string
	apiBase    string
	httpClient *http.Client
}

type User struct {
	ID        int64  `json:"id"`
	FirstName string `json:"first_name"`
	Username  string `json:"username"`
}

type Chat struct {
	ID   int64  `json:"id"`
	Type string `json:"type"`
}

type Message struct {
	MessageID int    `json:"message_id"`
	From      *User  `json:"from"`
	Chat      Chat   `json:"chat"`
	Text      string `json:"text"`
}

type CallbackQuery struct {
	ID      string   `json:"id"`
	From    User     `json:"from"`
	Message *Message `json:"message"`
	Data    string   `json:"data"`
}

type Update struct {
	UpdateID      int            `json:"update_id"`
	Message       *Message       `json:"message"`
	CallbackQuery *CallbackQuery `json:"callback_query"`
}

type InlineKeyboardButton struct {
	Text         string `json:"text"`
	CallbackData string `json:"callback_data,omitempty"`
	URL          string `json:"url,omitempty"`
}

type InlineKeyboardMarkup struct {
	InlineKeyboard [][]InlineKeyboardButton `json:"inline_keyboard"`
}

func NewBot(token string) *Bot {
	return &Bot{
		token:   token,
		apiBase: fmt.Sprintf("https://api.telegram.org/bot%s", token),
		httpClient: &http.Client{
			Timeout: 45 * time.Second,
		},
	}
}

func (b *Bot) GetMe() (*User, error) {
	url := fmt.Sprintf("%s/getMe", b.apiBase)
	resp, err := b.httpClient.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var apiResp struct {
		OK     bool  `json:"ok"`
		Result *User `json:"result"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&apiResp); err != nil {
		return nil, err
	}
	if !apiResp.OK {
		return nil, errors.New("failed to call getMe")
	}
	return apiResp.Result, nil
}

func (b *Bot) SendMessage(chatID int64, text string, replyMarkup interface{}) (*Message, error) {
	payload := map[string]interface{}{
		"chat_id":    chatID,
		"text":       text,
		"parse_mode": "HTML",
	}
	if replyMarkup != nil {
		payload["reply_markup"] = replyMarkup
	}

	data, _ := json.Marshal(payload)
	url := fmt.Sprintf("%s/sendMessage", b.apiBase)

	resp, err := b.httpClient.Post(url, "application/json", bytes.NewReader(data))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var apiResp struct {
		OK     bool     `json:"ok"`
		Result *Message `json:"result"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&apiResp); err != nil {
		return nil, err
	}
	if !apiResp.OK {
		return nil, errors.New("telegram API rejected sendMessage")
	}
	return apiResp.Result, nil
}

// SendPhotoBytes sends in-memory PNG image bytes without writing to disk
func (b *Bot) SendPhotoBytes(chatID int64, filename string, data []byte, caption string, replyMarkup interface{}) error {
	var body bytes.Buffer
	writer := multipart.NewWriter(&body)

	_ = writer.WriteField("chat_id", fmt.Sprintf("%d", chatID))
	_ = writer.WriteField("caption", caption)
	_ = writer.WriteField("parse_mode", "HTML")

	if replyMarkup != nil {
		markupJSON, _ := json.Marshal(replyMarkup)
		_ = writer.WriteField("reply_markup", string(markupJSON))
	}

	part, err := writer.CreateFormFile("photo", filename)
	if err != nil {
		return err
	}
	if _, err := part.Write(data); err != nil {
		return err
	}
	_ = writer.Close()

	url := fmt.Sprintf("%s/sendPhoto", b.apiBase)
	req, err := http.NewRequest("POST", url, &body)
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", writer.FormDataContentType())

	resp, err := b.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("telegram sendPhoto error (%d): %s", resp.StatusCode, string(respBody))
	}
	return nil
}

func (b *Bot) AnswerCallback(queryID, text string) error {
	payload := map[string]interface{}{
		"callback_query_id": queryID,
		"text":              text,
	}
	data, _ := json.Marshal(payload)
	url := fmt.Sprintf("%s/answerCallbackQuery", b.apiBase)
	resp, err := b.httpClient.Post(url, "application/json", bytes.NewReader(data))
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	return nil
}

func (b *Bot) GetUpdates(offset, timeout int) ([]Update, error) {
	url := fmt.Sprintf("%s/getUpdates?offset=%d&timeout=%d", b.apiBase, offset, timeout)
	resp, err := b.httpClient.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var apiResp struct {
		OK     bool     `json:"ok"`
		Result []Update `json:"result"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&apiResp); err != nil {
		return nil, err
	}
	if !apiResp.OK {
		return nil, errors.New("failed to fetch updates")
	}
	return apiResp.Result, nil
}

// PollUpdates continuously long-polls Telegram updates and invokes handler
func (b *Bot) PollUpdates(ctx context.Context, handler func(Update)) error {
	offset := 0
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
			updates, err := b.GetUpdates(offset, 25)
			if err != nil {
				time.Sleep(2 * time.Second)
				continue
			}
			for _, u := range updates {
				if u.UpdateID >= offset {
					offset = u.UpdateID + 1
				}
				handler(u)
			}
		}
	}
}
