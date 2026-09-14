package telegram

import (
	"fmt"

	qrcode "github.com/skip2/go-qrcode"
)

// GenerateQRCodePNG creates a PNG QR code purely in RAM without writing to disk
func GenerateQRCodePNG(content string, size int) ([]byte, error) {
	if size <= 0 {
		size = 256
	}

	pngBytes, err := qrcode.Encode(content, qrcode.Medium, size)
	if err != nil {
		return nil, fmt.Errorf("failed to encode QR code in memory: %w", err)
	}

	return pngBytes, nil
}
