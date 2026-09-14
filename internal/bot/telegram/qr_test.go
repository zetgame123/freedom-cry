package telegram

import (
	"bytes"
	"image/png"
	"testing"
)

func TestGenerateQRCodePNG(t *testing.T) {
	testData := "vless://00000000-0000-0000-0000-000000000000@1.2.3.4:443?security=reality"
	pngBytes, err := GenerateQRCodePNG(testData, 256)
	if err != nil {
		t.Fatalf("unexpected error generating QR: %v", err)
	}

	if len(pngBytes) == 0 {
		t.Fatal("expected non-empty png bytes")
	}

	// Verify valid PNG header and decoding
	img, err := png.Decode(bytes.NewReader(pngBytes))
	if err != nil {
		t.Fatalf("failed to decode generated PNG: %v", err)
	}

	bounds := img.Bounds()
	if bounds.Dx() != 256 || bounds.Dy() != 256 {
		t.Errorf("expected bounds 256x256, got %dx%d", bounds.Dx(), bounds.Dy())
	}
}
