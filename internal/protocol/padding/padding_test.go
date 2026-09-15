package padding

import (
	"bytes"
	"sync/atomic"
	"testing"
	"time"
)

func TestQuantizeSize(t *testing.T) {
	buckets := []int{128, 256, 512, 1024, 1420}

	// Small payload (10 bytes + 2 overhead = 12 bytes) -> bucket 128
	if q := QuantizeSize(10, buckets, 16384); q != 128 {
		t.Fatalf("expected 128, got %d", q)
	}

	// Exact bucket fit (126 bytes + 2 overhead = 128 bytes) -> bucket 128
	if q := QuantizeSize(126, buckets, 16384); q != 128 {
		t.Fatalf("expected 128, got %d", q)
	}

	// Just over bucket 128 (127 bytes + 2 = 129) -> bucket 256
	if q := QuantizeSize(127, buckets, 16384); q != 256 {
		t.Fatalf("expected 256, got %d", q)
	}

	// Over largest bucket (1419 bytes + 2 = 1421) -> rounded to 256 block (1536)
	if q := QuantizeSize(1419, buckets, 16384); q != 1536 {
		t.Fatalf("expected 1536, got %d", q)
	}
}

func TestEncodeDecodePadded(t *testing.T) {
	original := []byte("GET /index.html HTTP/1.1\r\nHost: blocked.org\r\n\r\n")
	targetSize := QuantizeSize(len(original), DefaultBuckets, 16384)

	padded, err := EncodePadded(original, targetSize)
	if err != nil {
		t.Fatalf("EncodePadded failed: %v", err)
	}

	if len(padded) != targetSize {
		t.Fatalf("expected padded len %d, got %d", targetSize, len(padded))
	}

	// Decode
	extracted, err := DecodePadded(padded)
	if err != nil {
		t.Fatalf("DecodePadded failed: %v", err)
	}

	if !bytes.Equal(extracted, original) {
		t.Fatalf("payload mismatch: expected %q, got %q", original, extracted)
	}
}

func TestEncodePadded_Overflow(t *testing.T) {
	payload := make([]byte, 100)
	_, err := EncodePadded(payload, 50)
	if err == nil {
		t.Fatalf("expected error on target size smaller than payload")
	}
}

func TestDecodePadded_Malformed(t *testing.T) {
	// Too short
	_, err := DecodePadded([]byte{0x01})
	if err == nil {
		t.Fatalf("expected error on 1-byte buffer")
	}

	// Declared length greater than buffer
	malformed := []byte{0x00, 0x10, 0xAA} // declared 16, buffer has 3
	_, err = DecodePadded(malformed)
	if err == nil {
		t.Fatalf("expected error on declared length exceeding buffer")
	}
}

func TestGenerateChaff(t *testing.T) {
	buckets := []int{128, 256, 512}
	chaff, err := GenerateChaff(buckets)
	if err != nil {
		t.Fatalf("GenerateChaff failed: %v", err)
	}

	found := false
	for _, b := range buckets {
		if len(chaff) == b {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("chaff size %d does not match any bucket", len(chaff))
	}
}

func TestChaffScheduler(t *testing.T) {
	var chaffCount atomic.Int32

	scheduler := NewChaffScheduler(
		10*time.Millisecond,
		30*time.Millisecond,
		[]int{128},
		func(payload []byte) error {
			chaffCount.Add(1)
			return nil
		},
	)

	scheduler.Start()
	time.Sleep(100 * time.Millisecond)
	scheduler.Stop()

	count := chaffCount.Load()
	if count < 2 {
		t.Fatalf("expected at least 2 chaff packets generated, got %d", count)
	}
}
