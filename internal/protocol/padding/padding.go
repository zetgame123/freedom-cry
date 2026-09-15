package padding

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"sync"
	"time"
)

var (
	ErrPayloadTooLarge = errors.New("payload exceeds maximum bucket size")
	ErrInvalidEnvelope = errors.New("malformed padded envelope")
)

// Standard DPI-evading quantization buckets (bytes)
var DefaultBuckets = []int{128, 256, 512, 1024, 1420}

// QuantizeSize calculates the target padded frame size for a given payload length.
// If the payload exceeds the largest bucket, it is padded to the next 256-byte boundary
// up to maxLimit, or left as-is if maxLimit is reached.
func QuantizeSize(payloadLen int, buckets []int, maxLimit int) int {
	overhead := 2 // 2-byte uint16 length prefix
	totalNeeded := payloadLen + overhead

	if len(buckets) == 0 {
		buckets = DefaultBuckets
	}

	for _, b := range buckets {
		if totalNeeded <= b {
			return b
		}
	}

	// For packets larger than standard buckets, round up to 256-byte blocks
	rounded := ((totalNeeded + 255) / 256) * 256
	if rounded > maxLimit && maxLimit > 0 {
		if totalNeeded > maxLimit {
			return totalNeeded
		}
		return maxLimit
	}
	return rounded
}

// EncodePadded packs a payload into a fixed-size quantized bucket with cryptographically
// secure random padding to prevent website fingerprinting and packet length analysis.
func EncodePadded(payload []byte, targetSize int) ([]byte, error) {
	if len(payload)+2 > targetSize {
		return nil, fmt.Errorf("%w: payload %d + overhead 2 > target %d", ErrPayloadTooLarge, len(payload), targetSize)
	}

	buf := make([]byte, targetSize)
	binary.BigEndian.PutUint16(buf[0:2], uint16(len(payload)))
	copy(buf[2:2+len(payload)], payload)

	padLen := targetSize - (2 + len(payload))
	if padLen > 0 {
		if _, err := rand.Read(buf[2+len(payload):]); err != nil {
			return nil, fmt.Errorf("failed to generate random padding: %w", err)
		}
	}

	return buf, nil
}

// DecodePadded extracts the original payload from a padded envelope and strips random padding.
func DecodePadded(buf []byte) ([]byte, error) {
	if len(buf) < 2 {
		return nil, ErrInvalidEnvelope
	}

	payloadLen := int(binary.BigEndian.Uint16(buf[0:2]))
	if 2+payloadLen > len(buf) {
		return nil, fmt.Errorf("%w: declared payload len %d exceeds buffer size %d", ErrInvalidEnvelope, payloadLen, len(buf))
	}

	res := make([]byte, payloadLen)
	copy(res, buf[2:2+payloadLen])
	return res, nil
}

// GenerateChaff generates a dummy/chaff payload of random bucket size filled with random bytes.
func GenerateChaff(buckets []int) ([]byte, error) {
	if len(buckets) == 0 {
		buckets = DefaultBuckets
	}

	// Pick a random bucket
	var bIdx [1]byte
	if _, err := rand.Read(bIdx[:]); err != nil {
		return nil, err
	}
	targetSize := buckets[int(bIdx[0])%len(buckets)]

	buf := make([]byte, targetSize)
	if _, err := rand.Read(buf); err != nil {
		return nil, err
	}
	return buf, nil
}

// ChaffScheduler manages background dummy packet injection with randomized jitter
// to mask flow timing, packet inter-arrival distributions, and idle connection states.
type ChaffScheduler struct {
	minInterval time.Duration
	maxInterval time.Duration
	buckets     []int
	sendFn      func(chaffPayload []byte) error
	stopCh      chan struct{}
	wg          sync.WaitGroup
	mu          sync.Mutex
	running     bool
}

func NewChaffScheduler(minInterval, maxInterval time.Duration, buckets []int, sendFn func([]byte) error) *ChaffScheduler {
	if minInterval <= 0 {
		minInterval = 1 * time.Second
	}
	if maxInterval < minInterval {
		maxInterval = minInterval + 2*time.Second
	}
	if len(buckets) == 0 {
		buckets = DefaultBuckets
	}

	return &ChaffScheduler{
		minInterval: minInterval,
		maxInterval: maxInterval,
		buckets:     buckets,
		sendFn:      sendFn,
		stopCh:      make(chan struct{}),
	}
}

func (s *ChaffScheduler) Start() {
	s.mu.Lock()
	if s.running {
		s.mu.Unlock()
		return
	}
	s.running = true
	s.stopCh = make(chan struct{})
	s.mu.Unlock()

	s.wg.Add(1)
	go s.loop()
}

func (s *ChaffScheduler) Stop() {
	s.mu.Lock()
	if !s.running {
		s.mu.Unlock()
		return
	}
	s.running = false
	close(s.stopCh)
	s.mu.Unlock()

	s.wg.Wait()
}

func (s *ChaffScheduler) loop() {
	defer s.wg.Done()

	for {
		// Calculate randomized next interval
		intervalRange := s.maxInterval - s.minInterval
		var rndByte [2]byte
		_, _ = rand.Read(rndByte[:])
		rndOffset := time.Duration(binary.BigEndian.Uint16(rndByte[:])) * time.Millisecond
		if intervalRange > 0 {
			rndOffset = rndOffset % intervalRange
		} else {
			rndOffset = 0
		}
		sleepDur := s.minInterval + rndOffset

		select {
		case <-s.stopCh:
			return
		case <-time.After(sleepDur):
			chaff, err := GenerateChaff(s.buckets)
			if err == nil && s.sendFn != nil {
				_ = s.sendFn(chaff)
			}
		}
	}
}
