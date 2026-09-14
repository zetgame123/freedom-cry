package middleware

import (
	"net/http"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
)

type clientLimit struct {
	count     int
	resetTime time.Time
}

// RateLimiter provides in-memory sliding-window rate limiting per IP address
type RateLimiter struct {
	mu      sync.Mutex
	limits  map[string]*clientLimit
	maxReq  int
	window  time.Duration
	stopCh  chan struct{}
}

// NewRateLimiter creates a rate limiter with a background cleaner
func NewRateLimiter(maxRequests int, window time.Duration) *RateLimiter {
	rl := &RateLimiter{
		limits: make(map[string]*clientLimit),
		maxReq: maxRequests,
		window: window,
		stopCh: make(chan struct{}),
	}

	go rl.cleanupLoop()
	return rl
}

func (rl *RateLimiter) cleanupLoop() {
	ticker := time.NewTicker(rl.window * 2)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			rl.mu.Lock()
			now := time.Now()
			for ip, entry := range rl.limits {
				if now.After(entry.resetTime) {
					delete(rl.limits, ip)
				}
			}
			rl.mu.Unlock()
		case <-rl.stopCh:
			return
		}
	}
}

// Middleware returns a Gin HandlerFunc enforcing the rate limit
func (rl *RateLimiter) Middleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		ip := c.ClientIP()
		now := time.Now()

		rl.mu.Lock()
		entry, exists := rl.limits[ip]
		if !exists || now.After(entry.resetTime) {
			rl.limits[ip] = &clientLimit{
				count:     1,
				resetTime: now.Add(rl.window),
			}
			rl.mu.Unlock()
			c.Next()
			return
		}

		entry.count++
		if entry.count > rl.maxReq {
			rl.mu.Unlock()
			c.Header("Retry-After", "60")
			c.AbortWithStatusJSON(http.StatusTooManyRequests, gin.H{
				"error": "Too many requests. Please wait before trying again.",
			})
			return
		}

		rl.mu.Unlock()
		c.Next()
	}
}
