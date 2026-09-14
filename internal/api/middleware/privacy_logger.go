package middleware

import (
	"fmt"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
)

// PrivacyLogger returns a Gin middleware that logs HTTP requests while strictly protecting
// user privacy:
// 1. Redacts secret subscription tokens in request paths (e.g. /sub/<token>/... -> /sub/[REDACTED]/...)
// 2. Suppresses client IP addresses to prevent recording user home IP addresses in server/container logs
// 3. Omits healthcheck endpoints
func PrivacyLogger() gin.HandlerFunc {
	return func(c *gin.Context) {
		path := c.Request.URL.Path

		// Skip health check logs
		if path == "/health" {
			c.Next()
			return
		}

		start := time.Now()

		c.Next()

		latency := time.Since(start)
		statusCode := c.Writer.Status()

		// Redact sensitive path elements
		safePath := maskSensitivePath(path)
		if c.Request.URL.RawQuery != "" {
			safePath += "?" + maskQuery(c.Request.URL.RawQuery)
		}

		// Privacy: mask client IP address
		maskedIP := "[PRIVACY_PROTECTED]"

		// Format output without leaking sensitive data
		fmt.Printf("[FC-ACCESS] %s | %3d | %12v | %s | %-7s %s\n",
			start.Format("2006/01/02 15:04:05"),
			statusCode,
			latency,
			maskedIP,
			c.Request.Method,
			safePath,
		)
	}
}

// maskSensitivePath replaces /sub/<token> with /sub/[REDACTED]
func maskSensitivePath(path string) string {
	if !strings.HasPrefix(path, "/sub/") {
		return path
	}

	parts := strings.Split(path, "/")
	// parts[0] == "", parts[1] == "sub", parts[2] == <token>, parts[3...] == subpaths
	if len(parts) >= 3 && len(parts[2]) > 0 {
		parts[2] = "[REDACTED]"
	}

	return strings.Join(parts, "/")
}

// maskQuery redacts token parameters in query strings
func maskQuery(rawQuery string) string {
	if rawQuery == "" {
		return ""
	}
	pairs := strings.Split(rawQuery, "&")
	for i, pair := range pairs {
		kv := strings.SplitN(pair, "=", 2)
		if len(kv) == 2 {
			k := strings.ToLower(kv[0])
			if k == "token" || k == "secret" || k == "key" || k == "password" {
				pairs[i] = kv[0] + "=[REDACTED]"
			}
		}
	}
	return strings.Join(pairs, "&")
}
