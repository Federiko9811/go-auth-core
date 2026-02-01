package api

import (
	"context"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/redis/go-redis/v9"
)

// RateLimiterMiddleware creates an IP-based rate limiting middleware.
// Uses sliding window algorithm with Redis for precision and scalability.
//
// Parameters:
// - rdb: Redis client
// - limit: Max requests per window
// - windowSeconds: Window duration in seconds
func RateLimiterMiddleware(rdb *redis.Client, limit int, windowSeconds int) gin.HandlerFunc {
	return func(c *gin.Context) {
		ctx := c.Request.Context()

		// Get Client IP (handles proxies)
		clientIP := c.ClientIP()

		// Skip rate limiting for health check
		if c.Request.URL.Path == "/health" || c.Request.URL.Path == "/" {
			c.Next()
			return
		}

		key := fmt.Sprintf("rate_limit:%s", clientIP)
		now := time.Now().Unix()
		windowStart := now - int64(windowSeconds)

		// Use Redis pipeline for efficiency
		pipe := rdb.Pipeline()

		// Remove requests outside the time window
		pipe.ZRemRangeByScore(ctx, key, "0", strconv.FormatInt(windowStart, 10))

		// Add current request
		pipe.ZAdd(ctx, key, redis.Z{
			Score:  float64(now),
			Member: fmt.Sprintf("%d-%d", now, time.Now().UnixNano()),
		})

		// Count requests in window
		countCmd := pipe.ZCard(ctx, key)

		// Set TTL on key for auto-cleanup
		pipe.Expire(ctx, key, time.Duration(windowSeconds)*time.Second)

		// Execute pipeline
		_, err := pipe.Exec(ctx)
		if err != nil {
			// Fail-open on Redis error
			// but log the error
			c.Next()
			return
		}

		count := countCmd.Val()
		remaining := int64(limit) - count
		if remaining < 0 {
			remaining = 0
		}

		// Calculate reset time
		resetTime := now + int64(windowSeconds)

		// Set Rate Limit Headers
		c.Header("X-RateLimit-Limit", strconv.Itoa(limit))
		c.Header("X-RateLimit-Remaining", strconv.FormatInt(remaining, 10))
		c.Header("X-RateLimit-Reset", strconv.FormatInt(resetTime, 10))

		// Check if limit exceeded
		if count > int64(limit) {
			c.Header("Retry-After", strconv.Itoa(windowSeconds))
			c.AbortWithStatusJSON(http.StatusTooManyRequests, gin.H{
				"error":       "Too many requests",
				"retry_after": windowSeconds,
			})
			return
		}

		c.Next()
	}
}

// getClientIP extracts real client IP, handling proxies and load balancers.
func getClientIP(c *gin.Context) string {
	// Try X-Forwarded-For (standard for proxies)
	if xff := c.GetHeader("X-Forwarded-For"); xff != "" {
		return xff
	}

	// Try X-Real-IP (nginx)
	if xri := c.GetHeader("X-Real-IP"); xri != "" {
		return xri
	}

	// Fallback to direct IP
	return c.ClientIP()
}

// ClearRateLimit clears rate limit for an IP (useful for testing).
func ClearRateLimit(ctx context.Context, rdb *redis.Client, ip string) error {
	key := fmt.Sprintf("rate_limit:%s", ip)
	return rdb.Del(ctx, key).Err()
}
