package redis

import (
	"context"
	"fmt"
	"go-auth-core/internal/conf"
	"log"
	"time"

	"github.com/redis/go-redis/v9"
)

// NewRedisClient initializes the connection to Redis.
func NewRedisClient(cfg *conf.Config) (*redis.Client, error) {
	// Client configuration
	rdb := redis.NewClient(&redis.Options{
		Addr:     cfg.RedisAddr,     // "localhost:6380" or "redis:6379"
		Password: cfg.RedisPassword, // "" (empty by default)
		DB:       0,                 // Default DB
	})

	// Test connection with PING
	// In Go Redis, every operation requires a Context (for timeout and cancellation)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	_, err := rdb.Ping(ctx).Result()
	if err != nil {
		return nil, fmt.Errorf("failed to connect to redis: %w", err)
	}

	log.Println("✅ Redis connection established successfully")
	return rdb, nil
}
