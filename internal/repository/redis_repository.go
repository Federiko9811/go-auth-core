package repository

import (
	"context"
	"time"

	"github.com/redis/go-redis/v9"
)

// RedisRepository handles key-value storage operations using Redis.
type RedisRepository struct {
	client *redis.Client
}

// NewRedisRepository creates a new RedisRepository instance with an existing client.
func NewRedisRepository(client *redis.Client) *RedisRepository {
	return &RedisRepository{client: client}
}

// Set stores a key-value pair with an expiration time.
func (r *RedisRepository) Set(ctx context.Context, key string, value interface{}, expiration time.Duration) error {
	return r.client.Set(ctx, key, value, expiration).Err()
}

// Get retrieves a value by key.
func (r *RedisRepository) Get(ctx context.Context, key string) (string, error) {
	return r.client.Get(ctx, key).Result()
}

// Delete removes a key.
func (r *RedisRepository) Delete(ctx context.Context, key string) error {
	return r.client.Del(ctx, key).Err()
}

// Client returns the underlying redis client (useful for advanced ops or checking status).
func (r *RedisRepository) Client() *redis.Client {
	return r.client
}

// Incr increments the integer value of a key by one.
func (r *RedisRepository) Incr(ctx context.Context, key string) (int64, error) {
	return r.client.Incr(ctx, key).Result()
}

// Expire sets a timeout on key.
func (r *RedisRepository) Expire(ctx context.Context, key string, expiration time.Duration) error {
	return r.client.Expire(ctx, key, expiration).Err()
}
