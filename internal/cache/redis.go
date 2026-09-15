package cache

import (
	"context"
	"fmt"
	"log"
	"time"

	"freedom-cry/internal/config"

	"github.com/redis/go-redis/v9"
)

type Client struct {
	rdb *redis.Client
}

func Connect(cfg *config.RedisConfig) (*Client, error) {
	rdb := redis.NewClient(&redis.Options{
		Addr:     cfg.Addr,
		Password: cfg.Password,
		DB:       cfg.DB,
	})

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := rdb.Ping(ctx).Err(); err != nil {
		log.Printf("[Redis] Warning: failed to connect to Redis at %s: %v (falling back to in-memory/disabled mode)", cfg.Addr, err)
		return &Client{rdb: nil}, nil
	}

	log.Println("[Redis] Connected successfully")
	return &Client{rdb: rdb}, nil
}

func (c *Client) Set(ctx context.Context, key string, value interface{}, expiration time.Duration) error {
	if c.rdb == nil {
		return nil
	}
	return c.rdb.Set(ctx, key, value, expiration).Err()
}

func (c *Client) Get(ctx context.Context, key string) (string, error) {
	if c.rdb == nil {
		return "", fmt.Errorf("redis not available")
	}
	return c.rdb.Get(ctx, key).Result()
}

func (c *Client) Del(ctx context.Context, keys ...string) error {
	if c.rdb == nil {
		return nil
	}
	return c.rdb.Del(ctx, keys...).Err()
}

func (c *Client) SetNX(ctx context.Context, key string, value interface{}, expiration time.Duration) (bool, error) {
	if c == nil || c.rdb == nil {
		return true, nil
	}
	return c.rdb.SetNX(ctx, key, value, expiration).Result()
}

func (c *Client) Raw() *redis.Client {
	if c == nil {
		return nil
	}
	return c.rdb
}
