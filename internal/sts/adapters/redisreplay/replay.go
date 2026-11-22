// Package redisreplay implements clientauth.ReplayCache with Redis SET NX.
package redisreplay

import (
	"context"
	"errors"
	"time"

	"github.com/redis/go-redis/v9"
)

// Cache records seen assertion IDs. SET key 1 NX PX ttl is atomic across
// every partner-sts replica: exactly one SET wins, the rest see the key.
type Cache struct {
	rdb    *redis.Client
	prefix string
}

func New(rdb *redis.Client) *Cache {
	return &Cache{rdb: rdb, prefix: "warden:sts:assertion-jti:"}
}

func (c *Cache) FirstUse(ctx context.Context, key string, ttl time.Duration) (bool, error) {
	if ttl <= 0 {
		return false, errors.New("redisreplay: ttl must be positive")
	}
	ok, err := c.rdb.SetNX(ctx, c.prefix+key, 1, ttl).Result()
	if err != nil {
		return false, err
	}
	return ok, nil
}
