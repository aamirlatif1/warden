package redisstore

import (
	"context"
	"errors"
	"time"

	"github.com/redis/go-redis/v9"
)

// ---- logout token replay cache ----

// Replay implements logouttoken.ReplayCache with SET NX PX: atomic across
// BFF replicas, so a logout token is acted on once.
type Replay struct {
	rdb    *redis.Client
	prefix string
}

func NewReplay(rdb *redis.Client, prefix string) *Replay {
	return &Replay{rdb: rdb, prefix: prefix + "logout-jti:"}
}

func (r *Replay) FirstUse(ctx context.Context, key string, ttl time.Duration) (bool, error) {
	if ttl <= 0 {
		return false, errors.New("redisstore: replay ttl must be positive")
	}
	// Hash: the key holds issuer and jti, both attacker-influenced lengths.
	return r.rdb.SetNX(ctx, r.prefix+hashID(key), 1, ttl).Result()
}

// ---- devices (adaptive authentication) ----

// Devices implements app.DeviceStore. Keys are a hash of the device
// cookie, so a Redis dump does not reveal cookie values. Shared by all BFF
// instances: one browser is one device for the portal and claims-app.
type Devices struct {
	rdb    *redis.Client
	prefix string
	ttl    time.Duration
}

// NewDevices: ttl is how long an unused device stays known (default 90 days).
func NewDevices(rdb *redis.Client, prefix string, ttl time.Duration) *Devices {
	if ttl == 0 {
		ttl = 90 * 24 * time.Hour
	}
	return &Devices{rdb: rdb, prefix: prefix + "device:", ttl: ttl}
}

func (d *Devices) LastCountry(ctx context.Context, deviceID string) (string, bool, error) {
	v, err := d.rdb.Get(ctx, d.prefix+hashID(deviceID)).Result()
	if errors.Is(err, redis.Nil) {
		return "", false, nil
	}
	if err != nil {
		return "", false, err
	}
	return v, true, nil
}

func (d *Devices) Remember(ctx context.Context, deviceID, country string) error {
	return d.rdb.Set(ctx, d.prefix+hashID(deviceID), country, d.ttl).Err()
}
