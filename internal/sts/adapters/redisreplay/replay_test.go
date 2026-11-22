package redisreplay_test

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/redis/go-redis/v9"

	"github.com/aamirlatif1/warden/internal/sts/adapters/redisreplay"
	"github.com/aamirlatif1/warden/internal/sts/clientauth"
)

var _ clientauth.ReplayCache = (*redisreplay.Cache)(nil)

func open(t *testing.T) (*redisreplay.Cache, *redis.Client) {
	t.Helper()
	addr := os.Getenv("WARDEN_TEST_REDIS_ADDR")
	if addr == "" {
		t.Skip("WARDEN_TEST_REDIS_ADDR not set; run make test-db")
	}
	rdb := redis.NewClient(&redis.Options{Addr: addr})
	t.Cleanup(func() { _ = rdb.Close() })
	return redisreplay.New(rdb), rdb
}

func key() string {
	var b [8]byte
	_, _ = rand.Read(b[:])
	return "it:" + hex.EncodeToString(b[:])
}

func TestFirstUse(t *testing.T) {
	c, rdb := open(t)
	ctx := context.Background()
	k := key()

	first, err := c.FirstUse(ctx, k, time.Minute)
	if err != nil || !first {
		t.Fatalf("first use = %v, %v", first, err)
	}
	again, err := c.FirstUse(ctx, k, time.Minute)
	if err != nil || again {
		t.Fatalf("second use = %v, %v", again, err)
	}
	ttl := rdb.PTTL(ctx, "warden:sts:assertion-jti:"+k).Val()
	if ttl <= 0 || ttl > time.Minute {
		t.Fatalf("PTTL = %v", ttl)
	}
	if _, err := c.FirstUse(ctx, key(), 0); err == nil {
		t.Fatal("accepted a zero ttl (key would never expire)")
	}
}

func TestFirstUseExpires(t *testing.T) {
	c, _ := open(t)
	ctx := context.Background()
	k := key()
	if ok, _ := c.FirstUse(ctx, k, 50*time.Millisecond); !ok {
		t.Fatal("first use failed")
	}
	time.Sleep(120 * time.Millisecond)
	if ok, _ := c.FirstUse(ctx, k, time.Minute); !ok {
		t.Fatal("key did not expire")
	}
}

func TestFirstUseIsAtomic(t *testing.T) {
	c, _ := open(t)
	k := key()
	var wins atomic.Int64
	var wg sync.WaitGroup
	for range 50 {
		wg.Go(func() {
			if ok, err := c.FirstUse(context.Background(), k, time.Minute); err == nil && ok {
				wins.Add(1)
			}
		})
	}
	wg.Wait()
	if wins.Load() != 1 {
		t.Fatalf("%d winners, want 1", wins.Load())
	}
}
