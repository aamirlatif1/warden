package redisstore

import (
	"context"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/aamirlatif1/warden/internal/bff/app"
	"github.com/aamirlatif1/warden/internal/bff/logouttoken"
)

var (
	_ logouttoken.ReplayCache = (*Replay)(nil)
	_ app.DeviceStore         = (*Devices)(nil)
)

func TestReplayFirstUse(t *testing.T) {
	rdb := open(t)
	p := prefix()
	r := NewReplay(rdb, p)
	ctx := context.Background()

	var wins atomic.Int64
	var wg sync.WaitGroup
	for range 20 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ok, err := r.FirstUse(ctx, "http://kc/realms/insurance|jti-1", time.Minute)
			if err != nil {
				t.Error(err)
			}
			if ok {
				wins.Add(1)
			}
		}()
	}
	wg.Wait()
	if wins.Load() != 1 {
		t.Fatalf("%d first uses, want 1", wins.Load())
	}
	keys := rdb.Keys(ctx, p+"logout-jti:*").Val()
	if len(keys) != 1 || strings.Contains(keys[0], "jti-1") {
		t.Fatalf("keys = %v, want one hashed key", keys)
	}
	if ttl := rdb.PTTL(ctx, keys[0]).Val(); ttl <= 0 || ttl > time.Minute {
		t.Fatalf("PTTL = %v", ttl)
	}
	if _, err := r.FirstUse(ctx, "k", 0); err == nil {
		t.Fatal("zero ttl accepted (entry would never expire)")
	}
}

func TestDevices(t *testing.T) {
	rdb := open(t)
	p := prefix()
	d := NewDevices(rdb, p, time.Hour)
	ctx := context.Background()

	if c, known, err := d.LastCountry(ctx, "dev-secret"); err != nil || known || c != "" {
		t.Fatalf("unknown device: %q %v %v", c, known, err)
	}
	if err := d.Remember(ctx, "dev-secret", "DE"); err != nil {
		t.Fatal(err)
	}
	if c, known, err := d.LastCountry(ctx, "dev-secret"); err != nil || !known || c != "DE" {
		t.Fatalf("known device: %q %v %v", c, known, err)
	}
	// Known with no country yet (header never sent) is still known.
	if err := d.Remember(ctx, "dev-2", ""); err != nil {
		t.Fatal(err)
	}
	if _, known, _ := d.LastCountry(ctx, "dev-2"); !known {
		t.Fatal("device with empty country reported unknown")
	}
	for _, k := range rdb.Keys(ctx, p+"*").Val() {
		if strings.Contains(k, "dev-secret") {
			t.Fatalf("cookie value in key %q", k)
		}
		if ttl := rdb.PTTL(ctx, k).Val(); ttl <= 0 || ttl > time.Hour {
			t.Fatalf("PTTL(%s) = %v", k, ttl)
		}
	}
}
