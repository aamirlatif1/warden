package redisstore

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/redis/go-redis/v9"

	"github.com/aamirlatif1/warden/internal/bff/app"
	"github.com/aamirlatif1/warden/internal/bff/domain"
)

func key32() []byte { k := make([]byte, 32); _, _ = rand.Read(k); return k }

func TestSealer(t *testing.T) {
	s, err := NewSealer(key32())
	if err != nil {
		t.Fatal(err)
	}
	blob, err := s.seal(domain.Session{ID: "x", AccessToken: "eyJ.secret.token"}, "k1")
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(blob, []byte("eyJ")) {
		t.Fatal("plaintext token visible in the stored blob")
	}
	var out domain.Session
	if err := s.open(blob, "k1", &out); err != nil || out.AccessToken != "eyJ.secret.token" {
		t.Fatalf("round trip: %+v, %v", out, err)
	}
	if err := s.open(blob, "k2", &out); err == nil {
		t.Fatal("blob decrypted under another key (AAD not bound)")
	}
	blob[len(blob)-1] ^= 1
	if err := s.open(blob, "k1", &out); err == nil {
		t.Fatal("tampered blob decrypted")
	}
	other, _ := NewSealer(key32())
	b2, _ := s.seal(domain.Session{ID: "x"}, "k1")
	if err := other.open(b2, "k1", &out); err == nil {
		t.Fatal("decrypted with the wrong key")
	}
	if _, err := NewSealer([]byte("short")); err == nil {
		t.Fatal("accepted a short key")
	}
}

func open(t *testing.T) *redis.Client {
	t.Helper()
	addr := os.Getenv("WARDEN_TEST_REDIS_ADDR")
	if addr == "" {
		t.Skip("WARDEN_TEST_REDIS_ADDR not set; run make test-db")
	}
	rdb := redis.NewClient(&redis.Options{Addr: addr})
	t.Cleanup(func() { _ = rdb.Close() })
	return rdb
}

// prefix isolates each test's keys on the shared Redis.
func prefix() string { return "it:" + app.NewSessionID()[:12] + ":" }

func TestSessions(t *testing.T) {
	rdb := open(t)
	seal, _ := NewSealer(key32())
	s := NewSessions(rdb, seal, SessionConfig{Prefix: prefix(), Idle: time.Minute, Absolute: time.Hour})
	ctx := context.Background()

	x := domain.Session{ID: app.NewSessionID(), Subject: "sub-anna", KeycloakSID: "kc-" + app.NewSessionID()[:8], AccessToken: "at", CreatedAt: time.Now()}
	if err := s.Create(ctx, x); err != nil {
		t.Fatal(err)
	}
	if err := s.Create(ctx, x); err == nil {
		// SET NX: an existing ID is never overwritten by Create
		if got, _ := s.Get(ctx, x.ID); got.Subject != "sub-anna" {
			t.Fatal("Create overwrote an existing session")
		}
	}

	// The Redis key is not the cookie value.
	if n := rdb.Exists(ctx, s.prefix+"sess:"+x.ID).Val(); n != 0 {
		t.Fatal("session stored under the raw cookie value")
	}

	got, err := s.Get(ctx, x.ID)
	if err != nil || got.Subject != "sub-anna" || got.AccessToken != "at" {
		t.Fatalf("Get = %+v, %v", got, err)
	}
	if ttl := rdb.TTL(ctx, s.key(x.ID)).Val(); ttl <= 0 || ttl > time.Minute {
		t.Fatalf("TTL = %v, want the idle timeout", ttl)
	}

	got.AccessToken = "at-2"
	if err := s.Save(ctx, got); err != nil {
		t.Fatal(err)
	}
	if again, _ := s.Get(ctx, x.ID); again.AccessToken != "at-2" {
		t.Fatal("Save not persisted")
	}

	if err := s.Delete(ctx, x.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Get(ctx, x.ID); !errors.Is(err, domain.ErrNoSession) {
		t.Fatalf("after delete: %v", err)
	}
	// Save must not resurrect a session deleted meanwhile (logout race).
	if err := s.Save(ctx, got); !errors.Is(err, domain.ErrNoSession) {
		t.Fatalf("Save after delete: %v", err)
	}
	if _, err := s.Get(ctx, ""); !errors.Is(err, domain.ErrNoSession) {
		t.Fatal("empty id")
	}
}

func TestAbsoluteTimeout(t *testing.T) {
	rdb := open(t)
	seal, _ := NewSealer(key32())
	s := NewSessions(rdb, seal, SessionConfig{Prefix: prefix(), Idle: time.Minute, Absolute: time.Hour})
	ctx := context.Background()
	x := domain.Session{ID: app.NewSessionID(), CreatedAt: time.Now().Add(-59 * time.Minute)}
	if err := s.Create(ctx, x); err != nil {
		t.Fatal(err)
	}
	if ttl := rdb.TTL(ctx, s.key(x.ID)).Val(); ttl > 61*time.Second {
		t.Fatalf("TTL = %v, want capped by the absolute timeout", ttl)
	}
	s.now = func() time.Time { return time.Now().Add(2 * time.Minute) }
	if _, err := s.Get(ctx, x.ID); !errors.Is(err, domain.ErrNoSession) {
		t.Fatalf("session past its absolute timeout: %v", err)
	}
}

func TestDeleteByKeycloakSID(t *testing.T) {
	rdb := open(t)
	seal, _ := NewSealer(key32())
	s := NewSessions(rdb, seal, SessionConfig{Prefix: prefix()})
	ctx := context.Background()
	kc := "kc-" + app.NewSessionID()[:8]
	a := domain.Session{ID: app.NewSessionID(), KeycloakSID: kc}
	b := domain.Session{ID: app.NewSessionID(), KeycloakSID: kc}
	c := domain.Session{ID: app.NewSessionID(), KeycloakSID: "other"}
	for _, x := range []domain.Session{a, b, c} {
		if err := s.Create(ctx, x); err != nil {
			t.Fatal(err)
		}
	}
	n, err := s.DeleteByKeycloakSID(ctx, kc)
	if err != nil || n != 2 {
		t.Fatalf("deleted %d, %v", n, err)
	}
	for _, x := range []domain.Session{a, b} {
		if _, err := s.Get(ctx, x.ID); !errors.Is(err, domain.ErrNoSession) {
			t.Fatal("session of the logged-out SSO session survived")
		}
	}
	if _, err := s.Get(ctx, c.ID); err != nil {
		t.Fatal("unrelated session deleted")
	}
}

func TestTxsAreSingleUse(t *testing.T) {
	rdb := open(t)
	seal, _ := NewSealer(key32())
	txs := NewTxs(rdb, seal, prefix())
	ctx := context.Background()
	tx := domain.LoginTx{ID: app.NewSessionID(), State: "st", Verifier: "secret-verifier"}
	if err := txs.Put(ctx, tx, time.Minute); err != nil {
		t.Fatal(err)
	}
	raw := rdb.Get(ctx, txs.key(tx.ID)).Val()
	if strings.Contains(raw, "secret-verifier") {
		t.Fatal("PKCE verifier stored in plaintext")
	}
	got, err := txs.Take(ctx, tx.ID)
	if err != nil || got.State != "st" || got.Verifier != "secret-verifier" {
		t.Fatalf("Take = %+v, %v", got, err)
	}
	if _, err := txs.Take(ctx, tx.ID); !errors.Is(err, app.ErrNoTx) {
		t.Fatalf("second Take: %v", err)
	}

	// Concurrent takes: exactly one wins.
	tx.ID = app.NewSessionID()
	_ = txs.Put(ctx, tx, time.Minute)
	var wins atomic.Int64
	var wg sync.WaitGroup
	for range 20 {
		wg.Go(func() {
			if _, err := txs.Take(ctx, tx.ID); err == nil {
				wins.Add(1)
			}
		})
	}
	wg.Wait()
	if wins.Load() != 1 {
		t.Fatalf("%d concurrent takes won", wins.Load())
	}
}

func TestLocker(t *testing.T) {
	rdb := open(t)
	l := NewLocker(rdb, prefix())
	ctx := context.Background()

	release, err := l.Acquire(ctx, "refresh:s1", 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	waitCtx, cancel := context.WithTimeout(ctx, 100*time.Millisecond)
	defer cancel()
	if _, err := l.Acquire(waitCtx, "refresh:s1", 5*time.Second); err == nil {
		t.Fatal("acquired a held lock")
	}
	release()
	r2, err := l.Acquire(ctx, "refresh:s1", 5*time.Second)
	if err != nil {
		t.Fatalf("after release: %v", err)
	}
	r2()

	// An expired holder must not release the next holder's lock.
	stale, _ := l.Acquire(ctx, "refresh:s2", 50*time.Millisecond)
	time.Sleep(80 * time.Millisecond)
	fresh, err := l.Acquire(ctx, "refresh:s2", 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	stale()
	shortCtx, c2 := context.WithTimeout(ctx, 100*time.Millisecond)
	defer c2()
	if _, err := l.Acquire(shortCtx, "refresh:s2", time.Second); err == nil {
		t.Fatal("a stale release freed the current holder's lock")
	}
	fresh()
}
