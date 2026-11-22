package revocation

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"io"
	"log/slog"
	"os"
	"testing"
	"time"

	"github.com/redis/go-redis/v9"

	"github.com/aamirlatif1/warden/internal/authn"
)

func openRedis(t *testing.T) *redis.Client {
	t.Helper()
	addr := os.Getenv("WARDEN_TEST_REDIS_ADDR")
	if addr == "" {
		t.Skip("WARDEN_TEST_REDIS_ADDR not set; run make test-db")
	}
	rdb := redis.NewClient(&redis.Options{Addr: addr})
	t.Cleanup(func() { _ = rdb.Close() })
	return rdb
}

func uid() string {
	var b [6]byte
	_, _ = rand.Read(b[:])
	return "it-" + hex.EncodeToString(b[:])
}

func waitFor(t *testing.T, d time.Duration, cond func() bool) time.Duration {
	t.Helper()
	start := time.Now()
	for !cond() {
		if time.Since(start) > d {
			t.Fatalf("condition not met within %v", d)
		}
		time.Sleep(2 * time.Millisecond)
	}
	return time.Since(start)
}

var quiet = slog.New(slog.NewTextHandler(io.Discard, nil))

// D13 propagation: revoke on the STS side, see it in a subscriber's local
// set well under 1 s.
func TestRevocationPropagates(t *testing.T) {
	rdb := openRedis(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	set := NewSet(nil)
	sub := NewSubscriber(rdb, set, quiet)
	go sub.Run(ctx)
	time.Sleep(100 * time.Millisecond) // let SUBSCRIBE land

	store := NewStore(rdb)
	iss, jti := "it-sts", uid()
	if err := store.Revoke(ctx, Event{Kind: KindJTI, Issuer: iss, Value: jti, ExpiresAt: time.Now().Add(time.Minute).Unix()}); err != nil {
		t.Fatal(err)
	}
	lag := waitFor(t, time.Second, func() bool { return set.Revoked(authn.TokenRef{Issuer: iss, JTI: jti}) })
	t.Logf("propagation lag: %v", lag)

	ok, err := store.IsRevoked(ctx, authn.TokenRef{Issuer: iss, JTI: jti})
	if err != nil || !ok {
		t.Fatalf("IsRevoked = %v, %v", ok, err)
	}
	ttl := rdb.TTL(ctx, keyPrefix+KindJTI+":"+iss+"|"+jti).Val()
	if ttl <= 0 || ttl > time.Minute {
		t.Fatalf("TTL = %v, want <= the token's remaining life", ttl)
	}
}

// A resource server that starts after the revocation still learns it.
func TestSubscriberLoadsSnapshotOnStart(t *testing.T) {
	rdb := openRedis(t)
	store := NewStore(rdb)
	iss, client := "it-sts", uid()
	cut := time.Now()
	if err := store.Revoke(context.Background(), Event{Kind: KindClient, Issuer: iss, Value: client, NotBefore: cut.Unix(), ExpiresAt: cut.Add(time.Minute).Unix()}); err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	set := NewSet(nil)
	go NewSubscriber(rdb, set, quiet).Run(ctx)
	waitFor(t, 2*time.Second, func() bool {
		return set.Revoked(authn.TokenRef{Issuer: iss, ClientID: client, IssuedAt: cut.Add(-time.Second)})
	})
	if set.Revoked(authn.TokenRef{Issuer: iss, ClientID: client, IssuedAt: cut.Add(2 * time.Second)}) {
		t.Fatal("token issued after the cut-off is revoked")
	}
	ok, err := store.IsRevoked(context.Background(), authn.TokenRef{Issuer: iss, ClientID: client, IssuedAt: cut.Add(-time.Second)})
	if err != nil || !ok {
		t.Fatalf("IsRevoked(client) = %v, %v", ok, err)
	}
}

func TestRevokeValidates(t *testing.T) {
	rdb := openRedis(t)
	s := NewStore(rdb)
	ctx := context.Background()
	if err := s.Revoke(ctx, Event{Kind: "everything", Issuer: "x", Value: "y", ExpiresAt: time.Now().Add(time.Minute).Unix()}); err == nil {
		t.Error("accepted an unknown kind")
	}
	if err := s.Revoke(ctx, Event{Kind: KindJTI, Value: "y", ExpiresAt: time.Now().Add(time.Minute).Unix()}); err == nil {
		t.Error("accepted an empty issuer")
	}
	if err := s.Revoke(ctx, Event{Kind: KindJTI, Issuer: "x", Value: uid(), ExpiresAt: time.Now().Add(-time.Minute).Unix()}); err != nil {
		t.Errorf("expired token: err = %v, want a no-op", err)
	}
}
