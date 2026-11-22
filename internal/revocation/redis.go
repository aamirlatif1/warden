package revocation

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"time"

	"github.com/redis/go-redis/v9"

	"github.com/aamirlatif1/warden/internal/authn"
)

const (
	Channel   = "warden.revocations"
	keyPrefix = "warden:revoked:"
)

func redisKey(e Event) string { return keyPrefix + e.Kind + ":" + e.key() }

// Store writes revocations (partner-sts) and answers point lookups for
// introspection.
type Store struct {
	rdb *redis.Client
	now func() time.Time
}

func NewStore(rdb *redis.Client) *Store { return &Store{rdb: rdb, now: time.Now} }

// Revoke stores e until it expires and publishes it, in one MULTI/EXEC:
// a subscriber that misses the message finds the key on its next resync.
func (s *Store) Revoke(ctx context.Context, e Event) error {
	if e.Kind != KindJTI && e.Kind != KindClient {
		return errors.New("revocation: unknown kind")
	}
	if e.Issuer == "" || e.Value == "" {
		return errors.New("revocation: issuer and value are required")
	}
	now := s.now()
	ttl := time.Unix(e.ExpiresAt, 0).Sub(now)
	if ttl <= 0 {
		return nil // the token(s) already expired: nothing to revoke
	}
	e.RevokedAt = now.UnixMilli()
	b, err := json.Marshal(e)
	if err != nil {
		return err
	}
	_, err = s.rdb.TxPipelined(ctx, func(p redis.Pipeliner) error {
		p.Set(ctx, redisKey(e), b, ttl)
		p.Publish(ctx, Channel, b)
		return nil
	})
	return err
}

// IsRevoked checks Redis directly (partner-sts introspection; resource
// servers use the local Set instead).
func (s *Store) IsRevoked(ctx context.Context, t authn.TokenRef) (bool, error) {
	if t.JTI != "" {
		n, err := s.rdb.Exists(ctx, redisKey(Event{Kind: KindJTI, Issuer: t.Issuer, Value: t.JTI})).Result()
		if err != nil {
			return false, err
		}
		if n > 0 {
			return true, nil
		}
	}
	if t.ClientID == "" {
		return false, nil
	}
	b, err := s.rdb.Get(ctx, redisKey(Event{Kind: KindClient, Issuer: t.Issuer, Value: t.ClientID})).Bytes()
	if errors.Is(err, redis.Nil) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	var e Event
	if err := json.Unmarshal(b, &e); err != nil {
		return true, nil // unreadable entry: fail closed
	}
	return t.IssuedAt.IsZero() || t.IssuedAt.Unix() <= e.NotBefore, nil
}

// Subscriber keeps a Set in sync with Redis: pub/sub for speed, plus a
// full resync on start and every ResyncEvery for anything missed while
// disconnected (pub/sub is fire-and-forget).
type Subscriber struct {
	rdb         *redis.Client
	set         *Set
	log         *slog.Logger
	ResyncEvery time.Duration
	// OnApply is called for each pub/sub event with its propagation lag
	// (S8 exports it as a histogram). Optional.
	OnApply func(e Event, lag time.Duration)
}

func NewSubscriber(rdb *redis.Client, set *Set, log *slog.Logger) *Subscriber {
	return &Subscriber{rdb: rdb, set: set, log: log, ResyncEvery: 30 * time.Second}
}

// Run blocks until ctx is done. It subscribes first and then loads the
// snapshot, so no revocation can fall between the two.
func (s *Subscriber) Run(ctx context.Context) {
	ps := s.rdb.Subscribe(ctx, Channel)
	defer func() { _ = ps.Close() }()
	if _, err := ps.Receive(ctx); err != nil && ctx.Err() == nil {
		s.log.Warn("revocation subscribe failed; relying on resync", "err", err)
	}
	s.resync(ctx)

	msgs := ps.Channel()
	tick := time.NewTicker(s.ResyncEvery)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case m, ok := <-msgs:
			if !ok {
				return
			}
			var e Event
			if err := json.Unmarshal([]byte(m.Payload), &e); err != nil {
				s.log.Warn("bad revocation message", "err", err)
				continue
			}
			s.set.Apply(e)
			lag := time.Since(time.UnixMilli(e.RevokedAt))
			s.log.Info("revocation applied", "kind", e.Kind, "iss", e.Issuer, "value", e.Value, "lag_ms", lag.Milliseconds())
			if s.OnApply != nil {
				s.OnApply(e, lag)
			}
		case <-tick.C:
			s.resync(ctx)
		}
	}
}

func (s *Subscriber) resync(ctx context.Context) {
	iter := s.rdb.Scan(ctx, 0, keyPrefix+"*", 500).Iterator()
	n := 0
	for iter.Next(ctx) {
		b, err := s.rdb.Get(ctx, iter.Val()).Bytes()
		if err != nil {
			continue // expired between SCAN and GET
		}
		var e Event
		if json.Unmarshal(b, &e) == nil {
			s.set.Apply(e)
			n++
		}
	}
	if err := iter.Err(); err != nil && ctx.Err() == nil {
		s.log.Warn("revocation resync failed; keeping the local set", "err", err)
		return
	}
	s.set.Purge()
	s.log.Debug("revocation resync", "entries", n, "live", s.set.Len())
}
