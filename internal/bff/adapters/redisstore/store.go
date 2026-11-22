package redisstore

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"time"

	"github.com/redis/go-redis/v9"

	"github.com/aamirlatif1/warden/internal/bff/app"
	"github.com/aamirlatif1/warden/internal/bff/domain"
)

// Sessions implements app.SessionStore.
type Sessions struct {
	rdb      *redis.Client
	seal     *Sealer
	prefix   string        // e.g. "bff:portal:"
	idle     time.Duration // sliding
	absolute time.Duration
	now      func() time.Time
}

type SessionConfig struct {
	Prefix   string        // per BFF instance: portal and claims-app share Redis
	Idle     time.Duration // default 15 min (FR-3)
	Absolute time.Duration // default 8 h
}

func NewSessions(rdb *redis.Client, seal *Sealer, cfg SessionConfig) *Sessions {
	if cfg.Idle == 0 {
		cfg.Idle = 15 * time.Minute
	}
	if cfg.Absolute == 0 {
		cfg.Absolute = 8 * time.Hour
	}
	return &Sessions{rdb: rdb, seal: seal, prefix: cfg.Prefix, idle: cfg.Idle, absolute: cfg.Absolute, now: time.Now}
}

func (s *Sessions) key(id string) string      { return s.prefix + "sess:" + hashID(id) }
func (s *Sessions) kcKey(kcSID string) string { return s.prefix + "kcsid:" + kcSID }

// ttl is the idle timeout, capped by what is left of the absolute one.
func (s *Sessions) ttl(created time.Time) time.Duration {
	left := created.Add(s.absolute).Sub(s.now())
	return min(s.idle, left)
}

func (s *Sessions) Create(ctx context.Context, x domain.Session) error {
	if x.ID == "" {
		return errors.New("redisstore: empty session id")
	}
	if x.CreatedAt.IsZero() {
		x.CreatedAt = s.now()
	}
	k := s.key(x.ID)
	blob, err := s.seal.seal(x, k)
	if err != nil {
		return err
	}
	ttl := s.ttl(x.CreatedAt)
	_, err = s.rdb.TxPipelined(ctx, func(p redis.Pipeliner) error {
		p.SetArgs(ctx, k, blob, redis.SetArgs{Mode: "NX", TTL: ttl})
		if x.KeycloakSID != "" {
			// Back-channel logout index (S7): Keycloak sid → session keys.
			p.SAdd(ctx, s.kcKey(x.KeycloakSID), hashID(x.ID))
			p.Expire(ctx, s.kcKey(x.KeycloakSID), s.absolute)
		}
		return nil
	})
	return err
}

// Get decrypts the session, enforces the absolute timeout, and slides the
// idle timeout (the Redis TTL).
func (s *Sessions) Get(ctx context.Context, id string) (domain.Session, error) {
	if id == "" {
		return domain.Session{}, domain.ErrNoSession
	}
	k := s.key(id)
	blob, err := s.rdb.Get(ctx, k).Bytes()
	if errors.Is(err, redis.Nil) {
		return domain.Session{}, domain.ErrNoSession
	}
	if err != nil {
		return domain.Session{}, err
	}
	var x domain.Session
	if err := s.seal.open(blob, k, &x); err != nil {
		_ = s.rdb.Del(ctx, k).Err()
		return domain.Session{}, domain.ErrNoSession
	}
	ttl := s.ttl(x.CreatedAt)
	if ttl <= 0 {
		_ = s.Delete(ctx, id)
		return domain.Session{}, domain.ErrNoSession
	}
	_ = s.rdb.Expire(ctx, k, ttl).Err()
	return x, nil
}

// Save overwrites an existing session (after a refresh).
func (s *Sessions) Save(ctx context.Context, x domain.Session) error {
	k := s.key(x.ID)
	blob, err := s.seal.seal(x, k)
	if err != nil {
		return err
	}
	ttl := s.ttl(x.CreatedAt)
	if ttl <= 0 {
		return domain.ErrNoSession
	}
	ok, err := s.rdb.SetXX(ctx, k, blob, ttl).Result()
	if err != nil {
		return err
	}
	if !ok {
		return domain.ErrNoSession // deleted meanwhile (logout): don't resurrect it
	}
	return nil
}

func (s *Sessions) Delete(ctx context.Context, id string) error {
	return s.rdb.Del(ctx, s.key(id)).Err()
}

// DeleteByKeycloakSID ends every BFF session of one Keycloak SSO session
// (back-channel logout, S7). It returns how many were deleted.
func (s *Sessions) DeleteByKeycloakSID(ctx context.Context, kcSID string) (int, error) {
	idx := s.kcKey(kcSID)
	hashes, err := s.rdb.SMembers(ctx, idx).Result()
	if err != nil {
		return 0, err
	}
	keys := make([]string, 0, len(hashes)+1)
	for _, h := range hashes {
		keys = append(keys, s.prefix+"sess:"+h)
	}
	keys = append(keys, idx)
	n, err := s.rdb.Del(ctx, keys...).Result()
	if err != nil {
		return 0, err
	}
	return int(n) - 1, nil
}

// ---- login transactions ----

// Txs implements app.TxStore.
type Txs struct {
	rdb    *redis.Client
	seal   *Sealer
	prefix string
}

func NewTxs(rdb *redis.Client, seal *Sealer, prefix string) *Txs {
	return &Txs{rdb: rdb, seal: seal, prefix: prefix}
}

func (t *Txs) key(id string) string { return t.prefix + "tx:" + hashID(id) }

func (t *Txs) Put(ctx context.Context, tx domain.LoginTx, ttl time.Duration) error {
	k := t.key(tx.ID)
	blob, err := t.seal.seal(tx, k)
	if err != nil {
		return err
	}
	return t.rdb.Set(ctx, k, blob, ttl).Err()
}

// Take is GETDEL: the transaction can be used exactly once.
func (t *Txs) Take(ctx context.Context, id string) (domain.LoginTx, error) {
	if id == "" {
		return domain.LoginTx{}, app.ErrNoTx
	}
	k := t.key(id)
	blob, err := t.rdb.GetDel(ctx, k).Bytes()
	if errors.Is(err, redis.Nil) {
		return domain.LoginTx{}, app.ErrNoTx
	}
	if err != nil {
		return domain.LoginTx{}, err
	}
	var tx domain.LoginTx
	if err := t.seal.open(blob, k, &tx); err != nil {
		return domain.LoginTx{}, app.ErrNoTx
	}
	return tx, nil
}

// ---- lock ----

// Locker implements app.Locker with SET NX PX and a compare-and-delete
// release, so a holder whose lock expired can't release someone else's.
type Locker struct {
	rdb    *redis.Client
	prefix string
	poll   time.Duration
}

func NewLocker(rdb *redis.Client, prefix string) *Locker {
	return &Locker{rdb: rdb, prefix: prefix, poll: 20 * time.Millisecond}
}

var releaseScript = redis.NewScript(`if redis.call("GET", KEYS[1]) == ARGV[1] then return redis.call("DEL", KEYS[1]) else return 0 end`)

func (l *Locker) Acquire(ctx context.Context, key string, ttl time.Duration) (func(), error) {
	var tok [16]byte
	_, _ = rand.Read(tok[:])
	owner := hex.EncodeToString(tok[:])
	k := l.prefix + "lock:" + key
	for {
		ok, err := l.rdb.SetNX(ctx, k, owner, ttl).Result()
		if err != nil {
			return nil, err
		}
		if ok {
			return func() { _ = releaseScript.Run(context.WithoutCancel(ctx), l.rdb, []string{k}, owner).Err() }, nil
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(l.poll):
		}
	}
}

var (
	_ app.SessionStore = (*Sessions)(nil)
	_ app.TxStore      = (*Txs)(nil)
	_ app.Locker       = (*Locker)(nil)
)
