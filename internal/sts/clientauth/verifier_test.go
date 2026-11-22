package clientauth_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"

	"github.com/aamirlatif1/warden/internal/sts/clientauth"
)

var now = time.Date(2026, 11, 22, 12, 0, 0, 0, time.UTC)

const (
	stsIss        = "http://localhost:8083"
	tokenEndpoint = "http://localhost:8083/token"
)

// ---- keys (generated once) ----

var (
	keysOnce                          sync.Once
	shopr1, shopr2, acme1, attackerEC *ecdsa.PrivateKey
	p384                              *ecdsa.PrivateKey
	rsaKey                            *rsa.PrivateKey
)

func initKeys() {
	keysOnce.Do(func() {
		gen := func() *ecdsa.PrivateKey { k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader); return k }
		shopr1, shopr2, acme1, attackerEC = gen(), gen(), gen(), gen()
		p384, _ = ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
		rsaKey, _ = rsa.GenerateKey(rand.Reader, 2048)
	})
}

func pub(k *ecdsa.PrivateKey, kid string) jose.JSONWebKey {
	return jose.JSONWebKey{Key: &k.PublicKey, KeyID: kid, Algorithm: "ES256", Use: "sig"}
}

// ---- fakes ----

type clients map[string]clientauth.Client

func (c clients) Client(_ context.Context, id string) (clientauth.Client, error) {
	cl, ok := c[id]
	if !ok {
		return clientauth.Client{}, clientauth.ErrUnknownClient
	}
	return cl, nil
}

type fakeReplay struct {
	mu   sync.Mutex
	seen map[string]time.Duration
	err  error
}

func newReplay() *fakeReplay { return &fakeReplay{seen: map[string]time.Duration{}} }

func (f *fakeReplay) FirstUse(_ context.Context, key string, ttl time.Duration) (bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.err != nil {
		return false, f.err
	}
	if _, ok := f.seen[key]; ok {
		return false, nil
	}
	f.seen[key] = ttl
	return true, nil
}

func (f *fakeReplay) count() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.seen)
}

func newVerifier(t *testing.T, r clientauth.ReplayCache) *clientauth.Verifier {
	t.Helper()
	initKeys()
	v, err := clientauth.NewVerifier(clientauth.Config{
		Audience: stsIss,
		Now:      func() time.Time { return now },
		Clients: clients{
			"shopr": {ID: "shopr", Keys: []jose.JSONWebKey{pub(shopr1, "shopr-1"), pub(shopr2, "shopr-2")}},
			"acme":  {ID: "acme", Keys: []jose.JSONWebKey{pub(acme1, "acme-1")}},
		},
		Replay: r,
	})
	if err != nil {
		t.Fatalf("NewVerifier: %v", err)
	}
	return v
}

// ---- assertion building ----

type claims = map[string]any

var jtiSeq atomic.Int64

func base() claims {
	return claims{
		"iss": "shopr", "sub": "shopr", "aud": stsIss,
		"iat": now.Unix(), "exp": now.Add(time.Minute).Unix(),
		"jti": fmt.Sprintf("jti-%d", jtiSeq.Add(1)),
	}
}

func with(c claims, kv ...any) claims {
	out := maps.Clone(c)
	for i := 0; i < len(kv); i += 2 {
		if kv[i+1] == nil {
			delete(out, kv[i].(string))
		} else {
			out[kv[i].(string)] = kv[i+1]
		}
	}
	return out
}

type spec struct {
	alg   jose.SignatureAlgorithm
	key   any
	kid   string
	embed bool
}

func shoprSpec() spec { initKeys(); return spec{alg: jose.ES256, key: shopr1, kid: "shopr-1"} }

func sign(t *testing.T, s spec, c claims) string {
	t.Helper()
	payload, _ := json.Marshal(c)
	opts := &jose.SignerOptions{EmbedJWK: s.embed}
	if s.kid != "" {
		opts = opts.WithHeader("kid", s.kid)
	}
	opts = opts.WithType("JWT")
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: s.alg, Key: s.key}, opts)
	if err != nil {
		t.Fatalf("NewSigner: %v", err)
	}
	obj, err := signer.Sign(payload)
	if err != nil {
		t.Fatal(err)
	}
	out, _ := obj.CompactSerialize()
	return out
}

var b64 = base64.RawURLEncoding

func unsigned(header map[string]any, c claims) string {
	h, _ := json.Marshal(header)
	p, _ := json.Marshal(c)
	return b64.EncodeToString(h) + "." + b64.EncodeToString(p) + "."
}

func parts(tok string) []string { return strings.SplitN(tok, ".", 3) }

// ---- tests ----

func TestVerifyRejects(t *testing.T) {
	initKeys()
	pubJSON, _ := json.Marshal(pub(shopr1, "shopr-1"))

	cases := []struct {
		name string
		tok  func(t *testing.T) string
		want clientauth.Reason
	}{
		// malformed
		{"empty", func(*testing.T) string { return "" }, clientauth.ReasonMalformed},
		{"two segments", func(*testing.T) string { return "eyJhbGciOiJFUzI1NiJ9.e30" }, clientauth.ReasonMalformed},
		{"garbage", func(*testing.T) string { return "!!.@@.##" }, clientauth.ReasonMalformed},
		{"oversized (16 KiB claim)", func(t *testing.T) string {
			return sign(t, shoprSpec(), with(base(), "pad", strings.Repeat("a", 16<<10)))
		}, clientauth.ReasonMalformed},
		{"exp is a string", func(t *testing.T) string { return sign(t, shoprSpec(), with(base(), "exp", "soon")) }, clientauth.ReasonMalformed},

		// alg pinning
		{"alg none", func(*testing.T) string {
			return unsigned(map[string]any{"alg": "none", "kid": "shopr-1"}, base())
		}, clientauth.ReasonAlgNotAllowed},
		{"HS256 keyed with the client's public JWK", func(t *testing.T) string {
			return sign(t, spec{alg: jose.HS256, key: pubJSON, kid: "shopr-1"}, base())
		}, clientauth.ReasonAlgNotAllowed},
		{"RS256", func(t *testing.T) string { return sign(t, spec{alg: jose.RS256, key: rsaKey, kid: "shopr-1"}, base()) }, clientauth.ReasonAlgNotAllowed},
		{"PS256", func(t *testing.T) string { return sign(t, spec{alg: jose.PS256, key: rsaKey, kid: "shopr-1"}, base()) }, clientauth.ReasonAlgNotAllowed},
		{"ES384", func(t *testing.T) string { return sign(t, spec{alg: jose.ES384, key: p384, kid: "shopr-1"}, base()) }, clientauth.ReasonAlgNotAllowed},

		// iss / sub / client
		{"iss missing", func(t *testing.T) string { return sign(t, shoprSpec(), with(base(), "iss", nil)) }, clientauth.ReasonClaimMissing},
		{"sub missing", func(t *testing.T) string { return sign(t, shoprSpec(), with(base(), "sub", nil)) }, clientauth.ReasonIssSubMismatch},
		{"sub differs from iss", func(t *testing.T) string { return sign(t, shoprSpec(), with(base(), "sub", "acme")) }, clientauth.ReasonIssSubMismatch},
		{"unregistered client", func(t *testing.T) string {
			return sign(t, shoprSpec(), with(base(), "iss", "evil", "sub", "evil"))
		}, clientauth.ReasonClientUnknown},

		// audience (rfc7523bis: issuer identifier only)
		{"aud is the token endpoint URL", func(t *testing.T) string { return sign(t, shoprSpec(), with(base(), "aud", tokenEndpoint)) }, clientauth.ReasonAudInvalid},
		{"aud has the issuer plus another value", func(t *testing.T) string {
			return sign(t, shoprSpec(), with(base(), "aud", []string{stsIss, tokenEndpoint}))
		}, clientauth.ReasonAudInvalid},
		{"aud missing", func(t *testing.T) string { return sign(t, shoprSpec(), with(base(), "aud", nil)) }, clientauth.ReasonAudInvalid},
		{"aud empty array", func(t *testing.T) string { return sign(t, shoprSpec(), with(base(), "aud", []string{})) }, clientauth.ReasonAudInvalid},
		{"aud with trailing slash", func(t *testing.T) string { return sign(t, shoprSpec(), with(base(), "aud", stsIss+"/")) }, clientauth.ReasonAudInvalid},
		{"aud is another server", func(t *testing.T) string { return sign(t, shoprSpec(), with(base(), "aud", "policy-api")) }, clientauth.ReasonAudInvalid},

		// keys and signature
		{"unknown kid", func(t *testing.T) string {
			return sign(t, spec{alg: jose.ES256, key: shopr1, kid: "shopr-9"}, base())
		}, clientauth.ReasonKidUnknown},
		{"no kid", func(t *testing.T) string { return sign(t, spec{alg: jose.ES256, key: shopr1}, base()) }, clientauth.ReasonKidUnknown},
		{"another client's kid (keys scoped per client)", func(t *testing.T) string {
			return sign(t, spec{alg: jose.ES256, key: acme1, kid: "acme-1"}, base())
		}, clientauth.ReasonKidUnknown},
		{"right kid, attacker's key", func(t *testing.T) string {
			return sign(t, spec{alg: jose.ES256, key: attackerEC, kid: "shopr-1"}, base())
		}, clientauth.ReasonSignatureInvalid},
		{"attacker key embedded as jwk header", func(t *testing.T) string {
			return sign(t, spec{alg: jose.ES256, key: attackerEC, kid: "shopr-1", embed: true}, base())
		}, clientauth.ReasonSignatureInvalid},
		{"payload tampered", func(t *testing.T) string {
			tok := sign(t, shoprSpec(), base())
			p, _ := json.Marshal(with(base(), "exp", now.Add(4*time.Minute).Unix()))
			ps := parts(tok)
			return ps[0] + "." + b64.EncodeToString(p) + "." + ps[2]
		}, clientauth.ReasonSignatureInvalid},
		{"signature stripped", func(t *testing.T) string {
			ps := parts(sign(t, shoprSpec(), base()))
			return ps[0] + "." + ps[1] + "."
		}, clientauth.ReasonSignatureInvalid},

		// time
		{"exp missing", func(t *testing.T) string { return sign(t, shoprSpec(), with(base(), "exp", nil)) }, clientauth.ReasonClaimMissing},
		{"expired 31 s ago", func(t *testing.T) string {
			return sign(t, shoprSpec(), with(base(), "iat", now.Add(-time.Minute).Unix(), "exp", now.Add(-31*time.Second).Unix()))
		}, clientauth.ReasonExpired},
		{"exp 10 min ahead, no iat (only the max-lifetime rule can catch it)", func(t *testing.T) string {
			return sign(t, shoprSpec(), with(base(), "iat", nil, "exp", now.Add(10*time.Minute).Unix()))
		}, clientauth.ReasonLifetimeTooLong},
		{"exp - iat over 5 min", func(t *testing.T) string {
			return sign(t, shoprSpec(), with(base(), "iat", now.Add(-10*time.Minute).Unix(), "exp", now.Add(time.Minute).Unix()))
		}, clientauth.ReasonLifetimeTooLong},
		{"nbf 60 s ahead", func(t *testing.T) string {
			return sign(t, shoprSpec(), with(base(), "nbf", now.Add(time.Minute).Unix()))
		}, clientauth.ReasonNotYetValid},
		{"iat 60 s ahead", func(t *testing.T) string {
			return sign(t, shoprSpec(), with(base(), "iat", now.Add(time.Minute).Unix(), "exp", now.Add(2*time.Minute).Unix()))
		}, clientauth.ReasonIssuedInFuture},

		// jti
		{"jti missing", func(t *testing.T) string { return sign(t, shoprSpec(), with(base(), "jti", nil)) }, clientauth.ReasonClaimMissing},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := newReplay()
			v := newVerifier(t, r)
			tok := tc.tok(t)
			a, err := v.Verify(context.Background(), tok)
			if err == nil {
				t.Fatalf("accepted: %+v", a)
			}
			if got := clientauth.ReasonOf(err); got != tc.want {
				t.Fatalf("reason = %q, want %q (err: %v)", got, tc.want, err)
			}
			if r.count() != 0 {
				t.Fatalf("a rejected assertion recorded its jti (%d keys): attackers could burn jtis", r.count())
			}
			if len(tok) > 20 && strings.Contains(err.Error(), tok[len(tok)-20:]) {
				t.Fatal("error leaks the assertion")
			}
		})
	}
}

func TestVerifyAccepts(t *testing.T) {
	cases := []struct {
		name string
		tok  func(t *testing.T) (string, claims)
	}{
		{"valid", func(t *testing.T) (string, claims) { c := base(); return sign(t, shoprSpec(), c), c }},
		{"aud as a one-element array", func(t *testing.T) (string, claims) {
			c := with(base(), "aud", []string{stsIss})
			return sign(t, shoprSpec(), c), c
		}},
		{"expired 20 s ago, within leeway", func(t *testing.T) (string, claims) {
			c := with(base(), "iat", now.Add(-time.Minute).Unix(), "exp", now.Add(-20*time.Second).Unix())
			return sign(t, shoprSpec(), c), c
		}},
		{"exp exactly 5 min ahead", func(t *testing.T) (string, claims) {
			c := with(base(), "exp", now.Add(5*time.Minute).Unix())
			return sign(t, shoprSpec(), c), c
		}},
		{"no iat", func(t *testing.T) (string, claims) {
			c := with(base(), "iat", nil)
			return sign(t, shoprSpec(), c), c
		}},
		{"client's second key", func(t *testing.T) (string, claims) {
			c := base()
			return sign(t, spec{alg: jose.ES256, key: shopr2, kid: "shopr-2"}, c), c
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := newReplay()
			v := newVerifier(t, r)
			tok, c := tc.tok(t)
			a, err := v.Verify(context.Background(), tok)
			if err != nil {
				t.Fatalf("rejected: %v", err)
			}
			if a.ClientID != "shopr" || a.JTI != c["jti"] || a.ExpiresAt.Unix() != c["exp"] {
				t.Fatalf("assertion = %+v", a)
			}
			ttl, ok := r.seen["shopr:"+a.JTI]
			if !ok || r.count() != 1 {
				t.Fatalf("replay key not recorded as client_id:jti, got %v", r.seen)
			}
			if remaining := time.Unix(c["exp"].(int64), 0).Sub(now); ttl < remaining {
				t.Fatalf("replay ttl %v shorter than the assertion's remaining life %v", ttl, remaining)
			}
		})
	}
}

func TestReplay(t *testing.T) {
	ctx := context.Background()

	t.Run("D12 same assertion twice", func(t *testing.T) {
		v := newVerifier(t, newReplay())
		tok := sign(t, shoprSpec(), base())
		if _, err := v.Verify(ctx, tok); err != nil {
			t.Fatal(err)
		}
		_, err := v.Verify(ctx, tok)
		if clientauth.ReasonOf(err) != clientauth.ReasonJTIReplayed {
			t.Fatalf("second use: %v", err)
		}
	})

	t.Run("same jti from two clients is not a replay", func(t *testing.T) {
		v := newVerifier(t, newReplay())
		jti := "shared-jti"
		a := sign(t, shoprSpec(), with(base(), "jti", jti))
		b := sign(t, spec{alg: jose.ES256, key: acme1, kid: "acme-1"}, with(base(), "iss", "acme", "sub", "acme", "jti", jti))
		if _, err := v.Verify(ctx, a); err != nil {
			t.Fatal(err)
		}
		if _, err := v.Verify(ctx, b); err != nil {
			t.Fatalf("acme blocked by shopr's jti: %v", err)
		}
	})

	t.Run("a forged assertion cannot burn a real jti", func(t *testing.T) {
		r := newReplay()
		v := newVerifier(t, r)
		jti := "victim-jti"
		forged := []string{
			sign(t, spec{alg: jose.ES256, key: attackerEC, kid: "shopr-1"}, with(base(), "jti", jti)),
			sign(t, shoprSpec(), with(base(), "jti", jti, "aud", tokenEndpoint)),
			sign(t, shoprSpec(), with(base(), "jti", jti, "iat", now.Add(-time.Hour).Unix(), "exp", now.Add(-time.Minute).Unix())),
		}
		for _, f := range forged {
			if _, err := v.Verify(ctx, f); err == nil {
				t.Fatal("forged assertion accepted")
			}
		}
		if _, err := v.Verify(ctx, sign(t, shoprSpec(), with(base(), "jti", jti))); err != nil {
			t.Fatalf("legitimate assertion rejected after forgeries: %v", err)
		}
	})

	t.Run("replay store down fails closed", func(t *testing.T) {
		r := newReplay()
		r.err = errors.New("redis: connection refused")
		v := newVerifier(t, r)
		_, err := v.Verify(ctx, sign(t, shoprSpec(), base()))
		if clientauth.ReasonOf(err) != clientauth.ReasonReplayUnavailable {
			t.Fatalf("err = %v, want replay_unavailable", err)
		}
	})

	t.Run("concurrent replays: exactly one wins", func(t *testing.T) {
		v := newVerifier(t, newReplay())
		tok := sign(t, shoprSpec(), base())
		var ok atomic.Int64
		var wg sync.WaitGroup
		for range 20 {
			wg.Go(func() {
				if _, err := v.Verify(ctx, tok); err == nil {
					ok.Add(1)
				}
			})
		}
		wg.Wait()
		if ok.Load() != 1 {
			t.Fatalf("%d concurrent uses accepted, want 1", ok.Load())
		}
	})
}

func TestNewVerifierRefusesWeakConfig(t *testing.T) {
	cl := clients{}
	r := newReplay()
	cases := map[string]clientauth.Config{
		"no audience": {Clients: cl, Replay: r},
		"no clients":  {Audience: stsIss, Replay: r},
		"no replay":   {Audience: stsIss, Clients: cl},
		"alg none":    {Audience: stsIss, Clients: cl, Replay: r, Alg: "none"},
		"alg HS256":   {Audience: stsIss, Clients: cl, Replay: r, Alg: jose.HS256},
	}
	for name, cfg := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := clientauth.NewVerifier(cfg); err == nil {
				t.Fatal("accepted a weak config")
			}
		})
	}
}
