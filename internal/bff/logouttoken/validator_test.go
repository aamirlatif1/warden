package logouttoken_test

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

	"github.com/aamirlatif1/warden/internal/bff/logouttoken"
)

var now = time.Date(2026, 11, 22, 12, 0, 0, 0, time.UTC)

const (
	kcIss    = "http://localhost:8080/realms/insurance"
	clientID = "portal-bff"
	maxAge   = 2 * time.Minute
	leeway   = 30 * time.Second
)

// ---- keys ----

var (
	keysOnce          sync.Once
	kc1, kc2, attackR *rsa.PrivateKey
	ecKey             *ecdsa.PrivateKey
)

func initKeys() {
	keysOnce.Do(func() {
		gen := func() *rsa.PrivateKey { k, _ := rsa.GenerateKey(rand.Reader, 2048); return k }
		kc1, kc2, attackR = gen(), gen(), gen()
		ecKey, _ = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	})
}

// ---- fakes ----

type keySource map[string]jose.JSONWebKey

func (k keySource) Key(_ context.Context, kid string) (jose.JSONWebKey, error) {
	key, ok := k[kid]
	if !ok {
		return jose.JSONWebKey{}, errors.New("kid not found")
	}
	return key, nil
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

func keys() keySource {
	initKeys()
	return keySource{
		"kc-1":  {Key: &kc1.PublicKey, KeyID: "kc-1", Algorithm: "RS256", Use: "sig"},
		"kc-2":  {Key: &kc2.PublicKey, KeyID: "kc-2", Algorithm: "RS256", Use: "sig"},
		"ec-1":  {Key: &ecKey.PublicKey, KeyID: "ec-1", Algorithm: "ES256", Use: "sig"},
		"other": {Key: &attackR.PublicKey, KeyID: "other", Algorithm: "RS256", Use: "sig"},
	}
}

func newValidator(t *testing.T, r logouttoken.ReplayCache) *logouttoken.Validator {
	t.Helper()
	v, err := logouttoken.NewValidator(logouttoken.Config{
		Issuer: kcIss, ClientID: clientID,
		Now:  func() time.Time { return now },
		Keys: keys(), Replay: r,
	})
	if err != nil {
		t.Fatalf("NewValidator: %v", err)
	}
	return v
}

// ---- token building ----

type claims = map[string]any

var jtiSeq atomic.Int64

func base() claims {
	return claims{
		"iss": kcIss, "aud": clientID, "sub": "user-anna", "sid": "kc-session-1",
		"iat": now.Unix(), "exp": now.Add(time.Minute).Unix(),
		"jti":    fmt.Sprintf("jti-%d", jtiSeq.Add(1)),
		"events": map[string]any{logouttoken.EventBackchannelLogout: map[string]any{}},
		"typ":    "Logout", // Keycloak adds this; harmless
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
	alg jose.SignatureAlgorithm
	key any
	kid string
}

func kcSpec() spec { initKeys(); return spec{alg: jose.RS256, key: kc1, kid: "kc-1"} }

func sign(t *testing.T, s spec, c claims) string {
	t.Helper()
	payload, _ := json.Marshal(c)
	opts := &jose.SignerOptions{}
	if s.kid != "" {
		opts = opts.WithHeader("kid", s.kid)
	}
	opts = opts.WithType("logout+jwt")
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

func ev(v any) map[string]any { return map[string]any{logouttoken.EventBackchannelLogout: v} }

// ---- tests ----

func TestValidateRejects(t *testing.T) {
	initKeys()
	pubJSON, _ := json.Marshal(jose.JSONWebKey{Key: &kc1.PublicKey, KeyID: "kc-1"})
	sg := func(c claims) func(*testing.T) string {
		return func(t *testing.T) string { return sign(t, kcSpec(), c) }
	}

	cases := []struct {
		name string
		tok  func(t *testing.T) string
		want logouttoken.Reason
	}{
		// malformed
		{"empty", func(*testing.T) string { return "" }, logouttoken.ReasonMalformed},
		{"two segments", func(*testing.T) string { return "eyJhbGciOiJSUzI1NiJ9.e30" }, logouttoken.ReasonMalformed},
		{"garbage", func(*testing.T) string { return "!!.@@.##" }, logouttoken.ReasonMalformed},
		{"oversized (16 KiB claim)", sg(with(base(), "pad", strings.Repeat("a", 16<<10))), logouttoken.ReasonMalformed},
		{"iat is a string", sg(with(base(), "iat", "now")), logouttoken.ReasonMalformed},

		// alg pinning
		{"alg none", func(*testing.T) string {
			return unsigned(map[string]any{"alg": "none", "kid": "kc-1"}, base())
		}, logouttoken.ReasonAlgNotAllowed},
		{"HS256 keyed with Keycloak's public JWK", func(t *testing.T) string {
			return sign(t, spec{alg: jose.HS256, key: pubJSON, kid: "kc-1"}, base())
		}, logouttoken.ReasonAlgNotAllowed},
		{"PS256 with the right key", func(t *testing.T) string {
			return sign(t, spec{alg: jose.PS256, key: kc1, kid: "kc-1"}, base())
		}, logouttoken.ReasonAlgNotAllowed},
		{"ES256 with a key the source knows", func(t *testing.T) string {
			return sign(t, spec{alg: jose.ES256, key: ecKey, kid: "ec-1"}, base())
		}, logouttoken.ReasonAlgNotAllowed},

		// keys and signature
		{"no kid", func(t *testing.T) string { return sign(t, spec{alg: jose.RS256, key: kc1}, base()) }, logouttoken.ReasonKidUnknown},
		{"unknown kid", func(t *testing.T) string { return sign(t, spec{alg: jose.RS256, key: kc1, kid: "kc-9"}, base()) }, logouttoken.ReasonKidUnknown},
		{"right kid, attacker's key", func(t *testing.T) string {
			return sign(t, spec{alg: jose.RS256, key: attackR, kid: "kc-1"}, base())
		}, logouttoken.ReasonSignatureInvalid},
		{"kid of key 2, signed with key 1", func(t *testing.T) string {
			return sign(t, spec{alg: jose.RS256, key: kc1, kid: "kc-2"}, base())
		}, logouttoken.ReasonSignatureInvalid},
		{"payload tampered (sid swapped)", func(t *testing.T) string {
			c := base()
			ps := parts(sign(t, kcSpec(), c))
			p, _ := json.Marshal(with(c, "sid", "someone-elses-session"))
			return ps[0] + "." + b64.EncodeToString(p) + "." + ps[2]
		}, logouttoken.ReasonSignatureInvalid},
		{"signature stripped", func(t *testing.T) string {
			ps := parts(sign(t, kcSpec(), base()))
			return ps[0] + "." + ps[1] + "."
		}, logouttoken.ReasonSignatureInvalid},

		// issuer and audience
		{"iss missing", sg(with(base(), "iss", nil)), logouttoken.ReasonIssuerMismatch},
		{"iss of another realm", sg(with(base(), "iss", "http://localhost:8080/realms/nordbank")), logouttoken.ReasonIssuerMismatch},
		{"iss with trailing slash", sg(with(base(), "iss", kcIss+"/")), logouttoken.ReasonIssuerMismatch},
		{"aud missing", sg(with(base(), "aud", nil)), logouttoken.ReasonAudienceMismatch},
		{"aud is the other BFF (claims-app)", sg(with(base(), "aud", "claims-app")), logouttoken.ReasonAudienceMismatch},
		{"aud array without us", sg(with(base(), "aud", []string{"claims-app", "policy-api"})), logouttoken.ReasonAudienceMismatch},
		{"aud empty array", sg(with(base(), "aud", []string{})), logouttoken.ReasonAudienceMismatch},

		// required claims and time
		{"iat missing", sg(with(base(), "iat", nil)), logouttoken.ReasonClaimMissing},
		{"jti missing", sg(with(base(), "jti", nil)), logouttoken.ReasonClaimMissing},
		{"jti empty", sg(with(base(), "jti", "")), logouttoken.ReasonClaimMissing},
		{"iat 31 s in the future", sg(with(base(), "iat", now.Add(31*time.Second).Unix())), logouttoken.ReasonIssuedInFuture},
		{"iat older than max age + leeway", sg(with(base(),
			"iat", now.Add(-maxAge-leeway-time.Second).Unix(), "exp", nil)), logouttoken.ReasonTooOld},
		{"expired 31 s ago", sg(with(base(),
			"iat", now.Add(-time.Minute).Unix(), "exp", now.Add(-31*time.Second).Unix())), logouttoken.ReasonExpired},

		// events (cross-JWT confusion)
		{"events missing (an ID token from the same realm)", sg(with(base(), "events", nil)), logouttoken.ReasonEventsInvalid},
		{"events is an array", sg(with(base(), "events", []string{logouttoken.EventBackchannelLogout})), logouttoken.ReasonEventsInvalid},
		{"events is a string", sg(with(base(), "events", logouttoken.EventBackchannelLogout)), logouttoken.ReasonEventsInvalid},
		{"events lacks the logout member", sg(with(base(), "events", map[string]any{"http://schemas.openid.net/event/other": map[string]any{}})), logouttoken.ReasonEventsInvalid},
		{"logout member is true, not an object", sg(with(base(), "events", ev(true))), logouttoken.ReasonEventsInvalid},
		{"logout member is null", sg(with(base(), "events", ev(nil))), logouttoken.ReasonEventsInvalid},

		// nonce, sid
		{"nonce present", sg(with(base(), "nonce", "n-1")), logouttoken.ReasonNoncePresent},
		{"nonce present but empty", sg(with(base(), "nonce", "")), logouttoken.ReasonNoncePresent},
		{"sid missing (sub only)", sg(with(base(), "sid", nil)), logouttoken.ReasonSIDMissing},
		{"sid empty", sg(with(base(), "sid", "")), logouttoken.ReasonSIDMissing},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := newReplay()
			_, err := newValidator(t, r).Validate(context.Background(), tc.tok(t))
			if got := logouttoken.ReasonOf(err); got != tc.want {
				t.Fatalf("reason = %q (err %v), want %q", got, err, tc.want)
			}
			var le *logouttoken.Error
			if !errors.As(err, &le) {
				t.Fatalf("error %T is not *logouttoken.Error", err)
			}
			if r.count() != 0 {
				t.Fatal("a rejected token recorded its jti: a forgery could burn a real jti")
			}
		})
	}
}

func TestValidateAccepts(t *testing.T) {
	cases := []struct {
		name string
		c    claims
		s    func() spec
	}{
		{"typical Keycloak token", base(), kcSpec},
		{"no exp (optional)", with(base(), "exp", nil), kcSpec},
		{"no sub (sid is enough)", with(base(), "sub", nil), kcSpec},
		{"aud array containing us", with(base(), "aud", []string{"claims-app", clientID}), kcSpec},
		{"extra events member", with(base(), "events", map[string]any{
			logouttoken.EventBackchannelLogout:      map[string]any{},
			"http://schemas.openid.net/event/other": map[string]any{},
		}), kcSpec},
		{"iat 29 s in the future (leeway)", with(base(), "iat", now.Add(29*time.Second).Unix()), kcSpec},
		{"iat at max age + leeway - 1 s", with(base(), "iat", now.Add(-maxAge-leeway+time.Second).Unix(), "exp", nil), kcSpec},
		{"expired 29 s ago (leeway)", with(base(), "iat", now.Add(-time.Minute).Unix(), "exp", now.Add(-29*time.Second).Unix()), kcSpec},
		{"second realm key", base(), func() spec { initKeys(); return spec{alg: jose.RS256, key: kc2, kid: "kc-2"} }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := newReplay()
			got, err := newValidator(t, r).Validate(context.Background(), sign(t, tc.s(), tc.c))
			if err != nil {
				t.Fatalf("rejected: %v", err)
			}
			want := logouttoken.Claims{
				Issuer: kcIss, SID: "kc-session-1", JTI: tc.c["jti"].(string),
				IssuedAt: time.Unix(tc.c["iat"].(int64), 0),
			}
			if s, ok := tc.c["sub"].(string); ok {
				want.Subject = s
			}
			if got.Issuer != want.Issuer || got.Subject != want.Subject || got.SID != want.SID ||
				got.JTI != want.JTI || !got.IssuedAt.Equal(want.IssuedAt) {
				t.Fatalf("claims = %+v, want %+v", got, want)
			}
			if r.count() != 1 {
				t.Fatalf("replay entries = %d, want 1", r.count())
			}
		})
	}
}

func TestReplayIsRejectedAndKeyedByIssuer(t *testing.T) {
	r := newReplay()
	v := newValidator(t, r)
	c := base()
	tok := sign(t, kcSpec(), c)

	if _, err := v.Validate(context.Background(), tok); err != nil {
		t.Fatalf("first: %v", err)
	}
	_, err := v.Validate(context.Background(), tok)
	if got := logouttoken.ReasonOf(err); got != logouttoken.ReasonJTIReplayed {
		t.Fatalf("second: reason %q, want jti_replayed", got)
	}
	wantKey := kcIss + "|" + c["jti"].(string)
	ttl, ok := r.seen[wantKey]
	if !ok {
		t.Fatalf("replay key not %q; have %v", wantKey, r.seen)
	}
	// Acceptable until iat + MaxAge + Leeway: the jti must be remembered
	// at least that long, or it could be replayed after the entry expires.
	if min := maxAge + leeway; ttl < min {
		t.Fatalf("replay ttl = %v, want >= %v", ttl, min)
	}
}

func TestReplayTTLCoversFutureIat(t *testing.T) {
	r := newReplay()
	c := with(base(), "iat", now.Add(20*time.Second).Unix())
	if _, err := newValidator(t, r).Validate(context.Background(), sign(t, kcSpec(), c)); err != nil {
		t.Fatal(err)
	}
	ttl := r.seen[kcIss+"|"+c["jti"].(string)]
	if min := 20*time.Second + maxAge + leeway; ttl < min {
		t.Fatalf("replay ttl = %v, want >= %v (iat + MaxAge + Leeway - now)", ttl, min)
	}
}

func TestReplayStoreErrorFailsClosed(t *testing.T) {
	r := newReplay()
	r.err = errors.New("redis down")
	_, err := newValidator(t, r).Validate(context.Background(), sign(t, kcSpec(), base()))
	if got := logouttoken.ReasonOf(err); got != logouttoken.ReasonReplayUnavailable {
		t.Fatalf("reason %q, want replay_unavailable", got)
	}
}

func TestConcurrentReplayOnlyOneWins(t *testing.T) {
	r := newReplay()
	v := newValidator(t, r)
	tok := sign(t, kcSpec(), base())
	var ok atomic.Int64
	var wg sync.WaitGroup
	for range 20 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := v.Validate(context.Background(), tok); err == nil {
				ok.Add(1)
			}
		}()
	}
	wg.Wait()
	if ok.Load() != 1 {
		t.Fatalf("%d of 20 concurrent validations succeeded, want 1", ok.Load())
	}
}

func TestNewValidatorRefusesWeakConfig(t *testing.T) {
	good := logouttoken.Config{Issuer: kcIss, ClientID: clientID, Keys: keys(), Replay: newReplay()}
	for name, mut := range map[string]func(*logouttoken.Config){
		"empty issuer": func(c *logouttoken.Config) { c.Issuer = "" },
		"empty client": func(c *logouttoken.Config) { c.ClientID = "" },
		"nil keys":     func(c *logouttoken.Config) { c.Keys = nil },
		"nil replay":   func(c *logouttoken.Config) { c.Replay = nil },
		"alg none":     func(c *logouttoken.Config) { c.Alg = "none" },
		"alg HS256":    func(c *logouttoken.Config) { c.Alg = jose.HS256 },
		"alg HS512":    func(c *logouttoken.Config) { c.Alg = jose.HS512 },
	} {
		cfg := good
		mut(&cfg)
		if _, err := logouttoken.NewValidator(cfg); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if _, err := logouttoken.NewValidator(good); err != nil {
		t.Fatalf("good config refused: %v", err)
	}
}

func TestErrorsNeverContainTheToken(t *testing.T) {
	tok := sign(t, kcSpec(), with(base(), "nonce", "x"))
	_, err := newValidator(t, newReplay()).Validate(context.Background(), tok)
	if err == nil || strings.Contains(err.Error(), tok) || strings.Contains(err.Error(), parts(tok)[1]) {
		t.Fatalf("error leaks the token: %v", err)
	}
}
