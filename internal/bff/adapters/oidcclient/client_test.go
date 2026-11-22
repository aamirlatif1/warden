package oidcclient_test

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"

	"github.com/aamirlatif1/warden/internal/bff/adapters/oidcclient"
	"github.com/aamirlatif1/warden/internal/bff/app"
)

// fakeOP is a minimal OpenID Provider: discovery, JWKS, token endpoint.
type fakeOP struct {
	srv       *httptest.Server
	key       *rsa.PrivateKey
	mu        sync.Mutex
	challenge string         // S256 challenge to enforce at the token endpoint
	idClaims  map[string]any // claims for the next ID token
}

func newOP(t *testing.T) *fakeOP {
	t.Helper()
	k, _ := rsa.GenerateKey(rand.Reader, 2048)
	op := &fakeOP{key: k}
	mux := http.NewServeMux()
	op.srv = httptest.NewServer(mux)
	t.Cleanup(op.srv.Close)
	iss := op.srv.URL

	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"issuer": iss, "authorization_endpoint": iss + "/auth", "token_endpoint": iss + "/token",
			"jwks_uri": iss + "/jwks", "end_session_endpoint": iss + "/logout",
			"id_token_signing_alg_values_supported": []string{"RS256"},
		})
	})
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: &k.PublicKey, KeyID: "k1", Algorithm: "RS256", Use: "sig"}}})
	})
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		w.Header().Set("Content-Type", "application/json")
		fail := func(code string) {
			w.WriteHeader(400)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": code, "error_description": "secret-detail eyJleak"})
		}
		switch r.PostForm.Get("grant_type") {
		case "authorization_code":
			sum := sha256.Sum256([]byte(r.PostForm.Get("code_verifier")))
			op.mu.Lock()
			ok := base64.RawURLEncoding.EncodeToString(sum[:]) == op.challenge
			op.mu.Unlock()
			if !ok {
				fail("invalid_grant")
				return
			}
		case "refresh_token":
			if r.PostForm.Get("refresh_token") != "rt-good" {
				fail("invalid_grant")
				return
			}
		default:
			fail("unsupported_grant_type")
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"access_token": "at-new", "refresh_token": "rt-new", "token_type": "Bearer",
			"expires_in": 300, "id_token": op.idToken(t, nil),
		})
	})
	return op
}

func (op *fakeOP) idToken(t *testing.T, override map[string]any) string {
	op.mu.Lock()
	c := map[string]any{
		"iss": op.srv.URL, "sub": "sub-anna", "aud": "portal-bff", "azp": "portal-bff",
		"exp": time.Now().Add(5 * time.Minute).Unix(), "iat": time.Now().Unix(),
		"nonce": "n1", "acr": "gold", "sid": "kc-sid", "auth_time": time.Now().Unix(), "preferred_username": "anna",
	}
	for k, v := range op.idClaims {
		c[k] = v
	}
	op.mu.Unlock()
	for k, v := range override {
		c[k] = v
	}
	s, _ := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: op.key}, (&jose.SignerOptions{}).WithHeader("kid", "k1"))
	b, _ := json.Marshal(c)
	obj, _ := s.Sign(b)
	out, _ := obj.CompactSerialize()
	return out
}

func newClient(t *testing.T, op *fakeOP) *oidcclient.Client {
	t.Helper()
	c, err := oidcclient.New(context.Background(), oidcclient.Config{
		Issuer: op.srv.URL, ClientID: "portal-bff", ClientSecret: "s", RedirectURL: "http://localhost:8082/callback",
	})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestAuthURL(t *testing.T) {
	op := newOP(t)
	c := newClient(t, op)
	u, _ := url.Parse(c.AuthURL(app.AuthParams{State: "st", Nonce: "n1", CodeChallenge: "ch", ACRValues: "gold", MaxAge: 5 * time.Minute}))
	q := u.Query()
	want := map[string]string{
		"response_type": "code", "client_id": "portal-bff", "redirect_uri": "http://localhost:8082/callback",
		"state": "st", "nonce": "n1", "code_challenge": "ch", "code_challenge_method": "S256",
		"acr_values": "gold", "max_age": "300",
	}
	for k, v := range want {
		if q.Get(k) != v {
			t.Errorf("%s = %q, want %q", k, q.Get(k), v)
		}
	}
	if !strings.Contains(q.Get("scope"), "openid") {
		t.Errorf("scope = %q", q.Get("scope"))
	}
	plain, _ := url.Parse(c.AuthURL(app.AuthParams{State: "st"}))
	if plain.Query().Has("acr_values") || plain.Query().Has("max_age") || plain.Query().Has("kc_idp_hint") {
		t.Error("step-up or broker params sent on an ordinary login")
	}
	broker, _ := url.Parse(c.AuthURL(app.AuthParams{State: "st", IDPHint: "nordbank"}))
	if got := broker.Query().Get("kc_idp_hint"); got != "nordbank" {
		t.Errorf("kc_idp_hint = %q, want nordbank", got)
	}
}

func TestExchangeSendsVerifier(t *testing.T) {
	op := newOP(t)
	c := newClient(t, op)
	verifier := strings.Repeat("v", 43)
	sum := sha256.Sum256([]byte(verifier))
	op.challenge = base64.RawURLEncoding.EncodeToString(sum[:])

	tok, err := c.Exchange(context.Background(), "code", verifier)
	if err != nil {
		t.Fatal(err)
	}
	if tok.AccessToken != "at-new" || tok.RefreshToken != "rt-new" || tok.IDToken == "" || tok.Expiry.IsZero() {
		t.Fatalf("tokens = %+v", tok)
	}
	_, err = c.Exchange(context.Background(), "code", "wrong-verifier")
	if err == nil {
		t.Fatal("exchange succeeded with the wrong verifier")
	}
	if strings.Contains(err.Error(), "eyJleak") || strings.Contains(err.Error(), "secret-detail") {
		t.Fatalf("error leaks the response body: %v", err)
	}
}

func TestVerifyIDToken(t *testing.T) {
	op := newOP(t)
	c := newClient(t, op)
	ctx := context.Background()

	cl, err := c.VerifyIDToken(ctx, op.idToken(t, nil))
	if err != nil {
		t.Fatal(err)
	}
	if cl.Subject != "sub-anna" || cl.Nonce != "n1" || cl.ACR != "gold" || cl.SID != "kc-sid" || cl.Username != "anna" || cl.AuthTime.IsZero() {
		t.Fatalf("claims = %+v", cl)
	}

	bad := map[string]map[string]any{
		"wrong aud":          {"aud": "claims-app", "azp": "claims-app"},
		"azp another client": {"aud": []string{"portal-bff", "claims-app"}, "azp": "claims-app"},
		"expired":            {"exp": time.Now().Add(-time.Hour).Unix()},
		"wrong issuer":       {"iss": "http://evil"},
	}
	for name, o := range bad {
		if _, err := c.VerifyIDToken(ctx, op.idToken(t, o)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	other, _ := rsa.GenerateKey(rand.Reader, 2048)
	s, _ := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: other}, (&jose.SignerOptions{}).WithHeader("kid", "k1"))
	b, _ := json.Marshal(map[string]any{"iss": op.srv.URL, "sub": "x", "aud": "portal-bff", "exp": time.Now().Add(time.Hour).Unix(), "iat": time.Now().Unix()})
	obj, _ := s.Sign(b)
	forged, _ := obj.CompactSerialize()
	if _, err := c.VerifyIDToken(ctx, forged); err == nil {
		t.Error("forged signature accepted")
	}
}

func TestRefresh(t *testing.T) {
	op := newOP(t)
	c := newClient(t, op)
	tok, err := c.Refresh(context.Background(), "rt-good")
	if err != nil || tok.AccessToken != "at-new" || tok.RefreshToken != "rt-new" {
		t.Fatalf("Refresh = %+v, %v", tok, err)
	}
	if _, err := c.Refresh(context.Background(), "rt-reused"); !errors.Is(err, app.ErrInvalidGrant) {
		t.Fatalf("err = %v, want ErrInvalidGrant", err)
	}
}

func TestEndSessionURL(t *testing.T) {
	op := newOP(t)
	c := newClient(t, op)
	u, _ := url.Parse(c.EndSessionURL("id-tok", "http://localhost:8082/"))
	q := u.Query()
	if u.Path != "/logout" || q.Get("id_token_hint") != "id-tok" || q.Get("post_logout_redirect_uri") != "http://localhost:8082/" || q.Get("client_id") != "portal-bff" {
		t.Fatalf("end session URL = %s", u)
	}
}
