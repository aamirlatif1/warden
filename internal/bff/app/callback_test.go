package app_test

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/aamirlatif1/warden/internal/bff/app"
	"github.com/aamirlatif1/warden/internal/bff/domain"
)

var quiet = slog.New(slog.NewTextHandler(io.Discard, nil))

type authFixture struct {
	auth     *app.AuthService
	oidc     *fakeOIDC
	sessions *memSessions
	txs      *memTxs
	clk      *clock
}

func newAuth() authFixture {
	clk := &clock{t: t0}
	o := &fakeOIDC{clk: clk, claims: app.IDClaims{Subject: "sub-anna", Username: "anna", ACR: "1", SID: "kc-sid-1", AuthTime: t0}}
	s, tx := newMemSessions(), newMemTxs()
	return authFixture{
		auth: app.NewAuthService(o, s, tx, quiet, app.AuthConfig{Now: clk.Now}),
		oidc: o, sessions: s, txs: tx, clk: clk,
	}
}

// login runs /login and returns the tx cookie and the state the IdP will echo.
func (f authFixture) login(t *testing.T, req app.LoginRequest) (txID, state string) {
	t.Helper()
	txID, url, err := f.auth.Login(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	p := f.oidc.lastAuth()
	if !strings.Contains(url, p.State) {
		t.Fatalf("redirect %q does not carry state", url)
	}
	return txID, p.State
}

func (f authFixture) callback(req app.CallbackRequest) (app.CallbackResult, error) {
	return f.auth.Callback(context.Background(), req)
}

func reasonOf(err error) app.LoginReason {
	var le *app.LoginError
	if errors.As(err, &le) {
		return le.Reason
	}
	return "<not a LoginError>"
}

func TestCallbackSuccess(t *testing.T) {
	f := newAuth()
	ctx := context.Background()

	prior := domain.Session{ID: "attacker-planted-sid", Subject: "sub-anna"}
	_ = f.sessions.Create(ctx, prior)

	tx, state := f.login(t, app.LoginRequest{ReturnTo: "/policies"})
	res, err := f.callback(app.CallbackRequest{TxID: tx, State: state, Code: "good-code", PriorSID: prior.ID})
	if err != nil {
		t.Fatal(err)
	}
	s := res.Session

	// D10: a fresh session ID; the planted one is gone.
	if s.ID == "" || s.ID == prior.ID || s.ID == tx || len(s.ID) < 43 {
		t.Fatalf("session ID %q is not fresh", s.ID)
	}
	if _, err := f.sessions.Get(ctx, prior.ID); !errors.Is(err, domain.ErrNoSession) {
		t.Fatal("prior session not deleted (session fixation)")
	}
	stored, err := f.sessions.Get(ctx, s.ID)
	if err != nil {
		t.Fatalf("new session not stored: %v", err)
	}
	if stored.Subject != "sub-anna" || stored.Username != "anna" || stored.KeycloakSID != "kc-sid-1" || stored.ACR != "1" ||
		stored.AccessToken != "at-0" || stored.RefreshToken != "rt-0" || stored.IDToken != "id-0" ||
		stored.CSRFToken == "" || stored.CSRFToken == s.ID || !stored.AuthTime.Equal(t0) || stored.AccessExpiry.IsZero() || stored.CreatedAt.IsZero() {
		t.Fatalf("stored session = %+v", stored)
	}
	if res.ReturnTo != "/policies" || res.Pending != nil {
		t.Fatalf("result = %+v", res)
	}
	// PKCE: the verifier presented at the token endpoint matched the challenge
	// (the fake IdP would have refused otherwise).
	if len(f.oidc.verifiers) != 1 || f.oidc.verifiers[0] == "" {
		t.Fatalf("verifiers = %v", f.oidc.verifiers)
	}
}

func TestCallbackRejects(t *testing.T) {
	cases := []struct {
		name  string
		setup func(f authFixture)
		req   func(tx, state string) app.CallbackRequest
		want  app.LoginReason
	}{
		{"IdP returned an error", nil,
			func(tx, state string) app.CallbackRequest {
				return app.CallbackRequest{TxID: tx, State: state, Error: "access_denied"}
			}, app.ReasonIdPError},
		{"no preauth cookie", nil,
			func(_, state string) app.CallbackRequest { return app.CallbackRequest{State: state, Code: "good-code"} }, app.ReasonTxMissing},
		{"unknown preauth cookie", nil,
			func(_, state string) app.CallbackRequest {
				return app.CallbackRequest{TxID: "forged", State: state, Code: "good-code"}
			}, app.ReasonTxMissing},
		{"transaction expired", func(f authFixture) { f.clk.Advance(11 * time.Minute) },
			func(tx, state string) app.CallbackRequest {
				return app.CallbackRequest{TxID: tx, State: state, Code: "good-code"}
			}, app.ReasonTxExpired},
		{"state mismatch (login CSRF)", nil,
			func(tx, _ string) app.CallbackRequest {
				return app.CallbackRequest{TxID: tx, State: "attacker-state", Code: "good-code"}
			}, app.ReasonStateMismatch},
		{"empty state", nil,
			func(tx, _ string) app.CallbackRequest { return app.CallbackRequest{TxID: tx, Code: "good-code"} }, app.ReasonStateMismatch},
		{"no code", nil,
			func(tx, state string) app.CallbackRequest { return app.CallbackRequest{TxID: tx, State: state} }, app.ReasonCodeMissing},
		{"code rejected by the IdP", nil,
			func(tx, state string) app.CallbackRequest {
				return app.CallbackRequest{TxID: tx, State: state, Code: "stolen-code"}
			}, app.ReasonExchangeFailed},
		{"token endpoint down", func(f authFixture) { f.oidc.exchangeErr = errors.New("connection refused") },
			func(tx, state string) app.CallbackRequest {
				return app.CallbackRequest{TxID: tx, State: state, Code: "good-code"}
			}, app.ReasonExchangeFailed},
		{"ID token invalid", func(f authFixture) { f.oidc.idTokenErr = errors.New("bad signature") },
			func(tx, state string) app.CallbackRequest {
				return app.CallbackRequest{TxID: tx, State: state, Code: "good-code"}
			}, app.ReasonIDTokenInvalid},
		{"nonce mismatch (ID token injection)", func(f authFixture) { f.oidc.overrideNonce = true; f.oidc.claims.Nonce = "other-nonce" },
			func(tx, state string) app.CallbackRequest {
				return app.CallbackRequest{TxID: tx, State: state, Code: "good-code"}
			}, app.ReasonNonceMismatch},
		{"ID token without nonce", func(f authFixture) { f.oidc.overrideNonce = true; f.oidc.claims.Nonce = "" },
			func(tx, state string) app.CallbackRequest {
				return app.CallbackRequest{TxID: tx, State: state, Code: "good-code"}
			}, app.ReasonNonceMismatch},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newAuth()
			tx, state := f.login(t, app.LoginRequest{})
			if tc.setup != nil {
				tc.setup(f)
			}
			_, err := f.callback(tc.req(tx, state))
			if got := reasonOf(err); got != tc.want {
				t.Fatalf("reason = %q, want %q (err %v)", got, tc.want, err)
			}
			if f.sessions.count() != 0 {
				t.Fatal("a failed callback created a session")
			}
			for _, secret := range []string{"at-0", "rt-0", "id-0", "good-code"} {
				if strings.Contains(err.Error(), secret) {
					t.Fatalf("error leaks %q: %v", secret, err)
				}
			}
		})
	}
}

func TestCallbackIsSingleUse(t *testing.T) {
	f := newAuth()
	tx, state := f.login(t, app.LoginRequest{})
	if _, err := f.callback(app.CallbackRequest{TxID: tx, State: state, Code: "good-code"}); err != nil {
		t.Fatal(err)
	}
	_, err := f.callback(app.CallbackRequest{TxID: tx, State: state, Code: "good-code"})
	if reasonOf(err) != app.ReasonTxMissing {
		t.Fatalf("replayed callback: %v", err)
	}
}

// An IdP error still burns the transaction: the attacker can't retry the
// same state with a code of their choosing afterwards.
func TestIdPErrorConsumesTransaction(t *testing.T) {
	f := newAuth()
	tx, state := f.login(t, app.LoginRequest{})
	_, _ = f.callback(app.CallbackRequest{TxID: tx, State: state, Error: "access_denied"})
	if _, err := f.callback(app.CallbackRequest{TxID: tx, State: state, Code: "good-code"}); reasonOf(err) != app.ReasonTxMissing {
		t.Fatalf("transaction survived an IdP error: %v", err)
	}
}

func TestCallbackStepUp(t *testing.T) {
	gold := app.LoginRequest{ACRValues: "gold", MaxAge: 5 * time.Minute}
	cases := []struct {
		name    string
		acr     string
		authAgo time.Duration
		wantErr bool
	}{
		{"gold, fresh", "gold", 10 * time.Second, false},
		{"acr 2, fresh", "2", 10 * time.Second, false},
		{"IdP returned acr 1", "1", 10 * time.Second, true},
		{"IdP returned silver", "silver", 10 * time.Second, true},
		{"no acr", "", 10 * time.Second, true},
		{"gold but auth too old", "gold", 10 * time.Minute, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newAuth()
			f.oidc.claims.ACR = tc.acr
			f.oidc.claims.AuthTime = t0.Add(-tc.authAgo)
			tx, state := f.login(t, gold)
			if p := f.oidc.lastAuth(); p.ACRValues != "gold" || p.MaxAge != 5*time.Minute {
				t.Fatalf("auth request did not ask for step-up: %+v", p)
			}
			res, err := f.callback(app.CallbackRequest{TxID: tx, State: state, Code: "good-code"})
			if tc.wantErr {
				if reasonOf(err) != app.ReasonACRInsufficient {
					t.Fatalf("err = %v, want acr_insufficient", err)
				}
				return
			}
			if err != nil || res.Session.ACR != tc.acr {
				t.Fatalf("res = %+v, err = %v", res, err)
			}
		})
	}
}

// Without step-up, a low acr is fine (ordinary login).
func TestOrdinaryLoginAcceptsLowACR(t *testing.T) {
	f := newAuth()
	f.oidc.claims.ACR = "1"
	f.oidc.claims.AuthTime = t0.Add(-time.Hour)
	tx, state := f.login(t, app.LoginRequest{})
	if _, err := f.callback(app.CallbackRequest{TxID: tx, State: state, Code: "good-code"}); err != nil {
		t.Fatal(err)
	}
}

func TestPendingActionOnlyForSameSubject(t *testing.T) {
	pending := &domain.PendingAction{Kind: domain.PendingUpdatePayout, PolicyID: "pol_anna_travel", IBAN: "DE89370400440532013000"}
	for _, tc := range []struct {
		name, loggedIn string
		wantPending    bool
	}{
		{"same user steps up", "sub-anna", true},
		{"someone else logs in", "sub-bob", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newAuth()
			f.oidc.claims.Subject = tc.loggedIn
			f.oidc.claims.ACR = "gold"
			tx, state := f.login(t, app.LoginRequest{ACRValues: "gold", MaxAge: 5 * time.Minute, Pending: pending, PendingSubject: "sub-anna"})
			res, err := f.callback(app.CallbackRequest{TxID: tx, State: state, Code: "good-code"})
			if err != nil {
				t.Fatal(err)
			}
			if (res.Pending != nil) != tc.wantPending {
				t.Fatalf("Pending = %+v, want present=%v", res.Pending, tc.wantPending)
			}
			if tc.wantPending && *res.Pending != *pending {
				t.Fatalf("Pending = %+v", res.Pending)
			}
		})
	}
}

func TestEachLoginGetsDistinctSessionAndCSRF(t *testing.T) {
	f := newAuth()
	seen := map[string]bool{}
	for range 20 {
		tx, state := f.login(t, app.LoginRequest{})
		res, err := f.callback(app.CallbackRequest{TxID: tx, State: state, Code: "good-code"})
		if err != nil {
			t.Fatal(err)
		}
		for _, v := range []string{res.Session.ID, res.Session.CSRFToken} {
			if seen[v] {
				t.Fatal("session ID or CSRF token repeated")
			}
			seen[v] = true
		}
	}
}

// ---- Login (delegated) ----

func TestLoginTransaction(t *testing.T) {
	f := newAuth()
	tx, _ := f.login(t, app.LoginRequest{ReturnTo: "/x"})
	p := f.oidc.lastAuth()
	stored := f.txs.m[tx]
	if p.State != stored.State || p.Nonce != stored.Nonce || p.CodeChallenge != s256(stored.Verifier) {
		t.Fatal("authorization request does not match the stored transaction")
	}
	if p.State == p.Nonce || stored.Verifier == p.CodeChallenge || len(stored.Verifier) < 43 {
		t.Fatal("state/nonce/verifier not independent or too short")
	}
}

func TestSafeReturnTo(t *testing.T) {
	cases := map[string]string{
		"":                     "/",
		"/policies":            "/policies",
		"/policies?x=1":        "/policies?x=1",
		"//evil.example":       "/",
		"/\\evil.example":      "/",
		"https://evil.example": "/",
		"javascript:alert(1)":  "/",
		"/x\r\nSet-Cookie: a":  "/",
		"policies":             "/",
	}
	for in, want := range cases {
		if got := app.SafeReturnTo(in); got != want {
			t.Errorf("SafeReturnTo(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestLogout(t *testing.T) {
	f := newAuth()
	ctx := context.Background()
	_ = f.sessions.Create(ctx, domain.Session{ID: "s1", IDToken: "id-xyz", Subject: "sub-anna"})
	url, err := f.auth.Logout(ctx, "s1", "http://localhost:8082/")
	if err != nil || !strings.Contains(url, "hint=id-xyz") {
		t.Fatalf("url = %q, err = %v", url, err)
	}
	if _, err := f.sessions.Get(ctx, "s1"); !errors.Is(err, domain.ErrNoSession) {
		t.Fatal("session survived logout")
	}
	if url, _ := f.auth.Logout(ctx, "gone", "http://localhost:8082/"); url != "http://localhost:8082/" {
		t.Fatalf("logout without session: %q", url)
	}
}

// Defence in depth: a stored transaction with an empty state or nonce (a
// corrupt record, or a future bug in Login) must not match an empty value
// from the request or the ID token. "" == "" is not a match.
func TestEmptyValuesNeverMatch(t *testing.T) {
	t.Run("empty state on both sides", func(t *testing.T) {
		f := newAuth()
		_ = f.txs.Put(context.Background(), domain.LoginTx{ID: "tx1", State: "", Nonce: "n", Verifier: "v", CreatedAt: t0}, time.Minute)
		_, err := f.callback(app.CallbackRequest{TxID: "tx1", State: "", Code: "good-code"})
		if reasonOf(err) != app.ReasonStateMismatch {
			t.Fatalf("err = %v, want state_mismatch", err)
		}
	})
	t.Run("empty nonce on both sides", func(t *testing.T) {
		f := newAuth()
		verifier := strings.Repeat("v", 43)
		_ = f.txs.Put(context.Background(), domain.LoginTx{ID: "tx1", State: "st", Nonce: "", Verifier: verifier, CreatedAt: t0}, time.Minute)
		f.oidc.auth = append(f.oidc.auth, app.AuthParams{State: "st", CodeChallenge: s256(verifier)})
		f.oidc.overrideNonce = true
		f.oidc.claims.Nonce = ""
		_, err := f.callback(app.CallbackRequest{TxID: "tx1", State: "st", Code: "good-code"})
		if reasonOf(err) != app.ReasonNonceMismatch {
			t.Fatalf("err = %v, want nonce_mismatch", err)
		}
	})
}
