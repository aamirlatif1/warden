package app_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"io"
	"log/slog"
	"sync"
	"testing"
	"time"

	"github.com/aamirlatif1/warden/internal/authn"
	"github.com/aamirlatif1/warden/internal/issuer"
	"github.com/aamirlatif1/warden/internal/issuer/keyring"
	"github.com/aamirlatif1/warden/internal/kms"
	"github.com/aamirlatif1/warden/internal/revocation"
	"github.com/aamirlatif1/warden/internal/sts/app"
	"github.com/aamirlatif1/warden/internal/sts/clientauth"
	"github.com/aamirlatif1/warden/internal/sts/domain"
)

// fakeRevoker stores events and answers like the Redis store.
type fakeRevoker struct {
	mu     sync.Mutex
	set    *revocation.Set
	events []revocation.Event
	err    error
}

func newFakeRevoker() *fakeRevoker { return &fakeRevoker{set: revocation.NewSet(nil)} }

func (f *fakeRevoker) Revoke(_ context.Context, e revocation.Event) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.err != nil {
		return f.err
	}
	f.events = append(f.events, e)
	f.set.Apply(e)
	return nil
}

func (f *fakeRevoker) IsRevoked(_ context.Context, t authn.TokenRef) (bool, error) {
	if f.err != nil {
		return false, f.err
	}
	return f.set.Revoked(t), nil
}

type adminPartners struct {
	mu sync.Mutex
	m  map[string]domain.Partner
}

func (a *adminPartners) Partner(_ context.Context, id string) (domain.Partner, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	p, ok := a.m[id]
	if !ok {
		return domain.Partner{}, domain.ErrNotFound
	}
	return p, nil
}

func (a *adminPartners) SetStatus(_ context.Context, id string, s domain.PartnerStatus) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	p, ok := a.m[id]
	if !ok {
		return domain.ErrNotFound
	}
	p.Status = s
	a.m[id] = p
	return nil
}

type noRotator struct{}

func (noRotator) Rotate(context.Context) (keyring.KeyInfo, error) {
	return keyring.KeyInfo{KID: "k2"}, nil
}
func (noRotator) Keys() []keyring.KeyInfo { return nil }

type lifecycleFixture struct {
	l        *app.Lifecycle
	minter   *issuer.Minter
	revoker  *fakeRevoker
	partners *adminPartners
}

func newLifecycle(t *testing.T, authenticated string) lifecycleFixture {
	t.Helper()
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	s, _ := kms.NewLocalSigner(k)
	m, err := issuer.New(issuer.Config{Issuer: "http://sts", Audience: "policy-api", Keys: issuer.SingleKey{S: s}})
	if err != nil {
		t.Fatal(err)
	}
	r := newFakeRevoker()
	p := &adminPartners{m: map[string]domain.Partner{
		"shopr": {ClientID: "shopr", PartnerID: "shopr", Status: domain.PartnerActive},
		"acme":  {ClientID: "acme", PartnerID: "acme", Status: domain.PartnerActive},
	}}
	v := fakeVerifier{assertion: clientauth.Assertion{ClientID: authenticated}}
	return lifecycleFixture{
		l:      app.NewLifecycle(v, m, r, p, noRotator{}, slog.New(slog.NewTextHandler(io.Discard, nil))),
		minter: m, revoker: r, partners: p,
	}
}

func (f lifecycleFixture) mint(t *testing.T, client string) string {
	t.Helper()
	tok, err := f.minter.Mint(context.Background(), issuer.Grant{ClientID: client, PartnerID: client, Scopes: []string{"quotes:write"}})
	if err != nil {
		t.Fatal(err)
	}
	return tok.Value
}

func revokeReq(token string) app.RevokeRequest {
	return app.RevokeRequest{ClientAssertionType: clientauth.AssertionType, ClientAssertion: "a.b.c", Token: token}
}

func TestRevokeOwnToken(t *testing.T) {
	f := newLifecycle(t, "shopr")
	ctx := context.Background()
	tok := f.mint(t, "shopr")

	if got, _ := f.l.Introspect(ctx, tok); !got.Active || got.ClientID != "shopr" || got.PartnerID != "shopr" || got.Scope != "quotes:write" {
		t.Fatalf("before revoke: %+v", got)
	}
	if err := f.l.Revoke(ctx, revokeReq(tok)); err != nil {
		t.Fatal(err)
	}
	if len(f.revoker.events) != 1 || f.revoker.events[0].Kind != revocation.KindJTI || f.revoker.events[0].Issuer != "http://sts" {
		t.Fatalf("events = %+v", f.revoker.events)
	}
	if exp := time.Unix(f.revoker.events[0].ExpiresAt, 0); exp.Before(time.Now().Add(4 * time.Minute)) {
		t.Fatalf("denylist entry expires at %v, before the token does", exp)
	}
	got, _ := f.l.Introspect(ctx, tok)
	if got != (app.Introspection{Active: false}) {
		t.Fatalf("after revoke: %+v (inactive must carry no other fields)", got)
	}
}

func TestRevokeRules(t *testing.T) {
	ctx := context.Background()

	t.Run("another client's token is refused", func(t *testing.T) {
		f := newLifecycle(t, "acme")
		err := f.l.Revoke(ctx, revokeReq(f.mint(t, "shopr")))
		var oe *app.OAuthError
		if !errors.As(err, &oe) || oe.Code != app.ErrUnauthorizedClient || len(f.revoker.events) != 0 {
			t.Fatalf("err = %v, events = %d", err, len(f.revoker.events))
		}
	})
	t.Run("garbage token is a silent 200", func(t *testing.T) {
		f := newLifecycle(t, "shopr")
		if err := f.l.Revoke(ctx, revokeReq("not.a.token")); err != nil || len(f.revoker.events) != 0 {
			t.Fatalf("err = %v, events = %d", err, len(f.revoker.events))
		}
	})
	t.Run("no client authentication", func(t *testing.T) {
		f := newLifecycle(t, "shopr")
		r := revokeReq(f.mint(t, "shopr"))
		r.ClientAssertion = ""
		var oe *app.OAuthError
		if err := f.l.Revoke(ctx, r); !errors.As(err, &oe) || oe.Code != app.ErrInvalidClient {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("missing token parameter", func(t *testing.T) {
		f := newLifecycle(t, "shopr")
		var oe *app.OAuthError
		if err := f.l.Revoke(ctx, revokeReq("")); !errors.As(err, &oe) || oe.Code != app.ErrInvalidRequest {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("store down is server_error", func(t *testing.T) {
		f := newLifecycle(t, "shopr")
		f.revoker.err = errors.New("redis down")
		var oe *app.OAuthError
		if err := f.l.Revoke(ctx, revokeReq(f.mint(t, "shopr"))); !errors.As(err, &oe) || oe.Code != app.ErrServerError {
			t.Fatalf("err = %v", err)
		}
	})
}

func TestSuspendAndResume(t *testing.T) {
	f := newLifecycle(t, "shopr")
	ctx := context.Background()
	before := f.mint(t, "shopr")
	other := f.mint(t, "acme")

	if err := f.l.SuspendPartner(ctx, "shopr"); err != nil {
		t.Fatal(err)
	}
	if p, _ := f.partners.Partner(ctx, "shopr"); p.Active() {
		t.Fatal("status not suspended")
	}
	if got, _ := f.l.Introspect(ctx, before); got.Active {
		t.Fatal("D13: token from before the suspension still active")
	}
	if got, _ := f.l.Introspect(ctx, other); !got.Active {
		t.Fatal("suspending shopr affected acme")
	}
	e := f.revoker.events[0]
	if e.Kind != revocation.KindClient || e.Value != "shopr" || time.Unix(e.ExpiresAt, 0).Sub(time.Unix(e.NotBefore, 0)) < 5*time.Minute {
		t.Fatalf("event = %+v (must outlive every token issued before the cut-off)", e)
	}

	if err := f.l.ResumePartner(ctx, "shopr"); err != nil {
		t.Fatal(err)
	}
	if got, _ := f.l.Introspect(ctx, before); got.Active {
		t.Fatal("old token came back to life after resume")
	}
	time.Sleep(1100 * time.Millisecond) // iat has 1 s resolution: next token is after the cut-off
	if got, _ := f.l.Introspect(ctx, f.mint(t, "shopr")); !got.Active {
		t.Fatal("new token after resume is inactive")
	}

	if err := f.l.SuspendPartner(ctx, "ghost"); !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("suspend unknown partner: %v", err)
	}
}

func TestIntrospectInactiveCases(t *testing.T) {
	ctx := context.Background()
	f := newLifecycle(t, "shopr")
	for name, raw := range map[string]string{"garbage": "x.y.z", "empty": ""} {
		if got, err := f.l.Introspect(ctx, raw); err != nil || got.Active {
			t.Errorf("%s: %+v, %v", name, got, err)
		}
	}
	tok := f.mint(t, "shopr")
	delete(f.partners.m, "shopr")
	if got, _ := f.l.Introspect(ctx, tok); got.Active {
		t.Error("token of a deleted partner is active")
	}

	f2 := newLifecycle(t, "shopr")
	tok2 := f2.mint(t, "shopr")
	f2.revoker.err = errors.New("redis down")
	if _, err := f2.l.Introspect(ctx, tok2); err == nil {
		t.Error("store error reported as an answer instead of an error")
	}
}
