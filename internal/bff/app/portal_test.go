package app_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/aamirlatif1/warden/internal/bff/app"
	"github.com/aamirlatif1/warden/internal/bff/domain"
)

type staticTokens struct{ err error }

func (s staticTokens) AccessToken(context.Context, string) (string, error) { return "at", s.err }

type fakeAPI struct {
	err      error
	gotToken string
}

func (f *fakeAPI) ListPolicies(_ context.Context, tok string) ([]app.Policy, error) {
	f.gotToken = tok
	return []app.Policy{{ID: "pol_anna_travel"}}, f.err
}

func (f *fakeAPI) UpdatePayout(_ context.Context, tok, id, iban string) (app.Policy, error) {
	f.gotToken = tok
	return app.Policy{ID: id, PayoutIBANMasked: "****" + iban[len(iban)-4:]}, f.err
}

func newPortal(api *fakeAPI, tokErr error) (*app.Portal, *memSessions) {
	s := newMemSessions()
	_ = s.Create(context.Background(), domain.Session{ID: "s1", Subject: "sub-anna"})
	return app.NewPortal(staticTokens{tokErr}, api, s, quiet), s
}

func TestDashboard(t *testing.T) {
	api := &fakeAPI{}
	p, _ := newPortal(api, nil)
	d, err := p.Dashboard(context.Background(), "s1")
	if err != nil || len(d.Policies) != 1 || d.Session.Subject != "sub-anna" || api.gotToken != "at" {
		t.Fatalf("Dashboard = %+v, %v", d, err)
	}
	if _, err := p.Dashboard(context.Background(), "nope"); !errors.Is(err, domain.ErrNoSession) {
		t.Fatalf("unknown session: %v", err)
	}
}

func TestUpdatePayoutStepUp(t *testing.T) {
	api := &fakeAPI{err: &app.StepUpRequired{ACR: "gold", MaxAge: 5 * time.Minute}}
	p, _ := newPortal(api, nil)
	_, err := p.UpdatePayout(context.Background(), "s1", "pol_anna_travel", "DE89370400440532013000")
	var need *app.StepUpNeeded
	if !errors.As(err, &need) {
		t.Fatalf("err = %v, want StepUpNeeded", err)
	}
	l := need.Login
	if l.ACRValues != "gold" || l.MaxAge != 5*time.Minute || l.PendingSubject != "sub-anna" ||
		l.Pending == nil || l.Pending.PolicyID != "pol_anna_travel" || l.Pending.IBAN != "DE89370400440532013000" || l.Pending.Kind != domain.PendingUpdatePayout {
		t.Fatalf("login request = %+v / %+v", l, l.Pending)
	}
}

func TestAPIUnauthorizedEndsSession(t *testing.T) {
	api := &fakeAPI{err: app.ErrAPIUnauthorized}
	p, s := newPortal(api, nil)
	if _, err := p.UpdatePayout(context.Background(), "s1", "p", "DE89370400440532013000"); !errors.Is(err, app.ErrSessionEnded) {
		t.Fatalf("err = %v", err)
	}
	if s.count() != 0 {
		t.Fatal("session kept after the API rejected its token")
	}
}

func TestOtherErrorsPassThrough(t *testing.T) {
	for _, e := range []error{app.ErrAPIForbidden, app.ErrAPIInvalid, app.ErrAPINotFound} {
		p, s := newPortal(&fakeAPI{err: e}, nil)
		if _, err := p.UpdatePayout(context.Background(), "s1", "p", "DE89370400440532013000"); !errors.Is(err, e) {
			t.Errorf("err = %v, want %v", err, e)
		}
		if s.count() != 1 {
			t.Errorf("%v ended the session", e)
		}
	}
	p, _ := newPortal(&fakeAPI{}, app.ErrSessionEnded)
	if _, err := p.Dashboard(context.Background(), "s1"); !errors.Is(err, app.ErrSessionEnded) {
		t.Errorf("token error not returned: %v", err)
	}
}
