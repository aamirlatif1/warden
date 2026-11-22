package app_test

import (
	"context"
	"errors"
	"testing"

	"github.com/aamirlatif1/warden/internal/bff/app"
	"github.com/aamirlatif1/warden/internal/bff/logouttoken"
)

type fakeLogoutValidator struct {
	claims logouttoken.Claims
	err    error
}

func (f fakeLogoutValidator) Validate(context.Context, string) (logouttoken.Claims, error) {
	return f.claims, f.err
}

type fakeBySID struct {
	sids []string
	n    int
	err  error
}

func (f *fakeBySID) DeleteByKeycloakSID(_ context.Context, sid string) (int, error) {
	f.sids = append(f.sids, sid)
	return f.n, f.err
}

func TestBackchannelDeletesBySID(t *testing.T) {
	s := &fakeBySID{n: 2}
	b := app.NewBackchannel(fakeLogoutValidator{claims: logouttoken.Claims{SID: "kc-sid-1", Subject: "sub-anna"}}, s, quiet)
	if err := b.Logout(context.Background(), "tok"); err != nil {
		t.Fatal(err)
	}
	if len(s.sids) != 1 || s.sids[0] != "kc-sid-1" {
		t.Fatalf("deleted sids = %v", s.sids)
	}
}

func TestBackchannelRejectedTokenDeletesNothing(t *testing.T) {
	s := &fakeBySID{}
	rej := logouttoken.Reject(logouttoken.ReasonSignatureInvalid, nil)
	b := app.NewBackchannel(fakeLogoutValidator{err: rej}, s, quiet)
	err := b.Logout(context.Background(), "tok")
	if logouttoken.ReasonOf(err) != logouttoken.ReasonSignatureInvalid {
		t.Fatalf("err = %v", err)
	}
	if len(s.sids) != 0 {
		t.Fatal("sessions deleted for a rejected token")
	}
}

func TestBackchannelStoreErrorIsReturned(t *testing.T) {
	boom := errors.New("redis down")
	b := app.NewBackchannel(fakeLogoutValidator{claims: logouttoken.Claims{SID: "x"}}, &fakeBySID{err: boom}, quiet)
	if err := b.Logout(context.Background(), "tok"); !errors.Is(err, boom) {
		t.Fatalf("err = %v", err)
	}
}

// ---- adaptive login risk ----

type memDevices struct {
	m   map[string]string
	err error
}

func (d *memDevices) LastCountry(_ context.Context, id string) (string, bool, error) {
	if d.err != nil {
		return "", false, d.err
	}
	c, ok := d.m[id]
	return c, ok, nil
}

func (d *memDevices) Remember(_ context.Context, id, country string) error {
	if d.err != nil {
		return d.err
	}
	d.m[id] = country
	return nil
}

func TestLoginRisk(t *testing.T) {
	ctx := context.Background()
	d := &memDevices{m: map[string]string{}}
	r := app.NewLoginRisk(d, quiet)

	if got := r.ACRValues(ctx, "dev-1", "DE"); got != "gold" {
		t.Fatalf("new device: %q, want gold", got)
	}
	if err := r.Remember(ctx, "dev-1", "DE"); err != nil {
		t.Fatal(err)
	}
	if got := r.ACRValues(ctx, "dev-1", "DE"); got != "" {
		t.Fatalf("known device, same country: %q, want none", got)
	}
	if got := r.ACRValues(ctx, "dev-1", "BR"); got != "gold" {
		t.Fatalf("new country: %q, want gold", got)
	}
	// Header absent at the next login: keep DE, don't forget it.
	if err := r.Remember(ctx, "dev-1", ""); err != nil {
		t.Fatal(err)
	}
	if d.m["dev-1"] != "DE" {
		t.Fatalf("country after a login without header = %q, want DE", d.m["dev-1"])
	}
	if got := r.ACRValues(ctx, "", "DE"); got != "gold" {
		t.Fatalf("no device cookie: %q, want gold", got)
	}
}

func TestLoginRiskStoreErrorFailsTowardsStepUp(t *testing.T) {
	d := &memDevices{m: map[string]string{"dev-1": "DE"}, err: errors.New("redis down")}
	if got := app.NewLoginRisk(d, quiet).ACRValues(context.Background(), "dev-1", "DE"); got != "gold" {
		t.Fatalf("store error: %q, want gold", got)
	}
}
