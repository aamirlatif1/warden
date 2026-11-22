package introspect_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/aamirlatif1/warden/internal/authn"
	"github.com/aamirlatif1/warden/internal/policy/adapters/introspect"
	"github.com/aamirlatif1/warden/internal/policy/app"
)

var _ app.Introspector = (*introspect.Client)(nil)

func server(t *testing.T, status int, body string, seen *http.Request) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		*seen = *r
		w.WriteHeader(status)
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(srv.Close)
	return srv
}

func ctxWith(raw string) context.Context {
	return authn.WithRawToken(context.Background(), raw)
}

var ben = authn.Principal{Subject: "sub-ben", Issuer: "http://kc"}

func TestActive(t *testing.T) {
	var seen http.Request
	srv := server(t, 200, `{"active":true,"sub":"sub-ben"}`, &seen)
	c := introspect.New(map[string]introspect.Endpoint{"http://kc": {URL: srv.URL, ClientID: "policy-api", Secret: "s"}}, nil)

	ok, err := c.Active(ctxWith("the.raw.token"), ben)
	if err != nil || !ok {
		t.Fatalf("Active = %v, %v", ok, err)
	}
	user, pass, _ := seen.BasicAuth()
	if user != "policy-api" || pass != "s" || seen.PostForm.Get("token") != "the.raw.token" || seen.PostForm.Get("token_type_hint") != "access_token" {
		t.Fatalf("request: basic %s:%s form %v", user, pass, seen.PostForm)
	}
}

func TestFailsClosed(t *testing.T) {
	var seen http.Request
	cases := []struct {
		name   string
		status int
		body   string
		p      authn.Principal
		ctx    context.Context
		active bool
		err    bool
	}{
		{"inactive", 200, `{"active":false}`, ben, ctxWith("t"), false, false},
		{"401 from issuer", 401, `{"error":"invalid_client"}`, ben, ctxWith("t"), false, true},
		{"garbage body", 200, `<html>`, ben, ctxWith("t"), false, true},
		{"subject mismatch", 200, `{"active":true,"sub":"sub-anna"}`, ben, ctxWith("t"), false, true},
		{"no raw token in ctx", 200, `{"active":true}`, ben, context.Background(), false, true},
		{"unknown issuer", 200, `{"active":true}`, authn.Principal{Subject: "x", Issuer: "http://evil"}, ctxWith("t"), false, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srv := server(t, tc.status, tc.body, &seen)
			c := introspect.New(map[string]introspect.Endpoint{"http://kc": {URL: srv.URL}}, nil)
			ok, err := c.Active(tc.ctx, tc.p)
			if ok != tc.active || (err != nil) != tc.err {
				t.Fatalf("Active = %v, %v", ok, err)
			}
		})
	}
}

func TestTimeout(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { time.Sleep(500 * time.Millisecond) }))
	t.Cleanup(srv.Close)
	c := introspect.New(map[string]introspect.Endpoint{"http://kc": {URL: srv.URL}}, &http.Client{Timeout: 50 * time.Millisecond})
	if ok, err := c.Active(ctxWith("t"), ben); ok || err == nil {
		t.Fatalf("Active = %v, %v", ok, err)
	}
}
