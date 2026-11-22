package ginauth_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"

	"github.com/aamirlatif1/warden/internal/authn"
	"github.com/aamirlatif1/warden/internal/authn/ginauth"
)

const goodToken = "good.token.sig"

// fakeValidator accepts only goodToken and records what it was given.
type fakeValidator struct{ got []string }

func (f *fakeValidator) Validate(_ context.Context, raw string) (authn.Principal, error) {
	f.got = append(f.got, raw)
	if raw != goodToken {
		return authn.Principal{}, authn.Reject(authn.ReasonSignatureInvalid, "keycloak", nil)
	}
	return authn.Principal{Subject: "user-anna", Issuer: "kc"}, nil
}

func newRouter(v ginauth.TokenValidator, called *bool, seen *authn.Principal) *gin.Engine {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.Use(ginauth.Middleware(v))
	r.GET("/x", func(c *gin.Context) {
		*called = true
		p, ok := authn.FromContext(c.Request.Context())
		raw, rawOK := authn.RawTokenFrom(c.Request.Context())
		if ok && rawOK && raw == goodToken {
			*seen = p
		}
		c.Status(http.StatusOK)
	})
	return r
}

func TestMiddleware(t *testing.T) {
	cases := []struct {
		name       string
		header     []string // Authorization values; nil = absent
		wantStatus int
		wantError  string // expected error= in WWW-Authenticate, "" = must have none
		wantRaw    string // what the validator must receive, "" = not called
	}{
		{"no Authorization header", nil, 401, "", ""},
		{"valid bearer token", []string{"Bearer " + goodToken}, 200, "", goodToken},
		{"scheme is case-insensitive", []string{"bearer " + goodToken}, 200, "", goodToken},
		{"invalid token", []string{"Bearer forged.token.sig"}, 401, "invalid_token", "forged.token.sig"},
		{"Basic scheme", []string{"Basic dXNlcjpwYXNz"}, 401, "invalid_token", ""},
		{"Bearer with no token", []string{"Bearer "}, 401, "invalid_token", ""},
		{"token without scheme", []string{goodToken}, 401, "invalid_token", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fv := &fakeValidator{}
			var called bool
			var seen authn.Principal
			r := newRouter(fv, &called, &seen)

			req := httptest.NewRequest(http.MethodGet, "/x", nil)
			for _, h := range tc.header {
				req.Header.Add("Authorization", h)
			}
			w := httptest.NewRecorder()
			r.ServeHTTP(w, req)

			if w.Code != tc.wantStatus {
				t.Fatalf("status = %d, want %d", w.Code, tc.wantStatus)
			}
			if called != (tc.wantStatus == 200) {
				t.Fatalf("handler called = %v, want %v", called, tc.wantStatus == 200)
			}
			if tc.wantStatus == 200 && seen.Subject != "user-anna" {
				t.Fatalf("principal and raw token not in request context, got %+v", seen)
			}
			if tc.wantRaw != "" && (len(fv.got) != 1 || fv.got[0] != tc.wantRaw) {
				t.Fatalf("validator got %q, want [%q]", fv.got, tc.wantRaw)
			}
			if tc.wantRaw == "" && len(fv.got) != 0 {
				t.Fatalf("validator should not be called, got %q", fv.got)
			}

			if tc.wantStatus == 401 {
				www := w.Header().Get("WWW-Authenticate")
				if !strings.HasPrefix(www, "Bearer") {
					t.Fatalf("WWW-Authenticate = %q, want a Bearer challenge", www)
				}
				hasErr := strings.Contains(www, "error=")
				if tc.wantError == "" && hasErr {
					t.Fatalf("WWW-Authenticate = %q: no error code when credentials are absent (RFC 6750 §3.1)", www)
				}
				if tc.wantError != "" && !strings.Contains(www, `error="`+tc.wantError+`"`) {
					t.Fatalf("WWW-Authenticate = %q, want error=%q", www, tc.wantError)
				}
				for _, h := range tc.header {
					tok := strings.TrimSpace(strings.TrimPrefix(h, "Bearer"))
					if len(tok) > 3 && (strings.Contains(w.Body.String(), tok) || strings.Contains(www, tok)) {
						t.Fatalf("response echoes the credential")
					}
				}
			}
		})
	}
}
