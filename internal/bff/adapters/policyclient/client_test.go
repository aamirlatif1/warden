package policyclient

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/aamirlatif1/warden/internal/bff/app"
)

func TestParseStepUp(t *testing.T) {
	cases := map[string]*app.StepUpRequired{
		`Bearer error="insufficient_user_authentication", error_description="acr_too_low", acr_values="gold", max_age=300`: {ACR: "gold", MaxAge: 5 * time.Minute},
		`bearer error="insufficient_user_authentication", acr_values="gold"`:                                               {ACR: "gold"},
		`Bearer error="invalid_token"`:                              nil,
		`Bearer realm="warden"`:                                     nil,
		`Basic realm="x", error="insufficient_user_authentication"`: nil,
		``: nil,
	}
	for h, want := range cases {
		got := ParseStepUp(h)
		if (got == nil) != (want == nil) || (got != nil && *got != *want) {
			t.Errorf("ParseStepUp(%q) = %+v, want %+v", h, got, want)
		}
	}
}

func TestClient(t *testing.T) {
	var status int
	var www string
	var gotAuth, gotPath, gotBody string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth, gotPath = r.Header.Get("Authorization"), r.URL.EscapedPath()
		var b map[string]string
		_ = json.NewDecoder(r.Body).Decode(&b)
		gotBody = b["iban"]
		if www != "" {
			w.Header().Set("WWW-Authenticate", www)
		}
		w.WriteHeader(status)
		_, _ = w.Write([]byte(`{"policies":[{"id":"p1","payout_iban_masked":"****3000"}],"policy":{"id":"p1","payout_iban_masked":"****3000"}}`))
	}))
	defer srv.Close()
	c := New(srv.URL, nil)
	ctx := context.Background()

	status = 200
	pols, err := c.ListPolicies(ctx, "tok")
	if err != nil || len(pols) != 1 || pols[0].PayoutIBANMasked != "****3000" || gotAuth != "Bearer tok" {
		t.Fatalf("list = %+v, %v, auth %q", pols, err, gotAuth)
	}
	if _, err := c.UpdatePayout(ctx, "tok", "../admin", "DE89"); err != nil {
		t.Fatal(err)
	}
	if gotPath != "/v1/policies/..%2Fadmin/payout-account" || gotBody != "DE89" {
		t.Fatalf("path %q (policy ID must be escaped), body %q", gotPath, gotBody)
	}

	errCases := []struct {
		status int
		www    string
		check  func(error) bool
	}{
		{401, `Bearer error="insufficient_user_authentication", acr_values="gold", max_age=300`, func(e error) bool {
			var su *app.StepUpRequired
			return errors.As(e, &su) && su.ACR == "gold" && su.MaxAge == 5*time.Minute
		}},
		{401, `Bearer error="invalid_token"`, func(e error) bool { return errors.Is(e, app.ErrAPIUnauthorized) }},
		{403, "", func(e error) bool { return errors.Is(e, app.ErrAPIForbidden) }},
		{404, "", func(e error) bool { return errors.Is(e, app.ErrAPINotFound) }},
		{400, "", func(e error) bool { return errors.Is(e, app.ErrAPIInvalid) }},
		{503, "", func(e error) bool { return e != nil }},
	}
	for _, tc := range errCases {
		status, www = tc.status, tc.www
		if _, err := c.UpdatePayout(ctx, "tok", "p1", "DE89"); !tc.check(err) {
			t.Errorf("HTTP %d %q: err = %v", tc.status, tc.www, err)
		}
	}
}
