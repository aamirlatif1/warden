package ratelimit_test

import (
	"testing"
	"time"

	"github.com/aamirlatif1/warden/internal/ratelimit"
)

func TestParseRate(t *testing.T) {
	l, w, err := ratelimit.ParseRate(" 30/1m ")
	if err != nil || l != 30 || w != time.Minute {
		t.Fatalf("got %d %v %v", l, w, err)
	}
	for _, bad := range []string{"", "30", "0/1m", "-1/1m", "x/1m", "30/", "30/abc", "30/0s", "30/1us"} {
		if _, _, err := ratelimit.ParseRate(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}
