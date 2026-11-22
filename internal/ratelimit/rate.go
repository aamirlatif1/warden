package ratelimit

import (
	"fmt"
	"strconv"
	"strings"
	"time"
)

// ParseRate reads "LIMIT/WINDOW", e.g. "30/1m" or "5/10s", for env config.
func ParseRate(s string) (limit int, window time.Duration, err error) {
	n, w, ok := strings.Cut(strings.TrimSpace(s), "/")
	if !ok {
		return 0, 0, fmt.Errorf("ratelimit: rate %q is not LIMIT/WINDOW", s)
	}
	limit, err = strconv.Atoi(n)
	if err != nil || limit <= 0 {
		return 0, 0, fmt.Errorf("ratelimit: bad limit in %q", s)
	}
	window, err = time.ParseDuration(w)
	if err != nil || window < time.Millisecond {
		return 0, 0, fmt.Errorf("ratelimit: bad window in %q", s)
	}
	return limit, window, nil
}
