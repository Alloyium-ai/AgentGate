// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package cli

import (
	"fmt"
	"strconv"
	"strings"
	"time"
)

// multiFlag collects a repeatable flag.
type multiFlag []string

func (m *multiFlag) String() string { return strings.Join(*m, ",") }
func (m *multiFlag) Set(v string) error {
	*m = append(*m, v)
	return nil
}

// listFlag collects a repeatable flag whose values may also be comma separated.
type listFlag []string

func (l *listFlag) String() string { return strings.Join(*l, ",") }
func (l *listFlag) Set(v string) error {
	for _, part := range strings.Split(v, ",") {
		if part = strings.TrimSpace(part); part != "" {
			*l = append(*l, part)
		}
	}
	return nil
}

// parseLifetime accepts a Go duration, a number of seconds, or Nd for days.
func parseLifetime(v string) (time.Duration, error) {
	v = strings.TrimSpace(v)
	if v == "" {
		return 0, fmt.Errorf("empty duration")
	}
	if n, err := strconv.Atoi(v); err == nil {
		return time.Duration(n) * time.Second, nil
	}
	if strings.HasSuffix(v, "d") {
		n, err := strconv.Atoi(strings.TrimSuffix(v, "d"))
		if err != nil || n < 0 {
			return 0, fmt.Errorf("invalid duration %q", v)
		}
		return time.Duration(n) * 24 * time.Hour, nil
	}
	d, err := time.ParseDuration(v)
	if err != nil {
		return 0, fmt.Errorf("invalid duration %q (use 90s, 30m, 2h or 7d)", v)
	}
	return d, nil
}

// parseSince accepts an RFC 3339 time or a duration before now.
func parseSince(v string, now time.Time) (string, error) {
	if t, err := time.Parse(time.RFC3339Nano, v); err == nil {
		return t.UTC().Format(time.RFC3339Nano), nil
	}
	d, err := parseLifetime(v)
	if err != nil || d <= 0 {
		return "", usageError("--since takes an RFC 3339 time or a duration such as 1h or 7d")
	}
	return now.Add(-d).UTC().Format(time.RFC3339Nano), nil
}

func defaultReason(reason, fallback string) (string, error) {
	r := strings.TrimSpace(reason)
	if r == "" {
		r = fallback
	}
	if len(r) < 3 || len(r) > 512 {
		return "", usageError("a --reason is 3 to 512 characters")
	}
	return r, nil
}
