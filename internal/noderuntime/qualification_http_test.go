// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package noderuntime

import (
	"context"
	"net/http"
	"testing"
	"time"
)

func TestFixedCommandServerKeepsTheConfiguredBound(t *testing.T) {
	for _, budget := range []int{0, -1, 30001} {
		if _, err := qualificationCommandServer(context.Background(), http.NotFoundHandler(), budget); err == nil {
			t.Fatal("an unbounded fixture server was accepted", budget)
		}
	}
	server, err := qualificationCommandServer(context.Background(), http.NotFoundHandler(), 20000)
	if err != nil || server.WriteTimeout != 20*time.Second || server.ReadTimeout != 20*time.Second || server.ReadHeaderTimeout != time.Second {
		t.Fatal("the response budget differs from the fixed request budget", err)
	}
}
