// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package noderuntime

import (
	"context"
	"errors"
	"net"
	"net/http"
	"time"
)

func qualificationCommandServer(ctx context.Context, handler http.Handler, timeoutMS int) (*http.Server, error) {
	if timeoutMS <= 0 || timeoutMS > 30000 {
		return nil, errors.New("the fixed fixture request timeout exceeds thirty seconds")
	}
	budget := time.Duration(timeoutMS) * time.Millisecond
	return &http.Server{Handler: handler, ReadHeaderTimeout: min(time.Second, budget), ReadTimeout: budget, WriteTimeout: budget, MaxHeaderBytes: 8192, BaseContext: func(net.Listener) context.Context { return ctx }}, nil
}
