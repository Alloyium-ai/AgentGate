// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package qualificationadapters

import (
	"context"

	"alloyium.local/kernel-poc/internal/qualification"
)

func (a *candidateDenial) run(ctx context.Context, request qualification.Request) (qualification.Result, error) {
	return a.runCandidate(ctx, request)
}

// Verify returns no coverage until actual transition, filter, map and call
// evidence pass. A summary, test count, or successful process exit is insufficient.
func (a *candidateDenial) Verify(request qualification.Request, result qualification.Result) ([]qualification.Coverage, error) {
	return a.verify(request, result)
}
