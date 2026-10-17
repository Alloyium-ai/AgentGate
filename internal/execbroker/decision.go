// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package execbroker

import (
	"fmt"
	"golang.org/x/sys/unix"
)

// responseFor rechecks the live binding after the durable decision write.
func responseFor(c Config, n Notification, clock func() (uint64, error), member func(int) error, installed func() error, emit func(Decision) error) (Response, error) {
	response := Response{ID: n.ID, Error: -int32(unix.EPERM)}
	now, err := clock()
	if err != nil {
		return response, err
	}
	reason := Check(c, n, now, member, installed)
	decision := Decision{Protocol: "agentgate.exec-decision.v1", Domain: c.DomainID, Generation: c.Generation, NotificationID: n.ID, MonotonicNS: now, PID: n.PID, Syscall: n.Data.Number, Continued: continues(reason), Reason: reason}
	if err = emit(decision); err != nil {
		return response, fmt.Errorf("persist broker decision: %w", err)
	}
	if !decision.Continued {
		return response, nil
	}
	now, err = clock()
	if err != nil {
		return response, err
	}
	finalReason := Check(c, n, now, member, installed)
	if continues(finalReason) {
		now, err = clock()
		if err != nil {
			return response, err
		}
		if now == 0 || now >= c.DeadlineNS {
			finalReason = "expired-binding"
		}
	}
	if !continues(finalReason) {
		decision.MonotonicNS, decision.Continued, decision.Reason = now, false, finalReason
		if err = emit(decision); err != nil {
			return response, fmt.Errorf("persist final broker denial: %w", err)
		}
		return response, nil
	}
	response.Error, response.Flags = 0, unix.SECCOMP_USER_NOTIF_FLAG_CONTINUE
	return response, nil
}
