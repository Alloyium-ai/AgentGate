// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package heldprocess

import (
	"errors"
	"golang.org/x/sys/unix"
)

// Exited checks the retained PIDFD. A reused numeric PID cannot satisfy it.
func (h *Held) Exited() (bool, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	select {
	case <-h.done:
		return true, nil
	default:
	}
	if h.pidfd < 0 {
		return false, errors.New("the helper exit PIDFD is unavailable")
	}
	poll := []unix.PollFd{{Fd: int32(h.pidfd), Events: unix.POLLIN}}
	n, err := unix.Poll(poll, 0)
	if err != nil {
		return false, err
	}
	if n == 0 {
		return false, nil
	}
	if poll[0].Revents&(unix.POLLERR|unix.POLLNVAL) != 0 {
		return false, errors.New("the helper exit PIDFD is invalid")
	}
	return poll[0].Revents&(unix.POLLIN|unix.POLLHUP) != 0, nil
}
