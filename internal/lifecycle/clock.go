// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package lifecycle

import (
	"errors"
	"golang.org/x/sys/unix"
	"math"
)

type MonotonicClock struct{}

func (MonotonicClock) NowNS() (uint64, error) {
	var value unix.Timespec
	if err := unix.ClockGettime(unix.CLOCK_MONOTONIC, &value); err != nil {
		return 0, err
	}
	if value.Sec < 0 || value.Nsec < 0 || value.Nsec >= 1000000000 || uint64(value.Sec) > (math.MaxUint64-uint64(value.Nsec))/1000000000 {
		return 0, errors.New("the monotonic clock value is invalid")
	}
	return uint64(value.Sec)*1000000000 + uint64(value.Nsec), nil
}
