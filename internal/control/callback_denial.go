// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package control

// callbackDenial carries identity only after token and nonce verification.
type callbackDenial struct {
	Actor Actor
	Cause error
}

func (e *callbackDenial) Error() string { return e.Cause.Error() }
func (e *callbackDenial) Unwrap() error { return e.Cause }

func deniedCallback(actor Actor, err error) error {
	return &callbackDenial{Actor: Actor{Subject: actor.Subject, Kind: actor.Kind}, Cause: err}
}
