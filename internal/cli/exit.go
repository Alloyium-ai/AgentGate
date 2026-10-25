// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package cli

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"strings"
)

// Exit codes. docs/CLI.md documents each one and TestExitCodeTableIsComplete
// keeps the table there identical to ExitCodes.
const (
	ExitOK              = 0
	ExitFailure         = 1
	ExitUsage           = 2
	ExitAuth            = 3
	ExitForbidden       = 4
	ExitNotFound        = 5
	ExitConflict        = 6
	ExitRejected        = 7
	ExitApprovalPending = 8
	ExitTimeout         = 9
	ExitServer          = 10
	ExitNetwork         = 11
	ExitLaunchFailed    = 12
	ExitTrust           = 13
	ExitInterrupted     = 130
)

// ExitCode describes one exit status.
type ExitCode struct {
	Code    int
	Name    string
	Meaning string
}

// ExitCodes is every status the CLI returns.
var ExitCodes = []ExitCode{
	{ExitOK, "ok", "The command did what it said."},
	{ExitFailure, "failure", "An unexpected local failure (a file could not be written, an internal error)."},
	{ExitUsage, "usage", "The command line is wrong, or a confirmation was needed and none was possible."},
	{ExitAuth, "auth", "Not signed in, or the API token is unknown, expired, revoked or for another service (HTTP 401)."},
	{ExitForbidden, "forbidden", "The service refused the operation for this identity, including deciding your own launch (HTTP 403), or a step of agentgate up needs root."},
	{ExitNotFound, "not_found", "The named target, profile, launch, secret or token does not exist (HTTP 404)."},
	{ExitConflict, "conflict", "The resource changed or is in the wrong state; read it again and retry (HTTP 409, 412)."},
	{ExitRejected, "rejected", "The service rejected the request as invalid; its message names the field (HTTP 400, 413, 415, 422, 428)."},
	{ExitApprovalPending, "approval_pending", "The launch or host key waits for a decision by a different human."},
	{ExitTimeout, "timeout", "A request or a --wait did not finish within its time limit."},
	{ExitServer, "server", "The service failed or is overloaded (HTTP 429, 5xx) after the allowed retries."},
	{ExitNetwork, "network", "The service could not be reached."},
	{ExitLaunchFailed, "launch_ended", "A followed launch ended (failed, rejected, cancelled, expired) without reaching the awaited state."},
	{ExitTrust, "trust", "A trust check failed: TLS verification, a certificate pin, a host key pin, or the custody of the configuration; nothing was sent."},
	{ExitInterrupted, "interrupted", "Interrupted (Ctrl-C or SIGTERM). Work already accepted by the service continues."},
}

// Error is a failure the CLI reports. Code and Message are the service's
// error code and message when the service answered; Hint is one line on what
// to do next. None of the fields ever holds a token or a secret value.
type Error struct {
	Exit      int
	Code      string
	Message   string
	Hint      string
	Status    int
	RequestID string
	// reported is set when --json output already printed the result, so the
	// error envelope is not printed as a second JSON value.
	reported bool
}

func (e *Error) Error() string {
	if e.Code != "" {
		return e.Code + ": " + e.Message
	}
	return e.Message
}

func newError(exit int, code, message, hint string) *Error {
	return &Error{Exit: exit, Code: code, Message: message, Hint: hint}
}

func usageError(format string, args ...any) *Error {
	return &Error{Exit: ExitUsage, Code: "usage", Message: fmt.Sprintf(format, args...), Hint: "Run agentgate help, or agentgate COMMAND --help."}
}

func failure(format string, args ...any) *Error {
	return &Error{Exit: ExitFailure, Code: "local_failure", Message: fmt.Sprintf(format, args...)}
}

func trustError(code, message, hint string) *Error {
	return &Error{Exit: ExitTrust, Code: code, Message: message, Hint: hint}
}

// exitForStatus maps an HTTP status to an exit code.
func exitForStatus(status int) int {
	switch {
	case status == 401:
		return ExitAuth
	case status == 403:
		return ExitForbidden
	case status == 404:
		return ExitNotFound
	case status == 409 || status == 412:
		return ExitConflict
	case status == 400 || status == 413 || status == 415 || status == 422 || status == 428:
		return ExitRejected
	case status == 429 || status >= 500:
		return ExitServer
	}
	return ExitFailure
}

// codeHints is the next step for service error codes the CLI knows.
var codeHints = map[string]string{
	"authentication_required":   "Run agentgate login URL to store an API token for this service.",
	"invalid_token":             "The token is unknown, expired or revoked (a password reset or a disabled account revokes every token): run agentgate login URL again.",
	"token_roles_revoked":       "Your roles changed: create a new token with agentgate token create.",
	"mount_root_not_allowed":    "An administrator allows the host folder with agentgate target mount-roots TARGET --root PATH (every mount still needs approval).",
	"token_scope":               "API tokens cannot call this endpoint; it needs a password sign-in (agentgate token ...) or the UI.",
	"session_required":          "This needs a password sign-in: agentgate token create signs in for you.",
	"csrf_failed":               "Use the service's public URL exactly as configured (settings.json public_url).",
	"invalid_credentials":       "Check the username and password.",
	"local_login_disabled":      "This service uses SSO: create a token in the UI and run agentgate login URL --token-stdin.",
	"forbidden":                 "Your token lacks the role for this; ask an administrator, or create a token with the role (agentgate token create --role ROLE).",
	"self_approval":             "You cannot decide your own launch: a different human with the approver role runs agentgate approve ID.",
	"role_not_held":             "A token carries only roles you hold; drop the role or ask an administrator.",
	"not_found":                 "Check the name or id with the matching ls command (agentgate target ls, profile ls, ps, secret ls).",
	"stale_parent":              "The profile changed meanwhile: run the command again to apply it to the new latest version.",
	"launch_changed":            "The launch changed concurrently: check agentgate show ID and retry.",
	"not_pending":               "The launch no longer waits for a decision: agentgate show ID shows its state.",
	"illegal_transition":        "The launch is not in a state that allows this: agentgate show ID shows its state.",
	"fingerprint_mismatch":      "Do not approve. Issue a new token (agentgate target enroll NAME) and install the host agent again.",
	"no_pending_key":            "The target has no host key waiting: agentgate target status NAME shows its state.",
	"target_unavailable":        "The target must be enrolled and active: agentgate target status NAME.",
	"target_exists":             "A live target already uses this name: pick another or retire the old one.",
	"target_retired":            "A retired target cannot change: add a new target.",
	"launches_active":           "Stop the target's live launches first (agentgate ps --active, agentgate stop ID).",
	"profile_exists":            "A profile already uses this name: pick another, or grant access on the existing one.",
	"profile_unavailable":       "Check the profile and version with agentgate profile versions NAME.",
	"profile_version_one":       "Add a version two document to the profile (agentgate grant NAME ... --upgrade) before launching.",
	"approval_policy_forbidden": "Only an administrator creates a profile whose launches skip approval; drop --no-approval.",
	"capability_missing":        "The target does not advertise the needed capability (agentgate target status NAME); use a snapshot mount or another target.",
	"secret_scope":              "The secret is not scoped to this profile or launcher: an administrator stores it again with --allow-profile and --allow-launcher.",
	"secret_unavailable":        "The secret is not stored on that target yet: agentgate secret ls.",
	"secret_exists":             "Remove the old value first: agentgate secret rm NAME --target TARGET.",
	"secret_in_use":             "Stop the launches that use this secret first.",
	"invalid_launch_spec":       "Fix the field the message names; agentgate schema launch-spec prints the schema.",
	"launch_spec_too_large":     "A launch spec is at most 64 KiB.",
	"invalid_json":              "The request does not match the API contract; check the flags against agentgate COMMAND --help.",
	"schema_constraint":         "A value is outside its allowed range or pattern; check the flags against agentgate COMMAND --help.",
	"invalid_reason":            "Give a --reason of 3 to 512 characters.",
	"idempotency_conflict":      "The same idempotency key was used for a different request; retry without --idempotency-key.",
	"rate_limited":              "Wait a minute and retry.",
	"request_capacity":          "The service is busy: retry shortly.",
	"persistence_unavailable":   "The service could not commit: retry shortly; if it persists, check the service logs.",
	"key_approval_pending":      "An administrator must approve the host key: agentgate target approve-key NAME --host-key-id ID.",
	"launch_limit":              "Too many launches are active: stop some first.",
	"token_limit":               "Revoke an unused token first: agentgate token ls, agentgate token revoke ID.",
	"grant_conflict":            "The edit contradicts another entry: revoke the conflicting entry first (agentgate grant NAME revoke KIND VALUE).",
	"grant_usage":               "Check the value: agentgate grant --help lists each action's arguments.",
	"grant_upgrade_required":    "The edit needs a version two profile: repeat it with --upgrade.",
	"grant_rejected":            "The resulting policy fails validation; the message names the rule.",
	"seal_key_changed":          "The target published a new seal key while this ran: run agentgate secret set again; it fetches and verifies the new key.",
	"seal_key_unavailable":      "The target's host has not published a host-signed seal key: start a current agentgate-hostd on it and wait for its next poll.",
	"invalid_ciphertext":        "The service refused the sealed envelope (another target, name or format): run agentgate secret set again; never reuse an envelope.",
	"invalid_secret":            "Fix the broker setting the message names (--upstream, --header, --scheme, --username, --rule, --extra-header).",
	"secret_rules_missing":      "The secret was stored without broker rules, so no launch can use it: an administrator removes it (agentgate secret rm) and stores it again with --rule or --allow-any-path.",
	"secrets_on_host":           "Approve the host key so its host can remove the secrets, or retire with --force and wipe the host.",
	"receipt_unavailable":       "The host has not answered the secret-put yet: agentgate secret ls shows its state.",
}

func hintForClass(exit int) string {
	switch exit {
	case ExitAuth:
		return "Run agentgate login URL to store an API token for this service."
	case ExitForbidden:
		return "Your identity lacks the role for this operation; ask an administrator."
	case ExitNotFound:
		return "Check the name or id with the matching ls command."
	case ExitConflict:
		return "Read the resource again (show or status) and retry."
	case ExitRejected:
		return "Fix the input the message names and retry."
	case ExitServer:
		return "Retry shortly; if it persists, check the service logs with the request id."
	case ExitNetwork:
		return "Check the service URL, that the service runs, and the network path."
	case ExitTimeout:
		return "Retry with a longer --timeout, or check the service."
	}
	return ""
}

// classifyTransport turns a transport failure into an Error.
func classifyTransport(parent context.Context, err error) *Error {
	var cliErr *Error
	if errors.As(err, &cliErr) {
		return cliErr
	}
	if parent.Err() != nil && errors.Is(parent.Err(), context.Canceled) {
		return &Error{Exit: ExitInterrupted, Code: "interrupted", Message: "Interrupted."}
	}
	if errors.Is(err, context.DeadlineExceeded) || isTimeout(err) {
		return &Error{Exit: ExitTimeout, Code: "timeout", Message: "The service did not answer within the time limit.", Hint: hintForClass(ExitTimeout)}
	}
	var unknown x509.UnknownAuthorityError
	var hostname x509.HostnameError
	var invalid x509.CertificateInvalidError
	var verify *tls.CertificateVerificationError
	switch {
	case errors.As(err, &unknown), errors.As(err, &verify) && errors.As(verify.Err, &unknown):
		return trustError("tls_unknown_authority", "The service certificate is not signed by a trusted authority.", "Pass the service CA with --ca-file FILE (agentgate up stores it for a local service).")
	case errors.As(err, &hostname):
		return trustError("tls_hostname", "The service certificate does not name this host.", "Use the host name in the service certificate (the public_url of the service).")
	case errors.As(err, &invalid), errors.As(err, &verify):
		return trustError("tls_invalid", "The service certificate failed verification.", "Check the service certificate and --ca-file.")
	case errors.Is(err, errPinMismatch):
		return trustError("certificate_pin_mismatch", "The service certificate does not match the pinned SHA-256 fingerprint for this context.", "Do not continue if you did not change the certificate; otherwise run agentgate login URL --pin-cert NEW.")
	}
	msg := err.Error()
	var op *net.OpError
	if errors.As(err, &op) && op.Op == "dial" {
		msg = "Cannot connect to " + op.Addr.String() + "."
	} else if i := strings.LastIndex(msg, ": "); i >= 0 && strings.Contains(msg, "dial tcp") {
		msg = "Cannot connect: " + msg[i+2:] + "."
	} else {
		msg = "The request failed: " + redactText(msg)
	}
	return &Error{Exit: ExitNetwork, Code: "network", Message: msg, Hint: hintForClass(ExitNetwork)}
}

func isTimeout(err error) bool {
	var t interface{ Timeout() bool }
	return errors.As(err, &t) && t.Timeout()
}

// asError converts any error into an Error with an exit code.
func asError(ctx context.Context, err error) *Error {
	if err == nil {
		return nil
	}
	var e *Error
	if errors.As(err, &e) {
		return e
	}
	if ctx.Err() != nil && errors.Is(err, context.Canceled) {
		return &Error{Exit: ExitInterrupted, Code: "interrupted", Message: "Interrupted."}
	}
	return &Error{Exit: ExitFailure, Code: "local_failure", Message: redactText(err.Error())}
}
