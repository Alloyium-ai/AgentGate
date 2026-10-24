// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package control

// AuditAction describes one audit action name.
type AuditAction struct {
	Action      string `json:"action"`
	Resource    string `json:"resource"`
	Description string `json:"description"`
}

// AuditCatalog lists the audit actions the provisioning control plane
// writes. Any action can also appear with the suffix ".denied" (result
// "denied") or ".replayed" (an idempotent replay). TestAuditCatalogCoversEmittedActions
// fails when code emits an action that is not listed.
var AuditCatalog = []AuditAction{
	{"api.denied", "api", "An API request failed authentication, authorization or validation."},
	{"schema.migrated", "database", "The database schema moved to a new version."},
	{"jobkey.activated", "jobkey:<key id>", "A job signing key became the active key."},
	{"jobkey.retired", "jobkey:<key id>", "A job signing key was retired; its targets need re-enrollment and its queued jobs were cancelled."},
	{"jobkey.rotated", "jobkey:<key id>", "An administrator rotated the job signing key."},
	{"apitoken.created", "apitoken:<id>", "A human created an API token. The token itself is never recorded."},
	{"apitoken.revoked", "apitoken:<id>", "An API token was revoked."},
	{"target.created", "target:<id>", "An administrator created a target and its one-time enrollment token."},
	{"target.enrollment.issued", "target:<id>", "An administrator issued a new one-time enrollment token."},
	{"target.enrolled", "target:<id>", "A host presented its key with a one-time token; the binding waits for key approval."},
	{"target.key.approved", "target:<id>", "An administrator compared and approved the host key fingerprint, activating the target."},
	{"target.sequence.reset", "target:<id>", "A host reset its request sequence with a signed resync."},
	{"hostd.resync", "target:<id>", "A signed host resync request (denials only)."},
	{"target.renamed", "target:<id>", "A target name changed."},
	{"target.retired", "target:<id>", "A target was retired and its host key revoked."},
	{"target.capabilities.changed", "target:<id>", "A host reported different capabilities or agent version."},
	{"target.seal_key.published", "target:<id>", "A host published a seal key record signed by its enrolled key; the service stored it verbatim."},
	{"target.seal_key.rejected", "target:<id>", "A host sent a seal key record that does not verify against its enrolled key; it was not stored."},
	{"hostd.enroll", "target", "A host enrollment request (denials only)."},
	{"hostd.poll", "target:<id>", "A signed host poll (denials only)."},
	{"hostd.events", "job:<id>", "A signed host event upload (denials only)."},
	{"profile.created", "profile:<id>", "A profile and its first version were created."},
	{"profile.approval.changed", "profile:<id>", "An administrator changed whether a profile's launches need approval."},
	{"profile.version.created", "profile:<id>", "A new immutable profile version was stored."},
	{"profile.grants.applied", "profile:<id>", "Typed grant edits produced a new profile version, or a no-op."},
	{"profile.grant.previewed", "profile:<id>", "A grant dry run computed the resulting document and changes without storing a version."},
	{"secret.created", "secret:<id>", "Secret metadata was recorded and a sealed value queued for its host."},
	{"secret.deletion.requested", "secret:<id>", "Removal of a secret value from its host was queued."},
	{"secret.stored", "secret:<id>", "The host stored a sealed secret and returned a receipt for exactly the relayed envelope."},
	{"secret.store.failed", "secret:<id>", "The host refused a sealed secret (replay, rollback, stale, wrong target or value), or its receipt did not match."},
	{"launch.planned", "launch-plan", "A launch plan was resolved without creating a launch."},
	{"launch.created", "launch:<id>", "A launch was created from a spec."},
	{"launch.approved", "launch:<id>", "A second human approved a launch."},
	{"launch.rejected", "launch:<id>", "A second human rejected a launch."},
	{"launch.stop.requested", "launch:<id>", "A stop was requested (idempotent)."},
	{"launch.state.changed", "launch:<id>", "One launch state transition, with the spec and policy digests."},
	{"launch.receipt.attached", "launch:<id>", "A late evidence receipt was attached to an ended launch."},
	{"job.queued", "job:<id>", "A signed host job was queued."},
	{"job.delivered", "job:<id>", "A job was delivered to its host for the first time."},
	{"job.completed", "job:<id>", "A host reported a job result."},
	{"job.expired", "job:<id>", "A job passed its deadline before delivery."},
}
