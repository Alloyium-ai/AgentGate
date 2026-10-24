// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package control

import (
	"alloyium.local/kernel-poc/internal/access"
	"alloyium.local/kernel-poc/internal/hostproto"
)

func reasonSchema() map[string]any {
	return map[string]any{"type": "string", "minLength": 3, "maxLength": 512}
}

func nameSchema() map[string]any {
	return map[string]any{"type": "string", "pattern": `^[a-z0-9][a-z0-9-]{0,39}$`, "maxLength": 40}
}

func object(required []string, properties map[string]any) map[string]any {
	return map[string]any{"type": "object", "additionalProperties": false, "required": required, "properties": properties}
}

// provisioningSchemas are the request bodies of the provisioning API. They
// are merged into apiSchemas, so decodeBody enforces the same required fields
// and bounds the OpenAPI document publishes.
func provisioningSchemas() map[string]any {
	strings := func(max int, item map[string]any) map[string]any {
		return map[string]any{"type": "array", "maxItems": max, "items": item}
	}
	short := map[string]any{"type": "string", "maxLength": access.MaxValueBytes}
	return map[string]any{
		"TargetInput":      object([]string{"name", "reason"}, map[string]any{"name": nameSchema(), "reason": reasonSchema()}),
		"KeyApprovalInput": object([]string{"host_key_id", "reason"}, map[string]any{"host_key_id": map[string]any{"type": "string", "pattern": "^ed25519:[a-f0-9]{32}$"}, "reason": reasonSchema()}),
		"ReasonInput":      object([]string{"reason"}, map[string]any{"reason": reasonSchema()}),
		"ProfileInput": object([]string{"name", "reason"}, map[string]any{"name": nameSchema(), "description": map[string]any{"type": "string", "maxLength": 1000},
			"preset": map[string]any{"type": "string", "enum": access.PresetNames()}, "document": map[string]any{"type": "object", "description": "An agentgate.network-poc.v1 or agentgate.poc.v2 policy document."},
			"require_approval": map[string]any{"type": "boolean", "description": "Defaults to true. Only an administrator may set false."}, "reason": reasonSchema()}),
		"ProfileSettingsInput": object([]string{"require_approval", "reason"}, map[string]any{"require_approval": map[string]any{"type": "boolean"}, "reason": reasonSchema()}),
		"ProfileVersionInput":  object([]string{"parent_version", "document", "reason"}, map[string]any{"parent_version": map[string]any{"type": "integer", "minimum": 1}, "document": map[string]any{"type": "object"}, "reason": reasonSchema()}),
		"Edit": object([]string{"action"}, map[string]any{
			"action":        map[string]any{"type": "string", "enum": access.Actions},
			"kind":          map[string]any{"type": "string", "enum": access.RevokeKinds},
			"values":        strings(access.MaxValues, short),
			"mode":          map[string]any{"type": "string", "enum": []string{"read-only", "read-write"}},
			"upgrade_to_v2": map[string]any{"type": "boolean"},
		}),
		"GrantInput":    object([]string{"edits", "reason"}, map[string]any{"edits": map[string]any{"type": "array", "minItems": 1, "maxItems": maxProfileEdits, "items": map[string]any{"$ref": "#/components/schemas/Edit"}}, "reason": reasonSchema()}),
		"DecisionInput": object([]string{"reason"}, map[string]any{"reason": reasonSchema()}),
		"SecretInput": object([]string{"name", "target", "upstreams", "header", "ciphertext", "allowed_profiles", "allowed_launchers", "reason"}, map[string]any{
			"allowed_profiles":  map[string]any{"type": "array", "minItems": 1, "maxItems": 32, "items": nameSchema()},
			"allowed_launchers": map[string]any{"type": "array", "minItems": 1, "maxItems": 64, "items": map[string]any{"type": "string", "pattern": safeMeta.String()}},
			"name":              nameSchema(), "target": map[string]any{"type": "string", "maxLength": 40},
			"upstreams": map[string]any{"type": "array", "minItems": 1, "maxItems": 8, "items": map[string]any{"type": "string", "pattern": hostproto.UpstreamPattern.String(), "maxLength": 253}},
			"header":    map[string]any{"type": "string", "pattern": hostproto.HeaderPattern.String()},
			"scheme":    map[string]any{"type": "string", "enum": []string{"", "Bearer", "Basic"}, "description": "How the broker injects the value; empty with an Authorization header means Bearer."},
			"username":  map[string]any{"type": "string", "maxLength": 64, "pattern": `^[!-9;-~]+$`, "description": "The Basic scheme's user name (visible ASCII, no colon)."},
			"rules": map[string]any{"type": "array", "maxItems": hostproto.MaxBrokerRules, "description": "Broker rules (deny by default: a secret without rules cannot be used by any launch). " +
				`The single rule {"methods":["*"],"path":"/"} is the explicit wildcard, flagged in every plan.`,
				"items": object([]string{"methods", "path"}, map[string]any{
					"methods": map[string]any{"type": "array", "minItems": 1, "maxItems": len(hostproto.BrokerMethods), "items": map[string]any{"type": "string", "enum": append([]string{"*"}, hostproto.BrokerMethods...)}},
					"path":    map[string]any{"type": "string", "minLength": 1, "maxLength": 512, "pattern": `^/`},
					"match":   map[string]any{"type": "string", "enum": []string{"exact", "prefix"}},
				})},
			"extra_headers": map[string]any{"type": "object", "maxProperties": hostproto.MaxBrokerExtraHeaders, "description": "Non-secret headers the broker sets on every forwarded request (for example an API version).",
				"additionalProperties": map[string]any{"type": "string", "minLength": 1, "maxLength": 256}},
			"ciphertext": map[string]any{"type": "string", "maxLength": (hostproto.MaxSealedBytes*4 + 2) / 3, "description": "secretseal.Envelope.Encode(): the value sealed to the target's host-signed seal key (GET /targets/{id}/seal-key), for this target id and secret name."},
			"reason":     reasonSchema(),
		}),
		"APITokenInput": object([]string{"name", "roles", "expires_in_seconds", "reason"}, map[string]any{
			"name":               map[string]any{"type": "string", "pattern": tokenNamePattern.String()},
			"roles":              map[string]any{"type": "array", "minItems": 1, "maxItems": len(validRoles), "items": map[string]any{"type": "string", "enum": []string{"viewer", "auditor", "editor", "launcher", "approver", "admin"}}},
			"expires_in_seconds": map[string]any{"type": "integer", "minimum": int(minTokenLifetime.Seconds()), "maximum": int(maxTokenLifetime.Seconds())},
			"reason":             reasonSchema(),
		}),
		"LaunchSpec": LaunchSpecSchema(),
		"HostEnvelope": object([]string{"domain", "key_id", "payload", "signature"}, map[string]any{
			"domain":    map[string]any{"type": "string", "enum": []string{hostproto.DomainEnroll, hostproto.DomainPoll, hostproto.DomainEvents, hostproto.DomainResync}},
			"key_id":    map[string]any{"type": "string"},
			"payload":   map[string]any{"type": "string", "description": "Unpadded base64url of the exact signed JSON payload (internal/hostproto)."},
			"signature": map[string]any{"type": "string"},
		}),
	}
}

func provisioningOperations() []apiOperation {
	return []apiOperation{
		{path: "targets", method: "get", scope: "target:read"},
		{path: "targets", method: "post", scope: "targets:admin (human admin)", body: "TargetInput"},
		{path: "targets/{id}", method: "get", scope: "target:read"},
		{path: "targets/{id}", method: "patch", scope: "targets:admin (human admin)", body: "TargetInput"},
		{path: "targets/{id}", method: "delete", scope: "targets:admin (human admin)", body: "ReasonInput"},
		{path: "targets/{id}/enrollment", method: "post", scope: "targets:admin (human admin)", body: "ReasonInput"},
		{path: "targets/{id}/approve-key", method: "post", scope: "targets:admin (human admin)", body: "KeyApprovalInput"},
		{path: "targets/{id}/seal-key", method: "get", scope: "target:read; the host-signed seal key record, served verbatim"},
		{path: "profiles", method: "get", scope: "policy:read"},
		{path: "profiles", method: "post", scope: "policy:write (editor)", body: "ProfileInput"},
		{path: "profiles/{id}", method: "get", scope: "policy:read"},
		{path: "profiles/{id}", method: "patch", scope: "profiles:admin (human admin)", body: "ProfileSettingsInput"},
		{path: "profiles/{id}/versions", method: "get", scope: "policy:read"},
		{path: "profiles/{id}/versions", method: "post", scope: "policy:write (editor)", body: "ProfileVersionInput"},
		{path: "profiles/{id}/versions/{n}", method: "get", scope: "policy:read"},
		{path: "profiles/{id}/versions/{n}/grants", method: "post", scope: "policy:write (editor)", body: "GrantInput"},
		{path: "access-presets", method: "get", scope: "policy:read"},
		{path: "launches", method: "get", scope: "launch:read"},
		{path: "launches", method: "post", scope: "launch:write (launcher)", body: "LaunchSpec"},
		{path: "launch-plans", method: "post", scope: "launch:write (launcher)", body: "LaunchSpec"},
		{path: "launches/{id}", method: "get", scope: "launch:read"},
		{path: "launches/{id}/approve", method: "post", scope: "launch:approve (approver, not the requester)", body: "DecisionInput"},
		{path: "launches/{id}/reject", method: "post", scope: "launch:approve (approver, not the requester)", body: "DecisionInput"},
		{path: "launches/{id}/stop", method: "post", scope: "launch:write (launcher); idempotent", body: "DecisionInput"},
		{path: "launches/{id}/events", method: "get", scope: "launch:read; Accept: text/event-stream streams"},
		{path: "launches/{id}/logs", method: "get", scope: "launch:read"},
		{path: "secrets", method: "get", scope: "secrets:admin (admin)"},
		{path: "secrets", method: "post", scope: "secrets:admin (human admin)", body: "SecretInput"},
		{path: "secrets/{id}", method: "delete", scope: "secrets:admin (human admin)", body: "ReasonInput"},
		{path: "secrets/{id}/receipt", method: "get", scope: "secrets:admin; the host's secretseal receipt for the sealing client to verify"},
		{path: "api-tokens", method: "get", scope: "human session"},
		{path: "api-tokens", method: "post", scope: "human browser session", body: "APITokenInput"},
		{path: "api-tokens/{id}", method: "delete", scope: "human session (own token, or admin)", body: "ReasonInput"},
		{path: "launch-spec-schema", method: "get", scope: "any authenticated actor"},
		{path: "audit-catalog", method: "get", scope: "audit:read"},
		{path: "hostd/enroll", method: "post", scope: "host key (one-time token)", body: "HostEnvelope"},
		{path: "hostd/poll", method: "post", scope: "host key", body: "HostEnvelope"},
		{path: "hostd/resync", method: "post", scope: "host key", body: "HostEnvelope"},
		{path: "hostd/jobs/{id}/events", method: "post", scope: "host key", body: "HostEnvelope"},
	}
}

// addProvisioning merges the provisioning API into an OpenAPI document.
func addProvisioning(api map[string]any) {
	paths := api["paths"].(map[string]any)
	for _, op := range provisioningOperations() {
		path := "/api/v1/" + op.path
		v, ok := paths[path].(map[string]any)
		if !ok {
			v = map[string]any{}
		}
		d := apiDescription(op)
		if len(op.path) > 6 && op.path[:6] == "hostd/" {
			d["security"] = []any{map[string]any{"hostSignature": []string{}}}
		} else {
			d["security"] = append(d["security"].([]any), map[string]any{"apiToken": []string{}})
		}
		v[op.method] = d
		paths[path] = v
	}
	security := api["components"].(map[string]any)["securitySchemes"].(map[string]any)
	security["apiToken"] = map[string]string{"type": "http", "scheme": "bearer", "description": "agt_ API token for one human, limited to the provisioning endpoints."}
	security["hostSignature"] = map[string]string{"type": "apiKey", "in": "header", "name": "none", "description": "The body is a hostproto Envelope signed by the enrolled host key."}
}
