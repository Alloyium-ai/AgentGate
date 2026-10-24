// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package control

import (
	"alloyium.local/kernel-poc/internal/policy"
	"strings"
)

type apiOperation struct {
	path, method, scope, body string
	idempotent, match         bool
}

func objectSchema(fields map[string]string, required ...string) map[string]any {
	properties := map[string]any{}
	for field, kind := range fields {
		var value any = map[string]any{"type": kind}
		if kind == "Rights" || kind == "Evidence" {
			value = map[string]any{"$ref": "#/components/schemas/" + kind}
		}
		if kind == "array" {
			value = map[string]any{"type": "array", "items": map[string]any{"type": "string"}, "maxItems": 16}
		}
		properties[field] = value
	}
	return map[string]any{"type": "object", "additionalProperties": false, "properties": properties, "required": required}
}

func apiSchemas() map[string]any {
	schemas := map[string]any{
		"TargetChallengeInput": objectSchema(map[string]string{"node": "string", "boot": "string", "reason": "string"}, "node", "boot", "reason"),
		"TargetReportInput":    objectSchema(map[string]string{"challenge_id": "string", "envelope": "string", "reason": "string"}, "challenge_id", "envelope", "reason"),
		"CreatePolicyDocument": objectSchema(map[string]string{"name": "string", "description": "string", "parent_id": "string", "format": "string", "source": "string", "schema_digest": "string", "reason": "string"}, "name", "format", "source", "schema_digest", "reason"),
		"PolicyPreviewInput":   objectSchema(map[string]string{"version_id": "string", "target_digest": "string", "node": "string", "boot": "string", "reason": "string"}, "version_id", "target_digest", "node", "boot", "reason"),
		"PolicyValidateInput":  objectSchema(map[string]string{"format": "string", "source": "string", "schema_digest": "string", "reason": "string"}, "format", "source", "schema_digest", "reason"),
		"UserInput":            objectSchema(map[string]string{"username": "string", "name": "string", "roles": "array", "enabled": "boolean", "password": "string", "parent_revision": "integer", "reason": "string"}, "username", "name", "roles", "enabled", "parent_revision", "reason"),
		"CreatePolicy":         objectSchema(map[string]string{"name": "string", "description": "string", "rights": "Rights", "reason": "string"}, "name", "rights", "reason"),
		"EditVersion":          objectSchema(map[string]string{"parent_id": "string", "rights": "Rights", "reason": "string"}, "parent_id", "rights", "reason"),
		"Decision":             objectSchema(map[string]string{"state": "string", "version_id": "string", "reason": "string"}, "state", "reason"),
		"PolicyRequest":        objectSchema(map[string]string{"version_id": "string", "agent_id": "string", "reason": "string"}, "version_id", "reason"),
		"Admission":            objectSchema(map[string]string{"request_id": "string", "run_id": "string", "node": "string", "boot": "string", "cgroup": "string", "workspace": "string", "deadline_ns": "string", "reason": "string"}, "request_id", "run_id", "node", "boot", "cgroup", "workspace", "deadline_ns", "reason"),
		"Activation":           objectSchema(map[string]string{"version_id": "string", "policy_digest": "string", "bpf_digest": "string", "reason": "string"}, "version_id", "policy_digest", "bpf_digest", "reason"),
		"Service":              objectSchema(map[string]string{"subject": "string", "kind": "string", "public_key": "string", "scopes": "array", "node": "string", "enabled": "boolean"}, "subject", "kind", "public_key", "scopes"),
		"ServiceStatus":        objectSchema(map[string]string{"enabled": "boolean", "reason": "string"}, "enabled", "reason"),
		"Ingest":               objectSchema(map[string]string{"admission_id": "string", "evidence": "Evidence", "reason": "string"}, "admission_id", "evidence", "reason"),
		"Evidence":             objectSchema(map[string]string{"grant": "string", "events": "string", "terminal": "object"}, "grant", "events"),
		"Rights":               map[string]any{"type": "object", "additionalProperties": false, "required": []string{"workspace_write", "tcp_address", "tcp_port"}, "properties": map[string]any{"workspace_write": map[string]string{"type": "boolean"}, "tcp_address": map[string]any{"type": "string", "enum": []string{"127.0.0.1"}}, "tcp_port": map[string]any{"type": "integer", "enum": []int{18081, 18082}}}},
		"Error":                map[string]any{"type": "object", "required": []string{"error", "request_id"}, "properties": map[string]any{"request_id": map[string]string{"type": "string"}, "error": objectSchema(map[string]string{"code": "string", "message": "string"}, "code", "message")}},
	}
	preview := schemas["PolicyValidateInput"].(map[string]any)["properties"].(map[string]any)
	preview["format"] = map[string]any{"type": "string", "enum": []string{"json", "yaml"}}
	preview["source"] = map[string]any{"type": "string", "minLength": 1, "maxLength": 65536}
	preview["schema_digest"] = map[string]any{"type": "string", "pattern": "^[a-f0-9]{64}$"}
	preview["reason"] = map[string]any{"type": "string", "minLength": 3, "maxLength": 512}
	for _, name := range []string{"TargetChallengeInput", "TargetReportInput", "CreatePolicyDocument", "PolicyPreviewInput"} {
		fields := schemas[name].(map[string]any)["properties"].(map[string]any)
		fields["reason"] = map[string]any{"type": "string", "minLength": 3, "maxLength": 512}
		for field := range fields {
			switch field {
			case "node", "boot":
				fields[field] = map[string]any{"type": "string", "minLength": 1, "maxLength": 100}
			case "challenge_id", "parent_id", "version_id":
				fields[field] = map[string]any{"type": "string", "pattern": "^[a-f0-9]{32}$"}
			case "target_digest", "schema_digest":
				fields[field] = map[string]any{"type": "string", "pattern": "^[a-f0-9]{64}$"}
			case "envelope", "source":
				fields[field] = map[string]any{"type": "string", "minLength": 1, "maxLength": policy.MaxBytes}
			case "name":
				fields[field] = map[string]any{"type": "string", "minLength": 2, "maxLength": 100}
			case "description":
				fields[field] = map[string]any{"type": "string", "maxLength": 1000}
			case "format":
				fields[field] = map[string]any{"type": "string", "enum": []string{"json", "yaml"}}
			}
		}
	}
	schemas["Evidence"].(map[string]any)["properties"].(map[string]any)["terminal"] = map[string]any{"type": []string{"object", "null"}, "description": "A missing terminal preserves incomplete execution evidence."}
	for name, schema := range provisioningSchemas() {
		schemas[name] = schema
	}
	return schemas
}

func apiParameters(op apiOperation) []any {
	params := []any{map[string]any{"name": "X-Request-ID", "in": "header", "schema": map[string]string{"type": "string"}}, map[string]any{"name": "X-Correlation-ID", "in": "header", "schema": map[string]string{"type": "string"}}}
	if strings.Contains(op.path, "{id}") {
		params = append(params, map[string]any{"name": "id", "in": "path", "required": true, "schema": map[string]string{"type": "string"}})
	}
	if strings.Contains(op.path, "{n}") {
		params = append(params, map[string]any{"name": "n", "in": "path", "required": true, "schema": map[string]string{"type": "integer"}})
	}
	if op.method == "get" {
		for _, name := range []string{"cursor", "actor", "resource", "version", "run", "action", "state", "after", "before", "agent", "verifier", "result"} {
			params = append(params, map[string]any{"name": name, "in": "query", "schema": map[string]string{"type": "string"}, "description": "Supported filters depend on the collection. Timestamps use RFC3339."})
		}
		params = append(params, map[string]any{"name": "limit", "in": "query", "schema": map[string]any{"type": "integer", "minimum": 1, "maximum": 100}})
	} else {
		params = append(params, map[string]any{"name": "X-CSRF-Token", "in": "header", "description": "Required with a human cookie session.", "schema": map[string]string{"type": "string"}})
	}
	if op.idempotent {
		params = append(params, map[string]any{"name": "Idempotency-Key", "in": "header", "required": true, "schema": map[string]string{"type": "string"}})
	}
	if op.match {
		params = append(params, map[string]any{"name": "If-Match", "in": "header", "required": true, "schema": map[string]string{"type": "string"}, "description": "Use the current revision ETag."})
	}
	return params
}

func apiDescription(op apiOperation) map[string]any {
	responses := map[string]any{"200": map[string]any{"description": "The operation completed. Lists return items and an optional next_cursor. Audit export returns NDJSON and X-Next-Cursor. Events uses text/event-stream."}}
	for _, code := range []string{"400", "401", "403", "404", "405", "409", "412", "413", "415", "422", "428", "429", "503"} {
		responses[code] = map[string]any{"description": "The operation failed with a structured error and request ID.", "content": map[string]any{"application/json": map[string]any{"schema": map[string]string{"$ref": "#/components/schemas/Error"}}}}
	}
	v := map[string]any{"summary": op.method + " " + op.path, "x-required-scope": op.scope, "parameters": apiParameters(op), "responses": responses, "security": []any{map[string]any{"cookieSession": []string{}}, map[string]any{"signedServiceProof": []string{}}}}
	if op.body != "" {
		v["requestBody"] = map[string]any{"required": true, "content": map[string]any{"application/json": map[string]any{"schema": map[string]string{"$ref": "#/components/schemas/" + op.body}}}}
	}
	if op.path == "machine-challenge" {
		v["security"] = []any{}
	}
	return v
}

func OpenAPI() map[string]any {
	ops := []apiOperation{}
	for _, read := range []struct{ path, scope string }{{"machine-challenge", "public"}, {"overview", "policy:read"}, {"session", "human session"}, {"policies", "policy:read"}, {"policies/{id}", "policy:read"}, {"policies/{id}/versions", "policy:read"}, {"versions/{id}", "policy:read"}, {"requests", "request:read"}, {"requests/{id}", "request:read"}, {"admissions", "admission:read"}, {"admissions/{id}", "admission:read"}, {"runs", "run:read"}, {"runs/{id}", "run:read"}, {"runs/{id}/verification", "run:read"}, {"audit", "audit:read"}, {"audit/export", "audit:export"}, {"agents", "agents:read"}, {"trust", "policy:read"}, {"openapi.json", "policy:read"}, {"events", "policy:read"}} {
		ops = append(ops, apiOperation{path: read.path, method: "get", scope: read.scope})
	}
	ops = append(ops,
		apiOperation{"users", "get", "users:write (human)", "", false, false},
		apiOperation{"users", "post", "users:write (human)", "UserInput", false, false},
		apiOperation{"policies", "post", "policy:write (human)", "CreatePolicy", false, false},
		apiOperation{"policies/{id}/versions", "post", "policy:write or proposal:create", "EditVersion", false, false},
		apiOperation{"versions/{id}/transition", "post", "policy:write for proposal; decision:write (human) for approval/publication/retirement", "Decision", true, true},
		apiOperation{"requests", "post", "request:create (own agent) or admin", "PolicyRequest", false, false},
		apiOperation{"requests/{id}/decision", "post", "decision:write (human)", "Decision", true, true},
		apiOperation{"admissions", "post", "admission:write (enrolled node)", "Admission", true, false},
		apiOperation{"admissions/{id}/activate", "post", "admission:write (enrolled node)", "Activation", true, false},
		apiOperation{"admissions/{id}/release", "post", "admission:release (enrolled node)", "Decision", true, false},
		apiOperation{"admissions/{id}/revoke", "post", "decision:write (human)", "Decision", true, false},
		apiOperation{"evidence/receipt", "post", "evidence:write (enrolled node)", "Ingest", true, false},
		apiOperation{"evidence", "post", "evidence:write (enrolled node)", "Ingest", true, false},
		apiOperation{"agents", "post", "agents:write (human)", "Service", false, false},
		apiOperation{"agents/{id}/status", "post", "agents:write (human)", "ServiceStatus", false, false},
	)
	paths := map[string]any{}
	for _, op := range ops {
		path := "/api/v1/" + op.path
		v, ok := paths[path].(map[string]any)
		if !ok {
			v = map[string]any{}
		}
		v[op.method] = apiDescription(op)
		paths[path] = v
	}
	api := map[string]any{"openapi": "3.1.0", "info": map[string]string{"title": "AgentGate policy control", "version": "0.2.6", "description": "Private prototype. Policy changes and execution evidence have separate trust boundaries. Machine mutations need a fresh signed proof even for an idempotent retry. Bodies have a four MiB limit."}, "paths": paths, "components": map[string]any{"schemas": apiSchemas(), "securitySchemes": map[string]any{"cookieSession": map[string]string{"type": "apiKey", "in": "cookie", "name": "__Host-enforcer-session"}, "signedServiceProof": map[string]string{"type": "apiKey", "in": "header", "name": "Authorization", "description": "Alloyium-Proof Ed25519 proof binds audience, receiver epoch, subject, method, URI, body digest, time and nonce."}}}}
	addProvisioning(api)
	return api
}
