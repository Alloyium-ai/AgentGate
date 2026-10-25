// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package control

import (
	"encoding/json"
	"fmt"
	"path"
	"regexp"
	"strings"
	"unicode/utf8"

	"alloyium.local/kernel-poc/internal/access"
	"alloyium.local/kernel-poc/internal/hostproto"
	"alloyium.local/kernel-poc/internal/pocpolicy"
)

// Launch spec bounds (agentgate.launch.v1).
const (
	MaxLaunchSpecBytes = 64 << 10
	maxCommandArgs     = 128
	maxCommandBytes    = 32 << 10
	maxArgBytes        = 4096
	maxEnvEntries      = 64
	maxEnvBytes        = 32 << 10
	maxEnvValueBytes   = 4096
	oneshotMin         = 1
	oneshotMax         = 3600
	sessionMin         = 60
	sessionMax         = 86400
	defaultWorkdir     = access.WritableMount
)

var (
	envNamePattern = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]{0,127}$`)
	// secretEnvPattern matches names that look like credentials. A spec that
	// sets one in agent.env is rejected: secrets arrive only through brokers.
	secretEnvPattern = regexp.MustCompile(`(?i)(^(KEY|TOKEN|SECRET|PAT)$|_(KEY|PAT|AUTH)$|PASSWORD|PASSWD|SECRET|TOKEN|APIKEY|API_KEY|PRIVATE_KEY|CREDENTIAL|AUTHORIZATION|COOKIE)`)
	// reservedEnvPattern names variables the runtime owns or that change how
	// programs load code.
	reservedEnvPattern = regexp.MustCompile(`(?i)^(LD_|AGENTGATE_|DYLD_)`)
)

func specError(format string, args ...any) error {
	return fail(422, "invalid_launch_spec", fmt.Sprintf(format, args...))
}

// SecretLikeEnv reports whether an environment variable name looks like it
// holds a credential.
func SecretLikeEnv(name string) bool { return secretEnvPattern.MatchString(name) }

func canonicalPath(label, value string, max int) error {
	if value == "" || value[0] != '/' || path.Clean(value) != value || value == "/" || len(value) > max || strings.ContainsAny(value, "\x00\n") {
		return specError("%s must be a canonical absolute path other than / of at most %d bytes", label, max)
	}
	return nil
}

func within(parent, child string) bool {
	return child == parent || strings.HasPrefix(child, parent+"/")
}

// ValidateLaunchSpec strictly decodes and validates one agentgate.launch.v1
// document and returns it with its canonical bytes and SHA-256. It checks
// only the document; the target, profile and secret references are resolved
// when a launch is planned.
func ValidateLaunchSpec(raw []byte) (hostproto.LaunchSpec, []byte, string, error) {
	var spec hostproto.LaunchSpec
	if len(raw) == 0 || len(raw) > MaxLaunchSpecBytes {
		return spec, nil, "", fail(413, "launch_spec_too_large", "A launch spec is at most 64 KiB.")
	}
	if err := hostproto.DecodeStrict(raw, &spec); err != nil {
		return spec, nil, "", specError("The launch spec is not one JSON object with only known fields: %v", strings.TrimPrefix(err.Error(), "hostproto: "))
	}
	if err := checkSpec(&spec); err != nil {
		return spec, nil, "", err
	}
	canonical, err := json.Marshal(spec)
	if err != nil {
		return spec, nil, "", err
	}
	return spec, canonical, digest(canonical), nil
}

func checkSpec(spec *hostproto.LaunchSpec) error {
	if spec.Version != hostproto.LaunchSpecVersion {
		return specError("version must be %s", hostproto.LaunchSpecVersion)
	}
	if !hostproto.NamePattern.MatchString(spec.Name) {
		return specError("name must match ^[a-z0-9][a-z0-9-]{0,39}$")
	}
	if !hostproto.NamePattern.MatchString(spec.Target) {
		return specError("target must name a target (^[a-z0-9][a-z0-9-]{0,39}$)")
	}
	switch spec.Mode {
	case "oneshot":
		if spec.LifetimeSeconds < oneshotMin || spec.LifetimeSeconds > oneshotMax {
			return specError("a oneshot lifetime_seconds is %d to %d", oneshotMin, oneshotMax)
		}
		if len(spec.Agent.Command) == 0 {
			return specError("a oneshot launch needs agent.command")
		}
	case "session":
		if spec.LifetimeSeconds < sessionMin || spec.LifetimeSeconds > sessionMax {
			return specError("a session lifetime_seconds is %d to %d", sessionMin, sessionMax)
		}
	default:
		return specError("mode must be oneshot or session")
	}
	if err := checkAgent(spec); err != nil {
		return err
	}
	if err := checkAccess(spec); err != nil {
		return err
	}
	if err := checkSpecMounts(spec); err != nil {
		return err
	}
	if err := checkSpecSecrets(spec); err != nil {
		return err
	}
	if spec.Approval != "auto" && spec.Approval != "required" {
		return specError("approval must be auto or required")
	}
	return nil
}

func checkAgent(spec *hostproto.LaunchSpec) error {
	a := &spec.Agent
	if !hostproto.ImagePattern.MatchString(a.Image) {
		return specError("agent.image must be an immutable digest reference (name@sha256:<64 hex>)")
	}
	if a.Command == nil {
		a.Command = []string{}
	}
	if len(a.Command) > maxCommandArgs {
		return specError("agent.command has at most %d arguments", maxCommandArgs)
	}
	total := 0
	for _, arg := range a.Command {
		total += len(arg)
		if len(arg) > maxArgBytes || strings.ContainsRune(arg, 0) || !utf8.ValidString(arg) {
			return specError("each agent.command argument is UTF-8 without NUL and at most %d bytes", maxArgBytes)
		}
	}
	if total > maxCommandBytes {
		return specError("agent.command is at most %d bytes", maxCommandBytes)
	}
	if a.Env == nil {
		a.Env = map[string]string{}
	}
	if len(a.Env) > maxEnvEntries {
		return specError("agent.env has at most %d entries", maxEnvEntries)
	}
	total = 0
	for name, value := range a.Env {
		total += len(name) + len(value)
		if !envNamePattern.MatchString(name) {
			return specError("agent.env name %q is not a valid variable name", name)
		}
		if SecretLikeEnv(name) {
			return specError("agent.env name %q looks like a credential; deliver secrets through the secrets list", name)
		}
		if reservedEnvPattern.MatchString(name) {
			return specError("agent.env name %q is reserved", name)
		}
		if len(value) > maxEnvValueBytes || strings.ContainsRune(value, 0) || !utf8.ValidString(value) {
			return specError("agent.env value for %q is UTF-8 without NUL and at most %d bytes", name, maxEnvValueBytes)
		}
	}
	if total > maxEnvBytes {
		return specError("agent.env is at most %d bytes", maxEnvBytes)
	}
	if a.Workdir == "" {
		a.Workdir = defaultWorkdir
	}
	if err := canonicalPath("agent.workdir", a.Workdir, 160); err != nil {
		return err
	}
	ok := within(defaultWorkdir, a.Workdir) || within("/tmp", a.Workdir)
	for _, m := range spec.Mounts {
		ok = ok || within(access.MountRoot+"/"+m.Name, a.Workdir)
	}
	if !ok {
		return specError("agent.workdir must be inside the workspace, /tmp or a spec mount")
	}
	return nil
}

func checkAccess(spec *hostproto.LaunchSpec) error {
	acc := &spec.Access
	inline := len(acc.Inline) > 0
	if inline == (acc.Profile != "") {
		return specError("access names a profile and version, or embeds one inline document, not both")
	}
	if inline {
		if acc.Version != 0 {
			return specError("an inline access document has no version")
		}
		doc, err := pocpolicy.Parse(acc.Inline)
		if err != nil {
			return specError("access.inline is not a valid policy: %v", err)
		}
		if doc.Version != pocpolicy.VersionV2 {
			return specError("a launch policy must be version %s with filesystem and process controls", pocpolicy.VersionV2)
		}
		canonical, _ := json.Marshal(doc)
		acc.Inline = canonical
		return nil
	}
	if !hostproto.NamePattern.MatchString(acc.Profile) || acc.Version < 1 || acc.Version > 1<<30 {
		return specError("access.profile must name a profile and access.version must be a positive version number")
	}
	return nil
}

func checkSpecMounts(spec *hostproto.LaunchSpec) error {
	if spec.Mounts == nil {
		spec.Mounts = []hostproto.SpecMount{}
	}
	if len(spec.Mounts) > hostproto.MaxMounts {
		return specError("at most %d mounts", hostproto.MaxMounts)
	}
	names := map[string]bool{}
	for i, m := range spec.Mounts {
		if !hostproto.MountNamePattern.MatchString(m.Name) || names[m.Name] {
			return specError("mounts[%d].name must be a unique name of 1..32 of a-z 0-9 _ -", i)
		}
		names[m.Name] = true
		if m.Mode != "read-only" && m.Mode != "snapshot" && m.Mode != "read-write" {
			return specError("mounts[%d].mode must be read-only, snapshot or read-write", i)
		}
		if err := hostproto.CheckMountSource(m.Source); err != nil {
			return specError("mounts[%d].source: %s", i, strings.TrimPrefix(err.Error(), "hostproto: "))
		}
		for _, other := range spec.Mounts[:i] {
			if within(other.Source, m.Source) || within(m.Source, other.Source) {
				return specError("mounts[%d].source overlaps mount %s", i, other.Name)
			}
		}
	}
	return nil
}

func checkSpecSecrets(spec *hostproto.LaunchSpec) error {
	if spec.Secrets == nil {
		spec.Secrets = []hostproto.SpecSecret{}
	}
	if len(spec.Secrets) > hostproto.MaxSecrets {
		return specError("at most %d secrets", hostproto.MaxSecrets)
	}
	refs, envs := map[string]bool{}, map[string]bool{}
	for i, s := range spec.Secrets {
		if !hostproto.NamePattern.MatchString(s.Ref) || refs[s.Ref] {
			return specError("secrets[%d].ref must be a unique secret name", i)
		}
		refs[s.Ref] = true
		if !envNamePattern.MatchString(s.Expose.Env) || envs[s.Expose.Env] || reservedEnvPattern.MatchString(s.Expose.Env) {
			return specError("secrets[%d].expose.env must be a unique unreserved variable name", i)
		}
		if _, clash := spec.Agent.Env[s.Expose.Env]; clash {
			return specError("secrets[%d].expose.env is also set in agent.env", i)
		}
		envs[s.Expose.Env] = true
	}
	return nil
}

// LaunchSpecSchema is the JSON Schema (draft 2020-12) for agentgate.launch.v1.
// It expresses every structural rule of ValidateLaunchSpec. Rules that relate
// several values (mount source overlap, workdir inside a mount, unique mount
// and secret names, a secret env that is also in agent.env) and every
// reference to stored records are checked by the service only; the schema
// lists them under x-service-rules.
func LaunchSpecSchema() map[string]any {
	str := func(pattern string, max int) map[string]any {
		v := map[string]any{"type": "string", "maxLength": max}
		if pattern != "" {
			v["pattern"] = pattern
		}
		return v
	}
	name := str(`^[a-z0-9][a-z0-9-]{0,39}$`, 40)
	envName := map[string]any{"type": "string", "pattern": envNamePattern.String(), "not": map[string]any{"anyOf": []any{map[string]any{"pattern": secretEnvPattern.String()}, map[string]any{"pattern": reservedEnvPattern.String()}}}}
	return map[string]any{
		"$schema":              "https://json-schema.org/draft/2020-12/schema",
		"$id":                  "https://agentgate.invalid/schemas/agentgate.launch.v1.json",
		"title":                "agentgate.launch.v1",
		"type":                 "object",
		"additionalProperties": false,
		"required":             []string{"version", "name", "target", "mode", "lifetime_seconds", "agent", "access", "approval"},
		"properties": map[string]any{
			"version":          map[string]any{"const": hostproto.LaunchSpecVersion},
			"name":             name,
			"target":           name,
			"mode":             map[string]any{"enum": []string{"oneshot", "session"}},
			"lifetime_seconds": map[string]any{"type": "integer", "minimum": oneshotMin, "maximum": sessionMax},
			"agent": map[string]any{
				"type": "object", "additionalProperties": false, "required": []string{"image"},
				"properties": map[string]any{
					"image":   str(hostproto.ImagePattern.String(), 300),
					"command": map[string]any{"type": "array", "maxItems": maxCommandArgs, "items": map[string]any{"type": "string", "maxLength": maxArgBytes, "pattern": "^[^\\x00]*$"}},
					"env": map[string]any{"type": "object", "maxProperties": maxEnvEntries, "propertyNames": envName,
						"additionalProperties": map[string]any{"type": "string", "maxLength": maxEnvValueBytes, "pattern": "^[^\\x00]*$"}},
					"workdir": str(`^/[^\x00\n]*[^/]$`, 160),
				},
			},
			"access": map[string]any{
				"type": "object", "additionalProperties": false,
				"oneOf": []any{
					map[string]any{"required": []string{"profile", "version"}, "not": map[string]any{"required": []string{"inline"}}},
					map[string]any{"required": []string{"inline"}, "not": map[string]any{"anyOf": []any{map[string]any{"required": []string{"profile"}}, map[string]any{"required": []string{"version"}}}}},
				},
				"properties": map[string]any{
					"profile": name,
					"version": map[string]any{"type": "integer", "minimum": 1, "maximum": 1 << 30},
					"inline":  map[string]any{"type": "object", "description": "A complete agentgate.poc.v2 policy document.", "properties": map[string]any{"version": map[string]any{"const": pocpolicy.VersionV2}}, "required": []string{"version", "filesystem", "process"}},
				},
			},
			"mounts": map[string]any{"type": "array", "maxItems": hostproto.MaxMounts, "items": map[string]any{
				"type": "object", "additionalProperties": false, "required": []string{"name", "source", "mode"},
				"properties": map[string]any{
					"name":   str(hostproto.MountNamePattern.String(), 32),
					"source": str(hostproto.BindSourcePattern.String(), 4096),
					"mode":   map[string]any{"enum": []string{"read-only", "snapshot", "read-write"}},
				},
			}},
			"secrets": map[string]any{"type": "array", "maxItems": hostproto.MaxSecrets, "items": map[string]any{
				"type": "object", "additionalProperties": false, "required": []string{"ref", "expose"},
				"properties": map[string]any{
					"ref": name,
					"expose": map[string]any{"type": "object", "additionalProperties": false, "required": []string{"env"},
						"properties": map[string]any{"env": map[string]any{"type": "string", "pattern": envNamePattern.String(), "not": map[string]any{"pattern": reservedEnvPattern.String()}}}},
				},
			}},
			"approval": map[string]any{"enum": []string{"auto", "required"}},
		},
		"allOf": []any{
			map[string]any{"if": map[string]any{"properties": map[string]any{"mode": map[string]any{"const": "oneshot"}}, "required": []string{"mode"}},
				"then": map[string]any{"properties": map[string]any{"lifetime_seconds": map[string]any{"maximum": oneshotMax}, "agent": map[string]any{"required": []string{"image", "command"}, "properties": map[string]any{"command": map[string]any{"minItems": 1}}}}}},
			map[string]any{"if": map[string]any{"properties": map[string]any{"mode": map[string]any{"const": "session"}}, "required": []string{"mode"}},
				"then": map[string]any{"properties": map[string]any{"lifetime_seconds": map[string]any{"minimum": sessionMin}}}},
		},
		"x-max-bytes": MaxLaunchSpecBytes,
		"x-service-rules": []string{
			"mount names and secret refs are unique; mount sources do not overlap and avoid protected trees, credential stores and home directories",
			"agent.workdir is inside /var/lib/agentgate/workspace, /tmp or /var/lib/agentgate/mounts/<a spec mount>",
			"a secret expose.env is not also set in agent.env",
			"access.inline passes the full agentgate.poc.v2 validator",
			"target, profile version and secrets exist; a read-write mount needs the target capability live-mounts and a snapshot mount needs snapshot-mounts",
		},
	}
}
