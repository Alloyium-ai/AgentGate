// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package control

import (
	"database/sql"
	"encoding/json"
	"errors"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"alloyium.local/kernel-poc/internal/broker"
	"alloyium.local/kernel-poc/internal/hostproto"
	"alloyium.local/kernel-poc/internal/secretseal"
)

// Secret is secret metadata. The service never sees a value: a client seals
// the value with internal/secretseal to the seal key the target host
// published (signed by its enrolled key, checked against the client's pin),
// and the service relays the envelope in a secret-put job and then drops it.
// It keeps only the envelope's SHA-256, its public context and the host's
// receipt. Scheme, Username, Rules and ExtraHeaders say how the launch broker
// injects the credential and which requests it forwards: a secret without
// rules is refused when a launch is planned (deny by default).
type Secret struct {
	ID           string                 `json:"id"`
	Name         string                 `json:"name"`
	TargetID     string                 `json:"target_id"`
	Upstreams    []string               `json:"upstreams"`
	Header       string                 `json:"header"`
	Scheme       string                 `json:"scheme"`
	Username     string                 `json:"username,omitempty"`
	Rules        []hostproto.BrokerRule `json:"rules"`
	Wildcard     bool                   `json:"wildcard_rules"`
	ExtraHeaders map[string]string      `json:"extra_headers"`
	Fingerprint  string                 `json:"ciphertext_sha256"`
	// Envelope is the public context the sealed envelope bound.
	Envelope *SecretEnvelope `json:"envelope,omitempty"`
	// ValueFingerprint is the host's keyed fingerprint of the stored value
	// (sfp1_...), from its receipt. It reveals nothing about the value.
	ValueFingerprint string `json:"value_fingerprint,omitempty"`
	// Receipt is the host's secretseal receipt, relayed verbatim for the
	// sealing client to verify with Sealed.VerifyReceipt.
	Receipt json.RawMessage `json:"receipt,omitempty"`
	// AllowedProfiles names the profiles whose launches may reference this
	// secret; AllowedLaunchers names the human subjects who may request them.
	AllowedProfiles  []string `json:"allowed_profiles"`
	AllowedLaunchers []string `json:"allowed_launchers"`
	State            string   `json:"state"`
	Created          string   `json:"created_at"`
	CreatedBy        string   `json:"created_by"`
	Updated          string   `json:"updated_at"`
	Revision         int      `json:"revision"`
}

// SecretEnvelope is the public context of a relayed secretseal envelope.
type SecretEnvelope struct {
	Format  string `json:"format"`
	KeyID   string `json:"key_id"`
	Version uint64 `json:"version"`
	Nonce   string `json:"nonce"`
}

// SecretRuleInput is one requested broker rule. The single rule
// {"methods":["*"],"path":"/"} is the explicit wildcard: every method on every
// path of the secret's upstreams, flagged in every plan that uses it.
type SecretRuleInput struct {
	Methods []string `json:"methods"`
	Path    string   `json:"path"`
	Match   string   `json:"match,omitempty"`
}

// SecretInput stores a sealed secret on one target.
type SecretInput struct {
	Name      string   `json:"name"`
	Target    string   `json:"target"`
	Upstreams []string `json:"upstreams"`
	Header    string   `json:"header"`
	// Scheme is "", Bearer or Basic; for an Authorization header an empty
	// scheme is stored as Bearer. Username is the Basic user name.
	Scheme       string            `json:"scheme,omitempty"`
	Username     string            `json:"username,omitempty"`
	Rules        []SecretRuleInput `json:"rules,omitempty"`
	ExtraHeaders map[string]string `json:"extra_headers,omitempty"`
	// Ciphertext is secretseal.Envelope.Encode(): unpadded base64url of the
	// envelope's canonical JSON, sealed for this target and name.
	Ciphertext string `json:"ciphertext"`
	// AllowedProfiles and AllowedLaunchers scope who may use the secret: 1 to
	// 32 profile names and 1 to 64 human subjects (for example local:alice).
	AllowedProfiles  []string `json:"allowed_profiles"`
	AllowedLaunchers []string `json:"allowed_launchers"`
	Reason           string   `json:"reason"`
}

// injection is the stored form of a secret's broker settings.
type injection struct {
	Scheme       string                 `json:"scheme"`
	Username     string                 `json:"username,omitempty"`
	Rules        []hostproto.BrokerRule `json:"rules"`
	ExtraHeaders map[string]string      `json:"extra_headers"`
	Wildcard     bool                   `json:"wildcard"`
}

const secretColumns = "id,name,target_id,upstreams,header,fingerprint,allowed_profiles,allowed_launchers,state,created,created_by,updated,revision,injection,envelope,receipt"
const secretJobLifetime = time.Hour

func scanSecret(row rowScanner) (Secret, error) {
	var sec Secret
	var upstreams, profiles, launchers, inject, envelope, receipt string
	err := row.Scan(&sec.ID, &sec.Name, &sec.TargetID, &upstreams, &sec.Header, &sec.Fingerprint, &profiles, &launchers, &sec.State, &sec.Created, &sec.CreatedBy, &sec.Updated, &sec.Revision, &inject, &envelope, &receipt)
	if err != nil {
		return sec, err
	}
	err = errors.Join(json.Unmarshal([]byte(upstreams), &sec.Upstreams), json.Unmarshal([]byte(profiles), &sec.AllowedProfiles), json.Unmarshal([]byte(launchers), &sec.AllowedLaunchers))
	sec.Rules, sec.ExtraHeaders = []hostproto.BrokerRule{}, map[string]string{}
	if inject != "" {
		var in injection
		if json.Unmarshal([]byte(inject), &in) == nil {
			sec.Scheme, sec.Username, sec.Wildcard = in.Scheme, in.Username, in.Wildcard
			if in.Rules != nil {
				sec.Rules = in.Rules
			}
			if in.ExtraHeaders != nil {
				sec.ExtraHeaders = in.ExtraHeaders
			}
		}
	}
	if envelope != "" {
		var e SecretEnvelope
		if json.Unmarshal([]byte(envelope), &e) == nil {
			sec.Envelope = &e
		}
	}
	if receipt != "" {
		sec.Receipt = json.RawMessage(receipt)
		var r hostproto.SecretReceipt
		if json.Unmarshal(sec.Receipt, &r) == nil {
			sec.ValueFingerprint = r.Fingerprint
		}
	}
	return sec, err
}

// Secrets lists secret metadata.
func (s *Store) Secrets() ([]Secret, error) {
	rows, err := s.DB.Query("SELECT " + secretColumns + " FROM secrets ORDER BY created DESC LIMIT 500")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Secret{}
	for rows.Next() {
		sec, err := scanSecret(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, sec)
	}
	return out, rows.Err()
}

// SecretReceipt is GET /secrets/{id}/receipt: the host's receipt for the
// envelope the service relayed, for the sealing client to verify. The service
// cannot verify its tag; only the client that sealed the value can.
func (s *Store) SecretReceipt(id string) (map[string]any, error) {
	sec, err := scanSecret(s.DB.QueryRow("SELECT "+secretColumns+" FROM secrets WHERE id=?", id))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, fail(404, "not_found", "The secret does not exist.")
	}
	if err != nil {
		return nil, err
	}
	if len(sec.Receipt) == 0 {
		return nil, fail(404, "receipt_unavailable", "The host has not returned a receipt for this secret (state "+sec.State+").")
	}
	return map[string]any{"secret_id": sec.ID, "target_id": sec.TargetID, "name": sec.Name, "state": sec.State,
		"ciphertext_sha256": sec.Fingerprint, "value_fingerprint": sec.ValueFingerprint, "receipt": sec.Receipt}, nil
}

// wildcardRule is the only spelling of the explicit wildcard.
func wildcardRule(rules []SecretRuleInput) (bool, error) {
	star := false
	for _, r := range rules {
		for _, m := range r.Methods {
			star = star || m == "*"
		}
	}
	if !star {
		return false, nil
	}
	if len(rules) != 1 || len(rules[0].Methods) != 1 || rules[0].Path != "/" || (rules[0].Match != "" && rules[0].Match != "prefix") {
		return false, fail(422, "invalid_secret", `The wildcard is exactly one rule {"methods":["*"],"path":"/"}: every method on every path of the upstreams.`)
	}
	return true, nil
}

// secretInjection validates a secret's broker settings with the broker's own
// configuration validator, the one the host runs before it starts a broker:
// every upstream becomes a route exactly as a launch would build it.
func secretInjection(name string, in SecretInput, now time.Time) (injection, error) {
	out := injection{Scheme: in.Scheme, Username: in.Username, Rules: []hostproto.BrokerRule{}, ExtraHeaders: map[string]string{}}
	if out.Scheme == "" && strings.EqualFold(in.Header, "authorization") {
		out.Scheme = "Bearer" // the broker's own default for Authorization, stored explicitly
	}
	for k, v := range in.ExtraHeaders {
		out.ExtraHeaders[k] = v
	}
	wild, err := wildcardRule(in.Rules)
	if err != nil {
		return out, err
	}
	if wild {
		out.Wildcard = true
		for _, r := range broker.DefaultRules() {
			out.Rules = append(out.Rules, hostproto.BrokerRule{Methods: r.Methods, Path: r.Path, Match: r.Match})
		}
	} else {
		for _, r := range in.Rules {
			out.Rules = append(out.Rules, hostproto.BrokerRule{Methods: r.Methods, Path: r.Path, Match: r.Match})
		}
	}
	// A secret may be stored without rules (older clients); every launch that
	// references it is refused until it is recreated with rules. Its other
	// settings are checked now all the same, against a placeholder rule.
	check := out
	if len(check.Rules) == 0 {
		check.Rules = []hostproto.BrokerRule{{Methods: []string{"GET"}, Path: "/", Match: "exact"}}
	}
	if err := hostproto.CheckInjection(in.Header, check.Scheme, check.Username, check.Rules, check.ExtraHeaders); err != nil {
		return out, fail(422, "invalid_secret", "Broker injection settings: "+err.Error()+".")
	}
	if err := brokerAccepts(name, in.Upstreams, in.Header, check, now); err != nil {
		return out, err
	}
	return out, nil
}

// brokerAccepts runs broker.BuildLaunchConfig on a synthetic launch that
// holds only this secret, so a value the broker would refuse at launch time
// is refused now. Errors name a field, never a value.
func brokerAccepts(name string, upstreams []string, header string, in injection, now time.Time) error {
	rules := make([]broker.Rule, 0, len(in.Rules))
	for _, r := range in.Rules {
		rules = append(rules, broker.Rule{Methods: r.Methods, Path: r.Path, Match: r.Match})
	}
	extra := map[string]string{}
	for k, v := range in.ExtraHeaders {
		extra[k] = v
	}
	_, _, _, err := broker.BuildLaunchConfig(broker.LaunchInput{LaunchID: "plan", TargetID: "plan", Deadline: now.Add(time.Hour),
		Listen:    broker.Listen{Network: "tcp", Address: "172.30.0.2", Port: brokerPort, Subnet: "172.30.0.0/29"},
		StatsPath: "/var/lib/agentgate/broker/stats.json", RunAs: broker.Identity{UID: 10002, GID: 10002},
		Secrets: []broker.LaunchSecret{{Ref: name, Upstreams: upstreams, Header: header, Scheme: in.Scheme, Username: in.Username,
			Rules: rules, SecretFile: "/run/agentgate/secrets/" + name, Extra: extra}}}, now)
	if err != nil {
		text := strings.TrimPrefix(err.Error(), "broker config: ")
		if i := strings.Index(text, "]."); strings.HasPrefix(text, "routes[") && i > 0 {
			text = text[i+2:]
		}
		return fail(422, "invalid_secret", "The broker would refuse this secret: "+text+".")
	}
	return nil
}

// CreateSecret records metadata and queues the sealed envelope for the host.
func (s *Store) CreateSecret(op Operation, in SecretInput) (any, error) {
	op.Action, op.Resource, op.Reason = "secret.created", "secret", safeReason(in.Reason)
	// The response holds no ciphertext, but a replayed body would; never
	// cache it.
	op.Idempotency = ""
	return s.Mutation(op, "secrets:admin", true, func(tx *sql.Tx, operation *Operation) (any, error) {
		if err := reasonValid(in.Reason); err != nil {
			return nil, err
		}
		if !hostproto.NamePattern.MatchString(in.Name) || !hostproto.HeaderPattern.MatchString(in.Header) {
			return nil, fail(422, "invalid_secret", "A secret needs a name matching ^[a-z0-9][a-z0-9-]{0,39}$ and an HTTP header name.")
		}
		if len(in.Upstreams) < 1 || len(in.Upstreams) > 8 {
			return nil, fail(422, "invalid_secret", "A secret needs 1 to 8 exact upstream host names.")
		}
		seen := map[string]bool{}
		for _, u := range in.Upstreams {
			if len(u) > 253 || !hostproto.UpstreamPattern.MatchString(u) || seen[u] {
				return nil, fail(422, "invalid_secret", "Each upstream is a unique lowercase DNS host name, optionally with a port.")
			}
			seen[u] = true
		}
		if err := checkScope(in.AllowedProfiles, 32, func(v string) bool { return hostproto.NamePattern.MatchString(v) }); err != nil {
			return nil, fail(422, "invalid_secret", "allowed_profiles needs 1 to 32 unique profile names.")
		}
		if err := checkScope(in.AllowedLaunchers, 64, func(v string) bool { return safeMeta.MatchString(v) }); err != nil {
			return nil, fail(422, "invalid_secret", "allowed_launchers needs 1 to 64 unique human subjects.")
		}
		inject, err := secretInjection(in.Name, in, s.now())
		if err != nil {
			return nil, err
		}
		raw, err := hostproto.DecodeSealed(in.Ciphertext)
		if err != nil {
			return nil, fail(422, "invalid_ciphertext", "Seal the value with secretseal to the target's published seal key (GET /targets/{id}/seal-key) and send Envelope.Encode().")
		}
		env, err := secretseal.ParseEnvelope(raw)
		if err != nil {
			return nil, fail(422, "invalid_ciphertext", "The ciphertext is not a secretseal envelope.")
		}
		target, err := s.targetBy(tx, in.Target)
		if err != nil {
			return nil, err
		}
		if target.State != "active" {
			return nil, fail(409, "target_unavailable", "The target is not enrolled and active.")
		}
		if env.TargetID != target.ID || env.Name != in.Name {
			return nil, fail(422, "invalid_ciphertext", "The envelope is sealed for another target or secret name; seal it for this target id and name.")
		}
		if target.sealKey == "" {
			return nil, fail(409, "seal_key_unavailable", "The target has not published a host-signed seal key; no envelope can be sealed to it.")
		}
		if env.KeyID != target.SealKeyID {
			return nil, fail(409, "seal_key_changed", "The envelope is sealed to another seal key than the one the target publishes; fetch the seal key again and reseal.")
		}
		sec := Secret{ID: newID(), Name: in.Name, TargetID: target.ID, Upstreams: in.Upstreams, Header: in.Header, Scheme: inject.Scheme, Username: inject.Username,
			Rules: inject.Rules, Wildcard: inject.Wildcard, ExtraHeaders: inject.ExtraHeaders, Fingerprint: hostproto.SHA256Hex(raw),
			Envelope:        &SecretEnvelope{Format: env.Format, KeyID: env.KeyID, Version: env.Version, Nonce: env.Nonce},
			AllowedProfiles: in.AllowedProfiles, AllowedLaunchers: in.AllowedLaunchers, State: "pending", Created: stamp(), CreatedBy: operation.Actor.Subject, Revision: 1}
		sec.Updated = sec.Created
		if _, err = tx.Exec("INSERT INTO secrets VALUES(?,?,?,?,?,?,?,?,'pending',?,?,?,1,?,?,'')", sec.ID, sec.Name, sec.TargetID, jsonText(sec.Upstreams), sec.Header, sec.Fingerprint,
			jsonText(sec.AllowedProfiles), jsonText(sec.AllowedLaunchers), sec.Created, sec.CreatedBy, sec.Updated, jsonText(inject), jsonText(sec.Envelope)); err != nil {
			return nil, fail(409, "secret_exists", "The target already holds a secret with this name; delete it first.")
		}
		payload := hostproto.SecretPutPayload{SecretID: sec.ID, Name: sec.Name, Upstreams: sec.Upstreams, Header: sec.Header, Ciphertext: hostproto.EncodeSealed(raw), CiphertextSHA256: sec.Fingerprint}
		if _, err = s.enqueueJob(tx, jobSpec{Type: hostproto.JobSecretPut, TargetID: target.ID, SecretID: sec.ID, Payload: payload, Deadline: s.now().Add(secretJobLifetime), Reason: "Deliver a sealed secret to its host", Actor: operation.Actor}, operation); err != nil {
			return nil, err
		}
		operation.Resource = "secret:" + sec.ID
		return sec, nil
	})
}

// DeleteSecret queues removal of the value from the host. The metadata
// moves to deleted when the host confirms.
func (s *Store) DeleteSecret(op Operation, id string, in ReasonInput) (any, error) {
	op.Action, op.Resource, op.Reason = "secret.deletion.requested", "secret:"+id, safeReason(in.Reason)
	return s.Mutation(op, "secrets:admin", true, func(tx *sql.Tx, operation *Operation) (any, error) {
		if err := reasonValid(in.Reason); err != nil {
			return nil, err
		}
		sec, err := scanSecret(tx.QueryRow("SELECT "+secretColumns+" FROM secrets WHERE id=?", id))
		if errors.Is(err, sql.ErrNoRows) {
			return nil, fail(404, "not_found", "The secret does not exist.")
		}
		if err != nil {
			return nil, err
		}
		switch sec.State {
		case "deleting", "deleted":
			return sec, nil
		case "failed":
			if _, err = tx.Exec("UPDATE secrets SET state='deleted',updated=?,revision=revision+1 WHERE id=?", stamp(), id); err != nil {
				return nil, err
			}
			return scanSecret(tx.QueryRow("SELECT "+secretColumns+" FROM secrets WHERE id=?", id))
		}
		var users int
		if err = tx.QueryRow("SELECT count(*) FROM launches WHERE state NOT IN ('stopped','expired','failed','rejected','cancelled') AND target_id=? AND EXISTS (SELECT 1 FROM json_each(json_extract(launches.plan,'$.secrets')) WHERE json_extract(value,'$.secret_id')=?)", sec.TargetID, sec.ID).Scan(&users); err != nil {
			return nil, err
		}
		if users > 0 {
			return nil, fail(409, "secret_in_use", "Stop the launches that use this secret first.")
		}
		if _, err = tx.Exec("UPDATE jobs SET state='cancelled',envelope='',completed=?,revision=revision+1 WHERE secret_id=? AND type='secret-put' AND state='queued'", stamp(), id); err != nil {
			return nil, err
		}
		if _, err = tx.Exec("UPDATE secrets SET state='deleting',updated=?,revision=revision+1 WHERE id=?", stamp(), id); err != nil {
			return nil, err
		}
		if _, err = s.enqueueJob(tx, jobSpec{Type: hostproto.JobSecretDelete, TargetID: sec.TargetID, SecretID: sec.ID, Payload: hostproto.SecretDeletePayload{SecretID: sec.ID, Name: sec.Name}, Deadline: s.now().Add(stopJobLifetime), Reason: "Remove a secret value from its host", Actor: operation.Actor}, operation); err != nil {
			return nil, err
		}
		return scanSecret(tx.QueryRow("SELECT "+secretColumns+" FROM secrets WHERE id=?", id))
	})
}

func checkScope(values []string, max int, valid func(string) bool) error {
	if len(values) < 1 || len(values) > max {
		return errors.New("scope size")
	}
	seen := map[string]bool{}
	for _, v := range values {
		if !valid(v) || seen[v] {
			return errors.New("scope value")
		}
		seen[v] = true
	}
	return nil
}

// Broker network layout. Every launch with secrets gets its own /29 inside
// brokerPool: the network address, the Docker gateway (.1), the broker (.2)
// and the target (.3). The guard denies the whole pool (it is inside
// 172.16.0.0/12) except the broker's exact address and port.
const (
	brokerPoolText = "172.30.0.0/16"
	brokerPort     = 8443
)

// PlanBroker is the per-launch broker endpoint in a plan.
type PlanBroker struct {
	Address       string `json:"address"`
	Port          int    `json:"port"`
	Subnet        string `json:"subnet"`
	TargetAddress string `json:"target_address"`
}

// brokerEndpoint derives the launch's broker /29 from its launch id: the
// service, not the host, chooses it, so the signed policy, the plan and the
// approval cover the exact endpoint. The host refuses one outside its pool or
// overlapping a network it already has.
func brokerEndpoint(launchID string) PlanBroker {
	sum := digest([]byte("agentgate.broker-network.v1\x00" + launchID))
	n, _ := strconv.ParseUint(sum[:8], 16, 32)
	// 8192 blocks of 8 addresses; block 0 is never used.
	block := uint32(n%8191) + 1
	base := netip.MustParsePrefix(brokerPoolText).Addr().As4()
	v := uint32(base[0])<<24 | uint32(base[1])<<16 | block*8
	addr := func(i uint32) netip.Addr {
		x := v + i
		return netip.AddrFrom4([4]byte{byte(x >> 24), byte(x >> 16), byte(x >> 8), byte(x)})
	}
	return PlanBroker{Address: addr(2).String(), Port: brokerPort, Subnet: netip.PrefixFrom(addr(0), 29).String(), TargetAddress: addr(3).String()}
}

// brokerBaseURL is the URL a route's agent variable receives.
func brokerBaseURL(b *PlanBroker, ref string) string {
	return "http://" + net.JoinHostPort(b.Address, strconv.Itoa(b.Port)) + "/" + ref
}
