// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package cli

import (
	"strconv"
	"strings"

	"alloyium.local/kernel-poc/internal/hostproto"
)

// A secret's injection policy (hostproto.SecretPolicy) is sealed with its
// value: secret set computes it from the operator's flags, shows it before
// the value is read, seals its digest into the envelope and refuses an answer
// whose settings make another digest. approve recomputes it from the plan's
// readable settings and refuses a plan whose settings do not make the digest
// the plan names. That detects only a plan that contradicts itself. It does
// not show which digest the host holds: a service that lies can show settings
// X together with their own digest D(X) while the host holds policy Y, and the
// approver cannot tell. The host still builds the broker only from the policy
// stored with the value (Y), so such a lie misleads the approver but does not
// change where or how the credential is used. Confirming the host's digest
// would need a fresh statement signed by the host key (open work, see
// docs/PROVISIONING.md, Trusted computing base).

// policyRules converts rules as the CLI and the service write them. The
// wildcard is the single rule {"methods":["*"],"path":"/"} on input and the
// expanded rule (every method on prefix /) once stored; both make the same
// policy.
func policyRules(rules []BrokerRule, wildcard bool) []hostproto.BrokerRule {
	if wildcard && len(rules) == 1 && len(rules[0].Methods) == 1 && rules[0].Methods[0] == "*" {
		return []hostproto.BrokerRule{{Methods: hostproto.BrokerMethods, Path: "/", Match: "prefix"}}
	}
	out := make([]hostproto.BrokerRule, 0, len(rules))
	for _, r := range rules {
		out = append(out, hostproto.BrokerRule{Methods: r.Methods, Path: r.Path, Match: r.Match})
	}
	return out
}

func newPolicy(upstreams []string, header, scheme, username string, rules []BrokerRule, wildcard bool, extra map[string]string, forward []string) (hostproto.SecretPolicy, error) {
	return hostproto.NewSecretPolicy(upstreams, header, scheme, username, policyRules(rules, wildcard), extra, forward, wildcard)
}

// secretPolicyOf is the policy a stored secret's settings make.
func secretPolicyOf(s Secret) (hostproto.SecretPolicy, error) {
	return newPolicy(s.Upstreams, s.Header, s.Scheme, s.Username, s.Rules, s.Wildcard, s.ExtraHeaders, s.ForwardHeaders)
}

// planPolicyOf is the policy a plan's secret settings make.
func planPolicyOf(s PlanSecret) (hostproto.SecretPolicy, error) {
	return newPolicy(s.Upstreams, s.Header, s.Scheme, s.Username, s.Rules, s.Wildcard, s.ExtraHeaders, s.ForwardHeaders)
}

// checkPlanPolicies refuses a plan whose readable broker settings do not make
// the policy digest it names for each secret: a plan that contradicts itself.
func checkPlanPolicies(plan LaunchPlan) error {
	for _, s := range plan.Secrets {
		p, err := planPolicyOf(s)
		if err != nil || s.PolicyDigest == "" || p.Digest() != s.PolicyDigest {
			return trustError("policy_digest_mismatch", "The plan shows broker settings for secret "+s.Ref+" that do not make the policy digest it names ("+orNone(s.PolicyDigest)+"): the plan contradicts itself, so what it shows is not a policy the host could hold under that digest. Nothing was decided.",
				"Do not approve this launch: the service sent an inconsistent plan. Reject it and report it to the service operator.")
		}
	}
	return nil
}

func orNone(s string) string {
	if s == "" {
		return "none"
	}
	return s
}

// policyFields renders a policy for review: every field the digest covers.
func policyFields(p hostproto.SecretPolicy) [][2]string {
	ups := []string{}
	for _, u := range p.Upstreams {
		ups = append(ups, "https://"+u.Host+":"+strconv.Itoa(u.Port))
	}
	header := p.Header
	if p.Scheme != "" {
		header += " (" + p.Scheme
		if p.Username != "" {
			header += ", user " + p.Username
		}
		header += ")"
	}
	rules := []string{}
	for _, r := range p.Rules {
		rules = append(rules, strings.Join(r.Methods, ",")+" "+r.Path+" ("+r.Match+")")
	}
	if p.Wildcard {
		rules = []string{"WILDCARD: every method on every path"}
	}
	extra := []string{}
	for _, h := range p.ExtraHeaders {
		extra = append(extra, h.Name+": "+h.Value)
	}
	return [][2]string{{"upstreams", strings.Join(ups, ", ")}, {"header", header}, {"rules", joinOr(rules, "none (every launch is refused: deny by default)")},
		{"extra headers", joinOr(extra, "none")}, {"forward headers", joinOr(p.ForwardHeaders, "the broker's defaults only")}, {"policy digest", p.Digest()}}
}
