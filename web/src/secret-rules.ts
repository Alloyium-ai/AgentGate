// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf

// Checks of a secret's broker settings that the secret form runs before it
// seals anything, and the explanations of the service's secret refusals.
// The service checks everything again with the broker's own validator.

export const SECRET_HEADER = /^[A-Za-z0-9-]{1,64}$/;
// The broker's own bounds (internal/hostproto CheckInjection); the service
// checks every rule again with the broker's validator.
export const BROKER_METHODS = ["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"];
// canonicalRulePath is hostproto.CanonicalRulePath: an absolute path of RFC
// 3986 path characters without percent-encoding, path parameters (";"),
// dot-only segments, segments ending in "." or empty segments (one trailing
// slash is allowed), at most 512 bytes.
export function canonicalRulePath(p: string): boolean {
  if (!/^\/[A-Za-z0-9\-._~!$&'()*+,=:@/]{0,511}$/.test(p)) return false;
  const segments = p.slice(1).split("/");
  return segments.every((seg, i) => (seg === "" ? i === segments.length - 1 : seg.replace(/\./g, "") !== "" && !seg.endsWith(".")));
}
export const BASIC_USER = /^[\x21-\x39\x3b-\x7e]{1,64}$/;
const NEVER_EXTRA = ["authorization", "x-api-key", "host", "cookie"];
export type RuleRow = { methods: string; path: string; match: "exact" | "prefix" };
export type HeaderRow = { name: string; value: string };

// ruleIssues checks the broker rules as the broker does, before sealing.
export function ruleIssues(rows: RuleRow[], wildcard: boolean, confirmed: boolean): string[] {
  if (wildcard) return confirmed ? [] : ["Confirm that the wildcard lets the broker forward every method on every path of the upstreams."];
  if (!rows.length) return ["The broker forwards nothing by default: add at least one rule (method and path), or allow every path explicitly."];
  if (rows.length > 64) return ["At most 64 rules."];
  const out: string[] = [];
  rows.forEach((r, i) => {
    const methods = r.methods.split(/[\s,]+/).filter(Boolean).map((m) => m.toUpperCase());
    if (!methods.length || methods.some((m) => !BROKER_METHODS.includes(m)) || new Set(methods).size !== methods.length) out.push(`Rule ${i + 1}: methods are unique ${BROKER_METHODS.join(", ")}.`);
    if (!canonicalRulePath(r.path)) out.push(`Rule ${i + 1}: the path is an absolute path such as /v1/messages, without percent-encoding, ";", dot segments, a segment ending in "." or //.`);
  });
  return out;
}

export function headerIssues(rows: HeaderRow[], header: string): string[] {
  if (rows.length > 8) return ["At most 8 extra headers."];
  const out: string[] = [];
  const names = rows.map((r) => r.name.toLowerCase());
  rows.forEach((r, i) => {
    const lower = r.name.toLowerCase();
    if (!SECRET_HEADER.test(r.name) || lower === header.toLowerCase() || NEVER_EXTRA.includes(lower) || lower.startsWith("proxy-") || lower.startsWith("x-forwarded-"))
      out.push(`Extra header ${i + 1}: a header name the broker may set (not the credential header, Host, Cookie, Proxy-* or X-Forwarded-*).`);
    if (!/^[\x21-\x7e]([\x20-\x7e]{0,254}[\x21-\x7e])?$/.test(r.value)) out.push(`Extra header ${i + 1}: 1 to 256 printable ASCII characters, no leading or trailing space.`);
  });
  if (new Set(names).size !== names.length) out.push("Each extra header appears once.");
  return out;
}

// sealFailure explains the service's refusals of a sealed secret.
export function sealFailureText(code: string, message: string): string | undefined {
  switch (code) {
    case "seal_key_changed":
      return "The target published a new seal key after this browser verified it. Nothing was stored: verify the seal key again and seal the value again.";
    case "seal_key_unavailable":
      return "The target's host has not published a host-signed seal key, so nothing can be sealed to it. Nothing was stored.";
    case "invalid_ciphertext":
      return "The service refused the sealed envelope: it names another target, name or format. Nothing was stored; verify and seal again (an envelope is never reused).";
    case "invalid_secret":
      return `The broker would refuse these settings: ${message} Nothing was stored.`;
    case "policy_mismatch":
      return "The service received other broker settings than the policy this browser sealed with the value. Nothing was stored. If you did not change the form while sealing, do not store secrets through this service until you know why.";
  }
  return undefined;
}

// refusalHelp says what to do about the service's secret refusals of a plan
// or a launch; the service's own message is shown beside it.
export function refusalHelp(code: string): string | undefined {
  switch (code) {
    case "secret_rules_missing":
      return "The secret was stored without broker rules, so the broker would forward nothing with it. An administrator stores it again (same name, a new envelope) with explicit rules, or with the confirmed wildcard; then plan again.";
    case "secret_unavailable":
      return "The secret is not stored on this target (or is being removed). Pick a secret listed for the target, or ask an administrator to store it there.";
    case "secret_scope":
      return "The secret is not scoped to this profile or to you. Use a reviewed profile and a secret whose scope includes you, or ask an administrator to widen the scope.";
    case "secret_policy_mismatch":
      return "The secret's stored broker settings are not the policy sealed with its value (or it was sealed before policies were), so no launch may use it. An administrator stores it again with a new envelope.";
  }
  return undefined;
}
