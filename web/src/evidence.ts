// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf

// Reads the evidence blocks of a launch receipt (hostproto.Receipt). The
// network and host-control blocks are carried verbatim from the host's guard
// (cmd/pilot-network-diagnostic), so every field is optional here and
// anything unexpected is reported as "not reported" rather than guessed.

export type OpCount = { operation: string; allowed: number; denied: number };
export type Denial = { operation: string; path: string; pid?: number; target?: number; sequence?: number };
export type Ring = {
  name: string;
  operations: OpCount[];
  denials: Denial[];
  denialsTruncated: boolean;
  lost?: number;
  decisions?: number;
  observed?: number;
  complete?: boolean;
  object?: string;
  objectSHA256?: string;
};
export type Evidence = {
  rings: Ring[];
  network?: Ring;
  hostComplete?: boolean;
  networkFacts: { label: string; value: string }[];
  trimmed: boolean;
};

const obj = (v: unknown): Record<string, unknown> | undefined => (v && typeof v === "object" && !Array.isArray(v) ? (v as Record<string, unknown>) : undefined);
const num = (v: unknown) => (typeof v === "number" && Number.isFinite(v) ? v : undefined);
const bool = (v: unknown) => (typeof v === "boolean" ? v : undefined);
const str = (v: unknown) => (typeof v === "string" ? v : undefined);

function counts(v: unknown): OpCount[] {
  const o = obj(v);
  if (!o) return [];
  return Object.entries(o)
    .map(([operation, c]) => ({ operation, allowed: num(obj(c)?.allowed) ?? 0, denied: num(obj(c)?.denied) ?? 0 }))
    .sort((a, b) => b.denied - a.denied || a.operation.localeCompare(b.operation));
}

function ring(name: string, v: unknown, opsKey = "operations"): Ring | undefined {
  const o = obj(v);
  if (!o) return undefined;
  const denials = Array.isArray(o.denials)
    ? o.denials
        .map(obj)
        .filter(Boolean)
        .map((d) => ({ operation: str(d!.operation) ?? "", path: str(d!.path) ?? "", pid: num(d!.pid), target: num(d!.target_pid), sequence: num(d!.sequence) }))
    : [];
  return {
    name,
    operations: counts(o[opsKey]),
    denials,
    denialsTruncated: Boolean(o.denials_truncated || o.events_truncated),
    lost: num(o.lost),
    decisions: num(o.decisions),
    observed: num(o.observed),
    complete: bool(o.complete),
    object: str(o.object),
    objectSHA256: str(o.object_sha256),
  };
}

export function readEvidence(network: unknown, host: unknown): Evidence {
  const h = obj(host);
  const n = obj(network);
  const rings: Ring[] = [];
  for (const key of ["filesystem", "process"]) {
    const r = ring(key, h?.[key]);
    if (r) rings.push(r);
  }
  const guard = obj(n?.guard);
  const stream = ring("network", guard?.network, "hooks");
  const facts: { label: string; value: string }[] = [];
  const fact = (label: string, v: unknown) => {
    if (v === undefined || v === null || v === "") return;
    facts.push({ label, value: Array.isArray(v) ? (v.length ? v.join(", ") : "none") : typeof v === "object" ? JSON.stringify(v) : String(v) });
  };
  fact("Launcher state", n?.state);
  fact("Launcher reason", n?.launcher_reason);
  fact("Evidence complete", n?.evidence_complete);
  fact("Evidence missing", n?.evidence_missing);
  fact("Effective policy digest", n?.effective_policy_digest);
  fact("Guard receipt SHA-256", n?.guard_receipt_sha256);
  fact("Image id", n?.image_id);
  fact("Setup error", n?.setup_error);
  fact("Cleanup errors", n?.cleanup_errors);
  fact("Mount identity errors", n?.mount_identity_errors);
  fact("Reconciled after restart", n?.reconciled);
  return {
    rings,
    network: stream,
    hostComplete: bool(h?.complete),
    networkFacts: facts,
    trimmed: Boolean(h?.trimmed || guard?.trimmed),
  };
}

export const MISSING_TEXT: Record<string, string> = {
  not_started: "The launch never reached its host, so nothing ran and there is no evidence to show.",
  lost_host: "The host stopped sending verified heartbeats. A stop job waits for the host; a receipt that arrives later is attached to this launch.",
  receipt_missing: "The host ended the launch without returning an evidence receipt.",
};
export const missingText = (code: string) => MISSING_TEXT[code] || `The host reported the code ${code} instead of a receipt.`;
