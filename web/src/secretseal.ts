// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf

// Browser client for internal/secretseal: the operator's browser seals a
// secret value to one target host so the service relays ciphertext it cannot
// read.
//
//  1. The host publishes an X25519 seal key in a record signed by its enrolled
//     Ed25519 key (agentgate.sealkey.v1).
//  2. The browser checks that Ed25519 key against the fingerprint the
//     administrator approved for the target (host_key_id) and against the
//     fingerprint this browser pinned, verifies the record signature with
//     WebCrypto, and checks the record's target, suite, key id and validity.
//  3. It seals with RFC 9180 HPKE base mode, DHKEM(X25519, HKDF-SHA256),
//     HKDF-SHA256, ChaCha20-Poly1305, exactly as secretseal.Seal does. The
//     associated data binds the target id, the secret name, the version (the
//     sealing time in milliseconds), the key id, a fresh nonce and the digest
//     of the secret's injection policy (hostproto.SecretPolicy, encoded here
//     byte for byte as Go does): the host stores and uses the value only
//     under that policy, so the service cannot redirect it.
//
// WebCrypto provides X25519, Ed25519, SHA-256 and HMAC. It has no
// ChaCha20-Poly1305, so this file implements RFC 8439 for that one AEAD; the
// QA tests check it against RFC 9180 test vectors, the Go known-answer vector
// and Node's OpenSSL implementation. Nothing here falls back: a browser
// without Ed25519 or X25519 cannot seal, and the caller must say so.
//
// Errors never include a value, a key or plaintext.

export const ENVELOPE_FORMAT = "agentgate.secretseal.v2";
export const RECEIPT_FORMAT = "agentgate.secretseal.receipt.v2";
export const KEY_RECORD_FORMAT = "agentgate.sealkey.v1";
export const SUITE = "hpke-base-x25519-hkdfsha256-hkdfsha256-chacha20poly1305";
export const MAX_VALUE_BYTES = 16 << 10;
const MAX_KEY_LIFETIME_MS = 90 * 24 * 3600 * 1000;
const MAX_SKEW_MS = 5 * 60 * 1000;
const EXPORT_RECEIPT = "agentgate.secretseal.v2 receipt";

export type KeyRecord = {
  format: string;
  target_id: string;
  key_id: string;
  suite: string;
  public_key: string;
  not_before: string;
  not_after: string;
  host_key: string;
};
export type SignedKeyRecord = { record: KeyRecord; signature: string };
export type Envelope = {
  format: string;
  target_id: string;
  name: string;
  version: number;
  key_id: string;
  nonce: string;
  policy_digest: string;
  sealed: string;
};
export type SealReceipt = {
  format: string;
  target_id: string;
  name: string;
  version: number;
  key_id: string;
  nonce: string;
  policy_digest: string;
  fingerprint: string;
  tag: string;
};
export type VerifiedKey = { publicKey: Uint8Array; keyID: string; targetID: string };
export type Sealed = { envelope: Envelope; confirm: Uint8Array };

export type SealErrorCode =
  | "unsupported"
  | "key_record"
  | "signature"
  | "fingerprint"
  | "context"
  | "value"
  | "receipt"
  | "envelope"
  | "policy";

export class SealError extends Error {
  constructor(
    public code: SealErrorCode,
    message: string,
  ) {
    super(message);
    this.name = "SealError";
  }
}

const messages: Record<SealErrorCode, string> = {
  unsupported: "This browser does not provide Ed25519 and X25519 in WebCrypto.",
  key_record: "The target's seal key record is invalid or outside its validity window.",
  signature: "The seal key record is not signed by the target's approved host key.",
  fingerprint: "The host key does not match the approved and pinned fingerprint.",
  context: "The seal key belongs to another target or the secret name is invalid.",
  value: "The value is empty or larger than 16 KiB.",
  receipt: "The host receipt does not authenticate.",
  envelope: "The sealed envelope is malformed.",
  policy: "The broker settings do not make a valid injection policy.",
};
const fail = (code: SealErrorCode): never => {
  throw new SealError(code, messages[code]);
};

const namePattern = /^[a-z0-9][a-z0-9-]{0,39}$/;
const targetPattern = /^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/;
const digestPattern = /^[0-9a-f]{64}$/;

function subtle(): SubtleCrypto {
  const s = globalThis.crypto?.subtle;
  if (!s) fail("unsupported");
  return s as SubtleCrypto;
}

// ---- encoding ---------------------------------------------------------------

export const utf8 = (s: string) => new TextEncoder().encode(s);

export function concat(...parts: Uint8Array[]): Uint8Array {
  let n = 0;
  for (const p of parts) n += p.length;
  const out = new Uint8Array(n);
  let o = 0;
  for (const p of parts) {
    out.set(p, o);
    o += p.length;
  }
  return out;
}

export function hex(bytes: Uint8Array): string {
  let s = "";
  for (const b of bytes) s += b.toString(16).padStart(2, "0");
  return s;
}

export function fromHex(s: string): Uint8Array {
  if (!/^([0-9a-f]{2})*$/i.test(s)) throw new SealError("envelope", messages.envelope);
  const out = new Uint8Array(s.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(s.slice(i * 2, i * 2 + 2), 16);
  return out;
}

const B64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
function b64encode(bytes: Uint8Array, alphabet: string): string {
  let out = "";
  for (let i = 0; i < bytes.length; i += 3) {
    const n = (bytes[i] << 16) | ((bytes[i + 1] ?? 0) << 8) | (bytes[i + 2] ?? 0);
    const chars = Math.min(4, Math.ceil(((bytes.length - i) * 8) / 6));
    for (let j = 0; j < chars; j++) out += alphabet[(n >> (18 - 6 * j)) & 63];
  }
  return out;
}
export const b64url = (bytes: Uint8Array) => b64encode(bytes, B64 + "-_");
export const b64std = (bytes: Uint8Array) => b64encode(bytes, B64 + "+/");

// b64urlStrict decodes unpadded base64url and refuses padding, other
// characters and non-canonical trailing bits, like Go's RawURLEncoding.Strict.
export function b64urlStrict(s: string): Uint8Array {
  if (typeof s !== "string" || !/^[A-Za-z0-9_-]*$/.test(s) || s.length % 4 === 1)
    throw new SealError("envelope", messages.envelope);
  const alphabet = B64 + "-_";
  const out = new Uint8Array(Math.floor((s.length * 6) / 8));
  let bits = 0;
  let value = 0;
  let o = 0;
  for (const c of s) {
    value = (value << 6) | alphabet.indexOf(c);
    bits += 6;
    if (bits >= 8) {
      bits -= 8;
      out[o++] = (value >> bits) & 255;
    }
  }
  if (b64url(out) !== s) throw new SealError("envelope", messages.envelope);
  return out;
}

// lp is secretseal's length-prefixed encoding: a big-endian uint32 length
// before each field.
export function lp(...fields: Uint8Array[]): Uint8Array {
  return concat(
    ...fields.flatMap((f) => {
      const n = new Uint8Array(4);
      new DataView(n.buffer).setUint32(0, f.length);
      return [n, f];
    }),
  );
}

export function u64(v: number): Uint8Array {
  if (!Number.isSafeInteger(v) || v < 0) throw new SealError("envelope", messages.envelope);
  const out = new Uint8Array(8);
  new DataView(out.buffer).setBigUint64(0, BigInt(v));
  return out;
}

// buf copies exactly the bytes of a view into a fresh ArrayBuffer. A view's
// .buffer can be larger than the view (a subarray, a pooled Node Buffer).
const buf = (b: Uint8Array): ArrayBuffer => {
  const copy = new Uint8Array(b.length);
  copy.set(b);
  return copy.buffer;
};

export async function sha256(data: Uint8Array): Promise<Uint8Array> {
  return new Uint8Array(await subtle().digest("SHA-256", buf(data)));
}

// ---- fingerprints -------------------------------------------------------------

// hostKeyID is hostproto.KeyID: "ed25519:" and the first 16 bytes of the
// key's SHA-256 in hex. The service shows it as host_key_id and the
// administrator approved it against the host console.
export async function hostKeyID(pub: Uint8Array): Promise<string> {
  return "ed25519:" + hex((await sha256(pub)).slice(0, 16));
}

// hostKeyFingerprint is secretseal.HostKeyFingerprint: "SHA256:" and the
// unpadded standard base64 of the key's SHA-256, in the style of OpenSSH.
export async function hostKeyFingerprint(pub: Uint8Array): Promise<string> {
  return "SHA256:" + b64std(await sha256(pub));
}

async function sealKeyID(pub: Uint8Array): Promise<string> {
  return hex(await sha256(concat(utf8(KEY_RECORD_FORMAT + "\x00"), pub)));
}

function signingInput(r: KeyRecord): Uint8Array {
  return lp(
    utf8(KEY_RECORD_FORMAT),
    utf8(r.target_id),
    utf8(r.key_id),
    utf8(r.suite),
    utf8(r.public_key),
    utf8(r.not_before),
    utf8(r.not_after),
    utf8(r.host_key),
  );
}

// ---- injection policy (hostproto.SecretPolicy) ---------------------------------

// A secret's injection policy says where and how the host's broker may use
// the value. The browser computes it from the form, shows it before sealing,
// seals its digest with the value and refuses an answer whose settings make
// another digest. The encoding below is internal/hostproto/policy.go's, byte
// for byte; web/qa/secretseal.node.mjs checks it against the Go vectors.

export const POLICY_FORMAT = "agentgate.secret-policy.v1";
export const BROKER_METHODS = ["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"];
const MAX_POLICY_RULES = 64;
const MAX_FORWARD_HEADERS = 16;
const upstreamPattern = /^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+(:[0-9]{1,5})?$/;
const headerPattern = /^[A-Za-z0-9-]{1,64}$/;

export type PolicyRule = { methods: string[]; path: string; match: string };
export type PolicyUpstream = { host: string; port: number; base_path: string; private_addresses: string[] };
export type SecretPolicy = {
  upstreams: PolicyUpstream[];
  header: string;
  scheme: string;
  username: string;
  extra_headers: { name: string; value: string }[];
  forward_headers: string[];
  rules: PolicyRule[];
  wildcard: boolean;
};
// PolicyInput is a secret's settings as the secrets API writes them (the
// wildcard is the expanded rule with wildcard set).
export type PolicyInput = {
  upstreams: string[];
  header: string;
  scheme?: string;
  username?: string;
  rules: PolicyRule[];
  extra_headers?: Record<string, string> | null;
  forward_headers?: string[] | null;
  wildcard?: boolean;
};

const bytewise = (a: string, b: string) => (a < b ? -1 : a > b ? 1 : 0);

// newSecretPolicy is hostproto.NewSecretPolicy: it normalizes the settings
// (explicit ports, lower-case header names, Bearer for an Authorization
// header without a scheme, sorted extra and forwarded headers, rule methods
// in BROKER_METHODS order) and refuses anything ambiguous.
export function newSecretPolicy(input: PolicyInput): SecretPolicy {
  const header = String(input.header ?? "");
  const ups = input.upstreams ?? [];
  if (!Array.isArray(ups) || ups.length < 1 || ups.length > 8 || !headerPattern.test(header)) fail("policy");
  const p: SecretPolicy = {
    upstreams: [],
    header: header.toLowerCase(),
    scheme: input.scheme ?? "",
    username: input.username ?? "",
    extra_headers: [],
    forward_headers: [],
    rules: [],
    wildcard: !!input.wildcard,
  };
  const seen = new Set<string>();
  for (const u of ups) {
    if (typeof u !== "string" || u.length > 253 || !upstreamPattern.test(u)) fail("policy");
    let host = u;
    let port = 443;
    const colon = u.lastIndexOf(":");
    if (colon >= 0) {
      host = u.slice(0, colon);
      port = Number(u.slice(colon + 1));
      if (!Number.isInteger(port) || port < 1 || port > 65535) fail("policy");
    }
    const key = host + ":" + port;
    if (seen.has(key)) fail("policy");
    seen.add(key);
    p.upstreams.push({ host, port, base_path: "", private_addresses: [] });
  }
  if (p.scheme === "" && p.header === "authorization") p.scheme = "Bearer";
  const names = new Set<string>();
  for (const [name, value] of Object.entries(input.extra_headers ?? {})) {
    const lower = name.toLowerCase();
    if (!headerPattern.test(name) || names.has(lower) || typeof value !== "string") fail("policy");
    names.add(lower);
    p.extra_headers.push({ name: lower, value });
  }
  p.extra_headers.sort((a, b) => bytewise(a.name, b.name));
  const forward = input.forward_headers ?? [];
  if (forward.length > MAX_FORWARD_HEADERS) fail("policy");
  const fw = new Set<string>();
  for (const f of forward) {
    const lower = String(f).toLowerCase();
    if (!headerPattern.test(f) || fw.has(lower)) fail("policy");
    fw.add(lower);
    p.forward_headers.push(lower);
  }
  p.forward_headers.sort(bytewise);
  const rules = input.rules ?? [];
  if (rules.length > MAX_POLICY_RULES) fail("policy");
  for (const r of rules) {
    const methods: string[] = [];
    for (const m of BROKER_METHODS) {
      const n = r.methods.filter((x) => x === m).length;
      if (n > 1) fail("policy");
      if (n === 1) methods.push(m);
    }
    if (methods.length !== r.methods.length) fail("policy");
    p.rules.push({ methods, path: r.path, match: r.match });
  }
  if (
    p.wildcard &&
    (p.rules.length !== 1 || p.rules[0].methods.length !== BROKER_METHODS.length || p.rules[0].path !== "/" || p.rules[0].match !== "prefix")
  )
    fail("policy");
  return p;
}

const lpStrings = (values: string[]) => lp(...values.map(utf8));

// canonicalPolicy is SecretPolicy.Canonical: nested length-prefixed fields
//   lp(format, lp(lp(host, port, base_path, lp(private_address...))...),
//      header, scheme, username, lp(lp(name, value)...), lp(forward...),
//      lp(lp(lp(method...), path, match)...), "true" | "false")
export function canonicalPolicy(p: SecretPolicy): Uint8Array {
  const ups = p.upstreams.map((u) =>
    lp(utf8(u.host), utf8(String(u.port)), utf8(u.base_path), lpStrings([...u.private_addresses].sort(bytewise))),
  );
  const extra = p.extra_headers.map((h) => lp(utf8(h.name), utf8(h.value)));
  const rules = p.rules.map((r) => lp(lpStrings(r.methods), utf8(r.path), utf8(r.match)));
  return lp(
    utf8(POLICY_FORMAT),
    lp(...ups),
    utf8(p.header),
    utf8(p.scheme),
    utf8(p.username),
    lp(...extra),
    lpStrings(p.forward_headers),
    lp(...rules),
    utf8(p.wildcard ? "true" : "false"),
  );
}

// policyDigest is SecretPolicy.Digest: the hex SHA-256 of the canonical
// encoding, the policy_digest a sealed envelope, its receipt, the service and
// the host all carry.
export async function policyDigest(p: SecretPolicy): Promise<string> {
  return hex(await sha256(canonicalPolicy(p)));
}

// settingsDigest is the digest of a secret's settings as the secrets API
// returns them (a stored secret or a plan's secret): what a reviewer checks
// against the policy_digest the same answer names.
export async function settingsDigest(s: {
  upstreams: string[];
  header: string;
  scheme?: string;
  username?: string;
  rules?: { methods: string[]; path: string; match?: string }[] | null;
  wildcard_rules?: boolean;
  extra_headers?: Record<string, string> | null;
  forward_headers?: string[] | null;
}): Promise<string | undefined> {
  try {
    return await policyDigest(
      newSecretPolicy({
        upstreams: s.upstreams,
        header: s.header,
        scheme: s.scheme,
        username: s.username,
        rules: (s.rules ?? []).map((r) => ({ methods: r.methods, path: r.path, match: r.match ?? "" })),
        extra_headers: s.extra_headers,
        forward_headers: s.forward_headers,
        wildcard: s.wildcard_rules,
      }),
    );
  } catch {
    return undefined;
  }
}

// ---- support -----------------------------------------------------------------

// sealSupport reports whether this browser can verify and seal. It tries the
// algorithms instead of trusting feature names.
export async function sealSupport(): Promise<{ ok: boolean; missing: string[] }> {
  const missing: string[] = [];
  const s = globalThis.crypto?.subtle;
  if (!s) return { ok: false, missing: ["WebCrypto"] };
  try {
    const kp = (await s.generateKey({ name: "Ed25519" } as Algorithm, false, ["sign", "verify"])) as CryptoKeyPair;
    const sig = await s.sign({ name: "Ed25519" } as Algorithm, kp.privateKey, new Uint8Array([1]));
    if (!(await s.verify({ name: "Ed25519" } as Algorithm, kp.publicKey, sig, new Uint8Array([1]))))
      missing.push("Ed25519");
  } catch {
    missing.push("Ed25519");
  }
  try {
    const a = (await s.generateKey({ name: "X25519" } as Algorithm, false, ["deriveBits"])) as CryptoKeyPair;
    const b = (await s.generateKey({ name: "X25519" } as Algorithm, false, ["deriveBits"])) as CryptoKeyPair;
    await s.deriveBits({ name: "X25519", public: b.publicKey } as EcdhKeyDeriveParams, a.privateKey, 256);
  } catch {
    missing.push("X25519");
  }
  try {
    const k = await s.importKey("raw", new Uint8Array(32), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
    await s.sign("HMAC", k, new Uint8Array([1]));
  } catch {
    missing.push("HMAC-SHA256");
  }
  return { ok: missing.length === 0, missing };
}

// ---- key record --------------------------------------------------------------

async function ed25519Verify(pub: Uint8Array, message: Uint8Array, signature: Uint8Array) {
  let key: CryptoKey;
  try {
    key = await subtle().importKey("raw", buf(pub), { name: "Ed25519" } as Algorithm, false, ["verify"]);
  } catch {
    return fail("unsupported");
  }
  return subtle().verify({ name: "Ed25519" } as Algorithm, key, buf(signature), buf(message));
}

const rfc3339 = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?(Z|[+-]\d{2}:\d{2})$/;
function parseTime(value: string): number {
  if (typeof value !== "string" || !rfc3339.test(value)) return NaN;
  return Date.parse(value);
}

// verifyKeyRecord is secretseal.VerifyKeyRecord. hostPub is the target's
// Ed25519 enrollment key; pinnedFingerprint is the SHA256: fingerprint this
// browser trusts for the target. A service that substitutes the seal key
// fails here: it would need a signature from the pinned host key.
export async function verifyKeyRecord(
  signed: SignedKeyRecord,
  hostPub: Uint8Array,
  pinnedFingerprint: string,
  targetID: string,
  now: number,
): Promise<VerifiedKey> {
  if (!signed || typeof signed !== "object" || !signed.record || hostPub.length !== 32) fail("key_record");
  const fp = await hostKeyFingerprint(hostPub);
  if (!pinnedFingerprint || fp !== pinnedFingerprint) fail("fingerprint");
  let signature: Uint8Array;
  try {
    signature = b64urlStrict(signed.signature);
  } catch {
    return fail("signature");
  }
  const r = signed.record;
  const fields = ["format", "target_id", "key_id", "suite", "public_key", "not_before", "not_after", "host_key"] as const;
  if (fields.some((f) => typeof r[f] !== "string")) fail("key_record");
  if (signature.length !== 64 || !(await ed25519Verify(hostPub, signingInput(r), signature))) fail("signature");
  if (r.host_key !== fp) fail("signature");
  if (r.format !== KEY_RECORD_FORMAT || r.suite !== SUITE) fail("key_record");
  if (r.target_id !== targetID || !targetPattern.test(targetID)) fail("context");
  const nb = parseTime(r.not_before);
  const na = parseTime(r.not_after);
  if (!Number.isFinite(nb) || !Number.isFinite(na) || !(na > nb) || na - nb > MAX_KEY_LIFETIME_MS || now < nb - MAX_SKEW_MS || !(now < na))
    fail("key_record");
  let raw: Uint8Array;
  try {
    raw = b64urlStrict(r.public_key);
  } catch {
    return fail("key_record");
  }
  if (raw.length !== 32 || r.key_id !== (await sealKeyID(raw))) fail("key_record");
  return { publicKey: raw, keyID: r.key_id, targetID };
}

// ---- HKDF and HPKE (RFC 9180) --------------------------------------------------

async function hmac(key: Uint8Array, data: Uint8Array): Promise<Uint8Array> {
  // An empty HKDF salt is HashLen zero bytes; HMAC pads keys with zeros, so
  // both are the same key. WebCrypto refuses zero-length HMAC keys.
  const k = await subtle().importKey("raw", buf(key.length ? key : new Uint8Array(32)), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  return new Uint8Array(await subtle().sign("HMAC", k, buf(data)));
}

async function expand(prk: Uint8Array, info: Uint8Array, length: number): Promise<Uint8Array> {
  const out = new Uint8Array(length);
  let prev = new Uint8Array(0);
  for (let i = 1, o = 0; o < length; i++) {
    prev = await hmac(prk, concat(prev, info, new Uint8Array([i])));
    out.set(prev.slice(0, Math.min(32, length - o)), o);
    o += 32;
  }
  return out;
}

const i2osp = (v: number, n: number) => {
  const out = new Uint8Array(n);
  for (let i = n - 1; i >= 0; i--, v >>= 8) out[i] = v & 255;
  return out;
};
const KEM_SUITE = concat(utf8("KEM"), i2osp(0x0020, 2));
const HPKE_SUITE = concat(utf8("HPKE"), i2osp(0x0020, 2), i2osp(0x0001, 2), i2osp(0x0003, 2));
const HPKE_V1 = utf8("HPKE-v1");

const labeledExtract = (suite: Uint8Array, salt: Uint8Array, label: string, ikm: Uint8Array) =>
  hmac(salt, concat(HPKE_V1, suite, utf8(label), ikm));
const labeledExpand = (suite: Uint8Array, prk: Uint8Array, label: string, info: Uint8Array, length: number) =>
  expand(prk, concat(i2osp(length, 2), HPKE_V1, suite, utf8(label), info), length);

const PKCS8_X25519 = fromHex("302e020100300506032b656e04220420");

async function importX25519Private(raw: Uint8Array, extractable: boolean): Promise<CryptoKey> {
  return subtle().importKey("pkcs8", buf(concat(PKCS8_X25519, raw)), { name: "X25519" } as Algorithm, extractable, ["deriveBits"]);
}

async function x25519(priv: CryptoKey, pub: Uint8Array): Promise<Uint8Array> {
  const peer = await subtle().importKey("raw", buf(pub), { name: "X25519" } as Algorithm, false, []);
  const shared = new Uint8Array(await subtle().deriveBits({ name: "X25519", public: peer } as EcdhKeyDeriveParams, priv, 256));
  // RFC 9180 7.1.4: an all-zero shared secret (a low-order peer key) fails.
  if (shared.every((b) => b === 0)) fail("key_record");
  return shared;
}

async function publicOf(priv: CryptoKey): Promise<Uint8Array> {
  const jwk = await subtle().exportKey("jwk", priv);
  return b64urlStrict(jwk.x || "");
}

async function extractAndExpand(dh: Uint8Array, kemContext: Uint8Array) {
  const prk = await labeledExtract(KEM_SUITE, new Uint8Array(0), "eae_prk", dh);
  return labeledExpand(KEM_SUITE, prk, "shared_secret", kemContext, 32);
}

async function keySchedule(shared: Uint8Array, info: Uint8Array) {
  const empty = new Uint8Array(0);
  const pskIDHash = await labeledExtract(HPKE_SUITE, empty, "psk_id_hash", empty);
  const infoHash = await labeledExtract(HPKE_SUITE, empty, "info_hash", info);
  const context = concat(new Uint8Array([0]), pskIDHash, infoHash);
  const secret = await labeledExtract(HPKE_SUITE, shared, "secret", empty);
  return {
    key: await labeledExpand(HPKE_SUITE, secret, "key", context, 32),
    nonce: await labeledExpand(HPKE_SUITE, secret, "base_nonce", context, 12),
    exporter: await labeledExpand(HPKE_SUITE, secret, "exp", context, 32),
  };
}

export type HPKESealed = { enc: Uint8Array; ct: Uint8Array; exporter: Uint8Array };

// hpkeSeal is the single-shot RFC 9180 base mode SealBase. ephemeralPrivate
// exists only for known-answer tests; production callers leave it out and a
// fresh non-extractable key is generated.
export async function hpkeSeal(
  recipient: Uint8Array,
  info: Uint8Array,
  aad: Uint8Array,
  plaintext: Uint8Array,
  ephemeralPrivate?: Uint8Array,
): Promise<HPKESealed> {
  let priv: CryptoKey;
  let enc: Uint8Array;
  if (ephemeralPrivate) {
    priv = await importX25519Private(ephemeralPrivate, true);
    enc = await publicOf(priv);
  } else {
    const kp = (await subtle().generateKey({ name: "X25519" } as Algorithm, false, ["deriveBits"])) as CryptoKeyPair;
    priv = kp.privateKey;
    enc = new Uint8Array(await subtle().exportKey("raw", kp.publicKey));
  }
  const dh = await x25519(priv, recipient);
  const shared = await extractAndExpand(dh, concat(enc, recipient));
  const ks = await keySchedule(shared, info);
  const ct = chachaPolySeal(ks.key, ks.nonce, plaintext, aad);
  dh.fill(0);
  shared.fill(0);
  ks.key.fill(0);
  return { enc, ct, exporter: ks.exporter };
}

// hpkeOpen is OpenBase for tests and for checking vectors. Browsers never hold
// a host private key.
export async function hpkeOpen(
  recipientPrivate: Uint8Array,
  enc: Uint8Array,
  info: Uint8Array,
  aad: Uint8Array,
  ct: Uint8Array,
): Promise<{ plaintext: Uint8Array; exporter: Uint8Array }> {
  const priv = await importX25519Private(recipientPrivate, true);
  const pub = await publicOf(priv);
  const dh = await x25519(priv, enc);
  const shared = await extractAndExpand(dh, concat(enc, pub));
  const ks = await keySchedule(shared, info);
  return { plaintext: chachaPolyOpen(ks.key, ks.nonce, ct, aad), exporter: ks.exporter };
}

export const hpkeExport = (exporter: Uint8Array, context: Uint8Array, length: number) =>
  labeledExpand(HPKE_SUITE, exporter, "sec", context, length);

// ---- secretseal envelope --------------------------------------------------------

export function envelopeAAD(e: Omit<Envelope, "sealed">): Uint8Array {
  return lp(utf8(ENVELOPE_FORMAT), utf8(SUITE), utf8(e.target_id), utf8(e.name), u64(e.version), utf8(e.key_id), utf8(e.nonce), utf8(e.policy_digest));
}
export const envelopeInfo = (keyID: string, targetID: string) => lp(utf8(ENVELOPE_FORMAT), utf8(SUITE), utf8(keyID), utf8(targetID));

export type SealOptions = { ephemeralPrivate?: Uint8Array; nonce?: string };

// seal is secretseal.SealAt: it seals value for one verified target key, to
// be used only under the injection policy whose digest is policyDigest (see
// policyDigest), with now (Unix milliseconds) as the version. The caller
// wipes value afterwards and keeps confirm in memory only until the host
// receipt is checked.
export async function seal(
  key: VerifiedKey,
  targetID: string,
  name: string,
  policyDigest: string,
  value: Uint8Array,
  now: number,
  options: SealOptions = {},
): Promise<Sealed> {
  if (!key || key.targetID !== targetID || !namePattern.test(name) || !targetPattern.test(targetID) || !digestPattern.test(policyDigest)) fail("context");
  if (value.length === 0 || value.length > MAX_VALUE_BYTES) fail("value");
  const nonce = options.nonce ?? hex(globalThis.crypto.getRandomValues(new Uint8Array(16)));
  if (!/^[0-9a-f]{32}$/.test(nonce)) fail("envelope");
  const head = { format: ENVELOPE_FORMAT, target_id: targetID, name, version: Math.floor(now), key_id: key.keyID, nonce, policy_digest: policyDigest };
  const sealed = await hpkeSeal(key.publicKey, envelopeInfo(key.keyID, targetID), envelopeAAD(head), value, options.ephemeralPrivate);
  const confirm = await hpkeExport(sealed.exporter, utf8(EXPORT_RECEIPT), 32);
  sealed.exporter.fill(0);
  return { envelope: { ...head, sealed: b64url(concat(sealed.enc, sealed.ct)) }, confirm };
}

// encodeEnvelope is secretseal.Envelope.Encode: the unpadded base64url of
// the envelope's JSON, the string the secrets API carries as ciphertext.
export function encodeEnvelope(e: Envelope): string {
  const ordered = {
    format: e.format,
    target_id: e.target_id,
    name: e.name,
    version: e.version,
    key_id: e.key_id,
    nonce: e.nonce,
    policy_digest: e.policy_digest,
    sealed: e.sealed,
  };
  return b64url(utf8(JSON.stringify(ordered)));
}

// envelopeDigest is the SHA-256 of the encoded envelope bytes, the value the
// service records as ciphertext_sha256, so the browser can check that the
// service stored exactly what it sent.
export async function envelopeDigest(encoded: string): Promise<string> {
  return hex(await sha256(b64urlStrict(encoded)));
}

// brokerValueOK is broker.ValidSecret: the broker injects only 8 to 8192
// bytes of visible ASCII. The host refuses anything else at secret-put time.
export function brokerValueOK(value: Uint8Array): boolean {
  if (value.length < 8 || value.length > 8192) return false;
  for (const c of value) if (c < 0x21 || c > 0x7e) return false;
  return true;
}

// openEnvelope is secretseal.Open without the host's version bookkeeping; it
// exists for tests.
export async function openEnvelope(hostPrivate: Uint8Array, e: Envelope): Promise<{ value: Uint8Array; confirm: Uint8Array }> {
  const raw = b64urlStrict(e.sealed);
  if (raw.length < 48) fail("envelope");
  const opened = await hpkeOpen(hostPrivate, raw.slice(0, 32), envelopeInfo(e.key_id, e.target_id), envelopeAAD(e), raw.slice(32));
  return { value: opened.plaintext, confirm: await hpkeExport(opened.exporter, utf8(EXPORT_RECEIPT), 32) };
}

function receiptMAC(r: SealReceipt): Uint8Array {
  return lp(utf8(RECEIPT_FORMAT), utf8(r.target_id), utf8(r.name), u64(r.version), utf8(r.key_id), utf8(r.nonce), utf8(r.policy_digest), utf8(r.fingerprint));
}

// verifyReceipt is Sealed.VerifyReceipt: the host proves it opened exactly
// this envelope and stored it under exactly the sealed policy. It returns the
// fingerprint the host reported.
export async function verifyReceipt(s: Sealed, r: SealReceipt): Promise<string> {
  const e = s.envelope;
  if (
    !r ||
    r.format !== RECEIPT_FORMAT ||
    r.target_id !== e.target_id ||
    r.name !== e.name ||
    r.version !== e.version ||
    r.key_id !== e.key_id ||
    r.nonce !== e.nonce ||
    r.policy_digest !== e.policy_digest ||
    !/^sfp1_[0-9a-f]{32}$/.test(r.fingerprint)
  )
    fail("receipt");
  let tag: Uint8Array;
  try {
    tag = b64urlStrict(r.tag);
  } catch {
    return fail("receipt");
  }
  const want = await hmac(s.confirm, receiptMAC(r));
  if (!constantEqual(tag, want)) fail("receipt");
  return r.fingerprint;
}

export function wipe(s?: Sealed | null) {
  s?.confirm.fill(0);
}

function constantEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let d = 0;
  for (let i = 0; i < a.length; i++) d |= a[i] ^ b[i];
  return d === 0;
}

// ---- ChaCha20-Poly1305 (RFC 8439) -------------------------------------------------

function chachaBlock(key: Uint32Array, counter: number, nonce: Uint32Array, out: Uint8Array) {
  const s = new Uint32Array(16);
  s[0] = 0x61707865;
  s[1] = 0x3320646e;
  s[2] = 0x79622d32;
  s[3] = 0x6b206574;
  s.set(key, 4);
  s[12] = counter >>> 0;
  s.set(nonce, 13);
  const w = s.slice();
  const q = (a: number, b: number, c: number, d: number) => {
    w[a] += w[b]; w[d] ^= w[a]; w[d] = (w[d] << 16) | (w[d] >>> 16);
    w[c] += w[d]; w[b] ^= w[c]; w[b] = (w[b] << 12) | (w[b] >>> 20);
    w[a] += w[b]; w[d] ^= w[a]; w[d] = (w[d] << 8) | (w[d] >>> 24);
    w[c] += w[d]; w[b] ^= w[c]; w[b] = (w[b] << 7) | (w[b] >>> 25);
  };
  for (let i = 0; i < 10; i++) {
    q(0, 4, 8, 12); q(1, 5, 9, 13); q(2, 6, 10, 14); q(3, 7, 11, 15);
    q(0, 5, 10, 15); q(1, 6, 11, 12); q(2, 7, 8, 13); q(3, 4, 9, 14);
  }
  const view = new DataView(out.buffer, out.byteOffset, 64);
  for (let i = 0; i < 16; i++) view.setUint32(i * 4, (w[i] + s[i]) >>> 0, true);
}

function words(bytes: Uint8Array): Uint32Array {
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  const out = new Uint32Array(bytes.length / 4);
  for (let i = 0; i < out.length; i++) out[i] = view.getUint32(i * 4, true);
  return out;
}

export function chacha20(key: Uint8Array, counter: number, nonce: Uint8Array, input: Uint8Array): Uint8Array {
  if (key.length !== 32 || nonce.length !== 12) fail("envelope");
  const k = words(key);
  const n = words(nonce);
  const out = new Uint8Array(input.length);
  const block = new Uint8Array(64);
  for (let o = 0, c = counter; o < input.length; o += 64, c++) {
    chachaBlock(k, c, n, block);
    for (let i = 0; i < 64 && o + i < input.length; i++) out[o + i] = input[o + i] ^ block[i];
  }
  block.fill(0);
  k.fill(0);
  return out;
}

function le(bytes: Uint8Array): bigint {
  let v = 0n;
  for (let i = bytes.length - 1; i >= 0; i--) v = (v << 8n) | BigInt(bytes[i]);
  return v;
}

export function poly1305(key: Uint8Array, msg: Uint8Array): Uint8Array {
  const r = le(key.slice(0, 16)) & 0x0ffffffc0ffffffc0ffffffc0fffffffn;
  const s = le(key.slice(16, 32));
  const p = (1n << 130n) - 5n;
  let acc = 0n;
  for (let i = 0; i < msg.length; i += 16) {
    const chunk = msg.slice(i, i + 16);
    acc = ((acc + le(chunk) + (1n << BigInt(8 * chunk.length))) * r) % p;
  }
  acc = (acc + s) & ((1n << 128n) - 1n);
  const out = new Uint8Array(16);
  for (let i = 0; i < 16; i++, acc >>= 8n) out[i] = Number(acc & 255n);
  return out;
}

function macData(aad: Uint8Array, ct: Uint8Array): Uint8Array {
  const pad = (n: number) => new Uint8Array((16 - (n % 16)) % 16);
  const lens = new Uint8Array(16);
  const view = new DataView(lens.buffer);
  view.setBigUint64(0, BigInt(aad.length), true);
  view.setBigUint64(8, BigInt(ct.length), true);
  return concat(aad, pad(aad.length), ct, pad(ct.length), lens);
}

export function chachaPolySeal(key: Uint8Array, nonce: Uint8Array, plaintext: Uint8Array, aad: Uint8Array): Uint8Array {
  const otk = chacha20(key, 0, nonce, new Uint8Array(32));
  const ct = chacha20(key, 1, nonce, plaintext);
  const tag = poly1305(otk, macData(aad, ct));
  otk.fill(0);
  return concat(ct, tag);
}

export function chachaPolyOpen(key: Uint8Array, nonce: Uint8Array, sealed: Uint8Array, aad: Uint8Array): Uint8Array {
  if (sealed.length < 16) fail("envelope");
  const ct = sealed.slice(0, sealed.length - 16);
  const otk = chacha20(key, 0, nonce, new Uint8Array(32));
  const tag = poly1305(otk, macData(aad, ct));
  otk.fill(0);
  if (!constantEqual(tag, sealed.slice(sealed.length - 16))) throw new SealError("envelope", "The sealed value does not authenticate.");
  return chacha20(key, 1, nonce, ct);
}

// ---- browser pins ---------------------------------------------------------------

// Pins are this browser's known-targets file: target id to the host_key_id
// (ed25519:…) the operator approved or confirmed against the host console. They live in localStorage, may be
// absent (private windows, cleared data) and never replace an existing pin.
const PIN_KEY = "agentgate.known-targets.v1";
export function readPin(targetID: string): string | undefined {
  try {
    const all = JSON.parse(localStorage.getItem(PIN_KEY) || "{}");
    return typeof all[targetID] === "string" ? all[targetID] : undefined;
  } catch {
    return undefined;
  }
}
export function writePin(targetID: string, fingerprint: string): boolean {
  try {
    const all = JSON.parse(localStorage.getItem(PIN_KEY) || "{}");
    if (all[targetID] && all[targetID] !== fingerprint) return false;
    all[targetID] = fingerprint;
    localStorage.setItem(PIN_KEY, JSON.stringify(all));
    return true;
  } catch {
    return false;
  }
}
export function forgetPin(targetID: string) {
  try {
    const all = JSON.parse(localStorage.getItem(PIN_KEY) || "{}");
    delete all[targetID];
    localStorage.setItem(PIN_KEY, JSON.stringify(all));
  } catch {
    /* storage unavailable: nothing was pinned */
  }
}
