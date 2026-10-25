// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf

// An independent implementation of the host side of internal/secretseal on
// node:crypto (OpenSSL): it signs seal key records with an Ed25519 host key
// and opens envelopes with the X25519 seal key. The QA uses it to show that
// what the browser seals opens with a second implementation.
import { createDecipheriv, createHash, createHmac, createPrivateKey, createPublicKey, diffieHellman, generateKeyPairSync, sign } from "node:crypto";

const SUITE = "hpke-base-x25519-hkdfsha256-hkdfsha256-chacha20poly1305";
const i2osp = (v, n) => Buffer.from(v.toString(16).padStart(n * 2, "0"), "hex");
export const lp = (...fields) => Buffer.concat(fields.flatMap((f) => [i2osp(Buffer.byteLength(f), 4), Buffer.from(f)]));
const u64 = (v) => {
  const b = Buffer.alloc(8);
  b.writeBigUInt64BE(BigInt(v));
  return b;
};
const sha256 = (b) => createHash("sha256").update(b).digest();

export const x25519Priv = (raw) => createPrivateKey({ key: Buffer.concat([Buffer.from("302e020100300506032b656e04220420", "hex"), Buffer.from(raw)]), format: "der", type: "pkcs8" });
export const x25519Pub = (raw) => createPublicKey({ key: Buffer.concat([Buffer.from("302a300506032b656e032100", "hex"), Buffer.from(raw)]), format: "der", type: "spki" });
export const rawPublic = (key) => Buffer.from(createPublicKey(key).export({ format: "jwk" }).x, "base64url");
export const rawPrivate = (key) => Buffer.from(key.export({ format: "jwk" }).d, "base64url");
export function ed25519FromSeed(seedHex) {
  const key = createPrivateKey({ key: Buffer.concat([Buffer.from("302e020100300506032b657004220420", "hex"), Buffer.from(seedHex, "hex")]), format: "der", type: "pkcs8" });
  return { key, pub: rawPublic(key) };
}
export const hostKeyID = (pub) => "ed25519:" + sha256(pub).subarray(0, 16).toString("hex");
export const hostFingerprint = (pub) => "SHA256:" + sha256(pub).toString("base64").replace(/=+$/, "");

const kemSuite = Buffer.concat([Buffer.from("KEM"), i2osp(0x20, 2)]);
const hpkeSuite = Buffer.concat([Buffer.from("HPKE"), i2osp(0x20, 2), i2osp(1, 2), i2osp(3, 2)]);
const hmac = (key, data) => createHmac("sha256", key).update(data).digest();
const lExtract = (suite, salt, label, ikm) => hmac(salt, Buffer.concat([Buffer.from("HPKE-v1"), suite, Buffer.from(label), ikm]));
function lExpand(suite, prk, label, info, length) {
  const full = Buffer.concat([i2osp(length, 2), Buffer.from("HPKE-v1"), suite, Buffer.from(label), info]);
  let prev = Buffer.alloc(0);
  const out = [];
  for (let i = 1; Buffer.concat(out).length < length; i++) {
    prev = hmac(prk, Buffer.concat([prev, full, Buffer.from([i])]));
    out.push(prev);
  }
  return Buffer.concat(out).subarray(0, length);
}

// nodeOpen is RFC 9180 OpenBase for DHKEM(X25519, HKDF-SHA256), HKDF-SHA256,
// ChaCha20-Poly1305; it also returns secretseal's receipt confirm secret.
export function nodeOpen(skR, enc, info, aad, sealed) {
  const priv = x25519Priv(skR);
  const dh = diffieHellman({ privateKey: priv, publicKey: x25519Pub(enc) });
  const kemContext = Buffer.concat([Buffer.from(enc), rawPublic(priv)]);
  const shared = lExpand(kemSuite, lExtract(kemSuite, Buffer.alloc(0), "eae_prk", dh), "shared_secret", kemContext, 32);
  const context = Buffer.concat([Buffer.from([0]), lExtract(hpkeSuite, Buffer.alloc(0), "psk_id_hash", Buffer.alloc(0)), lExtract(hpkeSuite, Buffer.alloc(0), "info_hash", Buffer.from(info))]);
  const secret = lExtract(hpkeSuite, shared, "secret", Buffer.alloc(0));
  const key = lExpand(hpkeSuite, secret, "key", context, 32);
  const nonce = lExpand(hpkeSuite, secret, "base_nonce", context, 12);
  const exporter = lExpand(hpkeSuite, secret, "exp", context, 32);
  const d = createDecipheriv("chacha20-poly1305", key, nonce, { authTagLength: 16 });
  const ct = Buffer.from(sealed.subarray(0, sealed.length - 16));
  d.setAAD(Buffer.from(aad), { plaintextLength: ct.length });
  d.setAuthTag(Buffer.from(sealed.subarray(sealed.length - 16)));
  const plaintext = Buffer.concat([d.update(ct), d.final()]);
  return { plaintext, confirm: lExpand(hpkeSuite, exporter, "sec", Buffer.from("agentgate.secretseal.v2 receipt"), 32) };
}

const envelopeAAD = (e) => lp("agentgate.secretseal.v2", SUITE, e.target_id, e.name, u64(e.version), e.key_id, e.nonce, e.policy_digest);
const envelopeInfo = (e) => lp("agentgate.secretseal.v2", SUITE, e.key_id, e.target_id);

// openEnvelope opens a secretseal envelope (object) with the seal private key.
export function openEnvelope(sealPrivate, e) {
  const raw = Buffer.from(e.sealed, "base64url");
  return nodeOpen(sealPrivate, raw.subarray(0, 32), envelopeInfo(e), envelopeAAD(e), raw.subarray(32));
}

export function hostReceipt(envelope, confirm, fingerprint) {
  const r = {
    format: "agentgate.secretseal.receipt.v2",
    target_id: envelope.target_id,
    name: envelope.name,
    version: envelope.version,
    key_id: envelope.key_id,
    nonce: envelope.nonce,
    policy_digest: envelope.policy_digest,
    fingerprint,
  };
  const mac = lp(r.format, r.target_id, r.name, u64(r.version), r.key_id, r.nonce, r.policy_digest, r.fingerprint);
  return { ...r, tag: hmac(confirm, mac).toString("base64url") };
}

// makeRecord is secretseal.GenerateHostKey's signed record.
export function makeRecord(hostKey, hostPub, sealPub, targetID, notBefore, notAfter) {
  const record = {
    format: "agentgate.sealkey.v1",
    target_id: targetID,
    key_id: sha256(Buffer.concat([Buffer.from("agentgate.sealkey.v1\x00"), Buffer.from(sealPub)])).toString("hex"),
    suite: SUITE,
    public_key: Buffer.from(sealPub).toString("base64url"),
    not_before: notBefore,
    not_after: notAfter,
    host_key: hostFingerprint(hostPub),
  };
  const input = lp("agentgate.sealkey.v1", record.target_id, record.key_id, record.suite, record.public_key, record.not_before, record.not_after, record.host_key);
  return { record, signature: sign(null, input, hostKey).toString("base64url") };
}

// newHost is a fresh host identity: Ed25519 enrollment key and X25519 seal key.
export function newHost() {
  const signing = generateKeyPairSync("ed25519");
  const seal = generateKeyPairSync("x25519");
  return { signingKey: signing.privateKey, hostPub: rawPublic(signing.privateKey), sealPrivate: rawPrivate(seal.privateKey), sealPub: rawPublic(seal.privateKey) };
}

export const rfc3339 = (ms) => new Date(ms).toISOString().replace(/\.\d+Z$/, "Z");
