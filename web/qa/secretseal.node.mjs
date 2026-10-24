// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf

// Known-answer and adversarial tests for the browser secret sealing client
// (web/src/secretseal.ts) against internal/secretseal. Fixtures:
//   fixtures/secretseal-vector-v1.json  copy of internal/secretseal/testdata/vector-v1.json
//   fixtures/hpke-rfc9180-a2-1.json     RFC 9180 A.2.1 (X25519, HKDF-SHA256, ChaCha20Poly1305)
// The independent opener (hpke-node.mjs) uses only node:crypto (OpenSSL), so a
// passing round trip shows the browser's bytes open with a second implementation.
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { test } from "node:test";
import { createCipheriv, generateKeyPairSync, randomBytes } from "node:crypto";
import { loadTS } from "./load-ts.mjs";
import { ed25519FromSeed, hostReceipt, makeRecord, nodeOpen, rawPublic } from "./hpke-node.mjs";

const S = await loadTS("secretseal");
const fixture = (name) => JSON.parse(readFileSync(new URL(`./fixtures/${name}`, import.meta.url), "utf8"));
const goVector = fixture("secretseal-vector-v1.json");
const rfc = fixture("hpke-rfc9180-a2-1.json");
const fromHex = (s) => new Uint8Array(Buffer.from(s, "hex"));
const at = Date.parse("2026-10-02T00:00:01Z");
const x25519Raw = (priv) => new Uint8Array(rawPublic(priv));

// The Go copy must match the fixture byte for byte when the repository is
// present, so the test notices a regenerated vector.
test("the fixture is the Go known-answer vector", () => {
  let go;
  try {
    go = readFileSync(new URL("../../internal/secretseal/testdata/vector-v1.json", import.meta.url), "utf8");
  } catch {
    return;
  }
  assert.equal(readFileSync(new URL("./fixtures/secretseal-vector-v1.json", import.meta.url), "utf8"), go);
});

// ---- RFC 9180 ------------------------------------------------------------------
test("HPKE seal reproduces RFC 9180 A.2.1 exactly with the vector's ephemeral key", async () => {
  const e = rfc.encryption;
  const out = await S.hpkeSeal(fromHex(rfc.pkRm), fromHex(rfc.info), fromHex(e.aad), fromHex(e.pt), fromHex(rfc.skEm));
  assert.equal(Buffer.from(out.enc).toString("hex"), rfc.enc);
  assert.equal(Buffer.from(out.ct).toString("hex"), e.ct);
  assert.equal(Buffer.from(out.exporter).toString("hex"), rfc.exporter_secret);
  for (const x of rfc.exports) {
    const got = await S.hpkeExport(out.exporter, fromHex(x.exporter_context), x.L);
    assert.equal(Buffer.from(got).toString("hex"), x.exported_value);
  }
  const opened = await S.hpkeOpen(fromHex(rfc.skRm), out.enc, fromHex(rfc.info), fromHex(e.aad), out.ct);
  assert.equal(Buffer.from(opened.plaintext).toString("hex"), e.pt);
  const independent = nodeOpen(fromHex(rfc.skRm), out.enc, fromHex(rfc.info), fromHex(e.aad), out.ct);
  assert.equal(independent.plaintext.toString("hex"), e.pt);
});

test("ChaCha20-Poly1305 equals OpenSSL for many lengths and refuses tampering", () => {
  for (let n = 0; n < 200; n++) {
    const key = randomBytes(32);
    const nonce = randomBytes(12);
    const pt = randomBytes((n * 7) % 300);
    const aad = randomBytes((n * 3) % 41);
    const c = createCipheriv("chacha20-poly1305", key, nonce, { authTagLength: 16 });
    c.setAAD(aad, { plaintextLength: pt.length });
    const want = Buffer.concat([c.update(pt), c.final(), c.getAuthTag()]);
    const got = S.chachaPolySeal(new Uint8Array(key), new Uint8Array(nonce), new Uint8Array(pt), new Uint8Array(aad));
    assert.equal(Buffer.from(got).toString("hex"), want.toString("hex"));
    assert.equal(Buffer.from(S.chachaPolyOpen(new Uint8Array(key), new Uint8Array(nonce), got, new Uint8Array(aad))).toString("hex"), pt.toString("hex"));
    const bad = got.slice();
    bad[n % bad.length] ^= 1;
    assert.throws(() => S.chachaPolyOpen(new Uint8Array(key), new Uint8Array(nonce), bad, new Uint8Array(aad)));
  }
});

// ---- the Go known-answer vector -----------------------------------------------------
test("the Go vector's signed record verifies against the pinned host key", async () => {
  const { pub } = ed25519FromSeed(goVector.host_ed25519_seed);
  const fp = await S.hostKeyFingerprint(pub);
  assert.equal(fp, goVector.record.record.host_key);
  const key = await S.verifyKeyRecord(goVector.record, pub, fp, goVector.target_id, at);
  assert.equal(key.keyID, goVector.record.record.key_id);
  assert.equal(S.b64url(key.publicKey), goVector.record.record.public_key);
  assert.match(await S.hostKeyID(pub), /^ed25519:[0-9a-f]{32}$/);
});

test("the browser opens the Go envelope and verifies the Go receipt", async () => {
  const opened = await S.openEnvelope(fromHex(goVector.seal_x25519_private), goVector.envelope);
  assert.equal(Buffer.from(opened.value).toString(), goVector.plaintext);
  const fingerprint = await S.verifyReceipt({ envelope: goVector.envelope, confirm: opened.confirm }, goVector.receipt);
  assert.equal(fingerprint, goVector.fingerprint);
});

test("a browser-sealed envelope opens with the Go host key in an independent implementation", async () => {
  const { pub } = ed25519FromSeed(goVector.host_ed25519_seed);
  const key = await S.verifyKeyRecord(goVector.record, pub, await S.hostKeyFingerprint(pub), goVector.target_id, at);
  const value = S.utf8("sk-test-FAKE-browser-value");
  const sealed = await S.seal(key, goVector.target_id, "browser", value, at);
  const e = sealed.envelope;
  assert.equal(e.format, "agentgate.secretseal.v1");
  assert.equal(e.version, at);
  assert.equal(e.key_id, goVector.record.record.key_id);
  assert.match(e.nonce, /^[0-9a-f]{32}$/);
  const raw = S.b64urlStrict(e.sealed);
  const independent = nodeOpen(fromHex(goVector.seal_x25519_private), raw.subarray(0, 32), S.envelopeInfo(e.key_id, e.target_id), S.envelopeAAD(e), raw.subarray(32));
  assert.equal(independent.plaintext.toString(), "sk-test-FAKE-browser-value");
  // The host's receipt verifies with the browser's in-memory confirm secret.
  const receipt = hostReceipt(e, independent.confirm, "sfp1_" + "ab".repeat(16));
  assert.equal(await S.verifyReceipt(sealed, receipt), receipt.fingerprint);
  // A receipt for another nonce, or with a forged tag, fails.
  await assert.rejects(S.verifyReceipt(sealed, { ...receipt, nonce: "0".repeat(32) }), { code: "receipt" });
  await assert.rejects(S.verifyReceipt(sealed, { ...receipt, tag: S.b64url(new Uint8Array(32)) }), { code: "receipt" });
  // The associated data binds target, name and version: changing any fails.
  for (const change of [{ name: "other" }, { target_id: "other-target" }, { version: e.version + 1 }, { nonce: "1".repeat(32) }]) {
    await assert.rejects(S.openEnvelope(fromHex(goVector.seal_x25519_private), { ...e, ...change }));
  }
  S.wipe(sealed);
  assert.ok(sealed.confirm.every((b) => b === 0));
});

// ---- key substitution (must fail) ------------------------------------------------------
test("a substituted host key or seal key is refused", async () => {
  const { pub } = ed25519FromSeed(goVector.host_ed25519_seed);
  const pinned = await S.hostKeyFingerprint(pub);
  const approved = await S.hostKeyID(pub);
  const attacker = generateKeyPairSync("ed25519");
  const attackerPub = new Uint8Array(Buffer.from(attacker.publicKey.export({ format: "jwk" }).x, "base64url"));
  const attackerSeal = x25519Raw(generateKeyPairSync("x25519").privateKey);
  const forged = await makeRecord(attacker.privateKey, attackerPub, attackerSeal, goVector.target_id, "2026-10-01T00:00:00Z", "2026-10-31T00:00:00Z");
  // 1. The service presents its own host key: neither the approved host_key_id
  //    nor this browser's pin matches.
  assert.notEqual(await S.hostKeyID(attackerPub), approved);
  await assert.rejects(S.verifyKeyRecord(forged, attackerPub, pinned, goVector.target_id, at), { code: "fingerprint" });
  // 2. The service keeps the real host key but signs a record with its own key.
  await assert.rejects(S.verifyKeyRecord(forged, pub, pinned, goVector.target_id, at), { code: "signature" });
  // 3. The service swaps only the seal key in the genuine record.
  const swapped = { ...goVector.record, record: { ...goVector.record.record, public_key: S.b64url(attackerSeal) } };
  await assert.rejects(S.verifyKeyRecord(swapped, pub, pinned, goVector.target_id, at), { code: "signature" });
  // 4. A genuine record for another target, an expired record, a bad signature encoding.
  await assert.rejects(S.verifyKeyRecord(goVector.record, pub, pinned, "another-target", at), { code: "context" });
  await assert.rejects(S.verifyKeyRecord(goVector.record, pub, pinned, goVector.target_id, Date.parse("2026-11-01T00:00:00Z")), { code: "key_record" });
  await assert.rejects(S.verifyKeyRecord({ ...goVector.record, signature: goVector.record.signature + "=" }, pub, pinned, goVector.target_id, at), { code: "signature" });
  // 5. A seal for a key that was never verified for this target is refused.
  const key = await S.verifyKeyRecord(goVector.record, pub, pinned, goVector.target_id, at);
  await assert.rejects(S.seal(key, "another-target", "x", S.utf8("v"), at), { code: "context" });
  await assert.rejects(S.seal(key, goVector.target_id, "Bad Name", S.utf8("v"), at), { code: "context" });
  await assert.rejects(S.seal(key, goVector.target_id, "x", new Uint8Array(0), at), { code: "value" });
  await assert.rejects(S.seal(key, goVector.target_id, "x", new Uint8Array(S.MAX_VALUE_BYTES + 1), at), { code: "value" });
});

test("a fresh record from a host key verifies; the same record under another pin does not", async () => {
  const host = generateKeyPairSync("ed25519");
  const hostPub = new Uint8Array(Buffer.from(host.publicKey.export({ format: "jwk" }).x, "base64url"));
  const sealPriv = generateKeyPairSync("x25519").privateKey;
  const sealPub = x25519Raw(sealPriv);
  const now = Date.now();
  const rec = await makeRecord(host.privateKey, hostPub, sealPub, "0123456789abcdef0123456789abcdef", new Date(now - 60000).toISOString().replace(/\.\d+Z$/, "Z"), new Date(now + 86400000).toISOString().replace(/\.\d+Z$/, "Z"));
  const key = await S.verifyKeyRecord(rec, hostPub, await S.hostKeyFingerprint(hostPub), "0123456789abcdef0123456789abcdef", now);
  const sealed = await S.seal(key, "0123456789abcdef0123456789abcdef", "model-api", S.utf8("value"), now);
  const raw = S.b64urlStrict(sealed.envelope.sealed);
  const skR = new Uint8Array(Buffer.from(sealPriv.export({ format: "jwk" }).d, "base64url"));
  assert.equal(nodeOpen(skR, raw.subarray(0, 32), S.envelopeInfo(key.keyID, key.targetID), S.envelopeAAD(sealed.envelope), raw.subarray(32)).plaintext.toString(), "value");
  await assert.rejects(S.verifyKeyRecord(rec, hostPub, "SHA256:" + "A".repeat(43), "0123456789abcdef0123456789abcdef", now), { code: "fingerprint" });
});

test("strict base64url matches Go's RawURLEncoding.Strict", () => {
  assert.deepEqual([...S.b64urlStrict("AQID")], [1, 2, 3]);
  assert.equal(S.b64url(new Uint8Array([255, 254])), "__4");
  for (const bad of ["AQID=", "AQ+D", "A", "AR", "AQ="]) assert.throws(() => S.b64urlStrict(bad));
  assert.equal(S.b64std(new Uint8Array([251, 255])), "+/8");
});

test("support detection finds WebCrypto Ed25519 and X25519 in this runtime", async () => {
  const support = await S.sealSupport();
  assert.deepEqual(support, { ok: true, missing: [] });
});

test("the envelope's wire form is secretseal.Envelope.Encode and its digest is over the decoded bytes", async () => {
  const encoded = S.encodeEnvelope(goVector.envelope);
  const json = Buffer.from(encoded, "base64url").toString();
  // Go's json.Marshal writes the fields in struct order without spaces.
  assert.equal(json, JSON.stringify({ format: goVector.envelope.format, target_id: goVector.envelope.target_id, name: goVector.envelope.name, version: goVector.envelope.version, key_id: goVector.envelope.key_id, nonce: goVector.envelope.nonce, sealed: goVector.envelope.sealed }));
  assert.doesNotMatch(encoded, /[=+/]/);
  const digest = await S.envelopeDigest(encoded);
  assert.equal(digest, Buffer.from(await crypto.subtle.digest("SHA-256", Buffer.from(json))).toString("hex"));
});

test("only values the broker can inject are sealed", () => {
  assert.equal(S.brokerValueOK(S.utf8("sk-test-1234")), true);
  for (const bad of ["short", "has space inside", "line\nbreak", "tab\there!!", "é-accented-value"]) assert.equal(S.brokerValueOK(S.utf8(bad)), false, bad);
  assert.equal(S.brokerValueOK(new Uint8Array(8193).fill(0x41)), false);
});
