// Epoch-reset (SPEC §4.8) doğrulama paritesi — Go internal/trust reset_test.go
// senaryolarını TS verifier'da aynalar. Reset, güven zincirinin TEK yaptırımlı
// süreksizliğidir (felaket kurtarma); geçerli bir root-imzalı reset KABUL edilir,
// bir rollback-aklama reset'i REDDEDİLİR. Worker verify-only'dir → reset manifest'i
// bu testte @noble ed25519 ile CONSTRUCT + SIGN edilir (byte-exact SignedObject).

import { describe, it, expect } from "vitest";
import { ed25519 } from "@noble/curves/ed25519";
import {
  ALG_ED25519,
  SIG_SCHEMA,
  Signature,
  SignedObject,
  bytesToB64,
  fingerprint,
  sha256,
  sha256Hex,
  utf8,
} from "../src/crypto/verify.js";
import {
  SCHEMA_TRUST,
  SCHEMA_TRUST_RESET,
  CHANGE_ROSTER,
  CHANGE_EPOCH_RESET,
  EpochResetRecord,
  Pin,
  TrustError,
  parseTrustBody,
  verifyEpochReset,
  verifyRosterChain,
} from "../src/trust.js";

// --- Test kripto/serileştirme yardımcıları ---------------------------------

interface EdKey {
  keyID: string;
  pubB64: string;
  sign(body: Uint8Array): Signature;
}

/** edKey, bir seed-bayt'ından deterministik Ed25519 anahtarı + imzalayıcı. */
function edKey(seedByte: number): EdKey {
  const seed = new Uint8Array(32).fill(seedByte);
  const pub = ed25519.getPublicKey(seed);
  const keyID = fingerprint(pub);
  return {
    keyID,
    pubB64: bytesToB64(pub),
    sign(body: Uint8Array): Signature {
      // İmza = Ed25519.Sign(sk, SHA-256(body)) — verifyRaw ile aynı digest.
      const sig = ed25519.sign(sha256(body), seed);
      return { schema: SIG_SCHEMA, key_id: keyID, alg: ALG_ED25519, sig };
    },
  };
}

function rootEntry(k: EdKey, holder: string): Record<string, unknown> {
  return { key_id: k.keyID, alg: ALG_ED25519, pubkey: k.pubB64, media: "yubikey-piv", holder, status: "active" };
}

interface ManifestOpts {
  epoch: number;
  prev: string;
  changeClass: string;
  roots: Record<string, unknown>[];
  epochReset?: EpochResetRecord | null;
}

function manifestObj(o: ManifestOpts): Record<string, unknown> {
  return {
    schema: SCHEMA_TRUST,
    admin_epoch: o.epoch,
    prev_trust_sha256: o.prev,
    created_at: "2026-07-10T12:00:00Z",
    change_class: o.changeClass,
    bootstrap_solo: true, // 3 kök tek holder → maxHolderShare 3 >= m 2
    quorum: { m: 2, n: 3 },
    roots: o.roots,
    admins: [],
    identities: [],
    grants: [],
    writer_allowlists: [],
    worker_receipt_pubkey: null,
    worker_mint_pubkeys: null,
    epoch_reset: o.epochReset ?? null,
  };
}

/** signObj, JS manifest objesini kanonik JSON baytlarına serileştirir + imzalar. */
function signObj(js: Record<string, unknown>, signers: EdKey[]): { obj: SignedObject; hash: string } {
  const bytes = utf8(JSON.stringify(js));
  const sigs = signers.map((k) => k.sign(bytes));
  return { obj: { bytes, sigs }, hash: sha256Hex(bytes) };
}

function errCode(fn: () => unknown): string {
  try {
    fn();
  } catch (e) {
    if (e instanceof TrustError) return e.code;
    throw e;
  }
  throw new Error("expected throw, got none");
}

// --- Ortak fikstür ---------------------------------------------------------

const HOLDER = "human:adnan@wapps.dev";
const r0 = edKey(0x80);
const r1 = edKey(0x81);
const r2 = edKey(0x82);
const roots = [rootEntry(r0, HOLDER), rootEntry(r1, HOLDER), rootEntry(r2, HOLDER)];

function resetRecord(lastEpoch: number, lastSHA: string, id = "0192-reset", reason = "escrow_restore"): EpochResetRecord {
  return { schema: SCHEMA_TRUST_RESET, reset_id: id, reason, prior_chain: { last_admin_epoch: lastEpoch, last_trust_sha256: lastSHA }, snapshot_ref: "snap-1" };
}

describe("epoch_reset (§4.8) verify parity", () => {
  it("standalone: a valid root-signed reset (head available) is ACCEPTED", () => {
    const { obj: priorObj, hash: priorSHA } = signObj(manifestObj({ epoch: 41, prev: "deadbeef", changeClass: CHANGE_ROSTER, roots }), [r0, r1]);
    const prior = parseTrustBody(priorObj.bytes);
    const { obj: resetObj } = signObj(manifestObj({ epoch: 42, prev: priorSHA, changeClass: CHANGE_EPOCH_RESET, roots, epochReset: resetRecord(41, priorSHA) }), [r0, r1]);
    const ep = verifyEpochReset(resetObj, prior, priorSHA, { admin_epoch: 41, sha256: "" }, 41, true);
    expect(ep.manifest.admin_epoch).toBe(42);
    expect(ep.manifest.epoch_reset?.reason).toBe("escrow_restore");
  });

  it("standalone: <M root signatures → TRUST_QUORUM_UNMET", () => {
    const { obj: priorObj, hash: priorSHA } = signObj(manifestObj({ epoch: 41, prev: "deadbeef", changeClass: CHANGE_ROSTER, roots }), [r0, r1]);
    const prior = parseTrustBody(priorObj.bytes);
    const { obj: reset1 } = signObj(manifestObj({ epoch: 42, prev: priorSHA, changeClass: CHANGE_EPOCH_RESET, roots, epochReset: resetRecord(41, priorSHA) }), [r0]); // 1-of-3
    expect(errCode(() => verifyEpochReset(reset1, prior, priorSHA, { admin_epoch: 41, sha256: "" }, 41, true))).toBe("TRUST_QUORUM_UNMET");
  });

  it("standalone: downgrade guard — pinned epoch newer than reset prior → TRUST_DOWNGRADE", () => {
    const { obj: priorObj, hash: priorSHA } = signObj(manifestObj({ epoch: 41, prev: "deadbeef", changeClass: CHANGE_ROSTER, roots }), [r0, r1]);
    const prior = parseTrustBody(priorObj.bytes);
    const { obj: resetObj } = signObj(manifestObj({ epoch: 42, prev: priorSHA, changeClass: CHANGE_EPOCH_RESET, roots, epochReset: resetRecord(41, priorSHA) }), [r0, r1]);
    // Pin epoch 45 > reset prior 41 → rollback aklama, red.
    expect(errCode(() => verifyEpochReset(resetObj, prior, priorSHA, { admin_epoch: 45, sha256: "" }, 41, true))).toBe("TRUST_DOWNGRADE");
  });

  it("standalone: reset epoch must exceed the witness bound → TRUST_CHAIN_BROKEN", () => {
    const { obj: priorObj, hash: priorSHA } = signObj(manifestObj({ epoch: 41, prev: "deadbeef", changeClass: CHANGE_ROSTER, roots }), [r0, r1]);
    const prior = parseTrustBody(priorObj.bytes);
    const { obj: resetObj } = signObj(manifestObj({ epoch: 42, prev: priorSHA, changeClass: CHANGE_EPOCH_RESET, roots, epochReset: resetRecord(41, priorSHA) }), [r0, r1]);
    // witnessBound 42 >= reset 42 → red.
    expect(errCode(() => verifyEpochReset(resetObj, prior, priorSHA, { admin_epoch: 41, sha256: "" }, 42, true))).toBe("TRUST_CHAIN_BROKEN");
  });

  it("standalone: lost-head (escrow-restore) requires empty prev — empty accepts, filled rejects", () => {
    const { obj: priorObj, hash: priorSHA } = signObj(manifestObj({ epoch: 41, prev: "deadbeef", changeClass: CHANGE_ROSTER, roots }), [r0, r1]);
    const prior = parseTrustBody(priorObj.bytes);
    // Kayıp head: prev "" → kabul.
    const { obj: okObj } = signObj(manifestObj({ epoch: 42, prev: "", changeClass: CHANGE_EPOCH_RESET, roots, epochReset: resetRecord(41, priorSHA) }), [r0, r1]);
    const ep = verifyEpochReset(okObj, prior, priorSHA, { admin_epoch: 0, sha256: "" }, 0, false);
    expect(ep.manifest.admin_epoch).toBe(42);
    // Kayıp head yolunda prev DOLU → red.
    const { obj: badObj } = signObj(manifestObj({ epoch: 42, prev: priorSHA, changeClass: CHANGE_EPOCH_RESET, roots, epochReset: resetRecord(41, priorSHA) }), [r0, r1]);
    expect(errCode(() => verifyEpochReset(badObj, prior, priorSHA, { admin_epoch: 0, sha256: "" }, 0, false))).toBe("TRUST_CHAIN_BROKEN");
  });

  it("standalone: wrong reset schema → TRUST_CHAIN_BROKEN", () => {
    const { obj: priorObj, hash: priorSHA } = signObj(manifestObj({ epoch: 41, prev: "deadbeef", changeClass: CHANGE_ROSTER, roots }), [r0, r1]);
    const prior = parseTrustBody(priorObj.bytes);
    const bad = resetRecord(41, priorSHA);
    bad.schema = "wapps-trust/v1"; // reset şeması değil
    const { obj: resetObj } = signObj(manifestObj({ epoch: 42, prev: priorSHA, changeClass: CHANGE_EPOCH_RESET, roots, epochReset: bad }), [r0, r1]);
    expect(errCode(() => verifyEpochReset(resetObj, prior, priorSHA, { admin_epoch: 41, sha256: "" }, 41, true))).toBe("TRUST_CHAIN_BROKEN");
  });

  it("in-chain: a genesis→reset walk is accepted (head available)", () => {
    const { obj: gObj, hash: gHash } = signObj(manifestObj({ epoch: 1, prev: "", changeClass: CHANGE_ROSTER, roots }), [r0, r1]);
    const gPin: Pin = { admin_epoch: 1, sha256: gHash };
    const { obj: resetObj } = signObj(manifestObj({ epoch: 5, prev: gHash, changeClass: CHANGE_EPOCH_RESET, roots, epochReset: resetRecord(1, gHash, "0192-walk", "quorum_recovery") }), [r0, r1]);
    const head = verifyRosterChain(gPin, gPin, [gObj, resetObj], null);
    expect(head.manifest.admin_epoch).toBe(5);
  });

  it("in-chain: rollback laundering — an old-epoch-signed reset cannot rewind past the client pin → TRUST_DOWNGRADE", () => {
    // genesis(1) → E2..E5 no-op roster epoch'ları; her biri 2-of-3 kökle imzalı.
    const { obj: gObj, hash: gHash } = signObj(manifestObj({ epoch: 1, prev: "", changeClass: CHANGE_ROSTER, roots }), [r0, r1]);
    const chain: SignedObject[] = [gObj];
    let parentHash = gHash;
    for (let e = 2; e <= 5; e++) {
      const { obj, hash } = signObj(manifestObj({ epoch: e, prev: parentHash, changeClass: CHANGE_ROSTER, roots }), [r0, r1]);
      chain.push(obj);
      parentHash = hash;
    }
    // reset: prior=E5(5), admin_epoch 100'e sıçrar; E5'in kökleriyle imzalı.
    const { obj: resetObj } = signObj(manifestObj({ epoch: 100, prev: parentHash, changeClass: CHANGE_EPOCH_RESET, roots, epochReset: resetRecord(5, parentHash, "0192-rollback", "quorum_recovery") }), [r0, r1]);
    chain.push(resetObj);
    // İstemci epoch 7'yi görmüş (pinnedLast=7). reset prior=5 < 7 → downgrade.
    const gPin: Pin = { admin_epoch: 1, sha256: gHash };
    const pinnedLast: Pin = { admin_epoch: 7, sha256: "ab" + gHash.slice(2) };
    expect(errCode(() => verifyRosterChain(gPin, pinnedLast, chain, null))).toBe("TRUST_DOWNGRADE");
  });
});
