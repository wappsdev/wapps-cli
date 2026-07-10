// Cross-vector parite testi (SPEC §3.1) — CLI↔Worker garantisi. TS doğrulayıcı,
// Go çekirdeğinin ürettiği HER imzayı doğrular, HER parmak izini byte-bayt yeniden
// üretir ve HER frozen manifest'i doğrular. Divergence = release-blocker; format
// ayrışırsa Go DONMUŞ'tur → TS düzeltilir.

import { describe, it, expect } from "vitest";
import { ed25519 } from "@noble/curves/ed25519";
import frozen from "./vectors/frozen_vectors.json";
import go from "./vectors/go-produced.json";
import {
  ALG_ED25519,
  ALG_ECDSA_P256_SHA256,
  SIG_SCHEMA,
  Signature,
  b64ToBytes,
  fingerprint,
  fingerprintRecipient,
  hexToBytes,
  newVerifierKey,
  parseSignedObject,
  sha256Hex,
  utf8,
  verifyRaw,
  verifySignatureEnvelope,
} from "../src/crypto/verify.js";
import { manifestObjectHash, verifyDataManifest, ManifestVerifyError } from "../src/manifest.js";
import { verifyGenesis, TrustError, Pin } from "../src/trust.js";

describe("frozen cross-vectors (Go → TS verify parity)", () => {
  it("ed25519: reproduces fingerprint + verifies the Go-produced signature", () => {
    const pub = ed25519.getPublicKey(hexToBytes(frozen.ed25519.seed_hex)); // test-side pub derivation
    const vk = newVerifierKey(ALG_ED25519, pub);
    expect(vk.keyID).toBe(frozen.ed25519.key_id); // parmak izi byte-bayt
    const sig = hexToBytes(frozen.ed25519.sig_hex);
    expect(verifyRaw(vk, utf8(frozen.ed25519.message), sig)).toBe(true);
    const env: Signature = { schema: SIG_SCHEMA, key_id: frozen.ed25519.key_id, alg: ALG_ED25519, sig };
    expect(verifySignatureEnvelope(utf8(frozen.ed25519.message), env, vk)).toBe(true);
    // Tampered mesaj → red.
    expect(verifyRaw(vk, utf8(frozen.ed25519.message + "x"), sig)).toBe(false);
  });

  it("X25519 recipient: reproduces the canonical-string fingerprint byte-for-byte", () => {
    expect(fingerprintRecipient(frozen.wrap.recipient)).toBe(frozen.wrap.recipient_fingerprint);
  });

  it("X25519 recipient: whitespace-padded input is NOT trimmed (Go parity — hashes raw bytes)", () => {
    // Go cryptoid.FingerprintRecipient = Fingerprint([]byte(recipient)) → trim YOK.
    // Trim, gerekiyorsa, PARSE zamanında yapılır (Go encid.go). Bu yüzden Worker'ın
    // fingerprintRecipient'ı da ham baytları trim ETMEDEN hash'lemelidir; aksi halde
    // boşluk-dolgulu girdi CLI↔Worker'da divergent parmak izi üretir.
    const padded = "  " + frozen.wrap.recipient + "\n";
    // fingerprint(utf8(x)) == Go'nun Fingerprint([]byte(x)) formülü (§3.7) →
    // fingerprintRecipient ham baytları hash'liyorsa bununla TAM eşleşmeli.
    expect(fingerprintRecipient(padded)).toBe(fingerprint(utf8(padded)));
    // Ve trim edilmiş sürümden FARKLI olmalı (içeride trim yapılmadığının kanıtı).
    expect(fingerprintRecipient(padded)).not.toBe(fingerprint(utf8(padded.trim())));
    // Trim edilmiş sürüm ise canonical (dolgusuz) parmak iziyle eşleşir.
    expect(fingerprintRecipient(padded.trim())).toBe(frozen.wrap.recipient_fingerprint);
  });

  it("blob: sha256 of the exact stored bytes == content address", () => {
    expect(sha256Hex(hexToBytes(frozen.blob.blob_hex))).toBe(frozen.blob.blob_hash);
  });

  it("ecdsa-p256-sha256: reproduces fingerprint, verifies P1363 sig, REJECTS DER", () => {
    const pub = hexToBytes(go.ecdsa.pubkey_sec1_hex);
    const vk = newVerifierKey(ALG_ECDSA_P256_SHA256, pub);
    expect(vk.keyID).toBe(go.ecdsa.key_id);
    const sig = hexToBytes(go.ecdsa.sig_hex);
    expect(verifyRaw(vk, utf8(go.ecdsa.message), sig)).toBe(true);
    // DER kesinlikle reddedilir (§3.2) — uzunluk 64 değil.
    expect(verifyRaw(vk, utf8(go.ecdsa.message), hexToBytes(go.ecdsa.sig_der_hex))).toBe(false);
    // Tampered mesaj → red.
    expect(verifyRaw(vk, utf8(go.ecdsa.message + "x"), sig)).toBe(false);
  });

  it("data manifest: verifies the Go-signed wrapper (verify-before-parse) + object hash parity", () => {
    const obj = parseSignedObject(JSON.parse(go.data_manifest.wrapper_json));
    const w = go.data_manifest.writer;
    const ring = new Map([[w.key_id, newVerifierKey(w.alg, b64ToBytes(w.pubkey_b64))]]);
    const m = verifyDataManifest(obj, ring);
    expect(m.project).toBe(go.data_manifest.expect.project);
    expect(m.epoch).toBe(go.data_manifest.expect.epoch);
    expect(m.prevManifestSha256).toBe("");
    expect(m.trustEpoch).toBe(1);
    expect(m.entries.map((e) => e.keyName).sort()).toEqual(go.data_manifest.expect.entry_key_names);
    // Object hash = sha256 of the EXACT stored wrapper bytes (§5.4.2).
    expect(manifestObjectHash(utf8(go.data_manifest.wrapper_json))).toBe(go.data_manifest.object_sha256);
  });

  it("data manifest: tampered bytes FAIL verification (SIG_INVALID)", () => {
    const obj = parseSignedObject(JSON.parse(go.data_manifest.tampered_wrapper_json));
    const w = go.data_manifest.writer;
    const ring = new Map([[w.key_id, newVerifierKey(w.alg, b64ToBytes(w.pubkey_b64))]]);
    expect(() => verifyDataManifest(obj, ring)).toThrowError(ManifestVerifyError);
    try {
      verifyDataManifest(obj, ring);
    } catch (e) {
      expect((e as ManifestVerifyError).code).toBe("SIG_INVALID");
    }
  });

  it("data manifest: unknown writer key → WRITER_UNKNOWN (empty ring)", () => {
    const obj = parseSignedObject(JSON.parse(go.data_manifest.wrapper_json));
    try {
      verifyDataManifest(obj, new Map());
      throw new Error("expected throw");
    } catch (e) {
      expect((e as ManifestVerifyError).code).toBe("WRITER_UNKNOWN");
    }
  });

  it("trust genesis: verifies 2-of-3 root M-of-N against the pinned genesis hash", () => {
    const obj = parseSignedObject(JSON.parse(go.trust_manifest.wrapper_json));
    const pin: Pin = { admin_epoch: go.trust_manifest.admin_epoch, sha256: go.trust_manifest.genesis_pin_sha256 };
    const head = verifyGenesis(pin, obj);
    expect(head.manifest.admin_epoch).toBe(1);
    expect(head.manifest.quorum).toEqual({ m: 2, n: 3 });
    expect(head.bytesSHA256).toBe(go.trust_manifest.genesis_pin_sha256);
  });

  it("trust genesis: ONE signature fails the 2-of-3 quorum", () => {
    const obj = parseSignedObject(JSON.parse(go.trust_manifest.one_sig_wrapper_json));
    const pin: Pin = { admin_epoch: 1, sha256: go.trust_manifest.genesis_pin_sha256 };
    expect(() => verifyGenesis(pin, obj)).toThrowError(TrustError);
  });

  it("trust genesis: tampered payload fails the pin hash check", () => {
    const obj = parseSignedObject(JSON.parse(go.trust_manifest.tampered_wrapper_json));
    const pin: Pin = { admin_epoch: 1, sha256: go.trust_manifest.genesis_pin_sha256 };
    expect(() => verifyGenesis(pin, obj)).toThrowError(TrustError);
  });
});
