// WSB1 zarf testleri (SPEC §2.1 — FROZEN, ZK §3.5 ile bayt-özdeş). Go çekirdeğinin
// ürettiği frozen blob vektörü (test/vectors/frozen_vectors.json "blob") çapraz-dil
// release gate'idir: TS seal aynı (dek, nonce, AAD, plaintext) ile AYNI baytları
// üretmeli, TS open Go'nun ürettiği blob'u açmalı (§8.7 gate 2).

import { describe, it, expect } from "vitest";
import frozen from "./vectors/frozen_vectors.json";
import { sealValue, openValue, bucketFor, validFramingLength, BlobError, PLAINTEXT_MAX } from "../src/crypto/blob.js";
import { bytesToHex, hexToBytes, sha256Hex, utf8 } from "../src/crypto/encoding.js";

const V = frozen.blob;
const dek = hexToBytes(V.dek_hex);
const nonce = hexToBytes(V.nonce_hex);
const slot = V.slot; // { project: "vaulter", keyName: "DATABASE_URL", keyVersion: 3 }

describe("WSB1 frozen cross-vector (Go ↔ TS, §2.1)", () => {
  it("seal reproduces the Go-produced blob byte-for-byte (incl. content address)", () => {
    const blob = sealValue(dek, slot.project, slot.keyName, slot.keyVersion, utf8(V.plaintext), nonce);
    expect(bytesToHex(blob)).toBe(V.blob_hex);
    expect(sha256Hex(blob)).toBe(V.blob_hash);
  });

  it("open decrypts the Go-produced blob to the exact plaintext", () => {
    const blob = hexToBytes(V.blob_hex);
    expect(new TextDecoder().decode(openValue(dek, slot.project, slot.keyName, slot.keyVersion, blob))).toBe(V.plaintext);
  });

  it("AAD slot binding: wrong project/keyName/keyVersion fails to open", () => {
    const blob = hexToBytes(V.blob_hex);
    expect(() => openValue(dek, slot.project, slot.keyName, slot.keyVersion + 1, blob)).toThrowError(BlobError);
    expect(() => openValue(dek, slot.project, "API_KEY", slot.keyVersion, blob)).toThrowError(BlobError);
    expect(() => openValue(dek, "lumira", slot.keyName, slot.keyVersion, blob)).toThrowError(BlobError);
  });

  it("ciphertext tamper → BLOB_MALFORMED", () => {
    const blob = hexToBytes(V.blob_hex);
    blob[60] ^= 0x01;
    expect(() => openValue(dek, slot.project, slot.keyName, slot.keyVersion, blob)).toThrowError(BlobError);
  });
});

describe("padding buckets (§2.1)", () => {
  it("bucketFor: 256 / 1024 / 4KB steps; cap → VALUE_TOO_LARGE", () => {
    expect(bucketFor(0)).toBe(256);
    expect(bucketFor(252)).toBe(256);
    expect(bucketFor(253)).toBe(1024);
    expect(bucketFor(1020)).toBe(1024);
    expect(bucketFor(1021)).toBe(4096);
    expect(bucketFor(4093)).toBe(8192);
    expect(bucketFor(PLAINTEXT_MAX)).toBe(61440);
    expect(() => bucketFor(PLAINTEXT_MAX + 1)).toThrowError(BlobError);
  });

  it("validFramingLength accepts only bucket+overhead lengths", () => {
    expect(validFramingLength(256 + 44)).toBe(true);
    expect(validFramingLength(1024 + 44)).toBe(true);
    expect(validFramingLength(4096 + 44)).toBe(true);
    expect(validFramingLength(61440 + 44)).toBe(true);
    expect(validFramingLength(300 + 1)).toBe(false);
    expect(validFramingLength(65536 + 44)).toBe(false);
  });

  it("round-trip across bucket sizes", () => {
    for (const n of [0, 1, 252, 253, 1020, 1021, 5000, PLAINTEXT_MAX]) {
      const pt = new Uint8Array(n).map((_, i) => (i * 7) & 0xff);
      const blob = sealValue(dek, "p1", "K", 1, pt);
      expect(bytesToHex(openValue(dek, "p1", "K", 1, blob))).toBe(bytesToHex(pt));
    }
  });

  it("zero-fill + in-bucket length verification: hand-built malformed padded → BLOB_MALFORMED", async () => {
    // Zarf katmanını elle kur (geçerli AEAD, ama padding kuralları ihlalli):
    const { xchacha20poly1305 } = await import("@noble/ciphers/chacha.js");
    const { slotAAD } = await import("../src/crypto/kek.js");
    const aad = slotAAD("p1", "K", 1);
    const n = new Uint8Array(24).fill(7);
    const build = (padded: Uint8Array): Uint8Array => {
      const ct = xchacha20poly1305(dek, n, aad).encrypt(padded);
      const out = new Uint8Array(4 + 24 + ct.length);
      out.set(utf8("WSB1"), 0);
      out.set(n, 4);
      out.set(ct, 28);
      return out;
    };
    // (a) declared length > bucket-4 → BLOB_MALFORMED.
    const tooLong = new Uint8Array(256);
    new DataView(tooLong.buffer).setUint32(0, 300, false);
    expect(() => openValue(dek, "p1", "K", 1, build(tooLong))).toThrowError(BlobError);
    // (b) nonzero fill → BLOB_MALFORMED (tamper kanıtı).
    const dirty = new Uint8Array(256);
    new DataView(dirty.buffer).setUint32(0, 4, false);
    dirty.set([1, 2, 3, 4], 4);
    dirty[200] = 0xff; // dolgu bölgesinde sıfır-olmayan bayt
    expect(() => openValue(dek, "p1", "K", 1, build(dirty))).toThrowError(BlobError);
    // Kontrol: temiz dolgulu aynı kurulum AÇILIR.
    const clean = new Uint8Array(256);
    new DataView(clean.buffer).setUint32(0, 4, false);
    clean.set([1, 2, 3, 4], 4);
    expect(bytesToHex(openValue(dek, "p1", "K", 1, build(clean)))).toBe("01020304");
  });

  it("non-framing stored length → PADDING_INVALID", () => {
    const pt = new Uint8Array(8);
    const blob = sealValue(dek, "p1", "K", 1, pt);
    expect(() => openValue(dek, "p1", "K", 1, blob.slice(0, blob.length - 1))).toThrowError(BlobError);
  });
});
