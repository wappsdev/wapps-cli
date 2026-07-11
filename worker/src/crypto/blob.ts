// At-rest değer zarfı — WSB1 (SPEC §2.1, ZK §3.5.1–§3.5.4 ile bayt-özdeş, FROZEN).
// Server-decrypt pivotunda TÜM zarf kriptosu server-side (§2.7): Worker padler,
// mühürler (seal) ve açar (open). Format:
//   padded  = uint32-BE len ‖ plaintext ‖ zero-fill  → kova 256B / 1KB / 4KB(+4KB)
//   blob    = "WSB1" ‖ nonce(24, random) ‖ XChaCha20-Poly1305(DEK, nonce, padded, AAD)
//   AAD     = project ‖ 0x00 ‖ keyName ‖ 0x00 ‖ keyVersion(decimal ASCII)
//   adres   = SHA-256(tüm depolanan baytlar), 64 KB depolama tavanı.
// Açarken zero-fill + kova-içi uzunluk DOĞRULANIR (tutmazsa tamper → BLOB_MALFORMED).
// Çapraz-dil frozen vektörleri (test/vectors/frozen_vectors.json "blob") release gate'idir.

import { xchacha20poly1305 } from "@noble/ciphers/chacha.js";
import { utf8 } from "./encoding.js";
import { slotAAD } from "./kek.js";

export const BLOB_MAGIC = "WSB1";
export const BLOB_CAP = 65_536; // depolanan bayt tavanı (§2.1)
const NONCE_LEN = 24;
const TAG_LEN = 16;
export const BLOB_OVERHEAD = 4 + NONCE_LEN + TAG_LEN; // 44
const MAX_BUCKET = Math.floor((BLOB_CAP - BLOB_OVERHEAD) / 4096) * 4096; // 61440
export const PLAINTEXT_MAX = MAX_BUCKET - 4; // 61436 (uint32 length prefix düşülür)

/** BlobError, zarf hata sınıfı (§7.5 error contract kodları). */
export class BlobError extends Error {
  constructor(public code: "VALUE_TOO_LARGE" | "BLOB_MALFORMED" | "PADDING_INVALID", msg?: string) {
    super(msg ?? code);
    this.name = "BlobError";
  }
}

/** bucketFor, len+4'ün düştüğü padding kovasını döner (§2.1); tavan aşımı → VALUE_TOO_LARGE. */
export function bucketFor(plaintextLen: number): number {
  const n = plaintextLen + 4;
  if (n <= 256) return 256;
  if (n <= 1024) return 1024;
  const bucket = Math.ceil(n / 4096) * 4096;
  if (bucket > MAX_BUCKET) throw new BlobError("VALUE_TOO_LARGE", "value exceeds 64 KB stored cap");
  return bucket;
}

/** validFramingLength, depolanan blob uzunluğunun kova framing'ine uyduğunu doğrular. */
export function validFramingLength(len: number): boolean {
  const bucket = len - BLOB_OVERHEAD;
  if (bucket === 256 || bucket === 1024) return true;
  return bucket >= 4096 && bucket <= MAX_BUCKET && bucket % 4096 === 0;
}

/**
 * sealValue, plaintext'i WSB1 blob'una mühürler (§2.1). nonce parametresi YALNIZCA
 * test determinizmi (frozen vector) içindir; üretimde verilmez → CSPRNG 24 bayt.
 */
export function sealValue(
  dek: Uint8Array,
  project: string,
  keyName: string,
  keyVersion: number,
  plaintext: Uint8Array,
  nonce?: Uint8Array,
): Uint8Array {
  const bucket = bucketFor(plaintext.length); // VALUE_TOO_LARGE burada fırlar (pre-upload)
  const padded = new Uint8Array(bucket); // zero-fill
  new DataView(padded.buffer).setUint32(0, plaintext.length, false); // uint32-BE
  padded.set(plaintext, 4);
  const n = nonce ?? crypto.getRandomValues(new Uint8Array(NONCE_LEN));
  if (n.length !== NONCE_LEN) throw new BlobError("BLOB_MALFORMED", "nonce must be 24 bytes");
  const aad = slotAAD(project, keyName, keyVersion);
  const ct = xchacha20poly1305(dek, n, aad).encrypt(padded); // bucket+16
  const out = new Uint8Array(4 + NONCE_LEN + ct.length);
  out.set(utf8(BLOB_MAGIC), 0);
  out.set(n, 4);
  out.set(ct, 4 + NONCE_LEN);
  return out;
}

/**
 * openValue, bir WSB1 blob'unu açar ve padding'i DOĞRULAR (§2.1): magic + framing
 * uzunluğu + AEAD + kova-içi uzunluk + zero-fill. Herhangi biri tutmazsa tamper →
 * BLOB_MALFORMED (AEAD/padding) veya PADDING_INVALID (framing) — fail-closed.
 */
export function openValue(
  dek: Uint8Array,
  project: string,
  keyName: string,
  keyVersion: number,
  blob: Uint8Array,
): Uint8Array {
  if (blob.length > BLOB_CAP) throw new BlobError("PADDING_INVALID", "blob exceeds 64 KB cap");
  if (!validFramingLength(blob.length)) throw new BlobError("PADDING_INVALID", "blob length not a valid framing length");
  if (new TextDecoder().decode(blob.slice(0, 4)) !== BLOB_MAGIC) throw new BlobError("BLOB_MALFORMED", "bad blob magic");
  const n = blob.slice(4, 4 + NONCE_LEN);
  const ct = blob.slice(4 + NONCE_LEN);
  const aad = slotAAD(project, keyName, keyVersion);
  let padded: Uint8Array;
  try {
    padded = xchacha20poly1305(dek, n, aad).decrypt(ct);
  } catch {
    throw new BlobError("BLOB_MALFORMED", "blob AEAD open failed");
  }
  const bucket = padded.length;
  const len = new DataView(padded.buffer, padded.byteOffset, padded.byteLength).getUint32(0, false);
  // Kova-içi uzunluk (§2.1): len, kovaya sığmalı.
  if (len > bucket - 4) throw new BlobError("BLOB_MALFORMED", "declared length exceeds bucket");
  // Zero-fill doğrulaması (§2.1): dolgu baytlarının TAMAMI sıfır olmalı.
  for (let i = 4 + len; i < bucket; i++) {
    if (padded[i] !== 0) throw new BlobError("BLOB_MALFORMED", "nonzero padding fill");
  }
  return padded.slice(4, 4 + len);
}
