// Ortak kodlama + hash primitifleri (SPEC v2). ZK tasarımın imza-doğrulama
// yüzeyi (Ed25519/ECDSA envelope, fingerprint, Go-parity strict parse) server-decrypt
// pivotuyla SİLİNDİ (§0.2); geriye yalnızca hex/base64/utf8 yardımcıları ve
// SHA-256 içerik adresi kaldı (sha256Hex, §2.1 blob adresi + §6.4 audit zinciri).

import { sha256 as nobleSha256 } from "@noble/hashes/sha256";

// --- Kodlama yardımcıları ---------------------------------------------------

const HEX = "0123456789abcdef";

/** bytesToHex, ham baytları küçük-harf hex'e çevirir (hash'ler, kid). */
export function bytesToHex(b: Uint8Array): string {
  let s = "";
  for (let i = 0; i < b.length; i++) {
    s += HEX[b[i] >> 4] + HEX[b[i] & 0x0f];
  }
  return s;
}

/** hexToBytes, hex string'i ham baytlara çevirir; geçersiz hex → hata. */
export function hexToBytes(hex: string): Uint8Array {
  const h = hex.length % 2 === 1 ? "0" + hex : hex;
  const out = new Uint8Array(h.length / 2);
  for (let i = 0; i < out.length; i++) {
    const v = Number.parseInt(h.slice(i * 2, i * 2 + 2), 16);
    if (Number.isNaN(v)) throw new Error("hexToBytes: invalid hex");
    out[i] = v;
  }
  return out;
}

// Kanonik standart base64 alfabesi + isteğe bağlı 1-2 padding '=' (yalnızca sonda).
const STRICT_B64_RE = /^[A-Za-z0-9+/]*={0,2}$/;

/**
 * b64ToBytes, standart RFC 4648 base64'ü ham baytlara çözer (KATİ kanonik:
 * uzunluk %4, yalnızca kanonik alfabe, roundtrip eşitliği). DEK wrap'leri (§2.4)
 * manifest'te base64 taşınır; tek kanonik kodlama zorlanır (fail-closed).
 */
export function b64ToBytes(b64: string): Uint8Array {
  if (b64.length % 4 !== 0) throw new Error("b64ToBytes: length not a multiple of 4 (unpadded/non-canonical)");
  if (!STRICT_B64_RE.test(b64)) throw new Error("b64ToBytes: non-canonical base64 (illegal char/whitespace/misplaced padding)");
  let bin: string;
  try {
    bin = atob(b64);
  } catch {
    throw new Error("b64ToBytes: invalid base64");
  }
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  if (bytesToB64(out) !== b64) throw new Error("b64ToBytes: non-canonical base64 (roundtrip mismatch)");
  return out;
}

/** bytesToB64, ham baytları standart base64'e (padding'li) kodlar. */
export function bytesToB64(b: Uint8Array): string {
  let bin = "";
  for (let i = 0; i < b.length; i++) bin += String.fromCharCode(b[i]);
  return btoa(bin);
}

const utf8Encoder = new TextEncoder();
/** utf8, bir string'in UTF-8 baytlarını döner. */
export function utf8(s: string): Uint8Array {
  return utf8Encoder.encode(s);
}

/** bytesEqual, sabit-zamanlı içerik karşılaştırması (uzunluk farkı → false). */
export function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i];
  return diff === 0;
}

// --- Hash --------------------------------------------------------------------

/** sha256, ham baytların SHA-256 digest'ini döner. */
export function sha256(data: Uint8Array): Uint8Array {
  return nobleSha256(data);
}

/** sha256Hex, SHA-256'nın küçük-harf hex'ini döner (blob/manifest içerik adresi). */
export function sha256Hex(data: Uint8Array): string {
  return bytesToHex(sha256(data));
}
