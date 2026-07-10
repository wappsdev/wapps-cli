// Verify-only kripto primitifleri (SPEC §3). Worker ASLA çözmez ve HİÇBİR özel
// anahtar tutmaz — kripto yüzeyi yalnızca DOĞRULAMA'dır: sha256, Ed25519 verify,
// ECDSA-P256 verify (P1363 64-bayt r‖s, sha256 digest üzerinde), X25519 alıcı
// parmak izi ve manifest hash/verify. Bayt formatları Go çekirdeğiyle (internal/
// cryptoid) TAM eşleşmelidir; frozen_vectors.json çapraz-testi bunu kilitler.
//
// XChaCha20/age/decrypt BU DOSYADA YOKTUR ve olmamalıdır (§6 intro).

import { ed25519 } from "@noble/curves/ed25519";
import { p256 } from "@noble/curves/p256";
import { sha256 as nobleSha256 } from "@noble/hashes/sha256";

// --- Kodlama yardımcıları -------------------------------------------------

const HEX = "0123456789abcdef";

/** bytesToHex, ham baytları küçük-harf hex'e çevirir (§3.7 parmak izleri, hash'ler). */
export function bytesToHex(b: Uint8Array): string {
  let s = "";
  for (let i = 0; i < b.length; i++) {
    s += HEX[b[i] >> 4] + HEX[b[i] & 0x0f];
  }
  return s;
}

/** hexToBytes, küçük/büyük-harf hex string'i ham baytlara çevirir. */
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

/**
 * b64ToBytes, standart RFC 4648 base64'ü (padding'li — Go'nun []byte JSON
 * kodlaması) ham baytlara çözer. workerd atob binary-string döner.
 */
export function b64ToBytes(b64: string): Uint8Array {
  const bin = atob(b64);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

/** bytesToB64, ham baytları standart base64'e (padding'li) kodlar. */
export function bytesToB64(b: Uint8Array): string {
  let bin = "";
  for (let i = 0; i < b.length; i++) bin += String.fromCharCode(b[i]);
  return btoa(bin);
}

const utf8Encoder = new TextEncoder();
/** utf8, bir string'in UTF-8 baytlarını döner (recipient parmak izi girdisi). */
export function utf8(s: string): Uint8Array {
  return utf8Encoder.encode(s);
}

/** bytesEqual, sabit-uzunlukta değilse false; içerik karşılaştırması. */
export function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i];
  return diff === 0;
}

// --- Hash -----------------------------------------------------------------

/** sha256, ham baytların SHA-256 digest'ini döner (v1'de TEK digest, §3.1). */
export function sha256(data: Uint8Array): Uint8Array {
  return nobleSha256(data);
}

/** sha256Hex, SHA-256'nın küçük-harf hex'ini döner (blob/manifest içerik adresi). */
export function sha256Hex(data: Uint8Array): string {
  return bytesToHex(sha256(data));
}

// --- Algoritma registry (kapalı küme, §3.2) -------------------------------

export const ALG_ED25519 = "ed25519";
export const ALG_ECDSA_P256_SHA256 = "ecdsa-p256-sha256";
export const SIG_SCHEMA = "wapps-secrets/sig/v1";
export const FINGERPRINT_PREFIX = "sha256:";

const P256_SCALAR_LEN = 32;
const ED25519_PUB_LEN = 32;
const P256_SEC1_LEN = 65; // 0x04 ‖ X(32) ‖ Y(32)

// --- Parmak izi (§3.7) ----------------------------------------------------

/**
 * fingerprint, sistemdeki HER anahtar için tek parmak izi formatı:
 * "sha256:" + ham public key baytlarının SHA-256'sının küçük-harf hex'i (§3.7).
 * Girdi: Ed25519 = 32B pubkey, P-256 = 65B SEC1, şifreleme = recipient UTF-8.
 */
export function fingerprint(pubBytes: Uint8Array): string {
  return FINGERPRINT_PREFIX + sha256Hex(pubBytes);
}

/**
 * fingerprintRecipient, bir age recipient string'inin (canonical bech32)
 * §3.7 parmak izidir: sha256:<hex> of the CANONICAL recipient string UTF-8.
 * Worker alıcıyı asla skalardan türetmez; yalnızca string üzerinden hash'ler.
 *
 * Ham baytları HİÇ trim ETMEDEN hash'ler → Go çekirdeği cryptoid.FingerprintRecipient
 * ile TAM parite (o da `Fingerprint([]byte(recipient))`, trim YOK). Boşluk kırpma —
 * gerekiyorsa — Go'daki gibi PARSE zamanında yapılır (encid.go: ParseX25519Recipient
 * `strings.TrimSpace` + age canonical `String()`), bu primitivin içinde DEĞİL. İçeride
 * trim yapmak boşluk-dolgulu girdi için divergent parmak izi üretirdi.
 */
export function fingerprintRecipient(recipient: string): string {
  return fingerprint(utf8(recipient));
}

// --- İmza doğrulama (§3.6.2) ----------------------------------------------

/** Signature, ayrık imzanın depolanan formu (§3.6.1). sig base64-decoded. */
export interface Signature {
  schema: string;
  key_id: string;
  alg: string;
  sig: Uint8Array;
}

/** SignedObject, imzalı sarmalayıcının decode edilmiş hali. bytes = TAM baytlar. */
export interface SignedObject {
  bytes: Uint8Array;
  sigs: Signature[];
}

/** VerifierKey, bir key_id'yi doğrulamak için gereken alg + ham pubkey. */
export interface VerifierKey {
  alg: string;
  keyID: string;
  pub: Uint8Array; // Ed25519: 32B, P-256: 65B SEC1
}

/**
 * newVerifierKey, alg + ham pubkey baytlarından VerifierKey kurar ve key_id'yi
 * §3.7'ye göre türetir. Ham bayt formatı §3.6.1 (Ed25519 32B, P-256 65B SEC1).
 * Kapalı-küme dışı alg / geçersiz nokta → hata (ALG_UNSUPPORTED semantiği).
 */
export function newVerifierKey(alg: string, pub: Uint8Array): VerifierKey {
  switch (alg) {
    case ALG_ED25519:
      if (pub.length !== ED25519_PUB_LEN) throw new Error("ALG_UNSUPPORTED: ed25519 pubkey must be 32 bytes");
      return { alg, pub, keyID: fingerprint(pub) };
    case ALG_ECDSA_P256_SHA256:
      if (pub.length !== P256_SEC1_LEN || pub[0] !== 0x04) throw new Error("ALG_UNSUPPORTED: P-256 pubkey must be 65-byte uncompressed SEC1");
      // Noktanın eğri üzerinde olduğunu doğrula (deprecated Unmarshal yerine).
      p256.Point.fromHex(pub);
      return { alg, pub, keyID: fingerprint(pub) };
    default:
      throw new Error(`ALG_UNSUPPORTED: ${alg}`);
  }
}

/**
 * verifyRaw, TAM msg baytları üzerinden imzayı doğrular (§3.6.2/§3.6.3):
 * D = SHA-256(msg) hesapla, sonra alg'a göre D üzerinde doğrula.
 * ECDSA: YALNIZCA ham 64-bayt r‖s (P1363); DER kesinlikle REDDEDİLİR (§3.2).
 * ECDSA malleability: Go ecdsa.Verify high-S kabul eder → lowS: false ile eşle.
 */
export function verifyRaw(vk: VerifierKey, msg: Uint8Array, sig: Uint8Array): boolean {
  const d = sha256(msg);
  switch (vk.alg) {
    case ALG_ED25519:
      if (sig.length !== 64) return false;
      try {
        return ed25519.verify(sig, d, vk.pub);
      } catch {
        return false;
      }
    case ALG_ECDSA_P256_SHA256:
      // Ham 64-bayt r‖s (P1363) dışındaki her şey (özellikle DER) reddedilir.
      // Go ecdsa.Verify high-S kabul eder → lowS:false ile parite.
      if (sig.length !== 2 * P256_SCALAR_LEN) return false;
      try {
        return p256.verify(sig, d, vk.pub, { lowS: false });
      } catch {
        return false;
      }
    default:
      return false;
  }
}

/**
 * verifySignatureEnvelope, tek bir Signature'ı verilen VerifierKey ile msg
 * üzerinde doğrular. Schema, alg tutarlılığı ve key_id eşleşmesi kontrol edilir
 * (§3.6.1). Herhangi biri tutmazsa false (fail-closed).
 */
export function verifySignatureEnvelope(msg: Uint8Array, s: Signature, vk: VerifierKey): boolean {
  if (s.schema !== SIG_SCHEMA) return false;
  if (s.alg !== vk.alg) return false;
  if (s.key_id !== vk.keyID) return false;
  return verifyRaw(vk, msg, s.sig);
}

// --- Sarmalayıcı parse (imza ÖNCESİ hash için ham baytlar) -----------------

interface RawSig {
  schema?: unknown;
  key_id?: unknown;
  alg?: unknown;
  sig?: unknown;
}
interface RawSignedObject {
  bytes?: unknown;
  sigs?: unknown;
}

/**
 * parseSignedObject, depolanan sarmalayıcı JSON'unu ({bytes,sigs}) SignedObject'e
 * çözer: bytes ve her sig.sig base64→bayt decode edilir. Bu YALNIZCA sarmalayıcı
 * kabuğunu açar — imzalı BODY hâlâ ham baytlardır ve doğrulanana kadar PARSE
 * EDİLMEZ (§3.6.3). Yapısal bozukluk → hata.
 */
export function parseSignedObject(raw: unknown): SignedObject {
  const o = raw as RawSignedObject;
  if (typeof o !== "object" || o === null) throw new Error("SIG_INVALID: signed object not an object");
  if (typeof o.bytes !== "string") throw new Error("SIG_INVALID: missing bytes");
  if (!Array.isArray(o.sigs)) throw new Error("SIG_INVALID: missing sigs");
  const sigs: Signature[] = o.sigs.map((s: RawSig) => {
    if (typeof s !== "object" || s === null) throw new Error("SIG_INVALID: sig not an object");
    if (typeof s.schema !== "string" || typeof s.key_id !== "string" || typeof s.alg !== "string" || typeof s.sig !== "string") {
      throw new Error("SIG_INVALID: malformed sig envelope");
    }
    return { schema: s.schema, key_id: s.key_id, alg: s.alg, sig: b64ToBytes(s.sig) };
  });
  return { bytes: b64ToBytes(o.bytes), sigs };
}
