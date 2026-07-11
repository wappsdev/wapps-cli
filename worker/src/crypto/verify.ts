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

// Kanonik standart base64 alfabesi + isteğe bağlı 1-2 padding '=' (yalnızca sonda).
// Boşluk, b64url ('-'/'_') ve fazla/eksik padding bu regex'te ELENİR.
const STRICT_B64_RE = /^[A-Za-z0-9+/]*={0,2}$/;

/**
 * b64ToBytes, standart RFC 4648 base64'ü (padding'li — Go base64.StdEncoding
 * paritesi) ham baytlara çözer. KATİ KANONİK: bu decoder yalnızca imzalı
 * sarmalayıcı/sig ve trust anahtar pubkey'lerini çözmek için kullanılır ve
 * bunlar için kanoniklik GÜVENLİK-KRİTİKTİR — dış sarmalayıcının KENDİSİ
 * imzalanmadığından, gevşek bir decoder (workerd atob unpadded/whitespace/
 * non-canonical son-bayt bitlerini KABUL eder) bir saldırganın `bytes`/`sig`
 * base64'ünü İMZALANAN payload'ı hiç bozmadan yeniden-kodlamasına izin verirdi
 * → Worker DOĞRULAR ama Go REDDEDER (veya tersi) → read/trust DESYNC. Bu yüzden:
 *   1) uzunluk %4==0 (padding'li),
 *   2) yalnızca kanonik alfabe + sondaki '=' (boşluk/b64url/iç padding red),
 *   3) roundtrip: bytesToB64(decoded)===input (non-canonical son-bayt bitleri
 *      dahil TEK kanonik kodlamayı zorlar — Go base64.StdEncoding.Strict paritesi).
 * Herhangi biri tutmazsa hata (fail-closed).
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
  // Kanoniklik kilidi: kodlama TEK olmalı; aksi halde yeniden-kodlama saldırısı açık kalır.
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

// --- JSON parse katılığı (Go parse paritesi, §3.6.3) ----------------------
//
// Bunlar KRİPTO DEĞİLDİR; imzalı body'lerin Go json decode'uyla BYTE-parite
// içinde ayrıştırılması için ortak katılık yardımcılarıdır. trust.ts + manifest.ts
// ikisi de burayı import eder (çift import merkezi).

// RFC3339 alanlarını AYRI yakala: yıl, ay, gün, saat, dakika, saniye, (ops. kesir),
// ve zaman-dilimi ya "Z" ya da ±hh:mm (işaret + zone-saat + zone-dakika).
const RFC3339_RE =
  /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.\d+)?(?:Z|([+-])(\d{2}):(\d{2}))$/;

/** isLeapYear, Gregoryen artık-yıl kuralı (Go time paketiyle aynı). */
function isLeapYear(year: number): boolean {
  return (year % 4 === 0 && year % 100 !== 0) || year % 400 === 0;
}

/** daysInMonth, ay (1-12) + yıl için takvim-gerçek gün sayısı (Şubat artık-yıl duyarlı). */
function daysInMonth(year: number, month: number): number {
  const table = [31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
  if (month === 2 && isLeapYear(year)) return 29;
  return table[month - 1];
}

/**
 * isRFC3339, Go `time.Time` JSON decode'unun (time.Parse(time.RFC3339, ...))
 * kabul ettiği KATİ RFC3339 biçimini doğrular (T ayracı + saniye + Z/offset
 * zorunlu; opsiyonel kesirli saniye).
 *
 * KRİTİK: `Date.parse` yalnızca GEVŞEK değil, aynı zamanda TAKVİM-NORMALLEŞTİRİCİ'dir:
 * "2026-02-31T00:00:00Z" → 3 Mart, "2026-01-01T24:00:00Z" → ertesi gün 00:00 gibi
 * İMKANSIZ tarihleri sessizce geçerli bir Date'e taşır. Go `time.Time` bunları
 * REDDEDER → imzalı bir createdAt/created_at/enrolled_at/rotate_by için
 * Go-reddet / Worker-kabul AYRIŞMASI (read/trust brick). Bu yüzden `Date.parse`
 * KULLANILMAZ; her alan regex ile SABİT-GENİŞLİKTE ayrıştırılır ve takvim
 * aralıklarıyla (normalleştirme YOK) doğrulanır — Go time.Parse paritesi:
 *   ay 1-12, gün 1-<aydaki-gün> (Şubat artık-yıl duyarlı),
 *   saat 0-23 (24:00 Go'da YASAK), dakika/saniye 0-59,
 *   zaman-dilimi offset saati 0-24, offset dakikası 0-60 (Go zone aralığı).
 * Sabit-genişlik alan + aralık kontrolü, bileşenlerin normalleştirilmeden
 * round-trip ettiğini garanti eder. Herhangi biri tutmazsa false (fail-closed).
 */
export function isRFC3339(s: string): boolean {
  const m = RFC3339_RE.exec(s);
  if (m === null) return false;
  const year = Number(m[1]);
  const month = Number(m[2]);
  const day = Number(m[3]);
  const hour = Number(m[4]);
  const minute = Number(m[5]);
  const second = Number(m[6]);
  // Takvim aralıkları (regex 2-basamağı 00-99 kısıtlar; üst sınırları BURADA zorla).
  if (month < 1 || month > 12) return false;
  if (day < 1 || day > daysInMonth(year, month)) return false;
  if (hour > 23) return false; // Go 24:00'ı REDDEDER
  if (minute > 59) return false;
  if (second > 59) return false; // Go artık-saniye 60'ı REDDEDER
  // Zaman-dilimi offset'i "Z" değilse (±hh:mm), Go zone aralığı: saat ≤24, dakika ≤60.
  if (m[7] !== undefined) {
    const zoneHour = Number(m[8]);
    const zoneMinute = Number(m[9]);
    if (zoneHour > 24) return false;
    if (zoneMinute > 60) return false;
  }
  return true;
}

/**
 * assertCanonicalIntegerJSON, imzalı bir body metnindeki TÜM sayı literallerinin
 * Go json integer-decode paritesiyle uyumlu olduğunu doğrular. Bu manifest'lerde
 * (trust + data) HİÇBİR float alan yoktur; tüm sayılar tam sayıdır. Go, integer
 * alanına `1e3` / `1.0` gibi literalleri REDDEDER ve >2^53 değerleri TAM taşır.
 * JS `JSON.parse` ise `1e3`'ü sessizce 1000'e çevirir (literal ayrımı kaybolur)
 * ve >2^53'ü yuvarlar. Parite için: string DIŞINDAKİ her sayı token'ı kanonik
 * tam-sayı biçiminde (`(0|[1-9][0-9]*)`) ve güvenli aralıkta (≤2^53-1) olmalı;
 * değilse hata (fail-closed). String literalleri (base64/hex içerik) atlanır.
 *
 * COORD round-5 (b): imzalı tam-sayı alanları İŞARETSİZ 0..2^53-1 tanım kümesindedir;
 * `-` ile başlayan HER sayı token'ı (negatif VE `-0`) REDDEDİLİR — Go
 * cryptoid.AssertCanonicalIntegerJSON ile TAM parite (aksi halde bir taraf `-0`/negatifi
 * kabul edip diğeri reddederek consensus split doğardı).
 */
export function assertCanonicalIntegerJSON(text: string): void {
  const n = text.length;
  let i = 0;
  let inStr = false;
  while (i < n) {
    const c = text[i];
    if (inStr) {
      if (c === "\\") {
        i += 2; // kaçış dizisi (\", \\, \uXXXX ...) — bir sonraki karakteri atla
        continue;
      }
      if (c === '"') inStr = false;
      i++;
      continue;
    }
    if (c === '"') {
      inStr = true;
      i++;
      continue;
    }
    // String dışında bir sayı ancak value pozisyonunda görünür (JSON anahtarları
    // daima string'tir) → '-' veya rakamla başlayan maksimal token'ı yakala. '-'
    // ile başlayan token'ı da YAKALARIZ ki (skip edip pozitif kısmı kabul etmek
    // yerine) aşağıdaki regex onu bütün olarak REDDETSİN (COORD b: işaretsiz küme).
    if (c === "-" || (c >= "0" && c <= "9")) {
      let j = i;
      while (j < n) {
        const d = text[j];
        if ((d >= "0" && d <= "9") || d === "-" || d === "+" || d === "." || d === "e" || d === "E") j++;
        else break;
      }
      const tok = text.slice(i, j);
      // COORD (b): işaretsiz kanonik tam sayı — lider '-' YOK (negatif ve `-0` red).
      if (!/^(0|[1-9][0-9]*)$/.test(tok)) {
        throw new Error(`JSON_STRICT: non-integer number literal ${JSON.stringify(tok)}`);
      }
      if (!Number.isSafeInteger(Number(tok))) {
        throw new Error(`JSON_STRICT: integer literal out of safe range ${JSON.stringify(tok)}`);
      }
      i = j;
      continue;
    }
    i++;
  }
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
        // Go crypto/ed25519 RFC8032 COFACTORSUZ (cofactorless): non-canonical
        // (y>=P) nokta kodlamalarını ve küçük-mertebe zaafını REDDEDER, S<L
        // ister. @noble VARSAYILANI zip215:true'dur → cofactorlu denklemle
        // non-canonical/küçük-mertebe pubkey'leri KABUL eder. `{ zip215: false }`
        // ile RFC8032 moduna sabitlenir; aksi halde güvenilir bir anahtar altında
        // Worker'ın KABUL edip her Go CLI'nin REDDETTİĞİ imzalar üretilebilir
        // (trust/read desync). Bkz. frozen.test.ts ed25519_negatives çapraz-vektörleri.
        return ed25519.verify(sig, d, vk.pub, { zip215: false });
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
