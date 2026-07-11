// MASTER_KEK → per-project KEK → DEK wrap (SPEC §2.2–§2.5). Server-decrypt
// pivotunun kripto çekirdeği:
//   - MASTER_KEK: 64-char hex Worker secret'ı (32 ham bayt). MASTER_KEK_PREV
//     yalnızca rotasyon penceresinde (§2.5) doğrulama/unwrap için.
//   - kid = SHA-256(32 RAW bayt)'ın ilk 16 küçük-harf hex karakteri (§2.2 —
//     hash girdisi ASLA ASCII hex string'i değil, hex-decode edilmiş ham baytlar).
//   - KEK(project) = HKDF-SHA-256(ikm=MASTER_KEK, salt="wapps-secrets/kek/v1",
//     info=project, L=32) (§2.3). İzolat-içi düz Map cache (KV/DO'ya ASLA yazılmaz).
//   - DEK wrap: "WKW1" ‖ nonce(24) ‖ XChaCha20-Poly1305(KEK, nonce, DEK, AAD) —
//     toplam 76 bayt; AAD = blob AEAD ile AYNI slot bağlaması (§2.4).
//
// XChaCha20-Poly1305: WebCrypto'da YOK → @noble/ciphers (pinli, TCB — §2.1 not).

import { xchacha20poly1305 } from "@noble/ciphers/chacha.js";
import { hkdf } from "@noble/hashes/hkdf";
import { sha256 as nobleSha256 } from "@noble/hashes/sha256";
import { bytesToHex, hexToBytes, b64ToBytes, bytesToB64, utf8 } from "./encoding.js";

export const WRAP_RECIPIENT = "worker-kek:v1"; // kapalı küme (§2.4)
export const WRAP_MAGIC = "WKW1";
const HKDF_SALT = "wapps-secrets/kek/v1"; // 20 ASCII bayt, sabit (§2.3)
const NONCE_LEN = 24;
const DEK_LEN = 32;
const TAG_LEN = 16;
export const WRAP_TOTAL_LEN = 4 + NONCE_LEN + DEK_LEN + TAG_LEN; // 76 (§2.4)

/** MasterKey, kurulu bir master anahtar (ham 32 bayt + kid). */
export interface MasterKey {
  kid: string; // 16 küçük-harf hex (§2.2)
  key: Uint8Array; // 32 ham bayt
}

/** KekEnv, master-key secret'larının okunduğu env alt kümesi. */
export interface KekEnv {
  MASTER_KEK?: string;
  MASTER_KEK_PREV?: string;
}

const MASTER_HEX_RE = /^[0-9a-f]{64}$/;

/** kekKid, 32 ham bayttan kid türetir: sha256(raw)[0:16] hex (§2.2). */
export function kekKid(raw: Uint8Array): string {
  return bytesToHex(nobleSha256(raw)).slice(0, 16);
}

/**
 * loadMasterKeys, MASTER_KEK(+PREV)'i env'den yükler. Dönen dizi [current, prev?]
 * sıralıdır; index 0 HER ZAMAN yeni wrap'lerin anahtarıdır. MASTER_KEK eksik/
 * bozuksa null (fail-closed → 503 SERVICE_MISCONFIGURED). Bozuk PREV yok sayılır
 * (aktif anahtar geçerli kaldıkça çalışmaya devam — rotasyon penceresi opsiyonel).
 */
export function loadMasterKeys(env: KekEnv): MasterKey[] | null {
  const cur = (env.MASTER_KEK ?? "").trim().toLowerCase();
  if (!MASTER_HEX_RE.test(cur)) return null;
  const curRaw = hexToBytes(cur);
  const keys: MasterKey[] = [{ kid: kekKid(curRaw), key: curRaw }];
  const prev = (env.MASTER_KEK_PREV ?? "").trim().toLowerCase();
  if (MASTER_HEX_RE.test(prev)) {
    const prevRaw = hexToBytes(prev);
    const prevKid = kekKid(prevRaw);
    if (prevKid !== keys[0].kid) keys.push({ kid: prevKid, key: prevRaw });
  }
  return keys;
}

// İzolat-içi KEK cache (§2.3): düz Map, ASLA KV/DO storage'a yazılmaz. Anahtar
// kid+project — MASTER_KEK rotasyonunda (kid değişir) eski girdiler kullanılmaz olur.
const kekCache = new Map<string, Uint8Array>();

/** deriveProjectKEK, per-project KEK'i türetir (HKDF §2.3; izolat-içi cache). */
export function deriveProjectKEK(master: MasterKey, project: string): Uint8Array {
  const cacheKey = `${master.kid}:${project}`;
  const hit = kekCache.get(cacheKey);
  if (hit) return hit;
  const kek = hkdf(nobleSha256, master.key, utf8(HKDF_SALT), utf8(project), 32);
  kekCache.set(cacheKey, kek);
  return kek;
}

/** __resetKekCache, testler arası izolasyon içindir. */
export function __resetKekCache(): void {
  kekCache.clear();
}

/**
 * slotAAD, hem blob AEAD'inin hem DEK wrap'inin slot bağlaması (§2.1/§2.4):
 * project ‖ 0x00 ‖ keyName ‖ 0x00 ‖ keyVersion(decimal ASCII). Aynı AAD iki
 * katmanda da kullanıldığından bir wrap başka anahtara/projeye/versiyona
 * replay edilemez.
 */
export function slotAAD(project: string, keyName: string, keyVersion: number): Uint8Array {
  const p = utf8(project);
  const k = utf8(keyName);
  const v = utf8(String(keyVersion));
  const out = new Uint8Array(p.length + 1 + k.length + 1 + v.length);
  out.set(p, 0);
  out[p.length] = 0x00;
  out.set(k, p.length + 1);
  out[p.length + 1 + k.length] = 0x00;
  out.set(v, p.length + 1 + k.length + 1);
  return out;
}

/** DekWrap, manifest'te taşınan tek wrap girdisi (§2.4/§2.6). */
export interface DekWrap {
  recipient: string; // "worker-kek:v1"
  kid: string; // 16-hex master-kek id
  wrap: string; // base64(76 bayt)
}

/** WrapError, wrap/unwrap hata sınıfı (§2.4 error contract). */
export class WrapError extends Error {
  constructor(public code: "WRAP_INVALID" | "ALG_UNSUPPORTED", msg?: string) {
    super(msg ?? code);
    this.name = "WrapError";
  }
}

/**
 * wrapDEK, taze DEK'i projenin KEK'i altında sarar (§2.4). nonce parametresi
 * YALNIZCA test determinizmi içindir (frozen vector); üretimde verilmez → CSPRNG.
 */
export function wrapDEK(
  master: MasterKey,
  project: string,
  keyName: string,
  keyVersion: number,
  dek: Uint8Array,
  nonce?: Uint8Array,
): DekWrap {
  if (dek.length !== DEK_LEN) throw new WrapError("WRAP_INVALID", "dek must be 32 bytes");
  const n = nonce ?? crypto.getRandomValues(new Uint8Array(NONCE_LEN));
  if (n.length !== NONCE_LEN) throw new WrapError("WRAP_INVALID", "nonce must be 24 bytes");
  const kek = deriveProjectKEK(master, project);
  const aad = slotAAD(project, keyName, keyVersion);
  const ct = xchacha20poly1305(kek, n, aad).encrypt(dek); // 32+16 bayt
  const out = new Uint8Array(WRAP_TOTAL_LEN);
  out.set(utf8(WRAP_MAGIC), 0);
  out.set(n, 4);
  out.set(ct, 4 + NONCE_LEN);
  return { recipient: WRAP_RECIPIENT, kid: master.kid, wrap: bytesToB64(out) };
}

/**
 * unwrapDEK, bir manifest wrap'ini kid'e uyan master anahtarla (current ya da
 * prev, §2.5 rotasyon penceresi) açar. Bilinmeyen recipient → ALG_UNSUPPORTED;
 * bilinmeyen kid / bozuk çerçeve / AEAD hatası → WRAP_INVALID (503-class,
 * tamper-veya-anahtar-uyuşmazlığı, alert A8 — çağıran fail-closed davranır).
 */
export function unwrapDEK(
  masters: MasterKey[],
  project: string,
  keyName: string,
  keyVersion: number,
  w: DekWrap,
): Uint8Array {
  if (w.recipient !== WRAP_RECIPIENT) throw new WrapError("ALG_UNSUPPORTED", `unknown wrap recipient`);
  const master = masters.find((m) => m.kid === w.kid);
  if (!master) throw new WrapError("WRAP_INVALID", "wrap kid does not match any installed master key");
  let bytes: Uint8Array;
  try {
    bytes = b64ToBytes(w.wrap);
  } catch {
    throw new WrapError("WRAP_INVALID", "wrap not canonical base64");
  }
  if (bytes.length !== WRAP_TOTAL_LEN) throw new WrapError("WRAP_INVALID", "wrap length != 76");
  if (new TextDecoder().decode(bytes.slice(0, 4)) !== WRAP_MAGIC) throw new WrapError("WRAP_INVALID", "bad wrap magic");
  const n = bytes.slice(4, 4 + NONCE_LEN);
  const ct = bytes.slice(4 + NONCE_LEN);
  const kek = deriveProjectKEK(master, project);
  const aad = slotAAD(project, keyName, keyVersion);
  try {
    return xchacha20poly1305(kek, n, aad).decrypt(ct);
  } catch {
    throw new WrapError("WRAP_INVALID", "wrap AEAD open failed");
  }
}
