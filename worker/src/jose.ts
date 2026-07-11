// Ortak JOSE/base64url yardımcıları (opsiyonel mint katmanı, §5.3). Worker'ın
// tuttuğu tek imza anahtarı sınıfı MINT_KEY'dir (§8.5). Bu dosya yalnızca
// kodlama + ES256 JWS mekaniğini içerir; anahtar politikası çağıranlarda.

const utf8Encoder = new TextEncoder();
export function utf8(s: string): Uint8Array {
  return utf8Encoder.encode(s);
}

/** b64urlEncode, ham baytları padding'siz base64url'e kodlar (JOSE). */
export function b64urlEncode(bytes: Uint8Array): string {
  let bin = "";
  for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
  return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

/** b64urlDecode, base64url string'i ham baytlara çözer (padding toleranslı). */
export function b64urlDecode(s: string): Uint8Array {
  const b64 = s.replace(/-/g, "+").replace(/_/g, "/") + "===".slice((s.length + 3) % 4);
  const bin = atob(b64);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

export function b64urlEncodeStr(s: string): string {
  return b64urlEncode(utf8(s));
}

export function jsonToB64url(obj: unknown): string {
  return b64urlEncodeStr(JSON.stringify(obj));
}

// --- uuidv7 (zaman-sıralı jti, §6.4) --------------------------------------

/**
 * uuidv7, RFC 9562 v7 UUID üretir (unix-ms timestamp + random). jti'lerin
 * zaman-sıralı olması için (audit sıralaması, deny-list TTL mantığı).
 */
export function uuidv7(): string {
  const now = Date.now();
  const bytes = new Uint8Array(16);
  crypto.getRandomValues(bytes);
  // 48-bit ms timestamp big-endian.
  bytes[0] = (now / 2 ** 40) & 0xff;
  bytes[1] = (now / 2 ** 32) & 0xff;
  bytes[2] = (now / 2 ** 24) & 0xff;
  bytes[3] = (now / 2 ** 16) & 0xff;
  bytes[4] = (now / 2 ** 8) & 0xff;
  bytes[5] = now & 0xff;
  bytes[6] = (bytes[6] & 0x0f) | 0x70; // version 7
  bytes[8] = (bytes[8] & 0x3f) | 0x80; // variant 10
  const h = [...bytes].map((b) => b.toString(16).padStart(2, "0"));
  return `${h[0]}${h[1]}${h[2]}${h[3]}-${h[4]}${h[5]}-${h[6]}${h[7]}-${h[8]}${h[9]}-${h[10]}${h[11]}${h[12]}${h[13]}${h[14]}${h[15]}`;
}

// --- ES256 JWS imza/doğrulama (WebCrypto) ----------------------------------

export interface PrivJwk {
  kty: string;
  crv: string;
  d: string;
  x: string;
  y: string;
  kid?: string;
}
export interface PubJwk {
  kty: string;
  crv: string;
  x: string;
  y: string;
  kid?: string;
}

/** importEs256Private, ES256 imza için özel JWK'yı yükler (non-extractable). */
export async function importEs256Private(jwk: PrivJwk): Promise<CryptoKey> {
  return crypto.subtle.importKey("jwk", jwk as JsonWebKey, { name: "ECDSA", namedCurve: "P-256" }, false, ["sign"]);
}

/** importEs256Public, ES256 doğrulama için genel JWK'yı yükler. */
export async function importEs256Public(jwk: PubJwk): Promise<CryptoKey> {
  const pub = { kty: jwk.kty, crv: jwk.crv, x: jwk.x, y: jwk.y };
  return crypto.subtle.importKey("jwk", pub as JsonWebKey, { name: "ECDSA", namedCurve: "P-256" }, false, ["verify"]);
}

/**
 * signCompactJWS, {header, claims}'i ES256 compact JWS'e imzalar. WebCrypto ECDSA
 * çıktısı ham r‖s (P1363, JOSE) → base64url. Header'da kid + alg=ES256 zorunlu.
 */
export async function signCompactJWS(privKey: CryptoKey, header: Record<string, unknown>, claims: Record<string, unknown>): Promise<string> {
  const signingInput = `${jsonToB64url(header)}.${jsonToB64url(claims)}`;
  const sig = new Uint8Array(await crypto.subtle.sign({ name: "ECDSA", hash: "SHA-256" }, privKey, utf8(signingInput)));
  return `${signingInput}.${b64urlEncode(sig)}`;
}

/** parseJwsHeader, compact JWS'in header'ını (imza doğrulaMADAN) çözer — kid seçimi için. */
export function parseJwsHeader(token: string): { alg?: string; kid?: string; typ?: string } {
  const parts = token.split(".");
  if (parts.length !== 3) throw new Error("bad jws");
  return JSON.parse(new TextDecoder().decode(b64urlDecode(parts[0])));
}

/** verifyCompactJWS, compact JWS imzasını verilen public anahtarla doğrular; claims döner ya da null. */
export async function verifyCompactJWS(pubKey: CryptoKey, token: string): Promise<Record<string, unknown> | null> {
  const parts = token.split(".");
  if (parts.length !== 3) return null;
  const signingInput = utf8(`${parts[0]}.${parts[1]}`);
  let sig: Uint8Array;
  try {
    sig = b64urlDecode(parts[2]);
  } catch {
    return null;
  }
  if (sig.length !== 64) return null; // ES256 = ham 64-bayt r‖s; DER reddedilir
  let ok = false;
  try {
    ok = await crypto.subtle.verify({ name: "ECDSA", hash: "SHA-256" }, pubKey, sig, signingInput);
  } catch {
    ok = false;
  }
  if (!ok) return null;
  try {
    return JSON.parse(new TextDecoder().decode(b64urlDecode(parts[1])));
  } catch {
    return null;
  }
}
