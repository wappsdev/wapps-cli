// CF Access kimlik doğrulama middleware'i (SPEC §6.1). Go cfaccess.go'nun TS
// portu + ISSUER PINNING (Go orijinalinde yok). Adımlar (hepsi MUST, sırayla;
// hata → 401, denial olarak audit'lenir — audit G7):
//   1. Cf-Access-Jwt-Assertion oku; yoksa 401 AUTH_REQUIRED.
//   2. Header parse; alg RS256|ES256; kid zorunlu.
//   3. kid'i JWKS'e çöz (1 saat cache; bilinmeyen kid → 1 refetch, sonra fail).
//   4. İmza + exp/nbf (leeway ≤ 60 s).
//   5. ISSUER PINNING: iss == https://{team_domain} (yoksa 401 ISSUER_MISMATCH).
//   6. AUD: rota sınıfının AUD'unu içermeli (yoksa 403 AUD_MISMATCH).
//   7. Kimlik: human (email) | service token (common_name, email YOK).
//   8. FORGEABLE Cf-Access-Authenticated-User-Email header'ı YOK SAYILIR/STRIP.
// Fail-closed: config eksik → 503 SERVICE_MISCONFIGURED.

import { HTTP, jsonError } from "./errors.js";

export interface Env {
  SECRETS_BUCKET: R2Bucket;
  PROJECT_WRITER: DurableObjectNamespace;
  ACCESS_TEAM_DOMAIN?: string;
  ACCESS_AUD_READ?: string;
  ACCESS_AUD_WRITE?: string;
  GENESIS_TRUST_SHA256?: string;
}

export interface AccessConfig {
  teamDomain: string;
  audRead: string;
  audWrite: string;
  issuer: string;
  certsURL: string;
}

export const FORGEABLE_EMAIL_HEADER = "Cf-Access-Authenticated-User-Email";
const ACCESS_ASSERTION_HEADER = "Cf-Access-Jwt-Assertion";
const LEEWAY_SECONDS = 60;
const JWKS_TTL_MS = 60 * 60 * 1000; // 1 saat (§6.1 step 3)

/** loadAccessConfig, fail-closed config yükler; herhangi biri eksikse null. */
export function loadAccessConfig(env: Env): AccessConfig | null {
  const teamDomain = (env.ACCESS_TEAM_DOMAIN ?? "").trim();
  const audRead = (env.ACCESS_AUD_READ ?? "").trim();
  const audWrite = (env.ACCESS_AUD_WRITE ?? "").trim();
  if (!teamDomain || !audRead || !audWrite) return null;
  return {
    teamDomain,
    audRead,
    audWrite,
    issuer: `https://${teamDomain}`,
    certsURL: `https://${teamDomain}/cdn-cgi/access/certs`,
  };
}

export type Principal =
  | { kind: "human"; id: string; email: string }
  | { kind: "seed"; id: string; commonName: string };

// --- base64url --------------------------------------------------------------

function b64urlToBytes(s: string): Uint8Array {
  const b64 = s.replace(/-/g, "+").replace(/_/g, "/") + "===".slice((s.length + 3) % 4);
  const bin = atob(b64);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}
function b64urlToJSON(s: string): Record<string, unknown> {
  return JSON.parse(new TextDecoder().decode(b64urlToBytes(s)));
}

// --- JWKS cache (mockable: outbound fetch, testte cloudflare:test fetchMock) --

interface JwkEntry {
  kty: string;
  kid: string;
  crv?: string;
  x?: string;
  y?: string;
  n?: string;
  e?: string;
}
interface CachedJwks {
  keys: Map<string, CryptoKey>;
  fetchedAt: number;
}
const jwksCache = new Map<string, CachedJwks>();

/** __resetJwksCache, testler arası izolasyon içindir. */
export function __resetJwksCache(): void {
  jwksCache.clear();
}

async function importJwk(jwk: JwkEntry): Promise<CryptoKey | null> {
  try {
    if (jwk.kty === "EC") {
      return await crypto.subtle.importKey(
        "jwk",
        { kty: "EC", crv: jwk.crv, x: jwk.x, y: jwk.y },
        { name: "ECDSA", namedCurve: jwk.crv ?? "P-256" },
        false,
        ["verify"],
      );
    }
    if (jwk.kty === "RSA") {
      return await crypto.subtle.importKey(
        "jwk",
        { kty: "RSA", n: jwk.n, e: jwk.e },
        { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" },
        false,
        ["verify"],
      );
    }
  } catch {
    return null;
  }
  return null;
}

async function fetchJwks(certsURL: string): Promise<Map<string, CryptoKey>> {
  const resp = await fetch(certsURL);
  if (!resp.ok) throw new Error(`JWKS fetch status ${resp.status}`);
  const body = (await resp.json()) as { keys?: JwkEntry[] };
  const keys = new Map<string, CryptoKey>();
  for (const jwk of body.keys ?? []) {
    if (!jwk.kid) continue;
    const key = await importJwk(jwk);
    if (key) keys.set(jwk.kid, key);
  }
  const cached: CachedJwks = { keys, fetchedAt: Date.now() };
  jwksCache.set(certsURL, cached);
  return keys;
}

async function resolveKid(certsURL: string, kid: string): Promise<CryptoKey | null> {
  const cached = jwksCache.get(certsURL);
  const fresh = cached && Date.now() - cached.fetchedAt < JWKS_TTL_MS;
  if (cached && fresh) {
    const k = cached.keys.get(kid);
    if (k) return k;
    // Bilinmeyen kid → bir kez refetch (§6.1 step 3).
  }
  const keys = await fetchJwks(certsURL); // boş cache + fetch hatası → throw → fail-closed
  return keys.get(kid) ?? null;
}

// --- JWT doğrulama ----------------------------------------------------------

interface VerifiedClaims {
  iss?: string;
  aud?: unknown;
  exp?: number;
  nbf?: number;
  email?: string;
  common_name?: string;
}

async function verifyAccessJWT(token: string, cfg: AccessConfig): Promise<VerifiedClaims> {
  const parts = token.split(".");
  if (parts.length !== 3) throw new AuthFail(HTTP.UNAUTHORIZED, "AUTH_INVALID", "malformed jwt");
  let header: { alg?: string; kid?: string };
  try {
    header = b64urlToJSON(parts[0]) as { alg?: string; kid?: string };
  } catch {
    throw new AuthFail(HTTP.UNAUTHORIZED, "AUTH_INVALID", "unparseable header"); // fail-closed, never 500
  }
  if (header.alg !== "RS256" && header.alg !== "ES256") throw new AuthFail(HTTP.UNAUTHORIZED, "AUTH_INVALID", "unexpected alg");
  if (!header.kid) throw new AuthFail(HTTP.UNAUTHORIZED, "AUTH_INVALID", "missing kid");

  let key: CryptoKey | null;
  try {
    key = await resolveKid(cfg.certsURL, header.kid);
  } catch {
    throw new AuthFail(HTTP.UNAUTHORIZED, "AUTH_INVALID", "jwks unavailable"); // fail-closed
  }
  if (!key) throw new AuthFail(HTTP.UNAUTHORIZED, "AUTH_INVALID", "unknown kid");

  const signingInput = new TextEncoder().encode(parts[0] + "." + parts[1]);
  const algo = header.alg === "ES256" ? { name: "ECDSA", hash: "SHA-256" } : { name: "RSASSA-PKCS1-v1_5" };
  let ok = false;
  try {
    ok = await crypto.subtle.verify(algo, key, b64urlToBytes(parts[2]), signingInput);
  } catch {
    ok = false; // bozuk imza baytları → fail-closed
  }
  if (!ok) throw new AuthFail(HTTP.UNAUTHORIZED, "AUTH_INVALID", "bad signature");

  let claims: VerifiedClaims;
  try {
    claims = b64urlToJSON(parts[1]) as VerifiedClaims;
  } catch {
    throw new AuthFail(HTTP.UNAUTHORIZED, "AUTH_INVALID", "unparseable claims");
  }
  const now = Math.floor(Date.now() / 1000);
  // exp ZORUNLU (§6.1 step 4): eksik/sayı-olmayan exp = süresiz token → reddet.
  // Yoksa exp'siz bir JWT hiç dolmaz (fail-closed).
  if (typeof claims.exp !== "number") throw new AuthFail(HTTP.UNAUTHORIZED, "AUTH_INVALID", "missing exp");
  if (now > claims.exp + LEEWAY_SECONDS) throw new AuthFail(HTTP.UNAUTHORIZED, "AUTH_EXPIRED", "token expired");
  if (typeof claims.nbf === "number" && now < claims.nbf - LEEWAY_SECONDS) throw new AuthFail(HTTP.UNAUTHORIZED, "AUTH_INVALID", "token not yet valid");

  // (5) ISSUER PINNING — cfaccess.go'ya göre delta.
  if (claims.iss !== cfg.issuer) throw new AuthFail(HTTP.UNAUTHORIZED, "ISSUER_MISMATCH", "issuer mismatch");
  return claims;
}

function audContains(aud: unknown, want: string): boolean {
  if (typeof aud === "string") return aud === want;
  if (Array.isArray(aud)) return aud.includes(want);
  return false;
}

export class AuthFail extends Error {
  constructor(public status: number, public code: string, msg: string) {
    super(msg);
  }
  toResponse(): Response {
    return jsonError(this.status, this.code, this.message);
  }
}

/**
 * authenticate, bir isteği CF Access JWT'sine göre doğrular ve principal döner.
 * routeAud: bu rotanın gerektirdiği AUD ("read" | "write", §6.1 step 6).
 * cfaccess.go'nun aksine iss PINLENİR ve forgeable email header'ı YOK SAYILIR
 * (kimlik yalnızca imzalı JWT'den).
 */
export async function authenticate(request: Request, cfg: AccessConfig, routeAud: "read" | "write"): Promise<Principal> {
  const token = request.headers.get(ACCESS_ASSERTION_HEADER);
  if (!token) throw new AuthFail(HTTP.UNAUTHORIZED, "AUTH_REQUIRED", "missing access assertion");

  const claims = await verifyAccessJWT(token, cfg);
  const wantAud = routeAud === "read" ? cfg.audRead : cfg.audWrite;
  if (!audContains(claims.aud, wantAud)) throw new AuthFail(HTTP.FORBIDDEN, "AUD_MISMATCH", "audience mismatch");

  // (7) İki kimlik şekli. FORGEABLE header ASLA okunmaz — kimlik imzalı JWT'den.
  const email = typeof claims.email === "string" ? claims.email.trim() : "";
  if (email) return { kind: "human", id: `human:${email}`, email };
  const cn = typeof claims.common_name === "string" ? claims.common_name.trim() : "";
  if (cn) return { kind: "seed", id: `seed:${cn}`, commonName: cn };
  throw new AuthFail(HTTP.UNAUTHORIZED, "AUTH_INVALID", "no identity claim");
}

/**
 * stripForgeableHeaders, downstream'e geçmeden önce forgeable Access header'ını
 * kaldıran bir Request kopyası döner (§6.1 step 8). Worker kimliği zaten JWT'den
 * alır; bu header'ın downstream'de HİÇBİR yolla okunamaması için de temizlenir.
 */
export function stripForgeableHeaders(request: Request): Request {
  const headers = new Headers(request.headers);
  headers.delete(FORGEABLE_EMAIL_HEADER);
  return new Request(request, { headers });
}
