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
import { TokenScope, verifyMintedToken } from "./mint.js";

export interface Env {
  SECRETS_BUCKET: R2Bucket;
  PROJECT_WRITER: DurableObjectNamespace;
  AUDIT_LOG: DurableObjectNamespace;
  // P2.4: tek-instance SchedulerDO (§8.3 zamanlama — cron yerine DO alarm).
  SCHEDULER: DurableObjectNamespace;
  AUDIT_DB: D1Database;
  JTI_DENYLIST: KVNamespace;
  RATE: KVNamespace;
  // §3.2 adım 3: get-identity sonuç cache'i (yalnızca GECİKME optimizasyonu —
  // grup-tazeliği sınırı DEĞİL; pinli: kendi namespace'i, §8.5).
  IDENTITY_CACHE: KVNamespace;
  ACCESS_TEAM_DOMAIN?: string;
  ACCESS_AUD_READ?: string;
  ACCESS_AUD_WRITE?: string;
  // §2.2 MASTER_KEK (64-hex Worker secret'ı) + rotasyon penceresi PREV (§2.5).
  MASTER_KEK?: string;
  MASTER_KEK_PREV?: string;
  // §4.5 kök admin çapası (virgülle ayrılmış e-postalar; first-boot + lockout kurtarma).
  ADMIN_EMAILS?: string;
  // Worker secret'ları (§5.3 opsiyonel mint katmanı, alert webhook'u).
  MINT_KEY?: string;
  MINT_KEY_PREV?: string;
  DISCORD_WEBHOOK_URL?: string;
  // §8.3 escrow write-through — NON-Cloudflare B2 replika hedefi (append-only key).
  B2_ENDPOINT?: string;
  B2_REGION?: string;
  B2_BUCKET?: string;
  B2_KEY_ID?: string;
  B2_APP_KEY?: string;
  GC_ENABLED_AT?: string; // ISO; ilk 30 gün DRY-RUN (GC cron)
  // Arch §5.2 tofu state → B2 replikasyonu: wapps-tofu-state bucket binding'i
  // (YALNIZCA prod wrangler.jsonc — staging'e asla verilmez; yoksa cron no-op).
  STATE_BUCKET?: R2Bucket;
  // Alert-on-read sentinel listesi (arch §2.3 Token A invariant'ı): virgülle
  // ayrılmış anahtar-adı glob'ları (ör. "TF_VAR_worker_admin_token,CF_TOKEN_A*").
  // Eşleşen anahtarın HER başarılı plaintext okuması A11 alert'i üretir.
  ALERT_ON_READ_KEYS?: string;
  // P2.4 prod-only gate: "1" değilse SchedulerDO tamamen dormant (staging no-op).
  SCHEDULER_ENABLED?: string;
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
  // service: CF Access service-token (client-id/secret → edge JWT, common_name).
  // v2'de DOĞRUDAN data-plane'e kabul edilir (§5.1) — mint zorunluluğu YOK.
  | { kind: "service"; id: string; commonName: string }
  // machine: service token'ın POST /v1/token'da exchange ettiği OPSİYONEL minted
  // token'dan türetilir (§5.3). Scope + project token'a pinlenmiştir; policy satırı
  // ile KESİŞİR (asla genişletmez).
  | { kind: "machine"; id: string; scope: TokenScope; project: string; jti: string };

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
  if (cn) return { kind: "service", id: `service:${cn}`, commonName: cn };
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

/**
 * resolveMachinePrincipal, service-token-shaped bir isteğin data-plane'e girebilmesi
 * için (§6.1 step 8-9) geçerli bir minted machine-token GEREKTİRİR: Authorization:
 * Bearer <token>. Token ES256 doğrulanır (kid + iss/aud/exp), sonra jti KV deny-list'te
 * DEĞİL kontrol edilir (≤60s lag). Principal minted token'ın sub/scope/project'inden
 * türetilir — ASLA seed'den. Eksik token → MACHINE_TOKEN_REQUIRED; revoke → TOKEN_REVOKED.
 *
 * PRINCIPAL BINDING (privilege-escalation guard): minted token'ın sub'ı, DIŞ
 * katmanda CF Access ile doğrulanmış service principal'ın id'sine (service:<cn>)
 * EŞİT olmak ZORUNDA. Mint anında sub = mint eden principal yazılır (token.ts);
 * dolayısıyla bir minted token yalnızca KENDİ ihraççısının scope'unu daraltabilir.
 * Başka bir principal'a mint'lenmiş (ör. çalınmış/yakalanmış) token sunan bir
 * service token → TOKEN_PRINCIPAL_MISMATCH (asla başka principal'a yükselme yok).
 */
export async function resolveMachinePrincipal(request: Request, env: Env, expectedSub: string): Promise<Principal> {
  const authz = request.headers.get("authorization") ?? "";
  const m = /^Bearer\s+(.+)$/i.exec(authz.trim());
  if (!m) throw new AuthFail(HTTP.FORBIDDEN, "MACHINE_TOKEN_REQUIRED", "service token needs a minted machine token");
  const token = m[1].trim();
  const v = await verifyMintedToken(env, token);
  if (!v.ok) {
    if (v.error === "TOKEN_EXPIRED") throw new AuthFail(HTTP.FORBIDDEN, "TOKEN_EXPIRED", "minted token expired");
    throw new AuthFail(HTTP.FORBIDDEN, "MACHINE_TOKEN_REQUIRED", `minted token invalid: ${v.error}`);
  }
  // Principal binding: minted sub ≠ dış doğrulanmış principal → red (yukarıdaki blok).
  if (v.claims.sub !== expectedSub) {
    throw new AuthFail(HTTP.FORBIDDEN, "TOKEN_PRINCIPAL_MISMATCH", "minted token was not issued to this service principal");
  }
  // jti deny-list (§6.1 step 9): HER istekte kontrol; KV propagation ≤60s pinned lag.
  const denied = await env.JTI_DENYLIST.get(v.claims.jti);
  if (denied) throw new AuthFail(HTTP.FORBIDDEN, "TOKEN_REVOKED", "minted token revoked");
  return { kind: "machine", id: v.claims.sub, scope: v.claims.scope, project: v.claims.project, jti: v.claims.jti };
}
