// CF Access authentication middleware (SPEC §6.1). A TS port of Go cfaccess.go plus
// ISSUER PINNING (absent in the Go original). Steps (all MUST, in order; failure → 401):
//   1. Read Cf-Access-Jwt-Assertion; absent → 401 AUTH_REQUIRED.
//   2. Parse the header; alg RS256|ES256; kid required.
//   3. Resolve kid against the JWKS (1 h cache; unknown kid → one refetch, then fail).
//   4. Signature + exp/nbf (leeway ≤ 60 s).
//   5. ISSUER PINNING: iss == https://{team_domain} (else 401 ISSUER_MISMATCH).
//   6. AUD: must contain the route class's AUD (else 403 AUD_MISMATCH). On the long
//      READ host (ACCESS_LONG_HOST) that is the long READ app's AUD, and only there.
//   7. Identity: human (email) | service token (common_name, NO email).
//   8. HUMAN ONLY: the verified assertion must carry the caller's own OAuth session
//      (requireOAuthSession): a signed `oauth` claim {client_id, client_redirect_uri}
//      of a client registered on a 127.0.0.1 / localhost redirect (the wapps CLI,
//      logged in through Access Managed OAuth), and no `warp_as_auth`; else 401
//      DEVICE_SESSION_ONLY (audited as a deny). Access also admits a Cloudflare One
//      client device session and then injects an assertion for ANY program on that
//      device; only the OAuth claim proves the caller itself logged in (1cb9a4c1).
//      Access does not forward the bearer, so nothing the caller sends is read:
//      headers and the CF_Authorization cookie (which Access adds itself for a
//      device session) do not count. Both claims are signed by Access.
//   9. The FORGEABLE Cf-Access-Authenticated-User-Email header is IGNORED and stripped.
// Fail-closed: missing config → 503 SERVICE_MISCONFIGURED.

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
  // A1/A2 burst-detector window counters (best-effort; errors are caught at the call site).
  RATE: KVNamespace;
  // §6.1 per-principal limiter (Workers Rate Limiting binding; 60 per 60 s, see ratelimit.ts).
  RATE_LIMITER: RateLimit;
  // §3.2 adım 3: get-identity sonuç cache'i (yalnızca GECİKME optimizasyonu —
  // grup-tazeliği sınırı DEĞİL; pinli: kendi namespace'i, §8.5).
  IDENTITY_CACHE: KVNamespace;
  ACCESS_TEAM_DOMAIN?: string;
  ACCESS_AUD_READ?: string;
  ACCESS_AUD_WRITE?: string;
  // The long READ app (204fffcc): a second READ app with a 24h session on its own host.
  // Its AUD is accepted only on that host, and only for read-class routes.
  ACCESS_LONG_HOST?: string;
  ACCESS_AUD_READ_LONG?: string;
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
  /** The long READ app's host (lower case) and AUD; "" when not configured. */
  longHost: string;
  audReadLong: string;
  issuer: string;
  certsURL: string;
}

/** RouteAud, the AUD a route class needs: the READ app's, the long READ app's (only on its
 * host) or the WRITE app's (/v1/admin, only on the gate's own host). */
export type RouteAud = "read" | "readLong" | "write";

export const FORGEABLE_EMAIL_HEADER = "Cf-Access-Authenticated-User-Email";
const ACCESS_ASSERTION_HEADER = "Cf-Access-Jwt-Assertion";
const LEEWAY_SECONDS = 60;
const JWKS_TTL_MS = 60 * 60 * 1000; // 1 saat (§6.1 step 3)
/** KID_REFETCH_COOLDOWN_MS: an unknown kid refetches the JWKS only when the cached set
 * is at least this old (L5). A real Access key rotation is seen within a minute. */
export const KID_REFETCH_COOLDOWN_MS = 60 * 1000;

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
    longHost: (env.ACCESS_LONG_HOST ?? "").trim().toLowerCase(),
    audReadLong: (env.ACCESS_AUD_READ_LONG ?? "").trim(),
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
    // Bilinmeyen kid → refetch (§6.1 step 3), but at most once per cooldown (L5):
    // otherwise any caller could make every request fetch the JWKS with a made-up kid.
    if (Date.now() - cached.fetchedAt < KID_REFETCH_COOLDOWN_MS) return null;
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
  sub?: string;
  email?: string;
  common_name?: string;
  /** Present on a device session (Cloudflare One client) assertion. */
  warp_as_auth?: unknown;
  /** Present on an OAuth bearer request: the registered client and its redirect. */
  oauth?: unknown;
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
 * routeAud: bu rotanın gerektirdiği AUD (RouteAud, §6.1 step 6).
 * cfaccess.go'nun aksine iss PINLENİR ve forgeable email header'ı YOK SAYILIR
 * (kimlik yalnızca imzalı JWT'den).
 */
export async function authenticate(request: Request, cfg: AccessConfig, routeAud: RouteAud): Promise<Principal> {
  const token = request.headers.get(ACCESS_ASSERTION_HEADER);
  if (!token) throw new AuthFail(HTTP.UNAUTHORIZED, "AUTH_REQUIRED", "missing access assertion");

  const claims = await verifyAccessJWT(token, cfg);
  const wantAud = { read: cfg.audRead, readLong: cfg.audReadLong, write: cfg.audWrite }[routeAud];
  // An unconfigured AUD is never matched (the caller refuses that route before this).
  if (!wantAud) throw new AuthFail(HTTP.FORBIDDEN, "AUD_MISMATCH", "audience mismatch");
  if (!audContains(claims.aud, wantAud)) throw new AuthFail(HTTP.FORBIDDEN, "AUD_MISMATCH", "audience mismatch");

  // (7) İki kimlik şekli. FORGEABLE header ASLA okunmaz — kimlik imzalı JWT'den.
  const email = typeof claims.email === "string" ? claims.email.trim() : "";
  if (email) {
    const principal: Principal = { kind: "human", id: `human:${email}`, email };
    requireOAuthSession(claims, principal.id);
    return principal;
  }
  const cn = typeof claims.common_name === "string" ? claims.common_name.trim() : "";
  if (cn) return { kind: "service", id: `service:${cn}`, commonName: cn };
  throw new AuthFail(HTTP.UNAUTHORIZED, "AUTH_INVALID", "no identity claim");
}

/** DeviceSessionOnly, a human assertion that does not prove the caller's own OAuth session
 * (step 8). It names the asserted principal so the refusal is audited under it. */
export class DeviceSessionOnly extends AuthFail {
  constructor(public principalId: string, msg: string) {
    super(HTTP.UNAUTHORIZED, "DEVICE_SESSION_ONLY", msg);
  }
}

const OAUTH_RECOVERY =
  "run 'wapps login'; a Cloudflare One device session or a browser session alone does not identify the program that sent this request";

/** isLoopbackRedirect, true when `uri` is an http URL whose host is exactly 127.0.0.1 or localhost. */
function isLoopbackRedirect(uri: unknown): boolean {
  if (typeof uri !== "string") return false;
  let url: URL;
  try {
    url = new URL(uri);
  } catch {
    return false;
  }
  return url.protocol === "http:" && (url.hostname === "127.0.0.1" || url.hostname === "localhost");
}

/**
 * requireOAuthSession, step 8: the already verified assertion must prove the caller's own
 * OAuth session. A device session (`warp_as_auth`) is refused even when an `oauth` claim is
 * present; otherwise `oauth` must be an object with a non-empty string `client_id` and a
 * `client_redirect_uri` on a loopback host (a CLI on this machine).
 */
function requireOAuthSession(claims: VerifiedClaims, principalId: string): void {
  if (claims.warp_as_auth !== undefined && claims.warp_as_auth !== false) {
    throw new DeviceSessionOnly(principalId, `the request came through a device session; ${OAUTH_RECOVERY}`);
  }
  const oauth = claims.oauth;
  if (typeof oauth !== "object" || oauth === null || Array.isArray(oauth)) {
    throw new DeviceSessionOnly(principalId, `the caller has no OAuth session of its own; ${OAUTH_RECOVERY}`);
  }
  const { client_id, client_redirect_uri } = oauth as { client_id?: unknown; client_redirect_uri?: unknown };
  if (typeof client_id !== "string" || client_id === "" || !isLoopbackRedirect(client_redirect_uri)) {
    throw new DeviceSessionOnly(principalId, `the OAuth session is not a local client's; ${OAUTH_RECOVERY}`);
  }
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
