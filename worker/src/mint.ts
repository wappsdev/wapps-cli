// Makine-token mint + doğrulama (SPEC §6.4). Woodpecker'da OIDC yoktur: makine
// bootstrap = statik per-repo CF Access service-token; TEK gücü kısa-TTL scoped
// token'a EXCHANGE'dir. Mint yalnızca POST /v1/token'da (§6.1 step 8) yapılır.
//
// Token = ES256 JWS, header.kid = aktif mint kid, MINT_KEY ile imzalanır. Dual-key
// rotation: MINT_KEY imzalar, MINT_KEY_PREV yalnızca DOĞRULAR (≥1 TTL penceresi).

import { PrivJwk, PubJwk, importEs256Private, importEs256Public, signCompactJWS, verifyCompactJWS, parseJwsHeader, uuidv7 } from "./jose.js";

export const MINT_ISS = "wapps-secrets-gate";
export const MINT_AUD = "wapps-secrets-data";
export const TTL_MAX_SECONDS = 600; // 10 dk hard cap (§6.4 rule 3)
const CLOCK_LEEWAY = 5; // exp/iat küçük tolerans

export interface TokenScope {
  verbs: string[]; // read | write | rotate
  keys: string[]; // exact key adları; ["*"] insan-yerine izin verilmez (makine allowlist)
}

export interface MintedClaims {
  iss: string;
  // sub = mint EDEN principal'ın id'si ("service:<common_name>") — token.ts mint
  // anında dış CF-Access-doğrulanmış principal'dan yazar. resolveMachinePrincipal
  // bu alanı dış principal'a EŞİTLİK için doğrular (principal binding); minted
  // token kendi ihraççısından başka bir kimliğe ASLA adapte edilemez.
  sub: string;
  aud: string;
  project: string;
  scope: TokenScope;
  jti: string;
  iat: number;
  exp: number;
}

// --- Mint anahtar konfigürasyonu (env'den) ---------------------------------

interface MintKeyEntry {
  kid: string;
  jwk: PrivJwk | PubJwk;
  canSign: boolean;
}

export interface MintEnv {
  MINT_KEY?: string; // aktif ES256 özel JWK (imzalar)
  MINT_KEY_PREV?: string; // önceki kid (yalnızca doğrular) — rotation penceresi
}

/** loadMintConfig, MINT_KEY(+PREV)'i parse eder; MINT_KEY eksik/bozuksa null (fail-closed config). */
export function loadMintConfig(env: MintEnv): { active: MintKeyEntry; all: MintKeyEntry[] } | null {
  const activeRaw = (env.MINT_KEY ?? "").trim();
  if (!activeRaw) return null;
  let activeJwk: PrivJwk;
  try {
    activeJwk = JSON.parse(activeRaw) as PrivJwk;
  } catch {
    return null;
  }
  if (!activeJwk.kid || !activeJwk.d || activeJwk.crv !== "P-256") return null;
  const active: MintKeyEntry = { kid: activeJwk.kid, jwk: activeJwk, canSign: true };
  const all: MintKeyEntry[] = [active];
  const prevRaw = (env.MINT_KEY_PREV ?? "").trim();
  if (prevRaw) {
    try {
      const prevJwk = JSON.parse(prevRaw) as PubJwk;
      if (prevJwk.kid && prevJwk.crv === "P-256" && prevJwk.kid !== active.kid) {
        all.push({ kid: prevJwk.kid, jwk: prevJwk, canSign: false });
      }
    } catch {
      // Bozuk PREV yok sayılır — aktif anahtar geçerli kaldığı sürece fail-closed değil.
    }
  }
  return { active, all };
}

/** activeMintKid, imzalayan aktif kid (metadata/audit için). */
export function activeMintKid(env: MintEnv): string | null {
  const cfg = loadMintConfig(env);
  return cfg ? cfg.active.kid : null;
}

// --- Mint --------------------------------------------------------------------

export interface MintRequest {
  sub: string;
  project: string;
  scope: TokenScope;
  ttlSeconds: number;
}

export interface MintResult {
  token: string;
  jti: string;
  exp: number;
  ttl: number;
}

/**
 * mintToken, kısa-TTL ES256 scoped token üretir (§6.4). ttl_seconds ≤ 600'e
 * CLAMP edilir (asla aşılmaz). kid = aktif mint kid; jti = uuidv7.
 */
export async function mintToken(env: MintEnv, req: MintRequest): Promise<MintResult> {
  const cfg = loadMintConfig(env);
  if (!cfg) throw new Error("MINT_KEY missing/invalid");
  const ttl = Math.min(req.ttlSeconds > 0 ? Math.floor(req.ttlSeconds) : TTL_MAX_SECONDS, TTL_MAX_SECONDS);
  const now = Math.floor(Date.now() / 1000);
  const jti = uuidv7();
  const claims: MintedClaims = {
    iss: MINT_ISS,
    sub: req.sub,
    aud: MINT_AUD,
    project: req.project,
    scope: req.scope,
    jti,
    iat: now,
    exp: now + ttl,
  };
  const priv = await importEs256Private(cfg.active.jwk as PrivJwk);
  const header = { alg: "ES256", kid: cfg.active.kid, typ: "JWT" };
  const token = await signCompactJWS(priv, header, claims as unknown as Record<string, unknown>);
  return { token, jti, exp: claims.exp, ttl };
}

// --- Doğrulama (§6.1 step 9) ------------------------------------------------

export type MintVerifyError =
  | "TOKEN_MALFORMED"
  | "TOKEN_UNKNOWN_KID"
  | "TOKEN_SIG_INVALID"
  | "TOKEN_CLAIMS_INVALID"
  | "TOKEN_EXPIRED";

export interface VerifiedToken {
  sub: string;
  project: string;
  scope: TokenScope;
  jti: string;
  exp: number;
}

/**
 * verifyMintedToken, minted machine-token'ı doğrular (§6.1 step 9 — jti deny-list
 * kontrolü HARİÇ; onu çağıran KV ile yapar): kid → aktif mint anahtarlarından biri,
 * ES256 imza, iss/aud, exp (TTL construction'la ≤600s). Başarısızlık → tipli hata.
 */
export async function verifyMintedToken(env: MintEnv, token: string): Promise<{ ok: true; claims: VerifiedToken } | { ok: false; error: MintVerifyError }> {
  const cfg = loadMintConfig(env);
  if (!cfg) return { ok: false, error: "TOKEN_SIG_INVALID" }; // mint config yok → doğrulanamaz (fail-closed)
  let hdr: { alg?: string; kid?: string };
  try {
    hdr = parseJwsHeader(token);
  } catch {
    return { ok: false, error: "TOKEN_MALFORMED" };
  }
  if (hdr.alg !== "ES256" || !hdr.kid) return { ok: false, error: "TOKEN_MALFORMED" };
  const entry = cfg.all.find((k) => k.kid === hdr.kid);
  if (!entry) return { ok: false, error: "TOKEN_UNKNOWN_KID" };
  const pub = await importEs256Public(entry.jwk as PubJwk);
  const claims = await verifyCompactJWS(pub, token);
  if (!claims) return { ok: false, error: "TOKEN_SIG_INVALID" };

  const c = claims as unknown as Partial<MintedClaims>;
  if (c.iss !== MINT_ISS || c.aud !== MINT_AUD) return { ok: false, error: "TOKEN_CLAIMS_INVALID" };
  if (typeof c.sub !== "string" || typeof c.project !== "string" || typeof c.jti !== "string") return { ok: false, error: "TOKEN_CLAIMS_INVALID" };
  if (!c.scope || !Array.isArray(c.scope.verbs) || !Array.isArray(c.scope.keys)) return { ok: false, error: "TOKEN_CLAIMS_INVALID" };
  if (typeof c.exp !== "number") return { ok: false, error: "TOKEN_CLAIMS_INVALID" };
  const now = Math.floor(Date.now() / 1000);
  if (now > c.exp + CLOCK_LEEWAY) return { ok: false, error: "TOKEN_EXPIRED" };
  return { ok: true, claims: { sub: c.sub, project: c.project, scope: { verbs: c.scope.verbs, keys: c.scope.keys }, jti: c.jti, exp: c.exp } };
}

// --- Scope yardımcıları (per-key confinement, §6.3/§6.4) --------------------

/** scopeAllowsVerb, token scope'unun bir verb'i kapsayıp kapsamadığı. §4.2 pinli
 * rotate⊃write genişletmesi BURADA DA uygulanır: rotasyon, değer yazımlarını normal
 * data-plane write rotalarından yürütür; rotate-scoped bir minted token bu yazmaları
 * da kapsamalıdır (policy expandVerbs ile tutarlı — daha dar semantik server-side
 * uygulanamaz). */
export function scopeAllowsVerb(scope: TokenScope, verb: string): boolean {
  if (scope.verbs.includes(verb)) return true;
  return verb === "write" && scope.verbs.includes("rotate");
}

/** scopeAllowsKey, token scope'unun bir anahtarı kapsayıp kapsamadığı ("*" = tümü).
 *  Anahtar adları case-insensitive KİMLİK olduğundan (policy keyGlobMatch ile tutarlı;
 *  writer-DO farklı-case varyantı reddeder), eşleşme CASE-INSENSITIVE'dir. */
export function scopeAllowsKey(scope: TokenScope, key: string): boolean {
  const lk = key.toLowerCase();
  return scope.keys.some((k) => k === "*" || k.toLowerCase() === lk);
}
